//go:build integration

package db_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/google/uuid"
)

// This characterization deliberately demonstrates the current timestamp-feed
// limitation. It is not a successful recovery test. R07/R08 must introduce a
// commit-ordered event cursor without silently assigning ordering to timestamps.
func TestTimestampCursorCanSkipEarlierStartedLateCommit(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	aliceRequest := newWSAuthV3DBRequest(t, 0x51, db.WSAuthV3AdmissionOpen, nil)
	aliceRequest.AllowOpenRegistration = true
	alice, err := database.AdmitWSAuthV3(ctx, aliceRequest)
	if err != nil {
		t.Fatal(err)
	}
	bobRequest := newWSAuthV3DBRequest(t, 0x61, db.WSAuthV3AdmissionOpen, nil)
	bobRequest.AllowOpenRegistration = true
	bob, err := database.AdmitWSAuthV3(ctx, bobRequest)
	if err != nil {
		t.Fatal(err)
	}
	conversation, _, err := database.FindOrCreateDM(ctx, alice.User.ID, bob.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := bytes.Repeat([]byte{0x51}, 32)
	security := &db.MessageSecurityContext{
		CryptoProfile: db.MessageCryptoProfileDirectV2, CryptoEra: db.MessageCryptoEraDirectV2,
		SenderDeviceID: aliceRequest.DeviceKey[:], SenderBindingVersion: aliceRequest.BindingVersion,
		SenderDeviceDatabaseID: alice.Device.ID, SenderDeviceIdentityKey: aliceRequest.DeviceIdentityKey[:],
		SenderDeviceSigningKey: aliceRequest.DeviceSigningKey[:], SenderDeviceCapabilities: aliceRequest.BindingCapabilities,
		SenderDeviceBindingStatus: aliceRequest.BindingStatus, SenderAccountSignature: aliceRequest.BindingSignature[:],
		TargetDeviceID: bobRequest.DeviceKey[:], TargetBindingVersion: bobRequest.BindingVersion,
		TargetDeviceDatabaseID: bob.Device.ID, DirectSessionID: sessionID,
	}
	message := func(label string) *db.Message {
		header := append([]byte{0x12}, sessionID...)
		header = append(header, bytes.Repeat([]byte{1}, 41)...)
		return &db.Message{ConversationID: conversation, SenderID: alice.User.ID, Ciphertext: []byte(label + " opaque"), Header: header, SecurityContext: security}
	}
	aClientID, bClientID := uuid.NewString(), uuid.NewString()
	if _, err := database.Pool.Exec(ctx, `CREATE FUNCTION pause_early_send() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.client_message_id = '`+aClientID+`'::uuid THEN PERFORM pg_advisory_xact_lock(901004); END IF; RETURN NEW; END $$;
		CREATE TRIGGER pause_early_send BEFORE INSERT ON message_send_idempotency FOR EACH ROW EXECUTE FUNCTION pause_early_send()`); err != nil {
		t.Fatal(err)
	}
	blocker, err := database.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = blocker.Rollback(cleanup)
	}()
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(901004)`); err != nil {
		t.Fatal(err)
	}
	firstDigest := sha256.Sum256([]byte("earlier-started-late-commit"))
	type result struct {
		outcome *db.MessageSendOutcome
		err     error
	}
	resultA := make(chan result, 1)
	go func() {
		outcome, err := database.StoreMessageIdempotent(ctx, message("A"), aClientID, firstDigest[:])
		resultA <- result{outcome, err}
	}()
	// Wait for the actual INSERT transaction to reach the server-side barrier.
	// This database belongs only to this test, so another suite cannot satisfy it.
	waitCtx, stopWait := context.WithTimeout(ctx, 5*time.Second)
	defer stopWait()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := database.Pool.QueryRow(waitCtx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
			WHERE datname=current_database() AND wait_event='advisory'
			AND query LIKE 'INSERT INTO message_send_idempotency%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-waitCtx.Done():
			t.Fatal("early send did not reach deterministic barrier")
		case <-ticker.C:
		}
	}
	secondDigest := sha256.Sum256([]byte("later-started-early-commit"))
	bOutcome, err := database.StoreMessageIdempotent(ctx, message("B"), bClientID, secondDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	firstPage, err := database.GetPendingMessages(ctx, conversation, bob.User.ID, time.Time{}, "", 1)
	if err != nil || len(firstPage) != 1 || firstPage[0].ID != bOutcome.MessageID {
		t.Fatalf("first page=%+v err=%v", firstPage, err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var aResult result
	select {
	case aResult = <-resultA:
	case <-ctx.Done():
		t.Fatal("late send did not complete after barrier release")
	}
	if aResult.err != nil {
		t.Fatal(aResult.err)
	}
	if !aResult.outcome.ServerTimestamp.Before(bOutcome.ServerTimestamp) {
		t.Fatalf("timestamp inversion not reproduced: A=%v B=%v", aResult.outcome.ServerTimestamp, bOutcome.ServerTimestamp)
	}
	all, err := database.GetPendingMessages(ctx, conversation, bob.User.ID, time.Time{}, "", 10)
	if err != nil || len(all) != 2 || all[0].ID != aResult.outcome.MessageID || all[1].ID != bOutcome.MessageID {
		t.Fatalf("committed rows=%+v err=%v", all, err)
	}
	afterCursor, err := database.GetPendingMessages(ctx, conversation, bob.User.ID, firstPage[0].CreatedAt, firstPage[0].ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterCursor) != 0 {
		t.Fatalf("timestamp-feed behavior changed; replace this limitation characterization with commit-order recovery assertions: %+v", afterCursor)
	}
	// Both sends succeeded and exist durably. A consumer that advances to B's
	// timestamp/ID before A commits cannot recover A with this incremental API.
}
