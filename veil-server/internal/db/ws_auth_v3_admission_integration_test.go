//go:build integration

package db_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/auth"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/curve25519"
)

func TestWSAuthV3AdmissionLifecycleExistingIdentityWinsBeforePass(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	invites, err := database.CreateNodeAccessInvites(ctx, 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request := newWSAuthV3DBRequest(t, 0x11, db.WSAuthV3AdmissionPass, invites[0].Token)
	first, err := database.AdmitWSAuthV3(ctx, request)
	if err != nil || !first.IsNew {
		t.Fatalf("first Pass admission result=%#v err=%v", first, err)
	}
	assertWSAuthV3CommittedGraph(t, ctx, database, request, first)
	assertWSAuthV3PassState(t, ctx, database, invites[0].Token, true, first.User.ID)

	// An uncertain post-commit retry presents the same now-used Pass. The
	// identity-scoped transaction must resolve the exact existing account first
	// and never turn this into a Pass-invalid result.
	retry, err := database.AdmitWSAuthV3(ctx, request)
	if err != nil || retry.IsNew || retry.User.ID != first.User.ID || retry.Device.ID != first.Device.ID {
		t.Fatalf("idempotent used-Pass retry result=%#v err=%v", retry, err)
	}

	// The same existing identity may also present a different unused Pass. It
	// must authenticate without touching that capability.
	unusedPassRequest := request
	unusedPassRequest.NodeAccessPass = invites[1].Token
	existing, err := database.AdmitWSAuthV3(ctx, unusedPassRequest)
	if err != nil || existing.IsNew || existing.User.ID != first.User.ID {
		t.Fatalf("existing identity with unused Pass result=%#v err=%v", existing, err)
	}
	assertWSAuthV3PassState(t, ctx, database, invites[1].Token, false, "")

	other := newWSAuthV3DBRequest(t, 0x22, db.WSAuthV3AdmissionPass, invites[1].Token)
	otherResult, err := database.AdmitWSAuthV3(ctx, other)
	if err != nil || !otherResult.IsNew || otherResult.User.ID == first.User.ID {
		t.Fatalf("unused Pass was not independently redeemable: result=%#v err=%v", otherResult, err)
	}
	assertWSAuthV3PassState(t, ctx, database, invites[1].Token, true, otherResult.User.ID)
}

func TestWSAuthV3AdmissionRollsBackPassAccountDeviceAndBindingTogether(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	owner := newWSAuthV3DBRequest(t, 0x31, db.WSAuthV3AdmissionOpen, nil)
	owner.AllowOpenRegistration = true
	ownerResult, err := database.AdmitWSAuthV3(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}

	invites, err := database.CreateNodeAccessInvites(ctx, 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	conflict := newWSAuthV3DBRequest(t, 0x32, db.WSAuthV3AdmissionPass, invites[0].Token)
	conflict.DeviceKey = owner.DeviceKey
	resignWSAuthV3DBBinding(t, &conflict, 0x32)
	if _, err := database.AdmitWSAuthV3(ctx, conflict); !errors.Is(err, db.ErrWSAuthV3AdmissionRejected) {
		t.Fatalf("cross-account device conflict error=%v, want admission rejection", err)
	}
	assertWSAuthV3AccountAbsent(t, ctx, database, conflict.AccountIdentityKey[:])
	assertWSAuthV3PassState(t, ctx, database, invites[0].Token, false, "")
	if ownerResult.User.ID == "" {
		t.Fatal("owner setup unexpectedly missing")
	}

	replacement := newWSAuthV3DBRequest(t, 0x33, db.WSAuthV3AdmissionPass, invites[0].Token)
	if result, err := database.AdmitWSAuthV3(ctx, replacement); err != nil || !result.IsNew {
		t.Fatalf("Pass did not survive rolled-back device conflict: result=%#v err=%v", result, err)
	}

	versionGap := newWSAuthV3DBRequest(t, 0x34, db.WSAuthV3AdmissionPass, invites[1].Token)
	versionGap.BindingVersion = 2
	resignWSAuthV3DBBinding(t, &versionGap, 0x34)
	if _, err := database.AdmitWSAuthV3(ctx, versionGap); !errors.Is(err, db.ErrWSAuthV3AdmissionRejected) {
		t.Fatalf("initial binding gap error=%v, want admission rejection", err)
	}
	assertWSAuthV3AccountAbsent(t, ctx, database, versionGap.AccountIdentityKey[:])
	assertWSAuthV3PassState(t, ctx, database, invites[1].Token, false, "")
	versionGap.BindingVersion = 1
	resignWSAuthV3DBBinding(t, &versionGap, 0x34)
	if result, err := database.AdmitWSAuthV3(ctx, versionGap); err != nil || !result.IsNew {
		t.Fatalf("Pass did not survive rolled-back binding gap: result=%#v err=%v", result, err)
	}
}

func TestWSAuthV3AdmissionCancellationReleasesTransactionWithoutEffectsAndCanRetry(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	invites, err := database.CreateNodeAccessInvites(ctx, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request := newWSAuthV3DBRequest(t, 0x35, db.WSAuthV3AdmissionPass, invites[0].Token)
	digest := sha256.Sum256(invites[0].Token)

	// Hold the exact Pass row so the admission deterministically blocks after
	// its identity lock and before any graph mutation. The separate conflict and
	// version-gap cases above exercise rollback after graph mutations.
	blocker, err := database.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	blockerOpen := true
	defer func() {
		if blockerOpen {
			rollbackContext, cancelRollback := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelRollback()
			_ = blocker.Rollback(rollbackContext)
		}
	}()
	var blockedPassID string
	if err := blocker.QueryRow(ctx,
		`SELECT id::text FROM node_access_invites WHERE token_hash = $1 FOR UPDATE`, digest[:],
	).Scan(&blockedPassID); err != nil {
		t.Fatal(err)
	}
	if blockedPassID == "" {
		t.Fatal("blocker did not resolve the target Pass")
	}

	type admissionOutcome struct {
		result *db.WSAuthV3AdmissionResult
		err    error
	}
	attemptContext, cancelAttempt := context.WithCancel(ctx)
	defer cancelAttempt()
	outcomes := make(chan admissionOutcome, 1)
	go func() {
		result, err := database.AdmitWSAuthV3(attemptContext, request)
		outcomes <- admissionOutcome{result: result, err: err}
	}()
	waitForWSAuthV3PassRowLock(t, ctx, database)
	cancelAttempt()

	select {
	case outcome := <-outcomes:
		if outcome.result != nil || !errors.Is(outcome.err, context.Canceled) {
			t.Fatalf("cancelled admission result=%#v err=%v, want nil context.Canceled", outcome.result, outcome.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled admission did not return")
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	blockerOpen = false

	assertWSAuthV3GraphAbsent(t, ctx, database, request)
	assertWSAuthV3PassState(t, ctx, database, invites[0].Token, false, "")
	retry, err := database.AdmitWSAuthV3(ctx, request)
	if err != nil || retry == nil || !retry.IsNew {
		t.Fatalf("retry after cancellation result=%#v err=%v", retry, err)
	}
	assertWSAuthV3CommittedGraph(t, ctx, database, request, retry)
	assertWSAuthV3PassState(t, ctx, database, invites[0].Token, true, retry.User.ID)
}

func TestWSAuthV3AdmissionConcurrentPassAndIdentityRaces(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("one Pass two identities", func(t *testing.T) {
		invites, err := database.CreateNodeAccessInvites(ctx, 1, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		requests := []db.WSAuthV3AdmissionRequest{
			newWSAuthV3DBRequest(t, 0x41, db.WSAuthV3AdmissionPass, invites[0].Token),
			newWSAuthV3DBRequest(t, 0x42, db.WSAuthV3AdmissionPass, invites[0].Token),
		}
		start := make(chan struct{})
		errorsOut := make(chan error, len(requests))
		var wait sync.WaitGroup
		for index := range requests {
			wait.Add(1)
			go func(request db.WSAuthV3AdmissionRequest) {
				defer wait.Done()
				<-start
				_, err := database.AdmitWSAuthV3(ctx, request)
				errorsOut <- err
			}(requests[index])
		}
		close(start)
		wait.Wait()
		close(errorsOut)
		var accepted, rejected int
		for err := range errorsOut {
			switch {
			case err == nil:
				accepted++
			case errors.Is(err, db.ErrNodeAccessInviteInvalid):
				rejected++
			default:
				t.Fatalf("unexpected concurrent Pass error: %v", err)
			}
		}
		if accepted != 1 || rejected != 1 {
			t.Fatalf("concurrent Pass results accepted=%d rejected=%d", accepted, rejected)
		}
	})

	t.Run("same identity uncertain commit", func(t *testing.T) {
		invites, err := database.CreateNodeAccessInvites(ctx, 1, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		request := newWSAuthV3DBRequest(t, 0x43, db.WSAuthV3AdmissionPass, invites[0].Token)
		start := make(chan struct{})
		results := make(chan *db.WSAuthV3AdmissionResult, 2)
		errorsOut := make(chan error, 2)
		var wait sync.WaitGroup
		for range 2 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				result, err := database.AdmitWSAuthV3(ctx, request)
				results <- result
				errorsOut <- err
			}()
		}
		close(start)
		wait.Wait()
		close(results)
		close(errorsOut)
		for err := range errorsOut {
			if err != nil {
				t.Fatalf("same-identity concurrent retry failed: %v", err)
			}
		}
		var newCount int
		var userID, deviceID string
		for result := range results {
			if result == nil {
				t.Fatal("same-identity admission returned nil result")
			}
			if result.IsNew {
				newCount++
			}
			if userID == "" {
				userID, deviceID = result.User.ID, result.Device.ID
			} else if result.User.ID != userID || result.Device.ID != deviceID {
				t.Fatal("identity-serialized retries produced different durable principals")
			}
		}
		if newCount != 1 {
			t.Fatalf("same-identity IsNew count=%d, want 1", newCount)
		}
	})
}

func TestWSAuthV3AdmissionIntentPolicyIsExplicit(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	existingOnly := newWSAuthV3DBRequest(t, 0x51, db.WSAuthV3AdmissionExisting, nil)
	if _, err := database.AdmitWSAuthV3(ctx, existingOnly); !errors.Is(err, db.ErrWSAuthV3IdentityAbsent) {
		t.Fatalf("absent existing-only error=%v, want identity absent", err)
	}
	open := newWSAuthV3DBRequest(t, 0x52, db.WSAuthV3AdmissionOpen, nil)
	if _, err := database.AdmitWSAuthV3(ctx, open); !errors.Is(err, db.ErrWSAuthV3RegistrationClosed) {
		t.Fatalf("closed OPEN error=%v, want registration closed", err)
	}
	open.AllowOpenRegistration = true
	if result, err := database.AdmitWSAuthV3(ctx, open); err != nil || !result.IsNew {
		t.Fatalf("explicitly open admission result=%#v err=%v", result, err)
	}
	invalidPass := newWSAuthV3DBRequest(t, 0x53, db.WSAuthV3AdmissionPass, bytes.Repeat([]byte{0xa5}, 32))
	if _, err := database.AdmitWSAuthV3(ctx, invalidPass); !errors.Is(err, db.ErrNodeAccessInviteInvalid) {
		t.Fatalf("unknown Pass error=%v, want indistinguishable Pass invalid", err)
	}
}

func newWSAuthV3DBRequest(
	t *testing.T,
	seed byte,
	intent db.WSAuthV3AdmissionIntent,
	pass []byte,
) db.WSAuthV3AdmissionRequest {
	t.Helper()
	accountIdentityPrivate := bytes.Repeat([]byte{seed}, 32)
	accountIdentityPublic, err := curve25519.X25519(accountIdentityPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	accountSigningPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 1}, ed25519.SeedSize))
	deviceIdentityPrivate := bytes.Repeat([]byte{seed + 2}, 32)
	deviceIdentityPublic, err := curve25519.X25519(deviceIdentityPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	deviceSigningPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 3}, ed25519.SeedSize))

	var request db.WSAuthV3AdmissionRequest
	request.Intent = intent
	copy(request.AccountIdentityKey[:], accountIdentityPublic)
	copy(request.AccountSigningKey[:], accountSigningPrivate.Public().(ed25519.PublicKey))
	for index := range request.DeviceKey {
		request.DeviceKey[index] = seed + 4
	}
	copy(request.DeviceIdentityKey[:], deviceIdentityPublic)
	copy(request.DeviceSigningKey[:], deviceSigningPrivate.Public().(ed25519.PublicKey))
	request.DeviceName = "integration device"
	request.BindingVersion = 1
	request.BindingCapabilities = db.RequiredChannelCapabilities
	request.BindingStatus = db.DeviceBindingActive
	request.NodeAccessPass = pass

	resignWSAuthV3DBBinding(t, &request, seed)
	return request
}

func resignWSAuthV3DBBinding(t *testing.T, request *db.WSAuthV3AdmissionRequest, seed byte) {
	t.Helper()
	accountSigningPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 1}, ed25519.SeedSize))
	bindingInput := &auth.DeviceBindingInput{
		DeviceKey:         request.DeviceKey[:],
		DeviceIdentityKey: request.DeviceIdentityKey[:],
		DeviceSigningKey:  request.DeviceSigningKey[:],
		Version:           request.BindingVersion,
		Capabilities:      request.BindingCapabilities,
		Status:            request.BindingStatus,
	}
	bindingMessage, err := auth.DeviceBindingSigningMessage(
		request.AccountIdentityKey[:], request.AccountSigningKey[:], bindingInput,
	)
	if err != nil {
		t.Fatal(err)
	}
	bindingSignature := ed25519.Sign(accountSigningPrivate, bindingMessage)
	copy(request.BindingSignature[:], bindingSignature)
	request.BindingCommitment = sha256.Sum256(bindingMessage)
}

func assertWSAuthV3CommittedGraph(
	t *testing.T,
	ctx context.Context,
	database *db.DB,
	request db.WSAuthV3AdmissionRequest,
	result *db.WSAuthV3AdmissionResult,
) {
	t.Helper()
	var userCount, deviceCount, keyCount, versionCount, headCount int
	if err := database.Pool.QueryRow(ctx,
		`SELECT
		   (SELECT count(*) FROM users WHERE id = $1::uuid),
		   (SELECT count(*) FROM devices WHERE id = $2::uuid AND user_id = $1::uuid),
		   (SELECT count(*) FROM device_crypto_keys WHERE device_id = $2::uuid),
		   (SELECT count(*) FROM device_binding_versions WHERE device_id = $2::uuid AND binding_version = $3),
		   (SELECT count(*) FROM device_binding_heads WHERE device_id = $2::uuid AND binding_version = $3)`,
		result.User.ID, result.Device.ID, int64(request.BindingVersion),
	).Scan(&userCount, &deviceCount, &keyCount, &versionCount, &headCount); err != nil {
		t.Fatal(err)
	}
	if userCount != 1 || deviceCount != 1 || keyCount != 1 || versionCount != 1 || headCount != 1 {
		t.Fatalf("incomplete committed v3 graph: user=%d device=%d keys=%d version=%d head=%d",
			userCount, deviceCount, keyCount, versionCount, headCount)
	}
}

func assertWSAuthV3PassState(t *testing.T, ctx context.Context, database *db.DB, pass []byte, used bool, userID string) {
	t.Helper()
	digest := sha256.Sum256(pass)
	var usedAt *time.Time
	var usedBy *string
	if err := database.Pool.QueryRow(ctx,
		`SELECT used_at, used_by_user_id::text FROM node_access_invites WHERE token_hash = $1`,
		digest[:],
	).Scan(&usedAt, &usedBy); err != nil {
		t.Fatal(err)
	}
	if used != (usedAt != nil) {
		t.Fatalf("Pass used state=%v, want %v", usedAt != nil, used)
	}
	if used {
		if usedBy == nil || *usedBy != userID {
			t.Fatalf("Pass used_by=%v, want %s", usedBy, userID)
		}
	} else if usedBy != nil {
		t.Fatalf("unused Pass unexpectedly has used_by=%v", *usedBy)
	}
}

func assertWSAuthV3AccountAbsent(t *testing.T, ctx context.Context, database *db.DB, identityKey []byte) {
	t.Helper()
	var userID string
	err := database.Pool.QueryRow(ctx,
		`SELECT id::text FROM users WHERE identity_key = $1`, identityKey,
	).Scan(&userID)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("rolled-back account lookup error=%v id=%q, want no rows", err, userID)
	}
}

func assertWSAuthV3GraphAbsent(
	t *testing.T,
	ctx context.Context,
	database *db.DB,
	request db.WSAuthV3AdmissionRequest,
) {
	t.Helper()
	var userCount, deviceCount, keyCount, versionCount, headCount int
	if err := database.Pool.QueryRow(ctx,
		`SELECT
		   (SELECT count(*) FROM users WHERE identity_key = $1),
		   (SELECT count(*) FROM devices WHERE device_key = $2),
		   (SELECT count(*) FROM device_crypto_keys keys
		      JOIN devices device ON device.id = keys.device_id WHERE device.device_key = $2),
		   (SELECT count(*) FROM device_binding_versions version
		      JOIN devices device ON device.id = version.device_id WHERE device.device_key = $2),
		   (SELECT count(*) FROM device_binding_heads head
		      JOIN devices device ON device.id = head.device_id WHERE device.device_key = $2)`,
		request.AccountIdentityKey[:], request.DeviceKey[:],
	).Scan(&userCount, &deviceCount, &keyCount, &versionCount, &headCount); err != nil {
		t.Fatal(err)
	}
	if userCount != 0 || deviceCount != 0 || keyCount != 0 || versionCount != 0 || headCount != 0 {
		t.Fatalf("cancelled v3 graph leaked rows: user=%d device=%d keys=%d version=%d head=%d",
			userCount, deviceCount, keyCount, versionCount, headCount)
	}
}

func waitForWSAuthV3PassRowLock(t *testing.T, ctx context.Context, database *db.DB) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := database.Pool.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1 FROM pg_stat_activity
			   WHERE datname = current_database()
			     AND pid <> pg_backend_pid()
			     AND state = 'active'
			     AND wait_event_type = 'Lock'
			     AND query LIKE '%FROM node_access_invites%'
			     AND query NOT LIKE '%pg_stat_activity%'
			)`,
		).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("admission did not reach the held Pass row lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
