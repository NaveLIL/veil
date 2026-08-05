//go:build integration

package db_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
	veiltransparency "github.com/NaveLIL/veil/veil-server/internal/transparency"
)

func TestIdentityTransparencyAccountAppendProofAndRestartAudit(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	origin, err := nodeorigin.ParseCanonical("https://node.example:443")
	if err != nil {
		t.Fatal(err)
	}
	nodePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	nodePublic := nodePrivate.Public().(ed25519.PublicKey)
	logID, err := veiltransparency.LogID(origin.String(), nodePublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.EnableIdentityTransparencyLog(ctx, origin, logID, nodePublic); err != nil {
		t.Fatal(err)
	}

	users := make([]*db.User, 5)
	for index := range users {
		accountPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x21 + index)}, ed25519.SeedSize))
		users[index], err = database.CreateUser(
			ctx,
			bytes.Repeat([]byte{byte(0x41 + index)}, 32),
			accountPrivate.Public().(ed25519.PublicKey),
			"transparent-account-"+string(rune('a'+index)),
		)
		if err != nil {
			t.Fatalf("create transparent account %d: %v", index, err)
		}
	}
	deviceKey := bytes.Repeat([]byte{0x91}, 16)
	device, err := database.CreateDevice(ctx, users[2].ID, deviceKey, "transparent-device")
	if err != nil {
		t.Fatal(err)
	}
	devicePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x92}, ed25519.SeedSize))
	bindings := []*db.DeviceBinding{
		{
			DeviceID:          device.ID,
			UserID:            users[2].ID,
			DeviceKey:         deviceKey,
			DeviceIdentityKey: bytes.Repeat([]byte{0x93}, 32),
			DeviceSigningKey:  devicePrivate.Public().(ed25519.PublicKey),
			Version:           1,
			Capabilities:      db.RequiredChannelCapabilities,
			Status:            db.DeviceBindingActive,
			AccountSignature:  bytes.Repeat([]byte{0x94}, ed25519.SignatureSize),
			Commitment:        bytes.Repeat([]byte{0x95}, sha256.Size),
		},
		{
			DeviceID:          device.ID,
			UserID:            users[2].ID,
			DeviceKey:         deviceKey,
			DeviceIdentityKey: bytes.Repeat([]byte{0x93}, 32),
			DeviceSigningKey:  devicePrivate.Public().(ed25519.PublicKey),
			Version:           2,
			Capabilities:      db.RequiredChannelCapabilities,
			Status:            db.DeviceBindingExcluded,
			AccountSignature:  bytes.Repeat([]byte{0x96}, ed25519.SignatureSize),
			Commitment:        bytes.Repeat([]byte{0x97}, sha256.Size),
		},
	}
	for index, binding := range bindings {
		if _, err := database.StoreDeviceBinding(ctx, binding); err != nil {
			t.Fatalf("store transparent device binding %d: %v", index, err)
		}
		if _, err := database.StoreDeviceBinding(ctx, binding); err != nil {
			t.Fatalf("retry transparent device binding %d: %v", index, err)
		}
	}
	var bindingLeafCount int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM identity_transparency_log_leaves WHERE event_kind = 2`,
	).Scan(&bindingLeafCount); err != nil || bindingLeafCount != len(bindings) {
		t.Fatalf("device-binding leaf count=%d err=%v", bindingLeafCount, err)
	}

	proof, err := database.IdentityTransparencyProofForAccount(ctx, users[2].ID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if proof.LeafIndex != 2 || proof.Head.TreeSize != 7 || proof.Head.LogID != logID ||
		proof.ConsistencyFrom != 3 {
		t.Fatalf("unexpected account proof coordinates: %#v", proof)
	}
	if !veiltransparency.VerifyInclusion(
		proof.CanonicalEvent,
		proof.LeafIndex,
		proof.Head.TreeSize,
		proof.InclusionProof,
		proof.Head.RootHash,
	) {
		t.Fatal("database returned an invalid inclusion proof")
	}
	deviceProof, err := database.IdentityTransparencyProofForDeviceBinding(ctx, deviceKey, 2, 5)
	if err != nil {
		t.Fatal(err)
	}
	if deviceProof.LeafIndex != 6 || deviceProof.Head.TreeSize != 7 || deviceProof.ConsistencyFrom != 5 ||
		!veiltransparency.VerifyInclusion(
			deviceProof.CanonicalEvent,
			deviceProof.LeafIndex,
			deviceProof.Head.TreeSize,
			deviceProof.InclusionProof,
			deviceProof.Head.RootHash,
		) {
		t.Fatalf("database returned an invalid device-binding proof: %#v", deviceProof)
	}
	firstHeadProof, err := database.IdentityTransparencyProofForAccount(ctx, users[0].ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstHeadProof.ConsistencyProof) != 0 {
		t.Fatal("first-contact proof manufactured a consistency anchor")
	}
	rows, err := database.Pool.Query(ctx,
		`SELECT canonical_event FROM identity_transparency_log_leaves
		 WHERE leaf_index < 3 ORDER BY leaf_index`,
	)
	if err != nil {
		t.Fatal(err)
	}
	var oldEvents [][]byte
	for rows.Next() {
		var event []byte
		if err := rows.Scan(&event); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		oldEvents = append(oldEvents, event)
	}
	rows.Close()
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	oldRoot, err := veiltransparency.TreeRoot(oldEvents)
	if err != nil || !veiltransparency.VerifyConsistency(
		3,
		proof.Head.TreeSize,
		oldRoot,
		proof.Head.RootHash,
		proof.ConsistencyProof,
	) {
		t.Fatalf("database returned an invalid consistency proof: %v", err)
	}

	// A process restart must reopen only the exact configured log and audit
	// every account-to-leaf cardinality before accepting another registration.
	reopened := &db.DB{Pool: database.Pool}
	if err := reopened.EnableIdentityTransparencyLog(ctx, origin, logID, nodePublic); err != nil {
		t.Fatalf("reopen audited transparency log: %v", err)
	}
	if err := reopened.EnableIdentityTransparencyLog(
		ctx,
		origin,
		veiltransparency.Hash(sha256.Sum256([]byte("other-log"))),
		nodePublic,
	); err == nil {
		t.Fatal("reopen accepted a different transparency log id")
	}

	message := veiltransparency.TreeHead{
		LogID:      proof.Head.LogID,
		TreeSize:   proof.Head.TreeSize,
		RootHash:   proof.Head.RootHash,
		IssuedAtMs: 1712345678901,
	}
	encoded, err := message.SigningMessage(origin.String())
	if err != nil {
		t.Fatal(err)
	}
	if !message.VerifyNodeSignature(origin.String(), nodePublic, ed25519.Sign(nodePrivate, encoded)) {
		t.Fatal("persisted head did not produce a valid exact-origin signature")
	}
}

func TestIdentityTransparencyRefusesSilentLegacyBackfill(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accountPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	if _, err := database.CreateUser(
		ctx,
		bytes.Repeat([]byte{0x51}, 32),
		accountPrivate.Public().(ed25519.PublicKey),
		"legacy-before-transparency",
	); err != nil {
		t.Fatal(err)
	}
	origin, _ := nodeorigin.ParseCanonical("https://node.example:443")
	nodePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	nodePublic := nodePrivate.Public().(ed25519.PublicKey)
	logID, err := veiltransparency.LogID(origin.String(), nodePublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.EnableIdentityTransparencyLog(
		ctx,
		origin,
		logID,
		nodePublic,
	); err == nil {
		t.Fatal("transparency activation silently backfilled an existing account")
	}
}
