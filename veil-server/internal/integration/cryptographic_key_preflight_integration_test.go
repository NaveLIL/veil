//go:build integration

package integration

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestCryptographicKeyPreflightRejectsLegacyWeakRows(t *testing.T) {
	harness := New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := harness.DB.ValidateCryptographicPublicKeys(ctx); err != nil {
		t.Fatalf("valid database failed key preflight: %v", err)
	}

	var weakUserID string
	if err := harness.DB.Pool.QueryRow(ctx,
		`INSERT INTO users(identity_key, signing_key, username)
		 VALUES ($1, $2, 'weak-key-preflight-user') RETURNING id::text`,
		bytes.Repeat([]byte{0xa1}, 32), make([]byte, 32),
	).Scan(&weakUserID); err != nil {
		t.Fatalf("seed weak account key: %v", err)
	}
	if err := harness.DB.ValidateCryptographicPublicKeys(ctx); err == nil {
		t.Fatal("startup preflight accepted a weak stored account signing key")
	}
	if _, err := harness.DB.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, weakUserID); err != nil {
		t.Fatalf("remove weak account fixture: %v", err)
	}

	owner := harness.CreateUser("weak-device-preflight-owner")
	device, err := harness.DB.CreateDevice(
		ctx,
		owner.ID,
		bytes.Repeat([]byte{0xb2}, 16),
		"weak-device-preflight",
	)
	if err != nil {
		t.Fatalf("create device fixture: %v", err)
	}
	if _, err := harness.DB.Pool.Exec(ctx,
		`INSERT INTO device_crypto_keys(device_id, device_identity_key, device_signing_key)
		 VALUES ($1::uuid, $2, $3)`,
		device.ID, bytes.Repeat([]byte{0xc3}, 32), make([]byte, 32),
	); err != nil {
		t.Fatalf("seed weak device key: %v", err)
	}
	if err := harness.DB.ValidateCryptographicPublicKeys(ctx); err == nil {
		t.Fatal("startup preflight accepted a weak stored device signing key")
	}
}
