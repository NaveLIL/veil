package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/AegisSec/veil-server/internal/cryptokey"
)

// ValidateCryptographicPublicKeys is a fail-closed startup preflight for rows
// that predate the application-level storage validators or were written by an
// operator directly. Invalid keys are not identified in the error because raw
// account/device identifiers and key bytes must not enter logs.
func (db *DB) ValidateCryptographicPublicKeys(ctx context.Context) error {
	checks := []struct {
		name  string
		query string
	}{
		{name: "account", query: `SELECT signing_key FROM users`},
		{name: "device", query: `SELECT device_signing_key FROM device_crypto_keys`},
	}
	for _, check := range checks {
		rows, err := db.Pool.Query(ctx, check.query)
		if err != nil {
			return fmt.Errorf("query %s signing-key preflight: %w", check.name, err)
		}
		valid := true
		for rows.Next() {
			var key []byte
			if err := rows.Scan(&key); err != nil {
				rows.Close()
				return fmt.Errorf("scan %s signing-key preflight: %w", check.name, err)
			}
			if !cryptokey.ValidEd25519PublicKey(key) {
				valid = false
				break
			}
		}
		iterationErr := rows.Err()
		rows.Close()
		if iterationErr != nil {
			return fmt.Errorf("iterate %s signing-key preflight: %w", check.name, iterationErr)
		}
		if !valid {
			return errors.New("database contains an invalid cryptographic signing key")
		}
	}
	return nil
}
