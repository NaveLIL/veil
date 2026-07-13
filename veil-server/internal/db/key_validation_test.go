package db

import (
	"context"
	"crypto/ed25519"
	"testing"
)

func TestStorageBoundariesRejectWeakSigningKeysBeforeDatabaseUse(t *testing.T) {
	database := &DB{}
	if _, err := database.CreateUser(context.Background(), make([]byte, 32), make([]byte, 32), "weak"); err == nil {
		t.Fatal("CreateUser accepted a weak account signing key")
	}

	binding := &DeviceBinding{
		DeviceID:          "550e8400-e29b-41d4-a716-446655440000",
		UserID:            "550e8400-e29b-41d4-a716-446655440001",
		DeviceKey:         make([]byte, 16),
		DeviceIdentityKey: make([]byte, 32),
		DeviceSigningKey:  make([]byte, 32),
		Version:           1,
		Status:            DeviceBindingActive,
		AccountSignature:  make([]byte, ed25519.SignatureSize),
		Commitment:        make([]byte, 32),
	}
	if _, err := database.StoreDeviceBinding(context.Background(), binding); err == nil {
		t.Fatal("StoreDeviceBinding accepted a weak device signing key")
	}
}
