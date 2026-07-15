package db

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestNodeAccessInviteTokenHashShape(t *testing.T) {
	token := bytes.Repeat([]byte{0x42}, NodeAccessInviteTokenSize)
	tokenHash, err := nodeAccessInviteTokenHash(token)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokenHash) != 32 || bytes.Equal(tokenHash[:], token) {
		t.Fatal("invite digest must be a distinct 32-byte SHA-256 value")
	}
	if _, err := nodeAccessInviteTokenHash(token[:31]); !errors.Is(err, ErrNodeAccessInviteInvalid) {
		t.Fatalf("short token error = %v", err)
	}
}

func TestCreateNodeAccessInvitesValidatesBeforeDatabaseUse(t *testing.T) {
	database := &DB{}
	if _, err := database.CreateNodeAccessInvites(context.Background(), 0, time.Hour); !errors.Is(err, ErrNodeAccessInviteCount) {
		t.Fatalf("zero count error = %v", err)
	}
	if _, err := database.CreateNodeAccessInvites(context.Background(), 1, time.Nanosecond); !errors.Is(err, ErrNodeAccessInviteExpiry) {
		t.Fatalf("sub-microsecond lifetime error = %v", err)
	}
	if _, err := database.CreateUserWithNodeAccessInvite(
		context.Background(), make([]byte, NodeAccessInviteTokenSize-1), nil, nil, "user",
	); !errors.Is(err, ErrNodeAccessInviteInvalid) {
		t.Fatalf("short invite error = %v", err)
	}
}
