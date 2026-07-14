package db

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

type inviteFailingReader struct{}

func (inviteFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("CSPRNG unavailable")
}

func TestGenerateVeilLinkTokenFailsClosedOnEntropyError(t *testing.T) {
	if _, err := generateVeilLinkTokenFrom(inviteFailingReader{}); err == nil {
		t.Fatal("Veil Link token generation ignored entropy failure")
	}
	token, err := generateVeilLinkTokenFrom(strings.NewReader(strings.Repeat("x", veilLinkTokenBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 43 {
		t.Fatalf("Veil Link token length=%d, want 43", len(token))
	}
	hash, err := hashVeilLinkSecret(token)
	if err != nil || len(hash) != sha256.Size {
		t.Fatalf("Veil Link hash length=%d err=%v", len(hash), err)
	}
}
