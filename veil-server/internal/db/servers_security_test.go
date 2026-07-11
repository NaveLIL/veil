package db

import (
	"errors"
	"strings"
	"testing"
)

type inviteFailingReader struct{}

func (inviteFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("CSPRNG unavailable")
}

func TestGenerateInviteCodeFailsClosedOnEntropyError(t *testing.T) {
	if _, err := generateInviteCodeFrom(inviteFailingReader{}); err == nil {
		t.Fatal("invite code generation ignored entropy failure")
	}
	code, err := generateInviteCodeFrom(strings.NewReader("123456"))
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 8 {
		t.Fatalf("invite code length=%d, want 8", len(code))
	}
}
