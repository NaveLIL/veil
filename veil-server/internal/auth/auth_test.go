package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/auth"
	"github.com/AegisSec/veil-server/internal/config"
)

func newTestService() *auth.Service {
	cfg := &config.Config{
		AuthChallengeTTL: 5 * time.Second,
		AuthMaxAttempts:  3,
	}
	// db is nil — tests that reach the DB will panic, but
	// challenge-related and validation tests won't touch it.
	return auth.NewService(nil, cfg)
}

func TestCreateChallenge(t *testing.T) {
	svc := newTestService()

	nonce, err := svc.CreateChallenge("conn-1")
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	// Nonce must not be all zeros
	allZero := true
	for _, b := range nonce {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("nonce is all zeros")
	}
}

func TestCreateChallenge_Unique(t *testing.T) {
	svc := newTestService()

	n1, _ := svc.CreateChallenge("conn-1")
	n2, _ := svc.CreateChallenge("conn-2")

	if n1 == n2 {
		t.Fatal("two challenges produced the same nonce")
	}
}

func TestRemoveChallenge(t *testing.T) {
	svc := newTestService()

	svc.CreateChallenge("conn-1")
	svc.RemoveChallenge("conn-1")

	// Now VerifyResponse should return ErrChallengeUnknown
	_, err := svc.VerifyResponse(context.Background(), "conn-1",
		make([]byte, 32), make([]byte, 32), make([]byte, 64), make([]byte, 16), "test")
	if err != auth.ErrChallengeUnknown {
		t.Fatalf("expected ErrChallengeUnknown, got %v", err)
	}
}

func TestVerifyResponse_UnknownChallenge(t *testing.T) {
	svc := newTestService()

	_, err := svc.VerifyResponse(context.Background(), "nonexistent",
		make([]byte, 32), make([]byte, 32), make([]byte, 64), make([]byte, 16), "")
	if err != auth.ErrChallengeUnknown {
		t.Fatalf("expected ErrChallengeUnknown, got %v", err)
	}
}

func TestVerifyResponse_BadKeyLength(t *testing.T) {
	svc := newTestService()
	svc.CreateChallenge("conn-1")

	// identity_key too short
	_, err := svc.VerifyResponse(context.Background(), "conn-1",
		make([]byte, 16), make([]byte, 32), make([]byte, 64), make([]byte, 16), "")
	if err != auth.ErrBadKeyLength {
		t.Fatalf("expected ErrBadKeyLength for short identity key, got %v", err)
	}
}

func TestVerifyResponse_BadDeviceID(t *testing.T) {
	svc := newTestService()
	svc.CreateChallenge("conn-1")

	// device_id too short
	_, err := svc.VerifyResponse(context.Background(), "conn-1",
		make([]byte, 32), make([]byte, 32), make([]byte, 64), make([]byte, 8), "")
	if err != auth.ErrBadDeviceID {
		t.Fatalf("expected ErrBadDeviceID, got %v", err)
	}
}

func TestVerifyResponse_BadSignature(t *testing.T) {
	svc := newTestService()
	nonce, _ := svc.CreateChallenge("conn-1")

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	identityKey := make([]byte, 32)
	rand.Read(identityKey)
	deviceID := make([]byte, 16)
	rand.Read(deviceID)

	// Wrong signature (all zeros)
	badSig := make([]byte, 64)

	_, err := svc.VerifyResponse(context.Background(), "conn-1",
		identityKey, []byte(pub), badSig, deviceID, "test")
	_ = nonce
	if err != auth.ErrBadSignature {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestVerifyResponse_ChallengeConsumedOnce(t *testing.T) {
	svc := newTestService()
	nonce, _ := svc.CreateChallenge("conn-1")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	identityKey := make([]byte, 32)
	rand.Read(identityKey)
	deviceID := make([]byte, 16)
	rand.Read(deviceID)

	sig := ed25519.Sign(priv, nonce[:])

	// First call: valid signature passes crypto check, then panics on nil DB.
	// We recover from the panic — the important thing is that the challenge
	// was consumed (deleted from the map) before reaching the DB layer.
	func() {
		defer func() { recover() }()
		svc.VerifyResponse(context.Background(), "conn-1",
			identityKey, []byte(pub), sig, deviceID, "test")
	}()

	// Second call: challenge should be gone regardless of the DB panic
	_, err := svc.VerifyResponse(context.Background(), "conn-1",
		identityKey, []byte(pub), sig, deviceID, "test")
	if err != auth.ErrChallengeUnknown {
		t.Fatalf("expected ErrChallengeUnknown on second verify, got %v", err)
	}
}

func TestVerifyResponse_ExpiredChallenge(t *testing.T) {
	cfg := &config.Config{
		AuthChallengeTTL: 1 * time.Millisecond, // Very short TTL
		AuthMaxAttempts:  3,
	}
	svc := auth.NewService(nil, cfg)
	nonce, _ := svc.CreateChallenge("conn-1")

	time.Sleep(5 * time.Millisecond) // Let it expire

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, nonce[:])
	identityKey := make([]byte, 32)
	rand.Read(identityKey)
	deviceID := make([]byte, 16)
	rand.Read(deviceID)

	_, err := svc.VerifyResponse(context.Background(), "conn-1",
		identityKey, []byte(pub), sig, deviceID, "")
	if err != auth.ErrChallengeTooOld {
		t.Fatalf("expected ErrChallengeTooOld, got %v", err)
	}
}
