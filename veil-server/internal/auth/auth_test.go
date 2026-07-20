package auth_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/auth"
	"github.com/NaveLIL/veil/veil-server/internal/config"
	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
	"golang.org/x/crypto/curve25519"
)

func x25519KeyPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return private, public
}

func signingPublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}

func signWSChallenge(t *testing.T, serverPublic, identityPrivate []byte, signingPrivate ed25519.PrivateKey) []byte {
	t.Helper()
	shared, err := curve25519.X25519(identityPrivate, serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	message, err := auth.WSAuthSigningMessage(serverPublic, shared)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.Sign(signingPrivate, message)
}

func newTestService() *auth.Service {
	cfg := &config.Config{
		AuthChallengeTTL: 5 * time.Second,
		AuthMaxAttempts:  3,
	}
	// db is nil — tests that reach the DB will panic, but
	// challenge-related and validation tests won't touch it.
	return auth.NewService(nil, cfg)
}

func newTestServiceWithPublicOrigin(t *testing.T, origin string) *auth.Service {
	t.Helper()
	canonicalOrigin, err := nodeorigin.ParseCanonical(origin)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		PublicOrigin:     canonicalOrigin,
		AuthChallengeTTL: 5 * time.Second,
		AuthMaxAttempts:  3,
	}
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

func TestCreateChallengeV3RequiresPublicOrigin(t *testing.T) {
	svc := newTestService()

	challenge, err := svc.CreateChallengeV3("v3-no-origin")
	if !errors.Is(err, auth.ErrPublicOriginRequired) {
		t.Fatalf("CreateChallengeV3 error = %v, want ErrPublicOriginRequired", err)
	}
	if challenge != (auth.ChallengeV3{}) {
		t.Fatalf("failed CreateChallengeV3 returned material: %+v", challenge)
	}
}

func TestCreateChallengeV3ReturnsExactFreshMaterial(t *testing.T) {
	const origin = "https://veil.example:443"
	svc := newTestServiceWithPublicOrigin(t, origin)

	first, err := svc.CreateChallengeV3("v3-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.CreateChallengeV3("v3-2")
	if err != nil {
		t.Fatal(err)
	}
	if auth.WSAuthProtocolVersionV3 != 3 {
		t.Fatalf("WSAuthProtocolVersionV3 = %d, want 3", auth.WSAuthProtocolVersionV3)
	}

	for index, challenge := range []auth.ChallengeV3{first, second} {
		if challenge.ProtocolVersion != auth.WSAuthProtocolVersionV3 {
			t.Errorf("challenge %d protocol version = %d, want 3", index, challenge.ProtocolVersion)
		}
		if challenge.CanonicalOrigin != origin {
			t.Errorf("challenge %d origin = %q, want exact %q", index, challenge.CanonicalOrigin, origin)
		}
		if challenge.ServerEphemeral == ([32]byte{}) {
			t.Errorf("challenge %d server ephemeral is zero", index)
		}
	}
	if first.ServerEphemeral == second.ServerEphemeral {
		t.Fatal("two v3 challenges produced the same server ephemeral")
	}
}

func TestVerifyResponseV2ConsumesAndRejectsV3Challenge(t *testing.T) {
	svc := newTestServiceWithPublicOrigin(t, "https://veil.example:443")
	if _, err := svc.CreateChallengeV3("v3-via-v2"); err != nil {
		t.Fatal(err)
	}

	verify := func() error {
		_, err := svc.VerifyResponseV2(
			context.Background(), "v3-via-v2",
			make([]byte, 32), signingPublicKey(t), make([]byte, ed25519.SignatureSize),
			make([]byte, 16), "test", nil, nil, nil,
		)
		return err
	}
	if err := verify(); !errors.Is(err, auth.ErrAuthProtocolMismatch) {
		t.Fatalf("first VerifyResponseV2 error = %v, want ErrAuthProtocolMismatch", err)
	}
	if err := verify(); !errors.Is(err, auth.ErrChallengeUnknown) {
		t.Fatalf("second VerifyResponseV2 error = %v, want ErrChallengeUnknown", err)
	}
}

func TestVerifyResponseV2InvalidInputDoesNotConsumeV2Challenge(t *testing.T) {
	svc := newTestService()
	if _, err := svc.CreateChallenge("v2-validation-order"); err != nil {
		t.Fatal(err)
	}

	_, err := svc.VerifyResponseV2(
		context.Background(), "v2-validation-order",
		make([]byte, 31), make([]byte, ed25519.PublicKeySize), make([]byte, ed25519.SignatureSize),
		make([]byte, 16), "test", nil, nil, nil,
	)
	if !errors.Is(err, auth.ErrBadKeyLength) {
		t.Fatalf("invalid input error = %v, want ErrBadKeyLength", err)
	}

	_, err = svc.VerifyResponseV2(
		context.Background(), "v2-validation-order",
		make([]byte, 32), signingPublicKey(t), make([]byte, ed25519.SignatureSize),
		make([]byte, 16), "test", nil, nil, nil,
	)
	if !errors.Is(err, auth.ErrBadIdentityProof) {
		t.Fatalf("post-validation VerifyResponseV2 error = %v, want ErrBadIdentityProof", err)
	}
}

func TestRemoveChallenge(t *testing.T) {
	svc := newTestService()

	svc.CreateChallenge("conn-1")
	svc.RemoveChallenge("conn-1")

	// Now VerifyResponse should return ErrChallengeUnknown
	_, err := svc.VerifyResponse(context.Background(), "conn-1",
		make([]byte, 32), signingPublicKey(t), make([]byte, 64), make([]byte, 16), "test")
	if err != auth.ErrChallengeUnknown {
		t.Fatalf("expected ErrChallengeUnknown, got %v", err)
	}
}

func TestVerifyResponse_UnknownChallenge(t *testing.T) {
	svc := newTestService()

	_, err := svc.VerifyResponse(context.Background(), "nonexistent",
		make([]byte, 32), signingPublicKey(t), make([]byte, 64), make([]byte, 16), "test")
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
		make([]byte, 32), signingPublicKey(t), make([]byte, 64), make([]byte, 8), "")
	if err != auth.ErrBadDeviceID {
		t.Fatalf("expected ErrBadDeviceID, got %v", err)
	}
}

func TestVerifyResponse_BadSignature(t *testing.T) {
	svc := newTestService()
	serverPublic, _ := svc.CreateChallenge("conn-1")

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, identityKey := x25519KeyPair(t)
	deviceID := make([]byte, 16)
	rand.Read(deviceID)

	// Wrong signature (all zeros)
	badSig := make([]byte, 64)

	_, err := svc.VerifyResponse(context.Background(), "conn-1",
		identityKey, []byte(pub), badSig, deviceID, "test")
	_ = serverPublic
	if err != auth.ErrBadSignature {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestVerifyResponseV2ChecksProofBeforeInvite(t *testing.T) {
	svc := newTestService()
	svc.CreateChallenge("invite-before-proof")

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, identityKey := x25519KeyPair(t)
	deviceID := make([]byte, 16)
	if _, err := rand.Read(deviceID); err != nil {
		t.Fatal(err)
	}

	// Even a malformed supplied invite must not be inspected until both key
	// possession proofs succeed. The bad signature is therefore authoritative.
	_, err = svc.VerifyResponseV2(
		context.Background(), "invite-before-proof",
		identityKey, pub, make([]byte, ed25519.SignatureSize),
		deviceID, "test", nil, nil, []byte("malformed-invite"),
	)
	if !errors.Is(err, auth.ErrBadSignature) {
		t.Fatalf("error = %v, want ErrBadSignature before invite evaluation", err)
	}
}

func TestVerifyResponse_RejectsLowOrderIdentityKey(t *testing.T) {
	svc := newTestService()
	svc.CreateChallenge("low-order")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	_, err := svc.VerifyResponse(context.Background(), "low-order",
		make([]byte, 32), pub, make([]byte, ed25519.SignatureSize), make([]byte, 16), "test")
	if err != auth.ErrBadIdentityProof {
		t.Fatalf("expected ErrBadIdentityProof, got %v", err)
	}
}

func TestVerifyResponseRejectsWeakEd25519SigningKeyBeforeRegistration(t *testing.T) {
	svc := newTestService()
	svc.CreateChallenge("weak-signing-key")

	_, err := svc.VerifyResponse(
		context.Background(),
		"weak-signing-key",
		bytes.Repeat([]byte{1}, 32),
		make([]byte, ed25519.PublicKeySize),
		make([]byte, ed25519.SignatureSize),
		make([]byte, 16),
		"test",
	)
	if err != auth.ErrBadSigningKey {
		t.Fatalf("weak signing key error = %v, want ErrBadSigningKey", err)
	}
}

func TestVerifyResponse_ChallengeConsumedOnce(t *testing.T) {
	svc := newTestService()
	serverPublic, _ := svc.CreateChallenge("conn-1")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	identityPrivate, identityKey := x25519KeyPair(t)
	deviceID := make([]byte, 16)
	rand.Read(deviceID)

	sig := signWSChallenge(t, serverPublic[:], identityPrivate, priv)

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

func TestVerifyResponse_ConcurrentConsumersObserveOneShotChallenge(t *testing.T) {
	svc := newTestService()
	if _, err := svc.CreateChallenge("concurrent-one-shot"); err != nil {
		t.Fatal(err)
	}
	signingKey := signingPublicKey(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := svc.VerifyResponseV2(
				context.Background(), "concurrent-one-shot",
				make([]byte, 32), signingKey, make([]byte, ed25519.SignatureSize),
				make([]byte, 16), "test", nil, nil, nil,
			)
			results <- err
		}()
	}
	close(start)

	counts := map[error]int{}
	for range 2 {
		counts[<-results]++
	}
	if counts[auth.ErrBadIdentityProof] != 1 || counts[auth.ErrChallengeUnknown] != 1 {
		t.Fatalf("concurrent one-shot results = %#v, want one identity failure and one unknown", counts)
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
		identityKey, []byte(pub), sig, deviceID, "test")
	if err != auth.ErrChallengeTooOld {
		t.Fatalf("expected ErrChallengeTooOld, got %v", err)
	}
	_, err = svc.VerifyResponse(context.Background(), "conn-1",
		identityKey, []byte(pub), sig, deviceID, "test")
	if err != auth.ErrChallengeUnknown {
		t.Fatalf("expected expired challenge to be consumed, got %v", err)
	}
}
