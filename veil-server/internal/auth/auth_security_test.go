package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/AegisSec/veil-server/internal/db"
)

// Regression test for account takeover via a public X25519 identity key.
// An attacker may sign the challenge with a key they own, but that key must
// never replace the Ed25519 key pinned to an existing account.
func TestVerifyRegisteredSigningKeyRejectsAttackerKey(t *testing.T) {
	victimPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attackerPublic, attackerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatal(err)
	}
	attackerSignature := ed25519.Sign(attackerPrivate, challenge)
	registered := &db.User{SigningKey: victimPublic}

	err = verifyRegisteredSigningKey(registered, attackerPublic, challenge, attackerSignature)
	if !errors.Is(err, ErrSigningKeyMismatch) {
		t.Fatalf("expected ErrSigningKeyMismatch, got %v", err)
	}
}

func TestVerifyRegisteredSigningKeyAcceptsPinnedKey(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatal(err)
	}
	registered := &db.User{SigningKey: public}

	if err := verifyRegisteredSigningKey(registered, public, challenge, ed25519.Sign(private, challenge)); err != nil {
		t.Fatalf("valid pinned key rejected: %v", err)
	}
}

func TestWSAuthSigningMessageIsDomainSeparated(t *testing.T) {
	serverPublic := make([]byte, 32)
	sharedSecret := make([]byte, 32)
	serverPublic[0] = 1
	sharedSecret[0] = 2
	message, err := WSAuthSigningMessage(serverPublic, sharedSecret)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := []byte("veil-ws-auth-v2\x00")
	if len(message) != len(wantPrefix)+64 || string(message[:len(wantPrefix)]) != string(wantPrefix) {
		t.Fatalf("unexpected WS auth domain/message layout: %x", message)
	}
	if string(message) == string(serverPublic) || string(message) == string(sharedSecret) {
		t.Fatal("WS auth message is not domain separated")
	}
}

func TestPreKeyUploadRejectsWrongDeviceOwner(t *testing.T) {
	device := &db.Device{UserID: "victim-user"}
	if deviceBelongsToUser(device, "attacker-user") {
		t.Fatal("attacker was authorized to upload prekeys for victim device")
	}
}

func TestValidateSignedPreKeyUsesRegisteredSigningKey(t *testing.T) {
	victimPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, attackerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := make([]byte, 32)
	if _, err := rand.Read(publicKey); err != nil {
		t.Fatal(err)
	}
	message, err := SignedPreKeySigningMessage(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	prekey := &preKeyInput{
		keyType:   0,
		publicKey: publicKey,
		signature: ed25519.Sign(attackerPrivate, message),
	}
	if err := validateSignedPreKey(&db.User{SigningKey: victimPublic}, prekey); err == nil {
		t.Fatal("signed prekey made by attacker key was accepted")
	}
}

func TestValidateSignedPreKeyAcceptsDomainSeparatedSignature(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prekeyPublic := make([]byte, 32)
	if _, err := rand.Read(prekeyPublic); err != nil {
		t.Fatal(err)
	}
	message, err := SignedPreKeySigningMessage(prekeyPublic)
	if err != nil {
		t.Fatal(err)
	}
	prekey := &preKeyInput{
		keyType: 0, publicKey: prekeyPublic, signature: ed25519.Sign(private, message),
	}
	if err := validateSignedPreKey(&db.User{SigningKey: public}, prekey); err != nil {
		t.Fatalf("valid domain-separated SPK signature rejected: %v", err)
	}
	if ed25519.Verify(public, prekeyPublic, prekey.signature) {
		t.Fatal("domain-separated signature unexpectedly verifies over raw SPK")
	}
}

func TestDecodePreKeyRequiresProtocolKeyIDAndStrictSignature(t *testing.T) {
	publicKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	signature := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))

	if _, err := decodePreKey(&PreKeyJSON{PublicKey: publicKey, Signature: signature}, 0); err == nil {
		t.Fatal("prekey without protocol key_id was accepted")
	}
	id := uint32(42)
	decoded, err := decodePreKey(&PreKeyJSON{KeyID: &id, PublicKey: publicKey, Signature: signature}, 0)
	if err != nil {
		t.Fatalf("valid signed prekey rejected: %v", err)
	}
	if decoded.protocolKeyID != id {
		t.Fatalf("protocol key id = %d, want %d", decoded.protocolKeyID, id)
	}
}

func TestNormalizeDeviceNameBoundsAndControls(t *testing.T) {
	name, err := normalizeDeviceName("  Windows laptop  ")
	if err != nil || name != "Windows laptop" {
		t.Fatalf("normalized device name=%q err=%v", name, err)
	}
	for label, input := range map[string]string{
		"empty":          "   ",
		"oversize":       strings.Repeat("x", 129),
		"newline":        "laptop\nforged log",
		"tab":            "laptop\tname",
		"c1 control":     "laptop\u0085name",
		"line separator": "laptop\u2028name",
		"invalid utf8":   string([]byte{0xff}),
	} {
		t.Run(label, func(t *testing.T) {
			if _, err := normalizeDeviceName(input); !errors.Is(err, ErrBadDeviceName) {
				t.Fatalf("invalid name error=%v, want ErrBadDeviceName", err)
			}
		})
	}
}
