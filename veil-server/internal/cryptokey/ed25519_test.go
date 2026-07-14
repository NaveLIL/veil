package cryptokey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
)

func TestValidEd25519PublicKeyAcceptsGeneratedKeys(t *testing.T) {
	for range 128 {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if !ValidEd25519PublicKey(publicKey) {
			t.Fatal("generated Ed25519 public key was rejected")
		}
	}
}

func TestValidEd25519PublicKeyRejectsMalformedAndTorsionPoints(t *testing.T) {
	weakEncodings := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	}
	for _, encoded := range weakEncodings {
		key, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if ValidEd25519PublicKey(key) {
			t.Fatalf("weak Ed25519 point %s was accepted", encoded)
		}
	}

	// The sign bit is forbidden when x = 0. Some decoders accept this
	// "negative zero" as another encoding of the identity point, so pin the
	// exact canonical re-encoding guard with a named regression vector.
	negativeZero := make([]byte, ed25519.PublicKeySize)
	negativeZero[0] = 1
	negativeZero[ed25519.PublicKeySize-1] = 0x80
	if ValidEd25519PublicKey(negativeZero) {
		t.Fatal("negative-zero Ed25519 identity encoding was accepted")
	}

	nonCanonical := make([]byte, ed25519.PublicKeySize)
	for index := range nonCanonical {
		nonCanonical[index] = 0xff
	}
	if ValidEd25519PublicKey(nonCanonical) {
		t.Fatal("non-canonical Ed25519 point was accepted")
	}

	orderTwo, err := hex.DecodeString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	if err != nil {
		t.Fatal(err)
	}
	torsion, err := new(edwards25519.Point).SetBytes(orderTwo)
	if err != nil {
		t.Fatal(err)
	}
	mixed := new(edwards25519.Point).Add(edwards25519.NewGeneratorPoint(), torsion).Bytes()
	if ValidEd25519PublicKey(mixed) {
		t.Fatal("mixed prime-order plus torsion Ed25519 point was accepted")
	}
}
