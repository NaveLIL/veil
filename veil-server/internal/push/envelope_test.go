package push

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, MinTransportKeyLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestEncodeAndSeal_Roundtrip(t *testing.T) {
	key := newKey(t)
	salt := []byte("integration-salt")
	env := NewEnvelope(salt, KindMessage, "conv-1", "sender-1", "msg-1", 42, []byte("inner-bytes"))

	sealed, err := EncodeAndSeal(key, env)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(sealed) != PaddingTarget {
		t.Fatalf("expected sealed length %d, got %d", PaddingTarget, len(sealed))
	}

	got, err := Open(key, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.ConversationIDHash != env.ConversationIDHash || got.SenderIDHash != env.SenderIDHash {
		t.Fatalf("envelope hashes lost in roundtrip")
	}
	if got.MessageID != "msg-1" || got.Counter != 42 || got.Kind != KindMessage {
		t.Fatalf("envelope fields lost: %+v", got)
	}
	if !bytes.Equal(got.InnerCiphertext, env.InnerCiphertext) {
		t.Fatalf("inner ciphertext lost")
	}
}

func TestEncodeAndSeal_ConstantSize(t *testing.T) {
	key := newKey(t)
	salt := []byte("salt")
	short := NewEnvelope(salt, KindMessage, "c", "s", "m", 1, nil)
	long := NewEnvelope(salt, KindMessage, "c", "s", "m", 1, bytes.Repeat([]byte("X"), 800))

	a, err := EncodeAndSeal(key, short)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncodeAndSeal(key, long)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatalf("padding broken: short=%d long=%d", len(a), len(b))
	}
}

func TestOpen_RejectsTamper(t *testing.T) {
	key := newKey(t)
	env := NewEnvelope([]byte("s"), KindMessage, "c", "s", "m", 1, nil)
	sealed, err := EncodeAndSeal(key, env)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the ciphertext region (skip the nonce prefix).
	sealed[100] ^= 0x01
	if _, err := Open(key, sealed); err == nil {
		t.Fatal("Open accepted tampered ciphertext")
	}
}

func TestOpen_RejectsWrongKey(t *testing.T) {
	key := newKey(t)
	other := newKey(t)
	env := NewEnvelope(nil, KindMessage, "c", "s", "m", 1, nil)
	sealed, err := EncodeAndSeal(key, env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(other, sealed); err == nil {
		t.Fatal("Open accepted wrong key")
	}
}

func TestEncodeAndSeal_RequiresKey(t *testing.T) {
	env := NewEnvelope(nil, KindMessage, "c", "s", "m", 1, nil)
	if _, err := EncodeAndSeal(nil, env); err == nil {
		t.Fatal("expected error for nil key")
	}
	if _, err := EncodeAndSeal(make([]byte, 8), env); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestHashID_DependsOnSalt(t *testing.T) {
	a := hashID([]byte("salt-A"), "conv-1")
	b := hashID([]byte("salt-B"), "conv-1")
	if a == b {
		t.Fatal("hashID must depend on salt")
	}
}

func TestEnvelope_JSONShape(t *testing.T) {
	env := NewEnvelope([]byte("s"), KindMention, "c", "s", "m", 7, nil)
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	// Field names are short on purpose to fit in distributor payload limits.
	for _, key := range []string{`"v":1`, `"k":"mention"`, `"cid":`, `"sid":`, `"mid":"m"`, `"n":7`, `"ts":`} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Fatalf("expected %s in %s", key, raw)
		}
	}
}
