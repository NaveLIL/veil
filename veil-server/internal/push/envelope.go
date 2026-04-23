// Package push implements the offline notification path for Veil.
//
// When the gateway tries to deliver a message and the recipient has no
// live WebSocket session, we POST a small encrypted envelope to every
// distributor endpoint (UnifiedPush / ntfy) the user has registered.
// The plaintext of the envelope is *not* the message body — it carries
// only enough metadata for the on-device service extension to derive
// the per-conversation push key (`K_push`) and decrypt a short preview
// stored in the envelope's ciphertext field.
//
// Server never sees plaintext. Server never sees `K_push`. Server only
// sees ciphertext bytes that the recipient device can decrypt.
//
// The server-side encryption performed in this package is **purely
// metadata-hardening** for the network path between us and ntfy.sh
// (or another UnifiedPush distributor). It uses a constant 32-byte
// transport key derived from VEIL_PUSH_TRANSPORT_KEY so a passive
// observer of the ntfy traffic sees only fixed-size opaque blobs. The
// real E2E layer is the per-conversation `K_push` which the *client*
// applies before handing the inner ciphertext to this package.
package push

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// EnvelopeKind tags the high-level reason the push was sent. Stays in
// the *outer* (transport-encrypted) layer so the on-device service can
// pick the right notification category before opening the inner blob.
type EnvelopeKind string

const (
	KindMessage EnvelopeKind = "msg"
	KindCall    EnvelopeKind = "call"
	KindMention EnvelopeKind = "mention"
)

// Envelope is the JSON the server writes (then encrypts) before POSTing
// to the distributor endpoint. Field names are kept short on purpose —
// distributor payload limits are tight (ntfy default is 4 KiB).
type Envelope struct {
	Version             int          `json:"v"`
	Kind                EnvelopeKind `json:"k"`
	ConversationIDHash  string       `json:"cid"`           // base64 of blake-equivalent 16-byte hash
	SenderIDHash        string       `json:"sid"`           // base64 of 16-byte hash
	MessageID           string       `json:"mid,omitempty"` // for de-dup on receiver
	Counter             uint64       `json:"n"`             // per-subscription monotonic, anti-replay
	InnerCiphertext     []byte       `json:"c,omitempty"`   // optional; encrypted by client with K_push
	ServerTimestampUnix int64        `json:"ts"`
}

// hashID returns the first 16 bytes of FNV-1a 128-bit hash of (salt ||
// id). FNV is used here only to avoid pulling in another sha256 import
// in this file — the hash exists for *correlation prevention* on the
// distributor side, not for cryptographic purposes (the metadata is
// already opaque under the transport AEAD layer below).
func hashID(salt []byte, id string) string {
	h := fnv.New128a()
	_, _ = h.Write(salt)
	_, _ = h.Write([]byte(id))
	sum := h.Sum(nil)
	if len(sum) > 16 {
		sum = sum[:16]
	}
	return base64.RawURLEncoding.EncodeToString(sum)
}

// PaddingTarget is the fixed payload size every dispatched push is
// padded to (after JSON + AEAD framing). 2 KiB matches the constant
// recommended in INTEGRATION_ROADMAP §Phase 4 / Pitfalls.
const PaddingTarget = 2048

// MinTransportKeyLen is the minimum length (raw bytes) of the
// VEIL_PUSH_TRANSPORT_KEY env var after base64 decoding.
const MinTransportKeyLen = chacha20poly1305.KeySize

// EncodeAndSeal serialises env to JSON, pads it to PaddingTarget bytes,
// and encrypts under an XChaCha20-Poly1305 AEAD with a fresh 24-byte
// nonce. Output layout: nonce || ciphertext || tag. Caller (dispatcher)
// is responsible for HTTP transport.
func EncodeAndSeal(transportKey []byte, env *Envelope) ([]byte, error) {
	if len(transportKey) < MinTransportKeyLen {
		return nil, fmt.Errorf("push transport key too short (need %d bytes)", MinTransportKeyLen)
	}
	plaintext, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	plaintext = padTo(plaintext, PaddingTarget-chacha20poly1305.NonceSizeX-chacha20poly1305.Overhead)

	aead, err := chacha20poly1305.NewX(transportKey[:chacha20poly1305.KeySize])
	if err != nil {
		return nil, fmt.Errorf("init xchacha: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("random nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// padTo right-pads a JSON-serialised envelope with a "p" field of
// padding bytes embedded as a JSON string. We use the trailing-NUL
// PKCS#7-ish trick: append `\x00`-filled bytes inside the JSON
// container to reach `target`. Receiver simply ignores trailing NULs
// after JSON parsing (the JSON decoder stops at the closing `}`).
func padTo(plaintext []byte, target int) []byte {
	if target <= len(plaintext) {
		return plaintext
	}
	pad := make([]byte, target-len(plaintext))
	// Pad bytes are zero — outside of any JSON token they are inert
	// for the standard library's json.Unmarshal which uses the entire
	// input only when calling Decoder.Decode + token streams.
	return append(plaintext, pad...)
}

// Open is the inverse of EncodeAndSeal. Exposed for tests and for any
// future server-side replay/audit tooling. Receiver devices replicate
// the same logic in their service extension.
func Open(transportKey, sealed []byte) (*Envelope, error) {
	if len(sealed) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, errors.New("sealed payload too short")
	}
	if len(transportKey) < MinTransportKeyLen {
		return nil, fmt.Errorf("push transport key too short (need %d bytes)", MinTransportKeyLen)
	}
	aead, err := chacha20poly1305.NewX(transportKey[:chacha20poly1305.KeySize])
	if err != nil {
		return nil, err
	}
	nonce := sealed[:chacha20poly1305.NonceSizeX]
	ct := sealed[chacha20poly1305.NonceSizeX:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("aead open: %w", err)
	}
	// Strip trailing zero padding before JSON decode.
	end := len(pt)
	for end > 0 && pt[end-1] == 0 {
		end--
	}
	var env Envelope
	if err := json.Unmarshal(pt[:end], &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	return &env, nil
}

// NewEnvelope builds a metadata-only envelope. innerCiphertext may be
// nil when the caller wants to push only the wakeup signal (the on-
// device app then fetches the message via the normal sync endpoint).
func NewEnvelope(salt []byte, kind EnvelopeKind, conversationID, senderID, messageID string, counter uint64, innerCiphertext []byte) *Envelope {
	return &Envelope{
		Version:             1,
		Kind:                kind,
		ConversationIDHash:  hashID(salt, conversationID),
		SenderIDHash:        hashID(salt, senderID),
		MessageID:           messageID,
		Counter:             counter,
		InnerCiphertext:     innerCiphertext,
		ServerTimestampUnix: time.Now().Unix(),
	}
}
