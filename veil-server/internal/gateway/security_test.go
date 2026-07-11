package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net/http/httptest"
	"testing"

	"github.com/AegisSec/veil-server/internal/httpmw"
)

func makeSenderKeyEnvelopeV3(group string, generation uint32, identity []byte, signingKey ed25519.PrivateKey, recipient []byte) []byte {
	const tailSize = 4 + 32 + 32 + 32 + 24 + 16 + 64
	wire := make([]byte, 3+len(group)+tailSize)
	wire[0] = 0x03
	binary.BigEndian.PutUint16(wire[1:3], uint16(len(group)))
	copy(wire[3:], group)
	cursor := 3 + len(group)
	binary.BigEndian.PutUint32(wire[cursor:cursor+4], generation)
	cursor += 4
	copy(wire[cursor:cursor+32], identity)
	cursor += 32
	signingPublic := signingKey.Public().(ed25519.PublicKey)
	copy(wire[cursor:cursor+32], signingPublic)
	cursor += 32
	ephemeral := wire[cursor : cursor+32]
	ephemeral[0] = 1
	cursor += 32
	nonce := wire[cursor : cursor+24]
	cursor += 24
	ciphertext := wire[cursor : cursor+16]
	ciphertext[0] = 1

	const domain = "veil-sealed-skdm-v3"
	aad := make([]byte, 0, len(domain)+1+2+len(group)+4+32*4)
	aad = append(aad, domain...)
	aad = append(aad, 0x03)
	aad = append(aad, wire[1:3]...)
	aad = append(aad, group...)
	aad = append(aad, wire[3+len(group):3+len(group)+4]...)
	aad = append(aad, identity...)
	aad = append(aad, signingPublic...)
	aad = append(aad, recipient...)
	aad = append(aad, ephemeral...)
	signed := append(aad, nonce...)
	signed = append(signed, ciphertext...)
	copy(wire[len(wire)-ed25519.SignatureSize:], ed25519.Sign(signingKey, signed))
	return wire
}

func TestSenderKeyEnvelopeV3BindsAllOuterMetadata(t *testing.T) {
	const conversation = "11111111-1111-4111-8111-111111111111"
	const otherConversation = "22222222-2222-4222-8222-222222222222"
	identity := make([]byte, 32)
	recipient := make([]byte, 32)
	identity[0] = 1
	recipient[0] = 3
	signingPublic, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire := makeSenderKeyEnvelopeV3(conversation, 7, identity, signingKey, recipient)

	if err := validateSenderKeyEnvelope(wire, conversation, 7, identity, signingPublic, recipient); err != nil {
		t.Fatalf("valid v3 envelope rejected: %v", err)
	}

	otherIdentity := append([]byte(nil), identity...)
	otherIdentity[0] ^= 0xff
	otherSigningKey := append([]byte(nil), signingPublic...)
	otherSigningKey[0] ^= 0xff
	otherRecipient := append([]byte(nil), recipient...)
	otherRecipient[0] ^= 0xff
	tests := []struct {
		name       string
		group      string
		generation uint32
		identity   []byte
		signingKey []byte
		recipient  []byte
	}{
		{name: "conversation", group: otherConversation, generation: 7, identity: identity, signingKey: signingPublic, recipient: recipient},
		{name: "generation", group: conversation, generation: 8, identity: identity, signingKey: signingPublic, recipient: recipient},
		{name: "identity", group: conversation, generation: 7, identity: otherIdentity, signingKey: signingPublic, recipient: recipient},
		{name: "signing key", group: conversation, generation: 7, identity: identity, signingKey: otherSigningKey, recipient: recipient},
		{name: "recipient", group: conversation, generation: 7, identity: identity, signingKey: signingPublic, recipient: otherRecipient},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSenderKeyEnvelope(wire, tc.group, tc.generation, tc.identity, tc.signingKey, tc.recipient); err == nil {
				t.Fatal("mismatched binding was accepted")
			}
		})
	}
}

func TestSenderKeyEnvelopeRejectsLegacyAndMalformedWire(t *testing.T) {
	const conversation = "11111111-1111-4111-8111-111111111111"
	identity := make([]byte, 32)
	recipient := make([]byte, 32)
	recipient[0] = 1
	signingPublic, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := makeSenderKeyEnvelopeV3(conversation, 1, identity, signingKey, recipient)

	for _, legacyVersion := range []byte{0x01, 0x02} {
		wire := append([]byte(nil), valid...)
		wire[0] = legacyVersion
		if err := validateSenderKeyEnvelope(wire, conversation, 1, identity, signingPublic, recipient); err == nil {
			t.Fatalf("legacy version %#x was accepted", legacyVersion)
		}
	}
	if err := validateSenderKeyEnvelope(valid[:len(valid)-1], conversation, 1, identity, signingPublic, recipient); err == nil {
		t.Fatal("truncated envelope was accepted")
	}
	wire := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(wire[1:3], ^uint16(0))
	if err := validateSenderKeyEnvelope(wire, conversation, 1, identity, signingPublic, recipient); err == nil {
		t.Fatal("invalid group length was accepted")
	}
	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)-ed25519.SignatureSize-1] ^= 1
	if err := validateSenderKeyEnvelope(tampered, conversation, 1, identity, signingPublic, recipient); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	tamperedSignature := append([]byte(nil), valid...)
	tamperedSignature[len(tamperedSignature)-1] ^= 1
	if err := validateSenderKeyEnvelope(tamperedSignature, conversation, 1, identity, signingPublic, recipient); err == nil {
		t.Fatal("tampered signature was accepted")
	}
	if err := validateSenderKeyEnvelope(make([]byte, 4097), conversation, 1, identity, signingPublic, recipient); err == nil {
		t.Fatal("oversize envelope was accepted")
	}
}

func TestWebSocketClientIPUsesSharedTrustedProxyPolicy(t *testing.T) {
	policy, err := httpmw.NewClientIPPolicy(false, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	httpmw.SetClientIPPolicy(policy)
	t.Cleanup(func() { httpmw.SetClientIPPolicy(nil) })
	req := httptest.NewRequest("GET", "http://example/ws", nil)
	req.RemoteAddr = "10.1.2.3:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	if got := wsClientIP(req); got != "203.0.113.7" {
		t.Fatalf("trusted WS proxy client IP = %q", got)
	}
}
