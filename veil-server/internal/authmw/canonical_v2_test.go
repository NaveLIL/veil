package authmw

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

const restAuthV2TestUser = "00112233-4455-4677-8899-aabbccddeeff"

func restAuthV2TestInput() RESTAuthV2Input {
	var nonce [RESTAuthV2NonceSize]byte
	for index := range nonce {
		nonce[index] = byte(index + 1)
	}
	return RESTAuthV2Input{
		CanonicalOrigin: "https://node.example.test:443",
		UserID:          restAuthV2TestUser,
		Method:          "POST",
		RequestTarget:   "/v2/messages?b=2&a=%2F",
		TimestampMS:     1_700_000_000_123,
		Nonce:           nonce,
		BodySHA256:      RESTAuthV2BodyDigest([]byte(`{"x":1}`)),
	}
}

func TestRESTAuthV2SigningMessageHasExactBinaryGrammar(t *testing.T) {
	input := restAuthV2TestInput()
	message, err := RESTAuthV2SigningMessage(input)
	if err != nil {
		t.Fatal(err)
	}

	userID, err := ParseCanonicalRESTUserIDV2(input.UserID)
	if err != nil {
		t.Fatal(err)
	}
	var expected bytes.Buffer
	expected.WriteString(RESTAuthV2Domain)
	writeLengthPrefixed := func(value string) {
		t.Helper()
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		expected.Write(length[:])
		expected.WriteString(value)
	}
	writeLengthPrefixed(input.CanonicalOrigin)
	expected.Write(userID[:])
	writeLengthPrefixed(input.Method)
	writeLengthPrefixed(input.RequestTarget)
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], input.TimestampMS)
	expected.Write(timestamp[:])
	expected.Write(input.Nonce[:])
	expected.Write(input.BodySHA256[:])

	if !bytes.Equal(message, expected.Bytes()) {
		t.Fatalf("binary transcript mismatch\n got: %x\nwant: %x", message, expected.Bytes())
	}
	transcriptDigest := sha256.Sum256(message)
	if got := hex.EncodeToString(transcriptDigest[:]); got != "c4f978f4012f36e39ba275182235a43e1c6f9b5e5f8f2729d8940d73665c5c4e" {
		t.Fatalf("transcript SHA-256 = %s", got)
	}
	if got := hex.EncodeToString(input.BodySHA256[:]); got != "5041bf1f713df204784353e82f6a4a535931cb64f1f4b4a5aeaffcb720918b22" {
		t.Fatalf("body SHA-256 = %s", got)
	}
}

func TestRESTAuthV2SignatureBindsEveryFieldAndDomain(t *testing.T) {
	input := restAuthV2TestInput()
	message, err := RESTAuthV2SigningMessage(input)
	if err != nil {
		t.Fatal(err)
	}
	var seed [ed25519.SeedSize]byte
	for index := range seed {
		seed[index] = byte(0x80 + index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, message)
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("valid REST auth v2 signature did not verify")
	}

	otherOrigin := input
	otherOrigin.CanonicalOrigin = "https://other.example.test:443"
	otherUser := input
	otherUser.UserID = "10112233-4455-4677-8899-aabbccddeeff"
	otherMethod := input
	otherMethod.Method = "PUT"
	otherTarget := input
	otherTarget.RequestTarget = "/v2/messages?b=3&a=%2F"
	otherTimestamp := input
	otherTimestamp.TimestampMS++
	otherNonce := input
	otherNonce.Nonce[0] ^= 0x80
	otherBody := input
	otherBody.BodySHA256 = RESTAuthV2BodyDigest([]byte(`{"x":2}`))

	for name, mutated := range map[string]RESTAuthV2Input{
		"origin":    otherOrigin,
		"user":      otherUser,
		"method":    otherMethod,
		"target":    otherTarget,
		"timestamp": otherTimestamp,
		"nonce":     otherNonce,
		"body":      otherBody,
	} {
		t.Run(name, func(t *testing.T) {
			mutatedMessage, err := RESTAuthV2SigningMessage(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(mutatedMessage, message) {
				t.Fatal("field mutation did not change the transcript")
			}
			if ed25519.Verify(publicKey, mutatedMessage, signature) {
				t.Fatal("field mutation retained signature validity")
			}
		})
	}

	legacy := append([]byte("veil-rest-v1\n"), message[len(RESTAuthV2Domain):]...)
	if ed25519.Verify(publicKey, legacy, signature) {
		t.Fatal("REST v1-domain bytes verified as REST v2")
	}
}

func TestValidateCanonicalRESTOriginV2(t *testing.T) {
	accepted := []string{
		"https://node.example.test:443",
		"https://node.example.test:8443",
		"https://127.0.0.1:443",
		"https://[2001:db8::1]:443",
		"https://xn--bcher-kva.example:443",
		"http://localhost:80",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	}
	for _, origin := range accepted {
		if err := ValidateCanonicalRESTOriginV2(origin); err != nil {
			t.Errorf("origin %q rejected: %v", origin, err)
		}
	}

	rejected := []string{
		"",
		"https://node.example.test",
		"HTTPS://node.example.test:443",
		"https://Node.example.test:443",
		"https://node.example.test:0443",
		"https://node.example.test.:443",
		"https://user@node.example.test:443",
		"https://node.example.test:443/",
		"https://node.example.test:443?x=1",
		"https://node.example.test:443#fragment",
		"http://node.example.test:80",
		"http://127.0.0.2:80",
		"https://b\u00fccher.example:443",
		"https://[fe80::1%25eth0]:443",
		"https://2001:db8::1:443",
		"https://[2001:0DB8::1]:443",
		"https://[2001:db8:0:0:0:0:0:1]:443",
		"https://[::ffff:192.0.2.1]:443",
		"https://999.1.1.1:443",
		"https://12345:443",
		"https://node.example.test:0",
		"https://node.example.test:65536",
	}
	for _, origin := range rejected {
		if err := ValidateCanonicalRESTOriginV2(origin); err == nil {
			t.Errorf("non-canonical origin %q was accepted", origin)
		}
	}
}

func TestRESTAuthV2CanonicalScalarParsers(t *testing.T) {
	userBytes, err := ParseCanonicalRESTUserIDV2(restAuthV2TestUser)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(userBytes[:]); got != "00112233445546778899aabbccddeeff" {
		t.Fatalf("UUID bytes = %s", got)
	}
	for _, userID := range []string{
		strings.ToUpper(restAuthV2TestUser),
		strings.ReplaceAll(restAuthV2TestUser, "-", ""),
		"{" + restAuthV2TestUser + "}",
		"00000000-0000-0000-0000-000000000000",
	} {
		if _, err := ParseCanonicalRESTUserIDV2(userID); err == nil {
			t.Errorf("non-canonical user id %q was accepted", userID)
		}
	}

	for _, method := range []string{"GET", "POST", "M-SEARCH", "X_VEIL1"} {
		if err := ValidateCanonicalRESTMethodV2(method); err != nil {
			t.Errorf("method %q rejected: %v", method, err)
		}
	}
	for _, method := range []string{"", "get", "PO ST", "G\u00c9T", strings.Repeat("A", RESTAuthV2MaxMethodBytes+1)} {
		if err := ValidateCanonicalRESTMethodV2(method); err == nil {
			t.Errorf("invalid method %q was accepted", method)
		}
	}

	if timestamp, err := ParseCanonicalRESTTimestampV2("1700000000123"); err != nil || timestamp != 1_700_000_000_123 {
		t.Fatalf("timestamp = %d, %v", timestamp, err)
	}
	for _, timestamp := range []string{"", "0", "00", "01", "+1", "-1", "1.0", "9223372036854775808"} {
		if _, err := ParseCanonicalRESTTimestampV2(timestamp); err == nil {
			t.Errorf("non-canonical timestamp %q was accepted", timestamp)
		}
	}

	input := restAuthV2TestInput()
	encodedNonce := base64.RawURLEncoding.EncodeToString(input.Nonce[:])
	parsedNonce, err := ParseCanonicalRESTNonceV2(encodedNonce)
	if err != nil || parsedNonce != input.Nonce {
		t.Fatalf("nonce parse = %x, %v", parsedNonce, err)
	}
	zeroNonce := make([]byte, RESTAuthV2NonceSize)
	for _, nonce := range []string{
		base64.RawURLEncoding.EncodeToString(zeroNonce),
		base64.RawURLEncoding.EncodeToString(input.Nonce[:RESTAuthV2NonceSize-1]),
		encodedNonce + "=",
		strings.Repeat("!", base64.RawURLEncoding.EncodedLen(RESTAuthV2NonceSize)),
	} {
		if _, err := ParseCanonicalRESTNonceV2(nonce); err == nil {
			t.Errorf("invalid nonce %q was accepted", nonce)
		}
	}
}

func TestValidateCanonicalRESTTargetV2(t *testing.T) {
	accepted := []string{
		"/",
		"/v2/messages",
		"/v2/messages?b=2&a=%2F",
		"/caf%C3%A9",
		"/a%20b",
		"/a?x=%23&x=1?2",
		"/a?x=?",
	}
	for _, target := range accepted {
		if err := ValidateCanonicalRESTTargetV2(target); err != nil {
			t.Errorf("target %q rejected: %v", target, err)
		}
	}

	rejected := []string{
		"",
		"*",
		"https://node.example.test/v2",
		"/?",
		"/a#fragment",
		"/a\\b",
		"/a//b",
		"/a%2Fb",
		"/a b",
		"/caf\u00e9",
		"/%",
		"/%2f",
		"/%4G",
		"/%41",
		"/%2E",
		"/%5C",
		"/.",
		"/..",
		"/a/./b",
		"/a/../b",
		"/a/%2E%2E/b",
		"/a?[x]",
		strings.Repeat("/a", RESTAuthV2MaxTargetBytes),
	}
	for _, target := range rejected {
		if err := ValidateCanonicalRESTTargetV2(target); err == nil {
			t.Errorf("non-canonical target %q was accepted", target)
		}
	}
}

func TestRESTAuthV2SigningMessageRejectsInvalidFixedFields(t *testing.T) {
	input := restAuthV2TestInput()
	input.TimestampMS = 0
	if _, err := RESTAuthV2SigningMessage(input); err == nil {
		t.Fatal("zero timestamp was accepted")
	}
	input = restAuthV2TestInput()
	input.TimestampMS = math.MaxInt64 + 1
	if _, err := RESTAuthV2SigningMessage(input); err == nil {
		t.Fatal("timestamp above MaxInt64 was accepted")
	}
	input = restAuthV2TestInput()
	input.Nonce = [RESTAuthV2NonceSize]byte{}
	if _, err := RESTAuthV2SigningMessage(input); err == nil {
		t.Fatal("zero nonce was accepted")
	}
}
