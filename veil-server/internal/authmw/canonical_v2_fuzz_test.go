package authmw

import (
	"bytes"
	"testing"
)

func FuzzRESTAuthV2SigningTranscript(f *testing.F) {
	f.Add(
		"https://veil.example:443",
		"10000000-0000-4000-8000-000000000001",
		"POST",
		"/v1/messages?limit=100",
		uint64(1),
		bytes.Repeat([]byte{0x41}, RESTAuthV2NonceSize),
		[]byte("body"),
	)
	f.Add("http://127.0.0.1:8080", "not-a-uuid", "get", "//alias", uint64(0), []byte{}, []byte{})
	f.Fuzz(func(
		t *testing.T,
		origin string,
		userID string,
		method string,
		target string,
		timestamp uint64,
		nonceBytes []byte,
		body []byte,
	) {
		var nonce [RESTAuthV2NonceSize]byte
		copy(nonce[:], nonceBytes)
		input := RESTAuthV2Input{
			CanonicalOrigin: origin,
			UserID:          userID,
			Method:          method,
			RequestTarget:   target,
			TimestampMS:     timestamp,
			Nonce:           nonce,
			BodySHA256:      RESTAuthV2BodyDigest(body),
		}
		first, err := RESTAuthV2SigningMessage(input)
		second, secondErr := RESTAuthV2SigningMessage(input)
		if (err == nil) != (secondErr == nil) || !bytes.Equal(first, second) {
			t.Fatal("REST auth v2 transcript construction is non-deterministic")
		}
		if err != nil {
			return
		}
		if ValidateCanonicalRESTOriginV2(origin) != nil ||
			ValidateCanonicalRESTMethodV2(method) != nil ||
			ValidateCanonicalRESTTargetV2(target) != nil {
			t.Fatal("transcript accepted a field rejected by its canonical validator")
		}
		if _, parseErr := ParseCanonicalRESTUserIDV2(userID); parseErr != nil {
			t.Fatal("transcript accepted a non-canonical user id")
		}
		mutated := input
		mutated.BodySHA256[0] ^= 1
		changed, changedErr := RESTAuthV2SigningMessage(mutated)
		if changedErr != nil || bytes.Equal(first, changed) {
			t.Fatal("body digest mutation did not change an accepted transcript")
		}
	})
}
