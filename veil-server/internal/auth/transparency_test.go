package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
	veiltransparency "github.com/NaveLIL/veil/veil-server/internal/transparency"
)

func transparencyTestSigner(t *testing.T) *IdentityTransparencySigner {
	t.Helper()
	origin, err := nodeorigin.ParseCanonical("https://node.example:443")
	if err != nil {
		t.Fatal(err)
	}
	var seed [ed25519.SeedSize]byte
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	signer, err := NewIdentityTransparencySigner(origin, seed)
	if err != nil {
		t.Fatal(err)
	}
	signer.now = func() time.Time { return time.UnixMilli(1_718_888_888_123) }
	return signer
}

func TestIdentityTransparencyResponseIsCanonicalAndSigned(t *testing.T) {
	signer := transparencyTestSigner(t)
	event := []byte("synthetic-account-event")
	root, err := veiltransparency.LeafHash(event)
	if err != nil {
		t.Fatal(err)
	}
	proof := &db.IdentityTransparencyAccountProof{
		CanonicalEvent: event,
		LeafIndex:      0,
		Head: db.IdentityTransparencyHead{
			LogID:          signer.LogID(),
			NodeSigningKey: signer.PublicKey(),
			TreeSize:       1,
			RootHash:       root,
		},
		ConsistencyFrom: 0,
	}
	response, err := signer.response(context.Background(), "77777777-7777-4777-8777-777777777777", proof)
	if err != nil {
		t.Fatal(err)
	}
	if response.Version != 1 || response.LeafIndex != "0" || response.TreeHead.TreeSize != "1" ||
		response.TreeHead.IssuedAtMS != "1718888888123" || len(response.InclusionProof) != 0 ||
		response.InclusionProof == nil || response.ConsistencyProof == nil {
		t.Fatalf("non-canonical transparency response: %#v", response)
	}
	logID := signer.LogID()
	if response.TreeHead.LogID != hex.EncodeToString(logID[:]) {
		t.Fatal("response log id differs from signer identity")
	}
	signature, err := hex.DecodeString(response.TreeHead.Signature)
	if err != nil {
		t.Fatal(err)
	}
	head := veiltransparency.TreeHead{
		LogID:      logID,
		TreeSize:   1,
		RootHash:   root,
		IssuedAtMs: 1_718_888_888_123,
	}
	publicKey := signer.PublicKey()
	if !head.VerifyNodeSignature(response.CanonicalOrigin, publicKey[:], signature) {
		t.Fatal("response tree head signature did not verify")
	}

	proof.Head.LogID[0] ^= 1
	if _, err := signer.response(context.Background(), response.AccountUserID, proof); err == nil {
		t.Fatal("signer accepted a proof from a different log")
	}
}

func TestPreKeyProofsResponseUsesOneExactSignedHead(t *testing.T) {
	signer := transparencyTestSigner(t)
	clockCalls := 0
	signer.now = func() time.Time {
		clockCalls++
		return time.UnixMilli(1_718_888_888_123 + int64(clockCalls))
	}
	accountEvent := []byte("synthetic-account-event")
	deviceEvent := []byte("synthetic-device-binding-event")
	events := [][]byte{accountEvent, deviceEvent}
	root, err := veiltransparency.TreeRoot(events)
	if err != nil {
		t.Fatal(err)
	}
	accountInclusion, err := veiltransparency.InclusionProof(events, 0)
	if err != nil {
		t.Fatal(err)
	}
	deviceInclusion, err := veiltransparency.InclusionProof(events, 1)
	if err != nil {
		t.Fatal(err)
	}
	head := db.IdentityTransparencyHead{
		LogID:          signer.LogID(),
		NodeSigningKey: signer.PublicKey(),
		TreeSize:       2,
		RootHash:       root,
	}
	accountProof := &db.IdentityTransparencyAccountProof{
		CanonicalEvent: accountEvent,
		LeafIndex:      0,
		Head:           head,
		InclusionProof: accountInclusion,
	}
	deviceProof := &db.IdentityTransparencyDeviceBindingProof{
		CanonicalEvent: deviceEvent,
		LeafIndex:      1,
		Head:           head,
		InclusionProof: deviceInclusion,
	}
	deviceKey := make([]byte, 16)
	for index := range deviceKey {
		deviceKey[index] = byte(index + 1)
	}

	response, sameHead, err := signer.preKeyProofsResponse(
		context.Background(),
		"77777777-7777-4777-8777-777777777777",
		accountProof,
		deviceKey,
		7,
		deviceProof,
	)
	if err != nil || !sameHead || response == nil {
		t.Fatalf("response=%#v same_head=%v err=%v", response, sameHead, err)
	}
	if clockCalls != 1 {
		t.Fatalf("signed-head clock was sampled %d times instead of once", clockCalls)
	}
	if !reflect.DeepEqual(response.Account.TreeHead, response.DeviceBinding.TreeHead) {
		t.Fatal("prekey proofs did not reuse one exact signed tree head")
	}
	if response.Account.CanonicalEvent != base64.RawURLEncoding.EncodeToString(accountEvent) ||
		response.DeviceBinding.CanonicalEvent != base64.RawURLEncoding.EncodeToString(deviceEvent) ||
		response.DeviceBinding.DeviceKey != hex.EncodeToString(deviceKey) ||
		response.DeviceBinding.DeviceBindingVersion != "7" {
		t.Fatalf("prekey proof subjects are not exact: %#v", response)
	}

	deviceProof.Head.TreeSize++
	if response, sameHead, err := signer.preKeyProofsResponse(
		context.Background(),
		"77777777-7777-4777-8777-777777777777",
		accountProof,
		deviceKey,
		7,
		deviceProof,
	); err != nil || sameHead || response != nil {
		t.Fatalf("accepted mismatched proof heads: response=%#v same_head=%v err=%v", response, sameHead, err)
	}
	if clockCalls != 1 {
		t.Fatal("mismatched proof heads were signed before rejection")
	}
}

func TestExactTransparencyFromSize(t *testing.T) {
	for _, value := range []uint64{0, 1, 42, ^uint64(0)} {
		t.Run(strconv.FormatUint(value, 10), func(t *testing.T) {
			request := httptest.NewRequest("GET", "/v1/transparency/accounts/id?from_size="+strconv.FormatUint(value, 10), nil)
			parsed, err := exactTransparencyFromSize(request)
			if err != nil || parsed != value {
				t.Fatalf("parsed=%d err=%v, want %d", parsed, err, value)
			}
		})
	}
	request := httptest.NewRequest("GET", "/v1/transparency/accounts/id", nil)
	if parsed, err := exactTransparencyFromSize(request); err != nil || parsed != 0 {
		t.Fatalf("missing from_size parsed=%d err=%v", parsed, err)
	}
	for name, rawQuery := range map[string]string{
		"empty":           "from_size=",
		"leading zero":    "from_size=01",
		"signed":          "from_size=+1",
		"percent encoded": "from_size=%31",
		"duplicate":       "from_size=1&from_size=1",
		"unknown":         "other=1",
		"overflow":        "from_size=18446744073709551616",
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "/?"+rawQuery, nil)
			if _, err := exactTransparencyFromSize(request); err == nil {
				t.Fatalf("accepted non-canonical query %q", rawQuery)
			}
		})
	}
}

func TestIdentityTransparencyUnavailableIsNoStore(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/v1/transparency/accounts/77777777-7777-4777-8777-777777777777", nil)
	identityTransparencyNoStore((&Handler{}).GetIdentityTransparencyAccountProof)(recorder, request)
	if recorder.Code != 503 || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache-control=%q", recorder.Code, recorder.Header().Get("Cache-Control"))
	}
}
