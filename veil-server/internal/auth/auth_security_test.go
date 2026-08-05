package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NaveLIL/veil/veil-server/internal/authmw"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/jackc/pgx/v5"
)

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

func TestDecodePreKeyRequiresPositiveIDAndCanonicalPaddedBase64(t *testing.T) {
	publicKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	signature := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	id := uint32(1)
	valid := &PreKeyJSON{KeyID: &id, PublicKey: publicKey, Signature: signature}
	if _, err := decodePreKey(valid, 0); err != nil {
		t.Fatalf("canonical signed prekey rejected: %v", err)
	}

	zero := uint32(0)
	cases := map[string]*PreKeyJSON{
		"zero key id": {
			KeyID: &zero, PublicKey: publicKey, Signature: signature,
		},
		"unpadded public key": {
			KeyID: &id, PublicKey: strings.TrimSuffix(publicKey, "="), Signature: signature,
		},
		"public key with newline": {
			KeyID: &id, PublicKey: publicKey + "\n", Signature: signature,
		},
		"non-zero public key padding bits": {
			KeyID: &id, PublicKey: publicKey[:len(publicKey)-2] + "B=", Signature: signature,
		},
		"unpadded signature": {
			KeyID: &id, PublicKey: publicKey, Signature: strings.TrimRight(signature, "="),
		},
		"signature with newline": {
			KeyID: &id, PublicKey: publicKey, Signature: signature + "\n",
		},
	}
	for name, prekey := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePreKey(prekey, 0); err == nil {
				t.Fatal("non-canonical prekey was accepted")
			}
		})
	}
}

func TestUploadPreKeysRequiresStrictSingleJSONAndSignedPreKey(t *testing.T) {
	deviceID := strings.Repeat("00", 16)
	publicKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	signature := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	signedPreKey := `{"key_id":1,"public_key":"` + publicKey + `","signature":"` + signature + `"}`
	validPrefix := `{"device_id":"` + deviceID + `","signed_prekey":` + signedPreKey

	cases := map[string]string{
		"missing signed prekey":   `{"device_id":"` + deviceID + `"}`,
		"unknown top-level field": validPrefix + `,"unexpected":true}`,
		"unknown nested field": `{"device_id":"` + deviceID + `","signed_prekey":` +
			`{"key_id":1,"public_key":"` + publicKey + `","signature":"` + signature + `","unexpected":true}}`,
		"trailing JSON value": validPrefix + `} {}`,
		"uppercase device id": `{"device_id":"` + strings.Repeat("AA", 16) + `","signed_prekey":` + signedPreKey + `}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/prekeys", strings.NewReader(body))
			req.Header.Set("X-User-ID", "authenticated-user")
			response := httptest.NewRecorder()

			(&Handler{}).UploadPreKeys(response, req)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control=%q, want no-store", got)
			}
		})
	}
}

func TestUploadPreKeysEnforcesBodyLimitWithoutEchoingBody(t *testing.T) {
	const sensitiveMarker = "sensitive-marker"
	tests := []struct {
		name   string
		body   string
		status int
	}{
		{
			name:   "exact limit reaches JSON validation",
			body:   strings.Repeat(" ", maxPreKeyUploadBodyBytes),
			status: http.StatusBadRequest,
		},
		{
			name:   "one byte over limit",
			body:   sensitiveMarker + strings.Repeat("x", maxPreKeyUploadBodyBytes-len(sensitiveMarker)+1),
			status: http.StatusRequestEntityTooLarge,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/prekeys", strings.NewReader(test.body))
			request.Header.Set("X-User-ID", "authenticated-user")
			response := httptest.NewRecorder()

			(&Handler{}).UploadPreKeys(response, request)

			if response.Code != test.status {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), test.status)
			}
			if strings.Contains(response.Body.String(), sensitiveMarker) {
				t.Fatal("oversized request material leaked into response")
			}
			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control=%q, want no-store", got)
			}
		})
	}
}

func TestRejectDuplicateJSONKeysAtAnyNestingLevel(t *testing.T) {
	duplicates := map[string]string{
		"top level":           `{"device_id":"a","device_id":"b"}`,
		"escaped equivalent":  `{"device_id":"a","device_\u0069d":"b"}`,
		"nested object":       `{"signed_prekey":{"key_id":1,"key_id":2}}`,
		"object inside array": `{"one_time_prekeys":[{"key_id":1,"public_key":"a","public_key":"b"}]}`,
		"deeply nested":       `{"outer":[{"inner":{"value":1,"value":2}}]}`,
	}
	for name, body := range duplicates {
		t.Run(name, func(t *testing.T) {
			if err := rejectDuplicateJSONKeys([]byte(body)); !errors.Is(err, errDuplicateJSONKey) {
				t.Fatalf("duplicate scan error=%v, want errDuplicateJSONKey", err)
			}
		})
	}

	compatible := []byte(`
		{
			"one_time_prekeys": [
				{"public_key": "a", "key_id": 2},
				{"key_id": 3, "public_key": "b"}
			],
			"signed_prekey": {"signature": "c", "key_id": 1, "public_key": "d"},
			"device_id": "00112233445566778899aabbccddeeff"
		}
	`)
	if err := rejectDuplicateJSONKeys(compatible); err != nil {
		t.Fatalf("whitespace/order-compatible JSON rejected: %v", err)
	}
}

func TestUploadPreKeysMapsDuplicateJSONKeysToGenericBadRequest(t *testing.T) {
	deviceID := strings.Repeat("00", 16)
	body := `{"device_id":"` + deviceID + `","device_id":"` + deviceID + `"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/prekeys", strings.NewReader(body))
	request.Header.Set("X-User-ID", "authenticated-user")
	response := httptest.NewRecorder()

	(&Handler{}).UploadPreKeys(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid JSON") {
		t.Fatalf("status=%d body=%s, want generic invalid JSON", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "device_id") {
		t.Fatal("duplicate attacker-controlled key leaked into response")
	}
}

func TestPreKeyIdentityPathsRequireCanonicalLowercaseUnescapedHex(t *testing.T) {
	lowercase := strings.Repeat("a", 64)
	uppercase := strings.Repeat("A", 64)
	tests := []struct {
		name       string
		path       string
		pathValue  string
		endpoint   func(http.ResponseWriter, *http.Request)
		authorized bool
	}{
		{
			name:      "bundle uppercase",
			path:      "/v1/prekeys/" + uppercase,
			pathValue: uppercase,
			endpoint:  (&Handler{}).GetPreKeyBundle,
		},
		{
			name:       "count uppercase",
			path:       "/v1/prekeys/" + uppercase + "/count",
			pathValue:  uppercase,
			endpoint:   (&Handler{}).GetOPKCount,
			authorized: true,
		},
		{
			name:      "bundle escaped",
			path:      "/v1/prekeys/%61" + lowercase[1:],
			pathValue: lowercase,
			endpoint:  (&Handler{}).GetPreKeyBundle,
		},
		{
			name:       "count escaped",
			path:       "/v1/prekeys/%61" + lowercase[1:] + "/count",
			pathValue:  lowercase,
			endpoint:   (&Handler{}).GetOPKCount,
			authorized: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.SetPathValue("identityKey", test.pathValue)
			if test.authorized {
				request.Header.Set("X-User-ID", "authenticated-user")
			}
			response := httptest.NewRecorder()

			test.endpoint(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control=%q, want no-store", got)
			}
		})
	}
}

func TestPreKeyReadEndpointsSetNoStoreOnErrors(t *testing.T) {
	handler := &Handler{}
	tests := map[string]func(http.ResponseWriter, *http.Request){
		"bundle": handler.GetPreKeyBundle,
		"count":  handler.GetOPKCount,
	}
	for name, endpoint := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			response := httptest.NewRecorder()

			endpoint(response, request)

			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control=%q, want no-store", got)
			}
		})
	}
}

func TestRegisteredPreKeyRoutesSetNoStoreBeforeSignatureMiddleware(t *testing.T) {
	middleware := authmw.New(authmw.LookupFunc(
		func(context.Context, string) (ed25519.PublicKey, error) {
			t.Fatal("unsigned request unexpectedly reached key lookup")
			return nil, nil
		},
	))
	defer middleware.Close()
	handler := NewHandler(nil, middleware, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	request := httptest.NewRequest(
		http.MethodGet,
		"/v1/prekeys/"+strings.Repeat("00", 32)+"/count",
		nil,
	)
	response := httptest.NewRecorder()

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s, want 503", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", got)
	}
}

func TestLoadDevicePreKeyCountsIncludesNullableSignedPreKeyID(t *testing.T) {
	devices := []db.Device{
		{ID: "with-spk", DeviceKey: make([]byte, 16)},
		{ID: "without-spk", DeviceKey: make([]byte, 16)},
	}
	counts, err := loadDevicePreKeyCounts(
		context.Background(),
		devices,
		func(context.Context, string) (int, error) { return 7, nil },
		func(_ context.Context, deviceID string) (*db.PreKey, error) {
			if deviceID == "without-spk" {
				return &db.PreKey{ProtocolKeyID: 999}, pgx.ErrNoRows
			}
			return &db.PreKey{ProtocolKeyID: 42}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if counts[0].SignedPreKeyID == nil || *counts[0].SignedPreKeyID != 42 {
		t.Fatalf("signed_prekey_id=%v, want 42", counts[0].SignedPreKeyID)
	}
	if counts[1].SignedPreKeyID != nil {
		t.Fatalf("missing signed prekey id=%v, want nil", *counts[1].SignedPreKeyID)
	}
	encoded, err := json.Marshal(counts[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"signed_prekey_id":null`) {
		t.Fatalf("nullable signed_prekey_id missing from JSON: %s", encoded)
	}
}

func TestLoadDevicePreKeyCountsPropagatesDatabaseErrors(t *testing.T) {
	databaseError := errors.New("database unavailable")
	device := []db.Device{{ID: "device", DeviceKey: make([]byte, 16)}}

	_, err := loadDevicePreKeyCounts(
		context.Background(),
		device,
		func(context.Context, string) (int, error) { return 0, databaseError },
		func(context.Context, string) (*db.PreKey, error) { return nil, nil },
	)
	if !errors.Is(err, databaseError) {
		t.Fatalf("count error=%v, want database error", err)
	}

	_, err = loadDevicePreKeyCounts(
		context.Background(),
		device,
		func(context.Context, string) (int, error) { return 0, nil },
		func(context.Context, string) (*db.PreKey, error) { return nil, databaseError },
	)
	if !errors.Is(err, databaseError) {
		t.Fatalf("signed prekey error=%v, want database error", err)
	}
}
