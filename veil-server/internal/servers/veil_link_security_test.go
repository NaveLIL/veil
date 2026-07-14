package servers

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/authmw"
)

func TestVeilLinkTokenValidationIsCanonicalAndFixedWidth(t *testing.T) {
	valid := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if !validVeilLinkToken(valid) {
		t.Fatal("canonical 256-bit Veil Link token was rejected")
	}
	for _, token := range []string{
		"",
		valid + "=",
		base64.RawURLEncoding.EncodeToString(make([]byte, 31)),
		base64.RawURLEncoding.EncodeToString(make([]byte, 33)),
		"../../join",
	} {
		if validVeilLinkToken(token) {
			t.Fatalf("invalid Veil Link token accepted: %q", token)
		}
	}
}

func TestVeilLinkPreviewAndJoinHaveIndependentRateLimits(t *testing.T) {
	previewRL := authmw.NewRateLimit(1, time.Hour)
	joinRL := authmw.NewRateLimit(1, time.Hour)
	t.Cleanup(previewRL.Close)
	t.Cleanup(joinRL.Close)
	handler := NewHandler(nil, nil, nil)
	handler.SetVeilLinkRateLimits(previewRL, joinRL)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	call := func(method, path, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "192.0.2.10:42500"
		req.Header.Set("X-User-ID", "00000000-0000-0000-0000-000000000001")
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, req)
		return recorder.Code
	}

	if got := call(http.MethodGet, "/v1/veil-links/invalid", ""); got != http.StatusNotFound {
		t.Fatalf("first preview status = %d, want 404", got)
	}
	if got := call(http.MethodGet, "/v1/veil-links/invalid", ""); got != http.StatusTooManyRequests {
		t.Fatalf("second preview status = %d, want 429", got)
	}
	if got := call(http.MethodPost, "/v1/veil-links/invalid/join", `{}`); got != http.StatusBadRequest {
		t.Fatalf("first join status = %d, want 400", got)
	}
	if got := call(http.MethodPost, "/v1/veil-links/invalid/join", `{}`); got != http.StatusTooManyRequests {
		t.Fatalf("second join status = %d, want 429", got)
	}
}

func TestPublicSpaceMarkSeedIsOpaqueAndDeterministic(t *testing.T) {
	spaceID := "915f5ec7-3b44-4a03-a428-8b9c6d4f2c46"
	first := publicSpaceMarkSeed("https://veil.example", spaceID)
	second := publicSpaceMarkSeed("https://veil.example", spaceID)
	if first != second || !validVeilLinkToken(first) {
		t.Fatalf("mark seed is not a stable 256-bit value: %q / %q", first, second)
	}
	if first == spaceID {
		t.Fatal("public mark seed leaked the internal Space ID")
	}
	if first == publicSpaceMarkSeed("https://veil.example", "2af5d5ca-97ce-4f4f-838c-aa3d25cd2f19") {
		t.Fatal("different Spaces produced the same mark seed")
	}
	if first == publicSpaceMarkSeed("https://other.example", spaceID) {
		t.Fatal("same Space ID on another Veil Node produced the same mark seed")
	}
}
