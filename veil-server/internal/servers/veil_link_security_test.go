package servers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	if got := call(http.MethodGet, veilLinkBackgroundPath, ""); got != http.StatusOK {
		t.Fatalf("first background asset status = %d, want 200", got)
	}
	if got := call(http.MethodGet, veilLinkBackgroundPath, ""); got != http.StatusOK {
		t.Fatalf("second background asset status = %d, want 200", got)
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

func TestVeilLinkBackgroundIsFixedAuditedSameOriginAsset(t *testing.T) {
	handler := NewHandler(nil, nil, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, veilLinkBackgroundPath, nil))

	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "image/jpeg" {
		t.Fatalf("background response = %d %v", recorder.Code, recorder.Header())
	}
	if recorder.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" ||
		recorder.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" ||
		recorder.Header().Get("ETag") != `"38824a5f41228389"` ||
		recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("background security headers = %v", recorder.Header())
	}
	if body := recorder.Body.Bytes(); len(body) != 149052 || len(body) < 2 || body[0] != 0xff || body[1] != 0xd8 {
		t.Fatalf("unexpected embedded JPEG length/header: %d", len(body))
	}
	sum := sha256.Sum256(recorder.Body.Bytes())
	if got := hex.EncodeToString(sum[:]); got != "38824a5f4122838998f4e33b69803c8e0e2a84f241478a0deb41ea8c9de39640" {
		t.Fatalf("embedded background digest = %s", got)
	}
}

func TestVeilLinkPortalTemplateHasOneFixedLocalImageAndNoRemoteLoader(t *testing.T) {
	if strings.Count(veilLinkPortalHTML, "url('"+veilLinkBackgroundPath+"')") != 1 {
		t.Fatal("portal must reference the reviewed local background exactly once")
	}
	canonicalLogo := "M4 4H8V11.8L4 13ZM4 16L8 14.8V20H4ZM10 2H14V10.5L10 11.7ZM10 14.7L14 13.5V22H10ZM16 5H20V8.2L16 9.4ZM16 12.4L20 11.2V19H16Z"
	if strings.Count(veilLinkPortalHTML, canonicalLogo) != 1 {
		t.Fatal("portal must embed the exact canonical Phase Shift geometry once")
	}
	for _, forbidden := range []string{
		`src="http`, `href="http`, `url('http`, `url("http`,
		"data:", "blob:", "@import", "fetch(", "XMLHttpRequest", "WebSocket",
	} {
		if strings.Contains(veilLinkPortalHTML, forbidden) {
			t.Fatalf("portal template contains forbidden loader %q", forbidden)
		}
	}
}

func TestVeilLinkPortalEscapesAuthoritativeSpaceText(t *testing.T) {
	markSeed := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	var output bytes.Buffer
	if err := veilLinkPortalTemplate.Execute(&output, map[string]string{
		"MarkSeed":    markSeed,
		"MarkRef":     markSeed[:12],
		"Name":        `<script>alert("name")</script>`,
		"Origin":      "https://veil.example",
		"Description": `</style><img src="https://attacker.invalid/pixel">`,
		"Expires":     "15 Jul 2026 · 07:30 UTC",
		"Nonce":       "AAAAAAAAAAAAAAAAAAAAAAAA",
	}); err != nil {
		t.Fatalf("render hostile portal text: %v", err)
	}
	body := output.String()
	for _, raw := range []string{`<script>alert("name")</script>`, `</style><img`} {
		if strings.Contains(body, raw) {
			t.Fatalf("portal rendered authoritative text as markup: %q", raw)
		}
	}
	if !strings.Contains(body, `data-seed="`+markSeed+`"`) ||
		!strings.Contains(body, "&lt;script&gt;alert") ||
		!strings.Contains(body, "&lt;img src=") {
		t.Fatalf("portal did not preserve escaped text/mark contract: %s", body)
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
