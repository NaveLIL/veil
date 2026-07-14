package authmw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/httpmw"
)

func TestRateLimit_AllowsBurstUpToCapacity(t *testing.T) {
	rl := NewRateLimit(3, time.Minute)
	defer rl.Close()
	h := rl.Wrap(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	for i := 0; i < 3; i++ {
		r := requestWithVerifiedUser("u1")
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("burst req %d: want 200, got %d", i, w.Code)
		}
	}
}

func TestRateLimit_RejectsAfterExhaustion(t *testing.T) {
	rl := NewRateLimit(2, time.Hour) // very slow refill
	defer rl.Close()
	h := rl.Wrap(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	for i := 0; i < 2; i++ {
		r := requestWithVerifiedUser("u1")
		h(httptest.NewRecorder(), r)
	}

	r := requestWithVerifiedUser("u1")
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
}

func TestRateLimit_BucketsAreIndependentPerUser(t *testing.T) {
	rl := NewRateLimit(1, time.Hour)
	defer rl.Close()
	h := rl.Wrap(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	for _, uid := range []string{"a", "b", "c"} {
		r := requestWithVerifiedUser(uid)
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("user %q: want 200, got %d", uid, w.Code)
		}
	}
}

func TestRateLimit_FallsBackToIPWhenNoUser(t *testing.T) {
	rl := NewRateLimit(1, time.Hour)
	defer rl.Close()
	h := rl.Wrap(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	r1 := httptest.NewRequest(http.MethodGet, "/x", nil)
	r1.RemoteAddr = "1.2.3.4:1111"
	w1 := httptest.NewRecorder()
	h(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first ip request: want 200, got %d", w1.Code)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	r2.RemoteAddr = "1.2.3.4:2222"
	w2 := httptest.NewRecorder()
	h(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second ip request: want 429, got %d", w2.Code)
	}
}

func TestRateLimit_IgnoresSpoofedIdentityHeaders(t *testing.T) {
	rl := NewRateLimit(1, time.Hour)
	defer rl.Close()
	h := rl.Wrap(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	first := httptest.NewRequest(http.MethodGet, "/x", nil)
	first.RemoteAddr = "1.2.3.4:1111"
	first.Header.Set("X-User-ID", "victim-a")
	h(httptest.NewRecorder(), first)

	second := httptest.NewRequest(http.MethodGet, "/x", nil)
	second.RemoteAddr = "1.2.3.4:2222"
	second.Header.Set("X-User-ID", "victim-b")
	w := httptest.NewRecorder()
	h(w, second)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed header selected a fresh quota bucket: got %d, want 429", w.Code)
	}
}

func TestClientIPTrustsOnlyExplicitProxyAndSingleHop(t *testing.T) {
	policy, err := httpmw.NewClientIPPolicy(false, []string{"172.18.0.0/16", "127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	httpmw.SetClientIPPolicy(policy)
	t.Cleanup(func() { httpmw.SetClientIPPolicy(nil) })

	direct := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
	direct.RemoteAddr = "198.51.100.10:4321"
	direct.Header.Set("X-Forwarded-For", "203.0.113.99")
	if got := clientIP(direct); got != "198.51.100.10" {
		t.Fatalf("public client spoofed forwarded IP: %q", got)
	}

	proxied := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
	proxied.RemoteAddr = "172.18.0.4:4321"
	proxied.Header.Set("X-Forwarded-For", "203.0.113.5")
	if got := clientIP(proxied); got != "203.0.113.5" {
		t.Fatalf("trusted proxy IP not extracted: %q", got)
	}
	multiHop := proxied.Clone(proxied.Context())
	multiHop.Header.Set("X-Forwarded-For", "203.0.113.5, 172.18.0.4")
	if got := clientIP(multiHop); got != "172.18.0.4" {
		t.Fatalf("multi-hop forwarded value should fail closed to peer: %q", got)
	}

	invalid := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
	invalid.RemoteAddr = "127.0.0.1:4321"
	invalid.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := clientIP(invalid); got != "127.0.0.1" {
		t.Fatalf("invalid forwarded value should fall back to peer: %q", got)
	}
}

func TestRequireSignedRunsBeforePrincipalRateLimit(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const userID = "11111111-1111-4111-8111-111111111111"
	middleware := New(LookupFunc(func(_ context.Context, requestedUserID string) (ed25519.PublicKey, error) {
		if requestedUserID != userID {
			t.Fatalf("lookup user = %q, want %q", requestedUserID, userID)
		}
		return publicKey, nil
	}))
	defer middleware.Close()
	limiter := NewRateLimit(1, time.Hour)
	defer limiter.Close()

	handler := middleware.RequireSigned(limiter.Wrap(func(w http.ResponseWriter, r *http.Request) {
		verified, ok := VerifiedUserID(r.Context())
		if !ok || verified != userID {
			t.Fatalf("downstream verified principal = %q, %v", verified, ok)
		}
		w.WriteHeader(http.StatusOK)
	}))

	// An unauthenticated request may spoof either identity header, but must be
	// rejected before it can consume the victim's authenticated quota.
	spoof := httptest.NewRequest(http.MethodGet, "https://example.test/x", nil)
	spoof.Header.Set("X-User-ID", userID)
	spoof.Header.Set("X-Veil-User", userID)
	spoofResponse := httptest.NewRecorder()
	handler(spoofResponse, spoof)
	if spoofResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned spoof status = %d, want 401", spoofResponse.Code)
	}

	now := time.Now().UnixMilli()
	valid := signedRateLimitRequest(t, userID, privateKey, now)
	valid.Header.Set("X-User-ID", "attacker-controlled-value")
	validResponse := httptest.NewRecorder()
	handler(validResponse, valid)
	if validResponse.Code != http.StatusOK {
		t.Fatalf("first authenticated request status = %d, want 200", validResponse.Code)
	}

	exhausted := signedRateLimitRequest(t, userID, privateKey, now+1)
	exhaustedResponse := httptest.NewRecorder()
	handler(exhaustedResponse, exhausted)
	if exhaustedResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("second authenticated request status = %d, want 429", exhaustedResponse.Code)
	}
}

func requestWithVerifiedUser(userID string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	ctx := context.WithValue(r.Context(), verifiedPrincipalContextKey{}, userID)
	return r.WithContext(ctx)
}

func signedRateLimitRequest(t *testing.T, userID string, privateKey ed25519.PrivateKey, timestamp int64) *http.Request {
	t.Helper()
	timestampString := strconv.FormatInt(timestamp, 10)
	request := httptest.NewRequest(http.MethodGet, "https://example.test/x", nil)
	canonical, err := CanonicalRequest(http.MethodGet, request.Host, "/x", timestampString, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Veil-User", userID)
	request.Header.Set("X-Veil-Timestamp", timestampString)
	request.Header.Set("X-Veil-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)))
	return request
}
