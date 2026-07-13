package authmw_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/authmw"
)

type fakeLookup struct {
	pub ed25519.PublicKey
	err error
}

const signedTestUserID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

func (f *fakeLookup) GetSigningKey(_ context.Context, _ string) (ed25519.PublicKey, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.pub, nil
}

func sign(t *testing.T, priv ed25519.PrivateKey, r *http.Request, ts int64, body []byte) string {
	t.Helper()
	target := r.URL.EscapedPath()
	if target == "" {
		target = "/"
	}
	if r.URL.ForceQuery || r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	canonical, err := authmw.CanonicalRequest(r.Method, r.Host, target, strconv.FormatInt(ts, 10), body)
	if err != nil {
		t.Fatalf("canonical request: %v", err)
	}
	sig := ed25519.Sign(priv, canonical)
	return base64.StdEncoding.EncodeToString(sig)
}

func newSignedRequest(t *testing.T, priv ed25519.PrivateKey, userID, method, path string, ts int64, body []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("X-Veil-User", userID)
	r.Header.Set("X-Veil-Timestamp", strconv.FormatInt(ts, 10))
	r.Header.Set("X-Veil-Signature", sign(t, priv, r, ts, body))
	return r
}

func TestRequireSigned_BindsAuthorityAndQuery(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub})
	defer mw.Close()

	assertRejected := func(r *http.Request) {
		t.Helper()
		w := httptest.NewRecorder()
		mw.RequireSigned(func(http.ResponseWriter, *http.Request) {
			t.Fatal("tampered authority/query must not reach handler")
		})(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", w.Code)
		}
	}

	timestamp := time.Now().UnixMilli()
	queryTampered := newSignedRequest(t, priv, signedTestUserID, http.MethodGet,
		"/v1/users/search?username=alice", timestamp, nil)
	queryTampered.URL.RawQuery = "username=mallory"
	assertRejected(queryTampered)

	hostTampered := newSignedRequest(t, priv, signedTestUserID, http.MethodGet,
		"/v1/users/search?username=alice", timestamp, nil)
	hostTampered.Host = "evil.example"
	assertRejected(hostTampered)
}

func TestCanonicalRequest_NormalizesAuthorityAndHasStableVector(t *testing.T) {
	canonical, err := authmw.CanonicalRequest(
		http.MethodPost,
		"Example.COM:0443",
		"/v1/prekeys?device=7",
		"1700000000123",
		[]byte(`{"x":1}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	want := "veil-rest-v1\nPOST\nexample.com:443\n/v1/prekeys?device=7\n1700000000123\n5041bf1f713df204784353e82f6a4a535931cb64f1f4b4a5aeaffcb720918b22"
	if string(canonical) != want {
		t.Fatalf("canonical mismatch\n got: %q\nwant: %q", canonical, want)
	}

	ipv6, err := authmw.CanonicalRequest(http.MethodGet, "[2001:0DB8::1]:00443", "/x", "1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ipv6), "\n[2001:db8::1]:443\n") {
		t.Fatalf("IPv6 authority was not normalized: %q", ipv6)
	}
}

func TestRequireSigned_HappyPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub})
	defer mw.Close()

	called := false
	h := mw.RequireSigned(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Header.Get("X-User-ID") != signedTestUserID {
			t.Errorf("X-User-ID not propagated, got %q", r.Header.Get("X-User-ID"))
		}
		w.WriteHeader(http.StatusOK)
	})

	body := []byte(`{"hello":"world"}`)
	r := newSignedRequest(t, priv, signedTestUserID, http.MethodPost, "/v1/things", time.Now().UnixMilli(), body)
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !called {
		t.Fatal("downstream handler was not called")
	}
}

func TestRequireSigned_BodyPreservedForHandler(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub})
	defer mw.Close()

	body := []byte(`{"x":42}`)
	var seen []byte
	h := mw.RequireSigned(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	r := newSignedRequest(t, priv, signedTestUserID, http.MethodPost, "/v1/x", time.Now().UnixMilli(), body)
	h(httptest.NewRecorder(), r)

	if !bytes.Equal(seen, body) {
		t.Fatalf("body not restored: got %q want %q", seen, body)
	}
}

func TestRequireSigned_RejectsTamperedBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub})
	defer mw.Close()

	body := []byte(`{"a":1}`)
	r := newSignedRequest(t, priv, signedTestUserID, http.MethodPost, "/v1/x", time.Now().UnixMilli(), body)
	r.Body = io.NopCloser(strings.NewReader(`{"a":2}`)) // attacker swap
	w := httptest.NewRecorder()
	mw.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not be invoked when body is tampered")
	})(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestRequireSignedBindsBodyEvenWhenContentLengthIsZero(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub})
	defer mw.Close()

	r := newSignedRequest(t, priv, signedTestUserID, http.MethodPost, "/v1/x", time.Now().UnixMilli(), nil)
	r.Body = io.NopCloser(strings.NewReader(`{"unsigned":true}`))
	r.ContentLength = 0
	w := httptest.NewRecorder()
	mw.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("Content-Length zero allowed unsigned body bytes downstream")
	})(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for body not covered by the signature, got %d", w.Code)
	}
}

func TestRequireSigned_RejectsStaleTimestamp(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub})
	defer mw.Close()

	stale := time.Now().Add(-2 * authmw.SignatureMaxSkew).UnixMilli()
	r := newSignedRequest(t, priv, signedTestUserID, http.MethodGet, "/v1/x", stale, nil)
	w := httptest.NewRecorder()
	mw.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not invoke")
	})(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestRequireSigned_RejectsReplay(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub})
	defer mw.Close()

	body := []byte(`{}`)
	ts := time.Now().UnixMilli()
	build := func() *http.Request {
		return newSignedRequest(t, priv, signedTestUserID, http.MethodPost, "/v1/x", ts, body)
	}

	w1 := httptest.NewRecorder()
	mw.RequireSigned(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})(w1, build())
	if w1.Code != http.StatusOK {
		t.Fatalf("first call: want 200, got %d (%s)", w1.Code, w1.Body.String())
	}

	w2 := httptest.NewRecorder()
	mw.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("replay must not invoke handler")
	})(w2, build())
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("replay: want 401, got %d", w2.Code)
	}
}

func TestRequireSignedRejectsBase64PaddingBitReplayAlias(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub})
	defer mw.Close()

	ts := time.Now().UnixMilli()
	request := newSignedRequest(t, priv, signedTestUserID, http.MethodPost, "/v1/x", ts, []byte(`{}`))
	canonical := request.Header.Get("X-Veil-Signature")
	if !strings.HasSuffix(canonical, "==") {
		t.Fatalf("64-byte signature base64 has unexpected form %q", canonical)
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	index := strings.IndexByte(alphabet, canonical[len(canonical)-3])
	if index < 0 || index&0x0f != 0 {
		t.Fatalf("canonical padding bits are not zero in %q", canonical)
	}
	alias := canonical[:len(canonical)-3] + string(alphabet[index|1]) + "=="
	canonicalBytes, err := base64.StdEncoding.DecodeString(canonical)
	if err != nil {
		t.Fatal(err)
	}
	aliasBytes, err := base64.StdEncoding.DecodeString(alias)
	if err != nil || !bytes.Equal(canonicalBytes, aliasBytes) {
		t.Fatalf("test alias does not decode to the same signature: %v", err)
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(alias); err == nil {
		t.Fatal("test alias unexpectedly has canonical padding bits")
	}

	called := false
	handler := mw.RequireSigned(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	first := httptest.NewRecorder()
	handler(first, request)
	if first.Code != http.StatusOK || !called {
		t.Fatalf("canonical request status=%d called=%v", first.Code, called)
	}
	called = false

	replay := newSignedRequest(t, priv, signedTestUserID, http.MethodPost, "/v1/x", ts, []byte(`{}`))
	replay.Header.Set("X-Veil-Signature", alias)
	second := httptest.NewRecorder()
	handler(second, replay)
	if second.Code != http.StatusUnauthorized || called {
		t.Fatalf("padding-bit signature alias status=%d called=%v, want 401/false", second.Code, called)
	}
}

func TestRequireSignedRejectsTextualAliasesOfCanonicalUserID(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub})
	defer mw.Close()
	aliases := []string{
		strings.ToUpper(signedTestUserID),
		strings.ReplaceAll(signedTestUserID, "-", ""),
		"{" + signedTestUserID + "}",
		"00000000-0000-0000-0000-000000000000",
	}
	for index, alias := range aliases {
		r := newSignedRequest(t, priv, alias, http.MethodGet, "/v1/x", time.Now().UnixMilli()+int64(index), nil)
		w := httptest.NewRecorder()
		mw.RequireSigned(func(http.ResponseWriter, *http.Request) {
			t.Fatalf("non-canonical alias %q reached the handler", alias)
		})(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("alias %q status=%d, want 401", alias, w.Code)
		}
	}
}

// TestRequireSigned_RejectsBareXUserID verifies the W3 invariant: after the
// allowUnsigned bypass was deleted, a request carrying only the legacy
// X-User-ID header (no X-Veil-* triplet) must always be rejected with 401,
// regardless of middleware configuration.
func TestRequireSigned_RejectsBareXUserID(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub})
	defer mw.Close()

	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r.Header.Set("X-User-ID", "legacy-uid")
	w := httptest.NewRecorder()
	mw.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("bare X-User-ID must never be accepted")
	})(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestRequireSigned_RejectsOversizedBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub})
	defer mw.Close()

	huge := bytes.Repeat([]byte("x"), 5<<20) // 5 MiB > 4 MiB limit
	r := newSignedRequest(t, priv, signedTestUserID, http.MethodPost, "/v1/x", time.Now().UnixMilli(), huge)
	w := httptest.NewRecorder()
	mw.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not invoke handler for oversized body")
	})(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", w.Code)
	}
}

type failingBodyReader struct{ sent bool }

func (r *failingBodyReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		copy(p, []byte("partial"))
		return len("partial"), nil
	}
	return 0, errors.New("body transport failed")
}

func TestRequireSigned_RejectsBodyReadError(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub})
	defer mw.Close()
	r := newSignedRequest(t, priv, signedTestUserID, http.MethodPost, "/v1/x", time.Now().UnixMilli(), []byte("partial"))
	r.Body = io.NopCloser(&failingBodyReader{})
	w := httptest.NewRecorder()
	mw.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("partial body read must not reach handler")
	})(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("body read failure status=%d, want 400", w.Code)
	}
}
