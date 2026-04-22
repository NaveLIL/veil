package authmw_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

func (f *fakeLookup) GetSigningKey(_ context.Context, _ string) (ed25519.PublicKey, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.pub, nil
}

func sign(t *testing.T, priv ed25519.PrivateKey, method, path string, ts int64, body []byte) string {
	t.Helper()
	h := sha256.Sum256(body)
	canonical := method + "\n" + path + "\n" + strconv.FormatInt(ts, 10) + "\n" + hex.EncodeToString(h[:])
	sig := ed25519.Sign(priv, []byte(canonical))
	return base64.StdEncoding.EncodeToString(sig)
}

func newSignedRequest(t *testing.T, priv ed25519.PrivateKey, userID, method, path string, ts int64, body []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("X-Veil-User", userID)
	r.Header.Set("X-Veil-Timestamp", strconv.FormatInt(ts, 10))
	r.Header.Set("X-Veil-Signature", sign(t, priv, method, path, ts, body))
	return r
}

func TestRequireSigned_HappyPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub}, false)
	defer mw.Close()

	called := false
	h := mw.RequireSigned(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Header.Get("X-User-ID") != "u1" {
			t.Errorf("X-User-ID not propagated, got %q", r.Header.Get("X-User-ID"))
		}
		w.WriteHeader(http.StatusOK)
	})

	body := []byte(`{"hello":"world"}`)
	r := newSignedRequest(t, priv, "u1", http.MethodPost, "/v1/things", time.Now().UnixMilli(), body)
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
	mw := authmw.New(&fakeLookup{pub: pub}, false)
	defer mw.Close()

	body := []byte(`{"x":42}`)
	var seen []byte
	h := mw.RequireSigned(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	r := newSignedRequest(t, priv, "u1", http.MethodPost, "/v1/x", time.Now().UnixMilli(), body)
	h(httptest.NewRecorder(), r)

	if !bytes.Equal(seen, body) {
		t.Fatalf("body not restored: got %q want %q", seen, body)
	}
}

func TestRequireSigned_RejectsTamperedBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub}, false)
	defer mw.Close()

	body := []byte(`{"a":1}`)
	r := newSignedRequest(t, priv, "u1", http.MethodPost, "/v1/x", time.Now().UnixMilli(), body)
	r.Body = io.NopCloser(strings.NewReader(`{"a":2}`)) // attacker swap
	w := httptest.NewRecorder()
	mw.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not be invoked when body is tampered")
	})(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestRequireSigned_RejectsStaleTimestamp(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub}, false)
	defer mw.Close()

	stale := time.Now().Add(-2 * authmw.SignatureMaxSkew).UnixMilli()
	r := newSignedRequest(t, priv, "u1", http.MethodGet, "/v1/x", stale, nil)
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
	mw := authmw.New(&fakeLookup{pub: pub}, false)
	defer mw.Close()

	body := []byte(`{}`)
	ts := time.Now().UnixMilli()
	build := func() *http.Request {
		return newSignedRequest(t, priv, "u1", http.MethodPost, "/v1/x", ts, body)
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

func TestRequireSigned_LegacyAllowedWhenConfigured(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub}, true)
	defer mw.Close()

	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r.Header.Set("X-User-ID", "legacy-uid")
	w := httptest.NewRecorder()
	called := false
	mw.RequireSigned(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})(w, r)
	if w.Code != http.StatusOK || !called {
		t.Fatalf("legacy path: want 200+called, got %d called=%v", w.Code, called)
	}
}

func TestRequireSigned_LegacyBlockedWhenStrict(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub}, false)
	defer mw.Close()

	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r.Header.Set("X-User-ID", "legacy-uid")
	w := httptest.NewRecorder()
	mw.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("strict mode must not allow legacy")
	})(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestRequireSigned_RejectsOversizedBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mw := authmw.New(&fakeLookup{pub: pub}, false)
	defer mw.Close()

	huge := bytes.Repeat([]byte("x"), 5<<20) // 5 MiB > 4 MiB limit
	r := newSignedRequest(t, priv, "u1", http.MethodPost, "/v1/x", time.Now().UnixMilli(), huge)
	w := httptest.NewRecorder()
	mw.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not invoke handler for oversized body")
	})(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", w.Code)
	}
}
