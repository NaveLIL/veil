package authmw_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/authmw"
)

func TestRateLimit_AllowsBurstUpToCapacity(t *testing.T) {
	rl := authmw.NewRateLimit(3, time.Minute)
	defer rl.Close()
	h := rl.Wrap(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	for i := 0; i < 3; i++ {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		r.Header.Set("X-User-ID", "u1")
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("burst req %d: want 200, got %d", i, w.Code)
		}
	}
}

func TestRateLimit_RejectsAfterExhaustion(t *testing.T) {
	rl := authmw.NewRateLimit(2, time.Hour) // very slow refill
	defer rl.Close()
	h := rl.Wrap(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		r.Header.Set("X-User-ID", "u1")
		h(httptest.NewRecorder(), r)
	}

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("X-User-ID", "u1")
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
	rl := authmw.NewRateLimit(1, time.Hour)
	defer rl.Close()
	h := rl.Wrap(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	for _, uid := range []string{"a", "b", "c"} {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		r.Header.Set("X-User-ID", uid)
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("user %q: want 200, got %d", uid, w.Code)
		}
	}
}

func TestRateLimit_FallsBackToIPWhenNoUser(t *testing.T) {
	rl := authmw.NewRateLimit(1, time.Hour)
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
