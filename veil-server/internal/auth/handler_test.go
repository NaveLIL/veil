package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/auth"
	"github.com/AegisSec/veil-server/internal/config"
)

func newTestHandler() *auth.Handler {
	cfg := &config.Config{
		AuthChallengeTTL: 5 * time.Second,
		AuthMaxAttempts:  3,
		PreKeyLowWarning: 10,
	}
	svc := auth.NewService(nil, cfg)
	return auth.NewHandler(svc)
}

func TestLookupUser_InvalidHex(t *testing.T) {
	handler := newTestHandler()
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/v1/users/not-valid-hex", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] == "" {
		t.Fatal("expected error message in response")
	}
}

func TestLookupUser_ShortKey(t *testing.T) {
	handler := newTestHandler()
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// 16 bytes hex (too short, need 32)
	req := httptest.NewRequest("GET", "/v1/users/aabbccdd00112233aabbccdd00112233", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestGetPreKeyBundle_InvalidKey(t *testing.T) {
	handler := newTestHandler()
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/v1/prekeys/zzzz", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}
