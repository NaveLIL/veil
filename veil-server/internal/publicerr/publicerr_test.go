package publicerr

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const secretCanary = "constraint users_identity_key_key /srv/veil/private.db 2cb4e936-225f-4768-9281-cf91fb4f173f https://token.example/secret"

func TestMapNeverDisclosesUnknownCause(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		detail := Map(status, errors.New(secretCanary))
		if strings.Contains(detail.Message, secretCanary) || detail.Code == "" {
			t.Fatalf("status %d produced unsafe detail: %#v", status, detail)
		}
	}
}

func TestExposedErrorRetainsCauseButOnlyRendersStaticContract(t *testing.T) {
	t.Parallel()
	cause := errors.New(secretCanary)
	err := New(http.StatusConflict, "sender_key_stale", "sender-key state changed", cause)
	if !errors.Is(err, cause) {
		t.Fatal("wrapped cause was lost")
	}
	detail := Map(http.StatusConflict, err)
	if detail.Code != "sender_key_stale" || detail.Message != "sender-key state changed" {
		t.Fatalf("unexpected public detail: %#v", detail)
	}
	if strings.Contains(detail.Message, secretCanary) {
		t.Fatal("cause leaked through exposed error")
	}
}

func TestWriteUsesLegacyErrorAndStableCode(t *testing.T) {
	t.Parallel()
	rr := httptest.NewRecorder()
	Write(rr, http.StatusInternalServerError, errors.New(secretCanary))
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), `"code":"internal_error"`) || !strings.Contains(rr.Body.String(), `"error":"internal server error"`) {
		t.Fatalf("unexpected response: status=%d body=%q", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), secretCanary) {
		t.Fatal("private cause leaked in JSON")
	}
}

func TestSanitizeServerErrorsReplacesThirdParty5xxBody(t *testing.T) {
	t.Parallel()
	h := SanitizeServerErrors(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "999")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(secretCanary))
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/uploads/private", nil))
	if rr.Code != http.StatusInternalServerError || strings.Contains(rr.Body.String(), secretCanary) {
		t.Fatalf("unsafe third-party response: status=%d body=%q", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type=%q", got)
	}
}

func TestSanitizeServerErrorsLeavesNon5xxBodyUntouched(t *testing.T) {
	t.Parallel()
	h := SanitizeServerErrors(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("safe conflict"))
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPatch, "/uploads/id", nil))
	if rr.Code != http.StatusConflict || rr.Body.String() != "safe conflict" {
		t.Fatalf("non-5xx response changed: status=%d body=%q", rr.Code, rr.Body.String())
	}
}
