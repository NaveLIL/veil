package httpmw_test

import (
	"bufio"
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AegisSec/veil-server/internal/httpmw"
)

func TestAccessLog_RecordsStatusAndUser(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	h := httpmw.AccessLog(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate auth middleware that propagates verified user.
		r.Header.Set("X-User-ID", "user-42")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`hello`))
	}))

	r := httptest.NewRequest(http.MethodPost, "/v1/things", nil)
	r.RemoteAddr = "10.0.0.1:5000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusTeapot {
		t.Fatalf("status not propagated: %d", w.Code)
	}
	line := buf.String()
	for _, want := range []string{
		`method=POST`,
		`path=/v1/things`,
		`status=418`,
		`bytes=5`,
		`user=user-42`,
		`ip=10.0.0.1`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("log missing %q in: %s", want, line)
		}
	}
}

func TestAccessLog_AnonymousUser(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := httpmw.AccessLog(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))
	if !strings.Contains(buf.String(), "user=-") {
		t.Errorf("expected user=- for anon, got: %s", buf.String())
	}
}

func TestSecurityHeaders_Applied(t *testing.T) {
	h := httpmw.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))

	for k, want := range map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Resource-Policy": "same-site",
	} {
		if got := w.Header().Get(k); got != want {
			t.Errorf("%s: want %q, got %q", k, want, got)
		}
	}
}

func TestCORS_AllowedOriginGetsHeaders(t *testing.T) {
	h := httpmw.CORS([]string{"https://app.example"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Origin", "https://app.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Errorf("ACAO: want %q, got %q", "https://app.example", got)
	}
}

func TestCORS_DisallowedOriginNoHeaders(t *testing.T) {
	h := httpmw.CORS([]string{"https://app.example"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("evil origin should not get ACAO, got %q", got)
	}
}

func TestCORS_PreflightHandled(t *testing.T) {
	h := httpmw.CORS([]string{"https://app.example"})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("preflight must short-circuit; downstream must not run")
	}))
	r := httptest.NewRequest(http.MethodOptions, "/x", nil)
	r.Header.Set("Origin", "https://app.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight: want 204, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("preflight missing Allow-Methods")
	}
}

// hijackableRecorder is an httptest.ResponseRecorder that also implements
// http.Hijacker, so we can verify AccessLog forwards Hijack() correctly.
// This guards against the regression where /ws upgrades returned 500.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}

func TestAccessLog_PreservesHijacker(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	h := httpmw.AccessLog(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("AccessLog stripped http.Hijacker — WS upgrades will fail")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		_ = conn.Close()
	}))

	rec := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ws", nil))

	if !rec.hijacked {
		t.Fatal("underlying Hijack was not called")
	}
	if !strings.Contains(buf.String(), "status=101") {
		t.Errorf("expected status=101 for hijacked conn, got: %s", buf.String())
	}
}
