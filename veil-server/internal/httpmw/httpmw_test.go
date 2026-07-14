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

	"github.com/NaveLIL/veil/veil-server/internal/httpmw"
	"github.com/prometheus/client_golang/prometheus"
)

func TestAccessLog_RecordsStatusAndPseudonymousRefs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	secret := bytes.Repeat([]byte{0x42}, 32)

	h := httpmw.AccessLogWithPseudonymSecret(logger, secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		`path=<unmatched>`,
		`status=418`,
		`bytes=5`,
		`user_ref=v1_`,
		`ip_ref=v1_`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("log missing %q in: %s", want, line)
		}
	}
	for _, forbidden := range []string{"user-42", "10.0.0.1"} {
		if strings.Contains(line, forbidden) {
			t.Errorf("access log leaked raw identifier %q in: %s", forbidden, line)
		}
	}
}

func TestAccessLog_UsesRouteTemplateWithoutRawPathIdentifiers(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	const rawID = "5a636f65-3ab4-48b9-84b8-f4996ab73c88"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/users/{userID}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := httpmw.AccessLogWithPseudonymSecret(logger, bytes.Repeat([]byte{0x51}, 32))(mux)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/users/"+rawID, nil))

	line := buf.String()
	if !strings.Contains(line, `path=/v1/users/{userID}`) {
		t.Fatalf("access log missing matched template: %s", line)
	}
	if strings.Contains(line, rawID) {
		t.Fatalf("access log leaked raw path identifier: %s", line)
	}

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	foundTemplate := false
	for _, family := range families {
		if family.GetName() != "veil_http_requests_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if strings.Contains(label.GetValue(), rawID) {
					t.Fatalf("HTTP metric label leaked raw path identifier: %s", label.GetValue())
				}
				if label.GetName() == "path" && label.GetValue() == "/v1/users/{userID}" {
					foundTemplate = true
				}
			}
		}
	}
	if !foundTemplate {
		t.Fatal("HTTP metrics did not record the matched route template")
	}
}

func TestAccessLog_UnmatchedIdentifierPathIsCollapsed(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	const rawID = "deec5a64-c948-4138-a39f-2f6509da4729"
	h := httpmw.AccessLog(logger)(http.NotFoundHandler())
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/users/"+rawID, nil))
	if line := buf.String(); !strings.Contains(line, `path=<unmatched>`) || strings.Contains(line, rawID) {
		t.Fatalf("unsafe unmatched access log: %s", line)
	}
}

func TestAccessLog_AnonymousUser(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := httpmw.AccessLog(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))
	if !strings.Contains(buf.String(), "user_ref=-") {
		t.Errorf("expected user_ref=- for anon, got: %s", buf.String())
	}
}

func TestAccessLog_PseudonymsAreStableOnlyForSameSecret(t *testing.T) {
	logOnce := func(secret []byte) string {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		h := httpmw.AccessLogWithPseudonymSecret(logger, secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("X-User-ID", "user-42")
			w.WriteHeader(http.StatusNoContent)
		}))
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		r.RemoteAddr = "10.0.0.1:5000"
		h.ServeHTTP(httptest.NewRecorder(), r)
		return buf.String()
	}
	field := func(line, name string) string {
		prefix := name + "="
		for _, part := range strings.Fields(line) {
			if strings.HasPrefix(part, prefix) {
				return strings.TrimPrefix(part, prefix)
			}
		}
		t.Fatalf("missing %s in %q", name, line)
		return ""
	}

	first := logOnce(bytes.Repeat([]byte{1}, 32))
	second := logOnce(bytes.Repeat([]byte{1}, 32))
	differentProcess := logOnce(bytes.Repeat([]byte{2}, 32))
	if field(first, "user_ref") != field(second, "user_ref") || field(first, "ip_ref") != field(second, "ip_ref") {
		t.Fatalf("same process secret/day must produce stable refs:\n%s\n%s", first, second)
	}
	if field(first, "user_ref") == field(differentProcess, "user_ref") || field(first, "ip_ref") == field(differentProcess, "ip_ref") {
		t.Fatal("different process secrets must not produce linkable refs")
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

func TestCORS_DisallowedPreflightFailsClosed(t *testing.T) {
	h := httpmw.CORS(nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("disallowed preflight must not reach downstream")
	}))
	r := httptest.NewRequest(http.MethodOptions, "/v1/profile", nil)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("disallowed preflight: want 403, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("disallowed preflight exposed ACAO=%q", got)
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
