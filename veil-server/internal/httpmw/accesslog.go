package httpmw

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/AegisSec/veil-server/internal/logsafe"
	"github.com/AegisSec/veil-server/internal/metrics"
)

// AccessLog wraps an http.Handler and emits one structured log line per
// request after it completes. The log line includes the HTTP method, path,
// status code, response size, duration, and short-lived pseudonymous
// correlation references for the client IP and authenticated user (if any).
// Raw stable identifiers are deliberately excluded from access logs.
//
// The middleware reads X-User-ID after the inner handler has run, so it
// captures the value set by authmw.RequireSigned on success.
func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return accessLog(logger, logsafe.Ref)
}

// AccessLogWithPseudonymSecret is identical to AccessLog but accepts an
// explicit 32-byte process secret. It exists for deterministic tests and for
// deployments that need same-day correlation across rolling gateway workers.
// The secret itself must come from a secret manager and must never be logged.
func AccessLogWithPseudonymSecret(logger *slog.Logger, secret []byte) func(http.Handler) http.Handler {
	pseudonyms, err := logsafe.New(secret)
	if err != nil {
		panic("httpmw: " + err.Error())
	}
	return accessLog(logger, pseudonyms.Ref)
}

func accessLog(logger *slog.Logger, pseudonymize func(domain, raw string) string) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			dur := time.Since(start)

			userRef := pseudonymize("user", r.Header.Get("X-User-ID"))
			ipRef := pseudonymize("ip", clientIP(r))
			logger.Info("http",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rw.status),
				slog.Int("bytes", rw.bytes),
				slog.String("dur", dur.String()),
				slog.String("dur_ms", strconv.FormatInt(dur.Milliseconds(), 10)),
				slog.String("user_ref", userRef),
				slog.String("ip_ref", ipRef),
			)

			// Prometheus: use the matched route template (e.g.
			// "/v1/servers/{serverID}") instead of the raw URL so id-bearing
			// paths do not blow up label cardinality. Falls back to URL.Path
			// for routes not registered on the mux (e.g. /metrics, /health).
			pathLabel := routeTemplate(r)
			metrics.ObserveHTTP(r.Method, pathLabel, rw.status, dur)
		})
	}
}

// routeTemplate returns the matched ServeMux pattern stripped of its
// HTTP-method prefix (e.g. "GET /v1/servers/{id}" → "/v1/servers/{id}").
// Falls back to r.URL.Path when no pattern is available so /metrics and
// /health still produce stable labels.
func routeTemplate(r *http.Request) string {
	p := r.Pattern
	if p == "" {
		return r.URL.Path
	}
	if i := strings.IndexByte(p, ' '); i >= 0 {
		p = p[i+1:]
	}
	return p
}

// responseRecorder captures the status code + bytes written so the access
// log can report them. It does not buffer the body.
type responseRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (r *responseRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
		r.ResponseWriter.WriteHeader(code)
	}
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.wroteHeader = true
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// Flush implements http.Flusher when the wrapped writer supports it (used
// for SSE / streaming).
func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker so that handlers performing protocol
// upgrades (e.g. the WebSocket gateway at /ws) keep working when wrapped by
// AccessLog. Without this, gorilla/websocket's Upgrade returns 500.
//
// Once the connection is hijacked we mark the request as handled with the
// special status 101 (Switching Protocols) so the access log records the
// upgrade rather than reporting a misleading 200/0-byte entry.
func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("httpmw: underlying ResponseWriter does not support hijacking")
	}
	if !r.wroteHeader {
		r.status = http.StatusSwitchingProtocols
		r.wroteHeader = true
	}
	return h.Hijack()
}
