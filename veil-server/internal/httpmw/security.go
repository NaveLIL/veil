// Package httpmw provides cross-cutting HTTP middleware reused across
// veil-server REST endpoints: access logging, security headers and CORS.
package httpmw

import (
	"net"
	"net/http"
	"strings"
)

// SecurityHeaders sets a conservative set of headers on every response. The
// gateway returns JSON only — there's no HTML to render — so we lock things
// down: deny framing, disable MIME sniffing, neutral referrer, strict
// permissions on browser features.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Resource-Policy", "same-site")
		// API never needs to be embedded; deny all powerful browser APIs.
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
		next.ServeHTTP(w, r)
	})
}

// CORS returns middleware that enforces an allow-list of origins. Origins
// not in the list are passed through without any CORS headers — for native
// (non-browser) clients those headers are irrelevant. Pass "*" to allow all
// origins (use only in development).
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowAll := false
	allow := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		o = strings.TrimSpace(o)
		if o == "*" {
			allowAll = true
		} else if o != "" {
			allow[strings.ToLower(o)] = struct{}{}
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				_, ok := allow[strings.ToLower(origin)]
				if allowAll || ok {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Vary", "Origin")
					w.Header().Set("Access-Control-Allow-Credentials", "true")
					if r.Method == http.MethodOptions {
						w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
						w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-User-ID, X-Veil-User, X-Veil-Timestamp, X-Veil-Signature")
						w.Header().Set("Access-Control-Max-Age", "600")
						w.WriteHeader(http.StatusNoContent)
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Chain composes middleware in the order given: Chain(a, b, c)(h) ==
// a(b(c(h))). Useful for keeping wiring readable in main().
func Chain(mw ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		for i := len(mw) - 1; i >= 0; i-- {
			h = mw[i](h)
		}
		return h
	}
}

// clientIP extracts the originating client IP, honouring X-Forwarded-For
// when present (trusts only the first hop). Mirrors authmw's helper but
// kept package-local to avoid an import cycle.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if comma := strings.IndexByte(xff, ','); comma >= 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
