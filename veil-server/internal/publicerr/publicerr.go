// Package publicerr defines the only error values that may cross an HTTP or
// WebSocket transport boundary. Arbitrary causes are deliberately never
// rendered: database, filesystem, crypto and third-party errors often contain
// identifiers, paths, query values or secret URLs.
package publicerr

import (
	"encoding/json"
	"errors"
	"net/http"
)

const (
	CodeInvalidRequest   = "invalid_request"
	CodeUnauthenticated  = "unauthenticated"
	CodePermissionDenied = "permission_denied"
	CodeNotFound         = "not_found"
	CodeConflict         = "conflict"
	CodeRateLimited      = "rate_limited"
	CodeUnsupported      = "unsupported"
	CodeUnavailable      = "unavailable"
	CodeInternal         = "internal_error"
)

// Error carries a stable public contract while retaining its private cause for
// errors.Is/errors.As and server-side diagnostics.
type Error struct {
	status  int
	code    string
	message string
	cause   error
}

// New marks code and message as safe to disclose. Keep messages static: never
// interpolate identifiers, paths, SQL details, URLs, tokens or cause.Error().
func New(status int, code, message string, cause error) *Error {
	if status < 400 || status > 599 {
		status = http.StatusInternalServerError
	}
	if code == "" || message == "" {
		fallback := fallbackForStatus(status)
		if code == "" {
			code = fallback.Code
		}
		if message == "" {
			message = fallback.Message
		}
	}
	return &Error{status: status, code: code, message: message, cause: cause}
}

func (e *Error) Error() string {
	if e == nil {
		return fallbackForStatus(http.StatusInternalServerError).Message
	}
	return e.message
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Detail is the sanitized transport representation.
type Detail struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"error"`
}

// Map returns a safe public representation. Unknown errors are mapped solely
// from the caller-selected HTTP-equivalent status; the cause text is ignored.
func Map(status int, err error) Detail {
	var exposed *Error
	if errors.As(err, &exposed) && exposed != nil {
		mappedStatus := status
		if mappedStatus == 0 {
			mappedStatus = exposed.status
		}
		// A 5xx cause is allowed to select only a deliberately generic public
		// message. Unknown 5xx values always fall through to the same contract.
		if mappedStatus == exposed.status {
			return Detail{Status: mappedStatus, Code: exposed.code, Message: exposed.message}
		}
	}
	if status < 400 || status > 599 {
		status = http.StatusInternalServerError
	}
	return fallbackForStatus(status)
}

// Write emits the common JSON error envelope. It intentionally adds a stable
// machine-readable code while retaining the legacy "error" string field.
func Write(w http.ResponseWriter, status int, err error) {
	detail := Map(status, err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(detail.Status)
	_ = json.NewEncoder(w).Encode(detail)
}

// Message is the WebSocket/protobuf adapter. The numeric envelope code remains
// the existing HTTP-equivalent status; only the human-readable text is mapped.
func Message(status int, err error) string {
	return Map(status, err).Message
}

func fallbackForStatus(status int) Detail {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return Detail{Status: status, Code: CodeInvalidRequest, Message: "invalid request"}
	case http.StatusUnauthorized:
		return Detail{Status: status, Code: CodeUnauthenticated, Message: "authentication required"}
	case http.StatusForbidden:
		return Detail{Status: status, Code: CodePermissionDenied, Message: "request not permitted"}
	case http.StatusNotFound:
		return Detail{Status: status, Code: CodeNotFound, Message: "resource not found"}
	case http.StatusConflict:
		return Detail{Status: status, Code: CodeConflict, Message: "request conflicts with current state"}
	case http.StatusTooManyRequests:
		return Detail{Status: status, Code: CodeRateLimited, Message: "too many requests"}
	case http.StatusNotImplemented:
		return Detail{Status: status, Code: CodeUnsupported, Message: "operation not supported"}
	case http.StatusServiceUnavailable:
		return Detail{Status: status, Code: CodeUnavailable, Message: "service unavailable"}
	default:
		if status >= 500 {
			return Detail{Status: status, Code: CodeInternal, Message: "internal server error"}
		}
		return Detail{Status: status, Code: CodeInvalidRequest, Message: "request rejected"}
	}
}

// SanitizeServerErrors protects third-party handlers that may otherwise put a
// storage error in a 5xx response body. Non-5xx responses pass through exactly.
func SanitizeServerErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&serverErrorWriter{ResponseWriter: w}, r)
	})
}

type serverErrorWriter struct {
	http.ResponseWriter
	wroteHeader bool
	suppressed  bool
}

// Unwrap lets net/http.ResponseController reach optional interfaces exposed by
// the underlying writer without making this wrapper transport-specific.
func (w *serverErrorWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *serverErrorWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if status < 500 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.suppressed = true
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Type", "application/json")
	w.ResponseWriter.WriteHeader(status)
	detail := fallbackForStatus(status)
	_ = json.NewEncoder(w.ResponseWriter).Encode(detail)
}

func (w *serverErrorWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.suppressed {
		return len(p), nil
	}
	return w.ResponseWriter.Write(p)
}
