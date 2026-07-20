package authmw

import (
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
)

type RESTAuthDispatchMode uint8

const (
	RESTAuthDispatchV2Only RESTAuthDispatchMode = iota + 1
	RESTAuthDispatchPreviewDual

	// Preview compatibility must be renewed deliberately. Apart from bounding
	// accidental configuration, deriving a short deadline keeps the duration
	// representable when it is reattached to time.Now's monotonic clock.
	restAuthPreviewMaxCompatibilityLifetime = 30 * 24 * time.Hour
)

var ErrRESTAuthDispatcherConfiguration = errors.New("REST authentication dispatcher configuration is invalid")

// RESTAuthPreviewCompatibility is mandatory only for the finite Preview dual
// stack. Owner is bounded non-secret operational metadata; ExpiresAt is checked
// both at construction and for every request so a long-running process stops
// selecting legacy v1 without requiring a restart.
type RESTAuthPreviewCompatibility struct {
	Owner     string
	ExpiresAt time.Time
}

// RESTAuthVersionDispatcher selects exactly one verifier before verification.
// There is intentionally no legacy-only mode: the current live v1 middleware
// remains outside this non-activated dispatcher until an explicit cutover.
// In PreviewDual, policy is enforced by the selected v2 boundary only; the v1
// branch preserves the live middleware's existing body/media semantics. Route
// policy parity therefore remains an explicit activation review gate rather
// than being simulated with a second body read or a second admission claim.
type RESTAuthVersionDispatcher struct {
	mode           RESTAuthDispatchMode
	legacy         *Middleware
	v2             *RESTAuthV2HTTPBoundary
	compatibility  RESTAuthPreviewCompatibility
	legacyDeadline time.Time
	legacyClosed   atomic.Bool
	now            func() time.Time
}

func NewRESTAuthVersionDispatcher(
	mode RESTAuthDispatchMode,
	legacy *Middleware,
	v2 *RESTAuthV2HTTPBoundary,
	compatibility RESTAuthPreviewCompatibility,
) (*RESTAuthVersionDispatcher, error) {
	return newRESTAuthVersionDispatcherWithClock(mode, legacy, v2, compatibility, time.Now)
}

func newRESTAuthVersionDispatcherWithClock(
	mode RESTAuthDispatchMode,
	legacy *Middleware,
	v2 *RESTAuthV2HTTPBoundary,
	compatibility RESTAuthPreviewCompatibility,
	now func() time.Time,
) (*RESTAuthVersionDispatcher, error) {
	if v2 == nil || v2.verifier == nil || v2.admission == nil || now == nil {
		return nil, ErrRESTAuthDispatcherConfiguration
	}
	switch mode {
	case RESTAuthDispatchV2Only:
		if legacy != nil || compatibility.Owner != "" || !compatibility.ExpiresAt.IsZero() {
			return nil, ErrRESTAuthDispatcherConfiguration
		}
	case RESTAuthDispatchPreviewDual:
		current := now()
		lifetime := compatibility.ExpiresAt.Sub(current)
		if !validRESTAuthLegacyMiddleware(legacy) || v2.admission != legacy || !validRESTAuthCompatibilityOwner(compatibility.Owner) ||
			compatibility.ExpiresAt.IsZero() || current.IsZero() || lifetime <= 0 ||
			lifetime > restAuthPreviewMaxCompatibilityLifetime {
			return nil, ErrRESTAuthDispatcherConfiguration
		}
		// ExpiresAt commonly comes from configuration and has no monotonic
		// reading. Reattach its bounded duration to the sampled current time so
		// normal wall-clock adjustments cannot extend the v1 window.
		legacyDeadline := current.Add(lifetime)
		return &RESTAuthVersionDispatcher{
			mode: mode, legacy: legacy, v2: v2, compatibility: compatibility,
			legacyDeadline: legacyDeadline, now: now,
		}, nil
	default:
		return nil, ErrRESTAuthDispatcherConfiguration
	}
	return &RESTAuthVersionDispatcher{
		mode: mode, legacy: legacy, v2: v2, compatibility: compatibility, now: now,
	}, nil
}

// validRESTAuthLegacyMiddleware prevents PreviewDual from accepting a partial
// or typed-nil v1 dependency that would panic only after a syntactically valid
// request reached key lookup, replay caching, or body admission. These fields
// are private and immutable after New; the dispatcher is constructed before
// serving requests.
func validRESTAuthLegacyMiddleware(middleware *Middleware) bool {
	if middleware == nil || nilRESTAuthV2Dependency(middleware.lookup) ||
		middleware.keys == nil || middleware.keys.entries == nil ||
		middleware.nonces == nil || middleware.nonces.entries == nil || middleware.nonces.maxEntries < 1 ||
		middleware.bodyIngress == nil || middleware.bodyIngress.buckets == nil ||
		middleware.bodyIngress.capacity < 1 || middleware.bodyIngress.refill <= 0 || middleware.bodyIngress.idleTTL <= 0 ||
		middleware.bodySlots == nil || cap(middleware.bodySlots) < 1 || middleware.bodyClientSlotsInUse == nil ||
		middleware.stop == nil || middleware.bodyIngress.stop == nil {
		return false
	}
	select {
	case <-middleware.stop:
		return false
	default:
	}
	select {
	case <-middleware.bodyIngress.stop:
		return false
	default:
	}
	return true
}

func validRESTAuthCompatibilityOwner(owner string) bool {
	if owner == "" || len(owner) > 64 || strings.TrimSpace(owner) != owner {
		return false
	}
	for index := 0; index < len(owner); index++ {
		character := owner[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._@-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

// RequireSigned returns a per-route version-selecting handler. The explicit
// media/body policy belongs to v2; see RESTAuthVersionDispatcher for the
// deliberately non-activated PreviewDual v1 limitation. A malformed selector
// is never tried against either verifier, and a selected v2 failure is never
// retried as v1.
func (dispatcher *RESTAuthVersionDispatcher) RequireSigned(
	policy RESTAuthV2HTTPPolicy,
	next http.HandlerFunc,
) http.HandlerFunc {
	if dispatcher == nil || dispatcher.v2 == nil || dispatcher.now == nil || !policy.valid() || next == nil {
		return func(w http.ResponseWriter, request *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if request != nil && request.Header != nil {
				deleteRESTAuthV2HTTPHeader(request.Header, "X-User-ID")
				deleteRESTAuthV2ProofHeaders(request.Header)
			}
			writeRESTAuthV2PublicError(w, http.StatusServiceUnavailable, publicerr.CodeUnavailable, "authentication service unavailable", nil)
		}
	}
	v2Handler := dispatcher.v2.RequireSigned(policy, next)
	var legacyHandler http.HandlerFunc
	if dispatcher.mode == RESTAuthDispatchPreviewDual && dispatcher.legacy != nil {
		legacyHandler = dispatcher.legacy.RequireSigned(next)
	}

	return func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if request == nil || request.Header == nil {
			writeRESTAuthV2PublicError(w, http.StatusBadRequest, publicerr.CodeInvalidRequest, "invalid authentication request", nil)
			return
		}
		deleteRESTAuthV2HTTPHeader(request.Header, "X-User-ID")
		versions, versionPresent := collectRESTAuthV2HTTPHeader(request.Header, RESTAuthV2VersionHeader)
		_, noncePresent := collectRESTAuthV2HTTPHeader(request.Header, RESTAuthV2NonceHeader)
		// The selected legacy middleware and its downstream handler may still
		// inspect v1 proof headers during this call. Remove them before control
		// returns to any outer post-request logger; v2 removes them earlier.
		defer deleteRESTAuthV2ProofHeaders(request.Header)

		if versionPresent {
			if len(versions) != 1 || versions[0] != RESTAuthV2ProtocolVersion {
				writeRESTAuthV2PublicError(w, http.StatusBadRequest, publicerr.CodeInvalidRequest, "invalid authentication request", nil)
				return
			}
			v2Handler(w, request)
			return
		}
		if noncePresent {
			writeRESTAuthV2PublicError(w, http.StatusBadRequest, publicerr.CodeInvalidRequest, "invalid authentication request", nil)
			return
		}
		if dispatcher.mode != RESTAuthDispatchPreviewDual || legacyHandler == nil || !dispatcher.legacyPreviewActive() {
			writeRESTAuthV2PublicError(w, http.StatusBadRequest, publicerr.CodeInvalidRequest, "invalid authentication request", nil)
			return
		}
		if !legacyRESTAuthHeaderCardinalityAllowed(request.Header) {
			writeRESTAuthV2PublicError(w, http.StatusBadRequest, publicerr.CodeInvalidRequest, "invalid authentication request", nil)
			return
		}
		legacyHandler(w, request)
	}
}

// legacyPreviewActive is sticky fail-closed. Once any request observes an
// expired/invalid clock, a later wall-clock rollback cannot silently re-enable
// v1 in the same process.
func (dispatcher *RESTAuthVersionDispatcher) legacyPreviewActive() bool {
	if dispatcher.legacyClosed.Load() {
		return false
	}
	current := dispatcher.now()
	if current.IsZero() || !current.Before(dispatcher.legacyDeadline) {
		dispatcher.legacyClosed.Store(true)
		return false
	}
	// If another request closed compatibility while this one sampled the
	// clock, prefer rejection to reviving a branch already observed closed.
	return !dispatcher.legacyClosed.Load()
}

func legacyRESTAuthHeaderCardinalityAllowed(header http.Header) bool {
	for _, name := range []string{RESTAuthV2UserHeader, RESTAuthV2TimestampHeader, RESTAuthV2SignatureHeader} {
		values, present := collectRESTAuthV2HTTPHeader(header, name)
		if present && len(values) != 1 {
			return false
		}
	}
	return true
}
