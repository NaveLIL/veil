package authmw

import (
	"errors"
	"net/http"

	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
)

var ErrRESTAuthDispatcherConfiguration = errors.New("REST authentication dispatcher configuration is invalid")

// RESTAuthVersionDispatcher is the stable route-facing wrapper around the
// mandatory REST v2 boundary. It intentionally has no mode or legacy
// dependency: a request either carries one exact v2 proof or is rejected.
type RESTAuthVersionDispatcher struct {
	v2 *RESTAuthV2HTTPBoundary
}

func NewRESTAuthVersionDispatcher(v2 *RESTAuthV2HTTPBoundary) (*RESTAuthVersionDispatcher, error) {
	if v2 == nil || v2.verifier == nil || v2.admission == nil {
		return nil, ErrRESTAuthDispatcherConfiguration
	}
	return &RESTAuthVersionDispatcher{v2: v2}, nil
}

// RequireSigned applies one exact v2 policy. There is no version negotiation
// and no fallback: malformed, missing, duplicate, or v1 proof headers fail at
// the v2 verifier before the downstream handler can observe them.
func (dispatcher *RESTAuthVersionDispatcher) RequireSigned(
	policy RESTAuthV2HTTPPolicy,
	next http.HandlerFunc,
) http.HandlerFunc {
	if dispatcher == nil || dispatcher.v2 == nil || !policy.valid() || next == nil {
		return func(w http.ResponseWriter, request *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if request != nil && request.Header != nil {
				deleteRESTAuthV2HTTPHeader(request.Header, "X-User-ID")
				deleteRESTAuthV2ProofHeaders(request.Header)
			}
			writeRESTAuthV2PublicError(w, http.StatusServiceUnavailable, publicerr.CodeUnavailable, "authentication service unavailable", nil)
		}
	}
	return dispatcher.v2.RequireSigned(policy, next)
}
