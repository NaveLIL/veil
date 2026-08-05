package authmw

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
)

const RESTAuthV2MaxBodyBytes = maxSignedBodyBytes

var ErrRESTAuthV2HTTPConfiguration = errors.New("REST auth v2 HTTP boundary configuration is invalid")

type restAuthV2HTTPBodyMode uint8

const (
	restAuthV2HTTPBodyInvalid restAuthV2HTTPBodyMode = iota
	restAuthV2HTTPBodyForbidden
	restAuthV2HTTPBodyRequired
)

// RESTAuthV2HTTPPolicy fixes the body and parser boundary for one signed route.
// Its fields are deliberately private so callers cannot construct a permissive
// or partially initialized policy. The zero value is invalid and fails closed.
type RESTAuthV2HTTPPolicy struct {
	bodyMode     restAuthV2HTTPBodyMode
	mediaTypes   []string
	maxBodyBytes int64
}

// RESTAuthV2BodylessHTTPPolicy rejects every message-content byte, Content-Type,
// Content-Encoding, and trailer. A declared Content-Length of zero is allowed;
// the boundary still reads a non-empty stream when one is supplied.
func RESTAuthV2BodylessHTTPPolicy() RESTAuthV2HTTPPolicy {
	return RESTAuthV2HTTPPolicy{bodyMode: restAuthV2HTTPBodyForbidden}
}

// NewRESTAuthV2FixedBodyHTTPPolicy requires a non-empty body with one exact
// canonical media type and a route-specific maximum no greater than the shared
// signed REST ceiling. Parameters and aliases are not accepted at runtime.
func NewRESTAuthV2FixedBodyHTTPPolicy(mediaType string, maxBodyBytes int64) (RESTAuthV2HTTPPolicy, error) {
	return NewRESTAuthV2AllowedBodyHTTPPolicy([]string{mediaType}, maxBodyBytes)
}

// NewRESTAuthV2AllowedBodyHTTPPolicy requires a non-empty body with exactly
// one Content-Type from a small, route-owned allowlist. It is intended for
// binary formats such as avatar uploads where changing the representation
// would degrade existing functionality. Parameters and duplicate aliases are
// rejected rather than normalized.
func NewRESTAuthV2AllowedBodyHTTPPolicy(mediaTypes []string, maxBodyBytes int64) (RESTAuthV2HTTPPolicy, error) {
	if len(mediaTypes) == 0 || len(mediaTypes) > 8 || maxBodyBytes < 1 || maxBodyBytes > RESTAuthV2MaxBodyBytes {
		return RESTAuthV2HTTPPolicy{}, ErrRESTAuthV2HTTPConfiguration
	}
	owned := make([]string, len(mediaTypes))
	seen := make(map[string]struct{}, len(mediaTypes))
	for index, mediaType := range mediaTypes {
		if !canonicalRESTAuthV2MediaType(mediaType) {
			return RESTAuthV2HTTPPolicy{}, ErrRESTAuthV2HTTPConfiguration
		}
		if _, duplicate := seen[mediaType]; duplicate {
			return RESTAuthV2HTTPPolicy{}, ErrRESTAuthV2HTTPConfiguration
		}
		seen[mediaType] = struct{}{}
		owned[index] = mediaType
	}
	return RESTAuthV2HTTPPolicy{
		bodyMode:     restAuthV2HTTPBodyRequired,
		mediaTypes:   owned,
		maxBodyBytes: maxBodyBytes,
	}, nil
}

// NewRESTAuthV2JSONHTTPPolicy is the fixed application/json route profile.
func NewRESTAuthV2JSONHTTPPolicy(maxBodyBytes int64) (RESTAuthV2HTTPPolicy, error) {
	return NewRESTAuthV2FixedBodyHTTPPolicy("application/json", maxBodyBytes)
}

func (policy RESTAuthV2HTTPPolicy) valid() bool {
	switch policy.bodyMode {
	case restAuthV2HTTPBodyForbidden:
		return len(policy.mediaTypes) == 0 && policy.maxBodyBytes == 0
	case restAuthV2HTTPBodyRequired:
		if len(policy.mediaTypes) == 0 || len(policy.mediaTypes) > 8 ||
			policy.maxBodyBytes < 1 || policy.maxBodyBytes > RESTAuthV2MaxBodyBytes {
			return false
		}
		seen := make(map[string]struct{}, len(policy.mediaTypes))
		for _, mediaType := range policy.mediaTypes {
			if !canonicalRESTAuthV2MediaType(mediaType) {
				return false
			}
			if _, duplicate := seen[mediaType]; duplicate {
				return false
			}
			seen[mediaType] = struct{}{}
		}
		return true
	default:
		return false
	}
}

func canonicalRESTAuthV2MediaType(value string) bool {
	if value == "" || len(value) > 127 || value != strings.ToLower(value) || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, ",;") {
		return false
	}
	parsed, parameters, err := mime.ParseMediaType(value)
	return err == nil && len(parameters) == 0 && parsed == value && strings.Count(value, "/") == 1
}

// RESTAuthV2HTTPBoundary owns only request adaptation. It deliberately does
// not choose an authentication version or register a route. Body admission is
// borrowed from the existing v1 Middleware so a future Preview dual stack
// cannot double the global or per-client retained-body capacity.
type RESTAuthV2HTTPBoundary struct {
	verifier  *RESTAuthV2Verifier
	admission *Middleware
}

func NewRESTAuthV2HTTPBoundary(
	verifier *RESTAuthV2Verifier,
	sharedBodyAdmission *Middleware,
) (*RESTAuthV2HTTPBoundary, error) {
	if verifier == nil || verifier.canonicalOrigin.IsZero() || verifier.lookup == nil || verifier.replay == nil ||
		verifier.now == nil || verifier.replayTimeout <= 0 || sharedBodyAdmission == nil ||
		sharedBodyAdmission.bodyIngress == nil || sharedBodyAdmission.bodySlots == nil ||
		sharedBodyAdmission.bodyClientSlotsInUse == nil {
		return nil, ErrRESTAuthV2HTTPConfiguration
	}
	return &RESTAuthV2HTTPBoundary{verifier: verifier, admission: sharedBodyAdmission}, nil
}

// RequireSigned adapts one exact HTTP request into the transport-neutral v2
// verifier. Live routes reach this boundary through the v2-only dispatcher.
func (boundary *RESTAuthV2HTTPBoundary) RequireSigned(
	policy RESTAuthV2HTTPPolicy,
	next http.HandlerFunc,
) http.HandlerFunc {
	if boundary == nil || boundary.verifier == nil || boundary.admission == nil || !policy.valid() || next == nil {
		return func(w http.ResponseWriter, request *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if request != nil && request.Header != nil {
				deleteRESTAuthV2HTTPHeader(request.Header, "X-User-ID")
				deleteRESTAuthV2ProofHeaders(request.Header)
			}
			writeRESTAuthV2PublicError(w, http.StatusServiceUnavailable, publicerr.CodeUnavailable, "authentication service unavailable", nil)
		}
	}

	return func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if request == nil || request.Header == nil {
			writeRESTAuthV2PublicError(w, http.StatusBadRequest, publicerr.CodeInvalidRequest, "invalid authentication request", nil)
			return
		}
		// Never let an attacker-selected compatibility header survive a v2
		// failure or become visible to a downstream handler.
		deleteRESTAuthV2HTTPHeader(request.Header, "X-User-ID")
		headers := collectRESTAuthV2HTTPHeaders(request.Header)
		deleteRESTAuthV2ProofHeaders(request.Header)

		if err := validateRESTAuthV2HTTPMetadata(request, policy); err != nil {
			writeRESTAuthV2HTTPMetadataError(w, err)
			return
		}

		preflight, err := boundary.verifier.preflight(
			request.Context(),
			headers,
			request.Method,
			request.RequestURI,
		)
		if err != nil {
			writeRESTAuthV2VerifierError(w, err)
			return
		}
		// Admission and body I/O can still fail after preflight. Bound the
		// continuation lifetime on every path; finish also clears it, and the
		// second clear on a successful path is intentionally harmless.
		defer preflight.clear()

		body, release, err := boundary.readAndRestoreBody(w, request, policy)
		if release != nil {
			defer release()
		}
		if err != nil {
			writeRESTAuthV2HTTPMetadataError(w, err)
			return
		}
		if len(request.Trailer) != 0 {
			writeRESTAuthV2PublicError(w, http.StatusUnsupportedMediaType, publicerr.CodeInvalidRequest, "unsupported request representation", nil)
			return
		}

		principal, err := preflight.finish(request.Context(), body)
		if err != nil {
			writeRESTAuthV2VerifierError(w, err)
			return
		}

		request.Header.Set("X-User-ID", principal.UserID())
		ctx := contextWithVerifiedRESTPrincipal(request.Context(), principal.UserID())
		next(w, request.WithContext(ctx))
	}
}

type restAuthV2HTTPMetadataError uint8

const (
	restAuthV2HTTPInvalid restAuthV2HTTPMetadataError = iota + 1
	restAuthV2HTTPTooLarge
	restAuthV2HTTPUnsupportedRepresentation
	restAuthV2HTTPBodyRateLimited
	restAuthV2HTTPBodyCapacityBusy
)

func (err restAuthV2HTTPMetadataError) Error() string { return "REST auth v2 HTTP request rejected" }

func validateRESTAuthV2HTTPMetadata(request *http.Request, policy RESTAuthV2HTTPPolicy) error {
	if request.RequestURI == "" {
		return restAuthV2HTTPInvalid
	}
	if request.ContentLength < -1 {
		return restAuthV2HTTPInvalid
	}
	if len(request.TransferEncoding) != 0 &&
		(len(request.TransferEncoding) != 1 || request.TransferEncoding[0] != "chunked") {
		return restAuthV2HTTPUnsupportedRepresentation
	}
	if _, present := collectRESTAuthV2HTTPHeader(request.Header, "Content-Encoding"); present {
		return restAuthV2HTTPUnsupportedRepresentation
	}
	if _, present := collectRESTAuthV2HTTPHeader(request.Header, "Trailer"); present || len(request.Trailer) != 0 {
		return restAuthV2HTTPUnsupportedRepresentation
	}
	contentTypes, contentTypePresent := collectRESTAuthV2HTTPHeader(request.Header, "Content-Type")
	switch policy.bodyMode {
	case restAuthV2HTTPBodyForbidden:
		if contentTypePresent || request.ContentLength > 0 {
			return restAuthV2HTTPUnsupportedRepresentation
		}
	case restAuthV2HTTPBodyRequired:
		if !contentTypePresent || len(contentTypes) != 1 || !policy.allowsMediaType(contentTypes[0]) {
			return restAuthV2HTTPUnsupportedRepresentation
		}
		if request.ContentLength > policy.maxBodyBytes {
			return restAuthV2HTTPTooLarge
		}
		if request.Body == nil || request.Body == http.NoBody {
			return restAuthV2HTTPInvalid
		}
	default:
		return restAuthV2HTTPInvalid
	}
	return nil
}

func (policy RESTAuthV2HTTPPolicy) allowsMediaType(value string) bool {
	for _, mediaType := range policy.mediaTypes {
		if value == mediaType {
			return true
		}
	}
	return false
}

func (boundary *RESTAuthV2HTTPBoundary) readAndRestoreBody(
	w http.ResponseWriter,
	request *http.Request,
	policy RESTAuthV2HTTPPolicy,
) ([]byte, func(), error) {
	if request.Body == nil || request.Body == http.NoBody {
		return nil, nil, nil
	}
	client := clientIP(request)
	if !boundary.admission.bodyIngress.allow("ip:" + client) {
		w.Header().Set("Retry-After", "1")
		return nil, nil, restAuthV2HTTPBodyRateLimited
	}
	switch boundary.admission.acquireBodySlot(client) {
	case bodyAdmissionClientBusy, bodyAdmissionGlobalBusy:
		w.Header().Set("Retry-After", "1")
		return nil, nil, restAuthV2HTTPBodyCapacityBusy
	case bodyAdmissionAccepted:
	default:
		return nil, nil, restAuthV2HTTPBodyCapacityBusy
	}
	release := func() { boundary.admission.releaseBodySlot(client) }

	maximum := policy.maxBodyBytes
	if policy.bodyMode == restAuthV2HTTPBodyForbidden {
		maximum = 0
	}
	original := request.Body
	body, err := io.ReadAll(io.LimitReader(original, maximum+1))
	closeErr := original.Close()
	if err != nil || closeErr != nil {
		return nil, release, restAuthV2HTTPInvalid
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	if int64(len(body)) > maximum {
		if policy.bodyMode == restAuthV2HTTPBodyForbidden {
			return nil, release, restAuthV2HTTPUnsupportedRepresentation
		}
		return nil, release, restAuthV2HTTPTooLarge
	}
	if policy.bodyMode == restAuthV2HTTPBodyRequired && len(body) == 0 {
		return nil, release, restAuthV2HTTPInvalid
	}
	return body, release, nil
}

func collectRESTAuthV2HTTPHeaders(header http.Header) RESTAuthV2HeaderValues {
	versions, _ := collectRESTAuthV2HTTPHeader(header, RESTAuthV2VersionHeader)
	users, _ := collectRESTAuthV2HTTPHeader(header, RESTAuthV2UserHeader)
	timestamps, _ := collectRESTAuthV2HTTPHeader(header, RESTAuthV2TimestampHeader)
	nonces, _ := collectRESTAuthV2HTTPHeader(header, RESTAuthV2NonceHeader)
	signatures, _ := collectRESTAuthV2HTTPHeader(header, RESTAuthV2SignatureHeader)
	return RESTAuthV2HeaderValues{
		Versions: versions, Users: users, Timestamps: timestamps,
		Nonces: nonces, Signatures: signatures,
	}
}

// collectRESTAuthV2HTTPHeader iterates instead of using Header.Get/Values so
// manually constructed requests cannot hide values under differently cased map
// keys. The real net/http parser canonicalizes names, while this still retains
// every field-line value and comma-combined value for strict rejection.
func collectRESTAuthV2HTTPHeader(header http.Header, name string) ([]string, bool) {
	var values []string
	present := false
	for key, candidates := range header {
		if !strings.EqualFold(key, name) {
			continue
		}
		present = true
		if len(candidates) == 0 {
			values = append(values, "")
			continue
		}
		values = append(values, candidates...)
	}
	return values, present
}

func deleteRESTAuthV2HTTPHeader(header http.Header, name string) {
	for key := range header {
		if strings.EqualFold(key, name) {
			delete(header, key)
		}
	}
}

func deleteRESTAuthV2ProofHeaders(header http.Header) {
	for _, name := range []string{
		RESTAuthV2VersionHeader,
		RESTAuthV2UserHeader,
		RESTAuthV2TimestampHeader,
		RESTAuthV2NonceHeader,
		RESTAuthV2SignatureHeader,
	} {
		deleteRESTAuthV2HTTPHeader(header, name)
	}
}

func writeRESTAuthV2HTTPMetadataError(w http.ResponseWriter, err error) {
	switch err {
	case restAuthV2HTTPTooLarge:
		writeRESTAuthV2PublicError(w, http.StatusRequestEntityTooLarge, publicerr.CodeInvalidRequest, "request body too large", nil)
	case restAuthV2HTTPUnsupportedRepresentation:
		writeRESTAuthV2PublicError(w, http.StatusUnsupportedMediaType, publicerr.CodeInvalidRequest, "unsupported request representation", nil)
	case restAuthV2HTTPBodyRateLimited, restAuthV2HTTPBodyCapacityBusy:
		writeRESTAuthV2PublicError(w, http.StatusTooManyRequests, publicerr.CodeRateLimited, "too many requests", nil)
	default:
		writeRESTAuthV2PublicError(w, http.StatusBadRequest, publicerr.CodeInvalidRequest, "invalid authentication request", nil)
	}
}

func writeRESTAuthV2VerifierError(w http.ResponseWriter, err error) {
	var typed *RESTAuthV2VerifyError
	if !errors.As(err, &typed) || typed == nil {
		writeRESTAuthV2PublicError(w, http.StatusServiceUnavailable, publicerr.CodeUnavailable, "authentication service unavailable", err)
		return
	}
	switch typed.Failure {
	case RESTAuthV2InvalidRequest:
		writeRESTAuthV2PublicError(w, http.StatusBadRequest, publicerr.CodeInvalidRequest, "invalid authentication request", err)
	case RESTAuthV2TimestampRejected:
		writeRESTAuthV2PublicError(w, http.StatusUnauthorized, publicerr.CodeUnauthenticated, "authentication timestamp rejected", err)
	case RESTAuthV2AuthenticationFailed:
		writeRESTAuthV2PublicError(w, http.StatusUnauthorized, publicerr.CodeUnauthenticated, "authentication failed", err)
	case RESTAuthV2KeyLookupFailed:
		w.Header().Set("Retry-After", "1")
		writeRESTAuthV2PublicError(w, http.StatusServiceUnavailable, publicerr.CodeUnavailable, "authentication service unavailable", err)
	case RESTAuthV2Replay:
		writeRESTAuthV2PublicError(w, http.StatusUnauthorized, publicerr.CodeUnauthenticated, "authentication proof already used", err)
	case RESTAuthV2ReplayStoreFailed:
		w.Header().Set("Retry-After", "1")
		writeRESTAuthV2PublicError(w, http.StatusServiceUnavailable, publicerr.CodeUnavailable, "authentication service unavailable", err)
	default:
		writeRESTAuthV2PublicError(w, http.StatusServiceUnavailable, publicerr.CodeUnavailable, "authentication service unavailable", err)
	}
}

func writeRESTAuthV2PublicError(w http.ResponseWriter, status int, code, message string, cause error) {
	publicerr.Write(w, status, publicerr.New(status, code, message, cause))
}

func contextWithVerifiedRESTPrincipal(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, verifiedPrincipalContextKey{}, userID)
}
