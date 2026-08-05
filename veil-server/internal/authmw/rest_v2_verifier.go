package authmw

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"math"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
)

const (
	RESTAuthV2VersionHeader   = "X-Veil-REST-Auth-Version"
	RESTAuthV2UserHeader      = "X-Veil-User"
	RESTAuthV2TimestampHeader = "X-Veil-Timestamp"
	RESTAuthV2NonceHeader     = "X-Veil-Nonce"
	RESTAuthV2SignatureHeader = "X-Veil-Signature"

	RESTAuthV2ProtocolVersion = "2"

	restAuthV2KeyLookupTimeout = 2 * time.Second
	restAuthV2ReplayTimeout    = 2 * time.Second
	// A staged proof may retain a resolved key only for one freshness window.
	// This is deliberately well below the durable replay marker retention and
	// uses time.Time's monotonic component in production.
	restAuthV2PreflightMaxAge = SignatureMaxSkew
)

// RESTAuthV2Failure is a stable, non-secret classification for an isolated
// verifier failure. It is not an HTTP status or a public wire error by itself.
type RESTAuthV2Failure string

const (
	RESTAuthV2InvalidRequest       RESTAuthV2Failure = "invalid_request"
	RESTAuthV2TimestampRejected    RESTAuthV2Failure = "timestamp_rejected"
	RESTAuthV2AuthenticationFailed RESTAuthV2Failure = "authentication_failed"
	RESTAuthV2KeyLookupFailed      RESTAuthV2Failure = "key_lookup_failed"
	RESTAuthV2Replay               RESTAuthV2Failure = "replay"
	RESTAuthV2ReplayStoreFailed    RESTAuthV2Failure = "replay_store_failed"
)

var ErrRESTAuthV2VerifierConfiguration = errors.New("REST auth v2 verifier configuration is invalid")

// RESTAuthV2VerifyError deliberately returns only a fixed message. Cause is
// retained for internal classification, but callers must select behavior from
// Failure rather than parse an error string.
type RESTAuthV2VerifyError struct {
	Failure RESTAuthV2Failure
	cause   error
}

func (err *RESTAuthV2VerifyError) Error() string {
	if err == nil {
		return "REST authentication failed"
	}
	switch err.Failure {
	case RESTAuthV2InvalidRequest:
		return "REST authentication request is invalid"
	case RESTAuthV2TimestampRejected:
		return "REST authentication timestamp was rejected"
	case RESTAuthV2AuthenticationFailed:
		return "REST authentication failed"
	case RESTAuthV2KeyLookupFailed:
		return "REST authentication signing key lookup is unavailable"
	case RESTAuthV2Replay:
		return "REST authentication nonce was already used"
	case RESTAuthV2ReplayStoreFailed:
		return "REST authentication replay protection is unavailable"
	default:
		return "REST authentication failed"
	}
}

func (err *RESTAuthV2VerifyError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func restAuthV2Failure(failure RESTAuthV2Failure, cause error) error {
	return &RESTAuthV2VerifyError{Failure: failure, cause: cause}
}

// RESTAuthV2HeaderValues preserves cardinality at the future HTTP boundary.
// The verifier accepts exactly one unmodified value for every field. A caller
// must not use Header.Get, comma splitting, trimming, or normalization first.
type RESTAuthV2HeaderValues struct {
	Versions   []string
	Users      []string
	Timestamps []string
	Nonces     []string
	Signatures []string
}

// RESTAuthV2Request contains exact already-bounded transport bytes. Method and
// RequestTarget are verified without normalization. Body is hashed exactly as
// supplied before any application parser may inspect it.
type RESTAuthV2Request struct {
	Headers       RESTAuthV2HeaderValues
	Method        string
	RequestTarget string
	Body          []byte
}

// RESTAuthV2ReplayStore atomically claims one account-scoped nonce. A true
// result means this caller is the only winner; false means the nonce was
// already claimed. Implementations must coordinate every gateway process,
// retain live markers beyond the full timestamp acceptance window, and fail
// closed instead of evicting a live marker.
type RESTAuthV2ReplayStore interface {
	ClaimRESTAuthV2Nonce(ctx context.Context, userID string, nonce [RESTAuthV2NonceSize]byte) (bool, error)
}

// VerifiedRESTAuthV2Principal is returned only after signature verification
// and a successful atomic replay claim.
type VerifiedRESTAuthV2Principal struct {
	userID string
}

func (principal VerifiedRESTAuthV2Principal) UserID() string { return principal.userID }

// RESTAuthV2Verifier is transport-neutral and deliberately not wired into the
// live HTTP middleware. Its origin is an opaque value from trusted gateway
// configuration, never a Host or forwarding header.
type RESTAuthV2Verifier struct {
	canonicalOrigin nodeorigin.Canonical
	lookup          UserKeyLookup
	replay          RESTAuthV2ReplayStore
	now             func() time.Time
	replayTimeout   time.Duration
}

// restAuthV2Preflight is an unexported, single-use verification continuation.
// It exists so the HTTP boundary can reject malformed metadata and resolve the
// candidate account key before admitting an attacker-controlled body. It never
// publishes an authenticated principal: only finish can do that, after the
// exact body signature and durable replay claim both succeed.
type restAuthV2Preflight struct {
	verifier      *RESTAuthV2Verifier
	userID        string
	method        string
	requestTarget string
	timestampMS   uint64
	startedAt     time.Time
	nonce         [RESTAuthV2NonceSize]byte
	signature     [ed25519.SignatureSize]byte
	publicKey     ed25519.PublicKey
	consumed      atomic.Bool
}

func NewRESTAuthV2Verifier(
	origin nodeorigin.Canonical,
	lookup UserKeyLookup,
	replay RESTAuthV2ReplayStore,
) (*RESTAuthV2Verifier, error) {
	return newRESTAuthV2VerifierWithClock(origin, lookup, replay, time.Now)
}

// newRESTAuthV2VerifierWithClock exists only for deterministic same-package
// boundary tests. Keeping clock injection private prevents an eventual
// production caller from weakening freshness with a caller-selected clock.
// A nil clock still selects time.Now.
func newRESTAuthV2VerifierWithClock(
	origin nodeorigin.Canonical,
	lookup UserKeyLookup,
	replay RESTAuthV2ReplayStore,
	now func() time.Time,
) (*RESTAuthV2Verifier, error) {
	if origin.IsZero() || nilRESTAuthV2Dependency(lookup) || nilRESTAuthV2Dependency(replay) {
		return nil, ErrRESTAuthV2VerifierConfiguration
	}
	if now == nil {
		now = time.Now
	}
	return &RESTAuthV2Verifier{
		canonicalOrigin: origin,
		lookup:          lookup,
		replay:          replay,
		now:             now,
		replayTimeout:   restAuthV2ReplayTimeout,
	}, nil
}

func nilRESTAuthV2Dependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// Verify checks a complete v2 proof and then atomically consumes its nonce.
// No replay-store call occurs before a valid Ed25519 account proof.
func (verifier *RESTAuthV2Verifier) Verify(
	ctx context.Context,
	request RESTAuthV2Request,
) (VerifiedRESTAuthV2Principal, error) {
	var empty VerifiedRESTAuthV2Principal
	if err := verifier.validateRESTAuthV2Runtime(ctx); err != nil {
		return empty, err
	}
	// The transport-neutral convenience API already owns the complete body, so
	// it can reject an oversized input before doing a database key lookup. The
	// HTTP adapter instead calls preflight before it starts its bounded read.
	if len(request.Body) > maxSignedBodyBytes {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("REST auth v2 body is oversized"))
	}
	preflight, err := verifier.preflight(ctx, request.Headers, request.Method, request.RequestTarget)
	if err != nil {
		return empty, err
	}
	return preflight.finish(ctx, request.Body)
}

func (verifier *RESTAuthV2Verifier) validateRESTAuthV2Runtime(ctx context.Context) error {
	if verifier == nil || verifier.canonicalOrigin.IsZero() || verifier.lookup == nil ||
		verifier.replay == nil || verifier.now == nil || verifier.replayTimeout <= 0 {
		return restAuthV2Failure(RESTAuthV2ReplayStoreFailed, ErrRESTAuthV2VerifierConfiguration)
	}
	if ctx == nil {
		return restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("nil request context"))
	}
	return nil
}

// preflight validates every body-independent proof field, samples freshness
// once, and resolves a strict copy of the pinned account signing key. It must
// run before the HTTP boundary acquires body-retention capacity or reads r.Body.
func (verifier *RESTAuthV2Verifier) preflight(
	ctx context.Context,
	headers RESTAuthV2HeaderValues,
	method string,
	requestTarget string,
) (*restAuthV2Preflight, error) {
	if err := verifier.validateRESTAuthV2Runtime(ctx); err != nil {
		return nil, err
	}

	version, ok := oneRESTAuthV2Header(headers.Versions)
	if !ok || version != RESTAuthV2ProtocolVersion {
		return nil, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("invalid protocol version header"))
	}
	userID, ok := oneRESTAuthV2Header(headers.Users)
	if !ok {
		return nil, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("invalid user header cardinality"))
	}
	if _, err := ParseCanonicalRESTUserIDV2(userID); err != nil {
		return nil, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}
	timestampHeader, ok := oneRESTAuthV2Header(headers.Timestamps)
	if !ok {
		return nil, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("invalid timestamp header cardinality"))
	}
	timestampMS, err := ParseCanonicalRESTTimestampV2(timestampHeader)
	if err != nil {
		return nil, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}
	nonceHeader, ok := oneRESTAuthV2Header(headers.Nonces)
	if !ok {
		return nil, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("invalid nonce header cardinality"))
	}
	nonce, err := ParseCanonicalRESTNonceV2(nonceHeader)
	if err != nil {
		return nil, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}
	signatureHeader, ok := oneRESTAuthV2Header(headers.Signatures)
	if !ok {
		return nil, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("invalid signature header cardinality"))
	}
	signature, err := parseCanonicalRESTSignatureV2(signatureHeader)
	if err != nil {
		return nil, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}
	// The decoded slice is temporary even when a later metadata or lookup
	// check fails. The continuation receives its own fixed-size copy below.
	defer clear(signature)
	if err := ValidateCanonicalRESTMethodV2(method); err != nil {
		return nil, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}
	if err := ValidateCanonicalRESTTargetV2(requestTarget); err != nil {
		return nil, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}

	now := verifier.now()
	if now.IsZero() || !restAuthV2TimestampWithinSkew(int64(timestampMS), now.UnixMilli()) {
		return nil, restAuthV2Failure(RESTAuthV2TimestampRejected, errors.New("timestamp outside acceptance window"))
	}

	lookupCtx, cancel := context.WithTimeout(ctx, restAuthV2KeyLookupTimeout)
	publicKey, err := verifier.lookup.GetSigningKey(lookupCtx, userID)
	lookupContextErr := lookupCtx.Err()
	cancel()
	if lookupContextErr != nil {
		return nil, restAuthV2Failure(RESTAuthV2KeyLookupFailed, lookupContextErr)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, restAuthV2Failure(RESTAuthV2KeyLookupFailed, err)
		}
		if signingKeyLookupErrorOnlyMatches(err, ErrSigningKeyNotFound) {
			return nil, restAuthV2Failure(RESTAuthV2AuthenticationFailed, err)
		}
		return nil, restAuthV2Failure(RESTAuthV2KeyLookupFailed, err)
	}
	publicKey = append(ed25519.PublicKey(nil), publicKey...)
	if !cryptokey.ValidEd25519PublicKey(publicKey) {
		return nil, restAuthV2Failure(RESTAuthV2KeyLookupFailed, errors.New("invalid account signing key"))
	}
	preflight := &restAuthV2Preflight{
		verifier:      verifier,
		userID:        userID,
		method:        method,
		requestTarget: requestTarget,
		timestampMS:   timestampMS,
		startedAt:     now,
		nonce:         nonce,
		publicKey:     publicKey,
	}
	copy(preflight.signature[:], signature)
	return preflight, nil
}

// finish consumes a preflight exactly once. The durable nonce claim remains
// the cross-process replay authority; this local guard only prevents accidental
// reuse of one in-memory continuation by an adapter bug.
func (preflight *restAuthV2Preflight) finish(
	ctx context.Context,
	body []byte,
) (VerifiedRESTAuthV2Principal, error) {
	var empty VerifiedRESTAuthV2Principal
	if preflight == nil {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("invalid REST auth v2 preflight"))
	}
	if !preflight.consumed.CompareAndSwap(false, true) {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("REST auth v2 preflight already consumed"))
	}
	defer preflight.clear()
	// Check mutable continuation fields only after winning the atomic consume.
	// Losing concurrent calls touch no data that clear can overwrite.
	if preflight.verifier == nil || ctx == nil {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("invalid REST auth v2 preflight"))
	}
	if len(body) > maxSignedBodyBytes {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("REST auth v2 body is oversized"))
	}

	message, err := RESTAuthV2SigningMessage(RESTAuthV2Input{
		CanonicalOrigin: preflight.verifier.canonicalOrigin.String(),
		UserID:          preflight.userID,
		Method:          preflight.method,
		RequestTarget:   preflight.requestTarget,
		TimestampMS:     preflight.timestampMS,
		Nonce:           preflight.nonce,
		BodySHA256:      RESTAuthV2BodyDigest(body),
	})
	if err != nil {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}
	defer clear(message)
	if !ed25519.Verify(preflight.publicKey, message, preflight.signature[:]) {
		return empty, restAuthV2Failure(RESTAuthV2AuthenticationFailed, errors.New("invalid account signature"))
	}
	// A staged HTTP body can arrive slowly after the key preflight. Recheck
	// freshness immediately before the durable claim so a proof cannot outlive
	// the replay store's timestamp-based retention assumptions while waiting
	// for admission or body I/O.
	now := preflight.verifier.now()
	age := now.Sub(preflight.startedAt)
	if now.IsZero() || preflight.startedAt.IsZero() || age < 0 || age > restAuthV2PreflightMaxAge ||
		!restAuthV2TimestampWithinSkew(int64(preflight.timestampMS), now.UnixMilli()) {
		return empty, restAuthV2Failure(RESTAuthV2TimestampRejected, errors.New("timestamp outside acceptance window"))
	}

	replayCtx, cancel := context.WithTimeout(ctx, preflight.verifier.replayTimeout)
	claimed, err := preflight.verifier.replay.ClaimRESTAuthV2Nonce(
		replayCtx,
		preflight.userID,
		preflight.nonce,
	)
	replayContextErr := replayCtx.Err()
	cancel()
	if replayContextErr != nil {
		return empty, restAuthV2Failure(RESTAuthV2ReplayStoreFailed, replayContextErr)
	}
	if err != nil {
		return empty, restAuthV2Failure(RESTAuthV2ReplayStoreFailed, err)
	}
	if !claimed {
		return empty, restAuthV2Failure(RESTAuthV2Replay, errors.New("nonce already claimed"))
	}
	return VerifiedRESTAuthV2Principal{userID: preflight.userID}, nil
}

func (preflight *restAuthV2Preflight) clear() {
	if preflight == nil {
		return
	}
	preflight.verifier = nil
	preflight.userID = ""
	preflight.method = ""
	preflight.requestTarget = ""
	preflight.timestampMS = 0
	preflight.startedAt = time.Time{}
	clear(preflight.nonce[:])
	clear(preflight.signature[:])
	clear(preflight.publicKey)
	preflight.publicKey = nil
}

func oneRESTAuthV2Header(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func restAuthV2TimestampWithinSkew(signedMS, nowMS int64) bool {
	skewMS := int64(SignatureMaxSkew / time.Millisecond)
	lower, upper := nowMS, nowMS
	if nowMS < math.MinInt64+skewMS {
		lower = math.MinInt64
	} else {
		lower = nowMS - skewMS
	}
	if nowMS > math.MaxInt64-skewMS {
		upper = math.MaxInt64
	} else {
		upper = nowMS + skewMS
	}
	return signedMS >= lower && signedMS <= upper
}

func parseCanonicalRESTSignatureV2(value string) ([]byte, error) {
	if len(value) != base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) {
		return nil, errors.New("REST auth v2 signature has invalid length")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("REST auth v2 signature is not canonical base64url")
	}
	return decoded, nil
}
