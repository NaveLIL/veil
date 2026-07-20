package authmw

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"math"
	"reflect"
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
)

// RESTAuthV2Failure is a stable, non-secret classification for an isolated
// verifier failure. It is not an HTTP status or a public wire error by itself.
type RESTAuthV2Failure string

const (
	RESTAuthV2InvalidRequest       RESTAuthV2Failure = "invalid_request"
	RESTAuthV2TimestampRejected    RESTAuthV2Failure = "timestamp_rejected"
	RESTAuthV2AuthenticationFailed RESTAuthV2Failure = "authentication_failed"
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
	switch err.Failure {
	case RESTAuthV2InvalidRequest:
		return "REST authentication request is invalid"
	case RESTAuthV2TimestampRejected:
		return "REST authentication timestamp was rejected"
	case RESTAuthV2AuthenticationFailed:
		return "REST authentication failed"
	case RESTAuthV2Replay:
		return "REST authentication nonce was already used"
	case RESTAuthV2ReplayStoreFailed:
		return "REST authentication replay protection is unavailable"
	default:
		return "REST authentication failed"
	}
}

func (err *RESTAuthV2VerifyError) Unwrap() error { return err.cause }

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
	if verifier == nil || verifier.canonicalOrigin.IsZero() || verifier.lookup == nil || verifier.replay == nil || verifier.now == nil {
		return empty, restAuthV2Failure(RESTAuthV2ReplayStoreFailed, ErrRESTAuthV2VerifierConfiguration)
	}
	if ctx == nil {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("nil request context"))
	}

	version, ok := oneRESTAuthV2Header(request.Headers.Versions)
	if !ok || version != RESTAuthV2ProtocolVersion {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("invalid protocol version header"))
	}
	userID, ok := oneRESTAuthV2Header(request.Headers.Users)
	if !ok {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("invalid user header cardinality"))
	}
	if _, err := ParseCanonicalRESTUserIDV2(userID); err != nil {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}
	timestampHeader, ok := oneRESTAuthV2Header(request.Headers.Timestamps)
	if !ok {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("invalid timestamp header cardinality"))
	}
	timestampMS, err := ParseCanonicalRESTTimestampV2(timestampHeader)
	if err != nil {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}
	nonceHeader, ok := oneRESTAuthV2Header(request.Headers.Nonces)
	if !ok {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("invalid nonce header cardinality"))
	}
	nonce, err := ParseCanonicalRESTNonceV2(nonceHeader)
	if err != nil {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}
	signatureHeader, ok := oneRESTAuthV2Header(request.Headers.Signatures)
	if !ok {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("invalid signature header cardinality"))
	}
	signature, err := parseCanonicalRESTSignatureV2(signatureHeader)
	if err != nil {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}
	if err := ValidateCanonicalRESTMethodV2(request.Method); err != nil {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}
	if err := ValidateCanonicalRESTTargetV2(request.RequestTarget); err != nil {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}
	if len(request.Body) > maxSignedBodyBytes {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, errors.New("REST auth v2 body is oversized"))
	}

	now := verifier.now()
	if now.IsZero() || !restAuthV2TimestampWithinSkew(int64(timestampMS), now.UnixMilli()) {
		return empty, restAuthV2Failure(RESTAuthV2TimestampRejected, errors.New("timestamp outside acceptance window"))
	}

	lookupCtx, cancel := context.WithTimeout(ctx, restAuthV2KeyLookupTimeout)
	publicKey, err := verifier.lookup.GetSigningKey(lookupCtx, userID)
	cancel()
	if err != nil {
		return empty, restAuthV2Failure(RESTAuthV2AuthenticationFailed, err)
	}
	publicKey = append(ed25519.PublicKey(nil), publicKey...)
	if !cryptokey.ValidEd25519PublicKey(publicKey) {
		return empty, restAuthV2Failure(RESTAuthV2AuthenticationFailed, errors.New("invalid account signing key"))
	}

	message, err := RESTAuthV2SigningMessage(RESTAuthV2Input{
		CanonicalOrigin: verifier.canonicalOrigin.String(),
		UserID:          userID,
		Method:          request.Method,
		RequestTarget:   request.RequestTarget,
		TimestampMS:     timestampMS,
		Nonce:           nonce,
		BodySHA256:      RESTAuthV2BodyDigest(request.Body),
	})
	if err != nil {
		return empty, restAuthV2Failure(RESTAuthV2InvalidRequest, err)
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return empty, restAuthV2Failure(RESTAuthV2AuthenticationFailed, errors.New("invalid account signature"))
	}

	claimed, err := verifier.replay.ClaimRESTAuthV2Nonce(ctx, userID, nonce)
	if err != nil {
		return empty, restAuthV2Failure(RESTAuthV2ReplayStoreFailed, err)
	}
	if !claimed {
		return empty, restAuthV2Failure(RESTAuthV2Replay, errors.New("nonce already claimed"))
	}
	return VerifiedRESTAuthV2Principal{userID: userID}, nil
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
