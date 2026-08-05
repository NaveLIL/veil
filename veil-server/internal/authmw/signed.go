// Package authmw provides shared HTTP middleware for the veil-server REST
// surface: Ed25519 request-signature verification, replay protection and
// per-user rate limiting.
//
// All authenticated REST endpoints across auth/, chat/ and servers/ wrap
// their handlers via Middleware.RequireSigned. The middleware verifies a
// domain-separated canonical signature
//
//	"veil-rest-v1\n" METHOD "\n" AUTHORITY "\n" REQUEST_TARGET
//	"\n" TIMESTAMP_MS "\n" hex(sha256(body))
//
// using the caller's signing key (stored at registration), with a small
// ±SignatureMaxSkew window to mitigate replay attacks. Within that window
// each signature may only be used once — the nonce cache rejects duplicates.
package authmw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
	"github.com/google/uuid"
)

// SignatureMaxSkew is the tolerance for client/server clock skew + network
// delay when validating X-Veil-Timestamp.
const SignatureMaxSkew = 60 * time.Second

const restSignatureDomain = "veil-rest-v1"

type verifiedPrincipalContextKey struct{}

// VerifiedUserID returns the user identity established by RequireSigned.
// Callers must not fall back to identity headers for authorization or quota
// accounting because those headers are attacker-controlled before signature
// verification.
func VerifiedUserID(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(verifiedPrincipalContextKey{}).(string)
	return userID, ok && userID != ""
}

// ContextWithVerifiedUserIDForTesting publishes a principal only for isolated
// handler tests that intentionally omit authentication middleware. Production
// request paths must obtain this context exclusively from a verifier.
func ContextWithVerifiedUserIDForTesting(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, verifiedPrincipalContextKey{}, userID)
}

// keyCacheTTL controls how long we cache a user's signing public key in
// memory. Short enough that a rotated key takes effect quickly, long enough
// to avoid hitting the DB on every request.
const keyCacheTTL = 5 * time.Minute

// maxSignedBodyBytes caps the request body read for signature verification, both
// to bound memory use and to provide cheap DoS protection. Real handlers
// should still apply their own per-route limits as appropriate.
const maxSignedBodyBytes = 4 << 20 // 4 MiB

const (
	signedBodyReadConcurrency          = 16
	signedBodyReadPerClientConcurrency = 2
	signedBodyRequestsPerMin           = 60
	maxNonceCacheEntries               = 65536
)

type bodyAdmissionStatus uint8

const (
	bodyAdmissionAccepted bodyAdmissionStatus = iota
	bodyAdmissionClientBusy
	bodyAdmissionGlobalBusy
)

type nonceAddStatus uint8

const (
	nonceAccepted nonceAddStatus = iota
	nonceReplay
	nonceCapacityBusy
)

// gcInterval is how often background sweepers prune expired cache entries.
const gcInterval = time.Minute

// UserKeyLookup returns the Ed25519 public signing key for a given user UUID.
// Implementations must be safe for concurrent use.
type UserKeyLookup interface {
	GetSigningKey(ctx context.Context, userID string) (ed25519.PublicKey, error)
}

// ErrSigningKeyNotFound is the only lookup error that means a syntactically
// valid account ID is explicitly absent. REST v2 maps this condition to an
// authentication failure. Implementations must return every timeout,
// cancellation, storage outage, malformed row, and other indeterminate result
// as a different error so REST v2 can fail closed as unavailable. Legacy v1
// intentionally retains its existing behavior of treating every lookup error
// as an unknown user until its public contract is versioned separately.
var ErrSigningKeyNotFound = errors.New("signing key account not found")

// NormalizeSigningKeyLookupError adapts a storage-specific absence sentinel to
// the shared lookup contract. Cancellation and deadline errors always take
// precedence, including joined errors, so an indeterminate query can never be
// downgraded to an authentication failure.
func NormalizeSigningKeyLookupError(ctx context.Context, lookupErr, storageNotFound error) error {
	if lookupErr == nil {
		return nil
	}
	if ctx == nil {
		return lookupErr
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	if errors.Is(lookupErr, context.Canceled) || errors.Is(lookupErr, context.DeadlineExceeded) {
		return lookupErr
	}
	if storageNotFound != nil && signingKeyLookupErrorOnlyMatches(lookupErr, storageNotFound) {
		return ErrSigningKeyNotFound
	}
	return lookupErr
}

// signingKeyLookupErrorOnlyMatches accepts a wrapped or joined absence result
// only when every leaf has exactly that meaning. A mixed
// not-found-plus-outage tree is operational uncertainty and must not be
// downgraded to an authentication failure merely because errors.Is finds one
// absence branch.
func signingKeyLookupErrorOnlyMatches(err, target error) bool {
	if err == nil || target == nil {
		return false
	}
	if err == target {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !signingKeyLookupErrorOnlyMatches(child, target) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if child := wrapped.Unwrap(); child != nil {
			return signingKeyLookupErrorOnlyMatches(child, target)
		}
	}
	return errors.Is(err, target)
}

// LookupFunc is a convenience adapter that turns a plain function into a
// UserKeyLookup. Useful for handler packages that already have a
// FindUserByID-style helper and don't want to declare a wrapper type.
type LookupFunc func(ctx context.Context, userID string) (ed25519.PublicKey, error)

// GetSigningKey implements UserKeyLookup.
func (f LookupFunc) GetSigningKey(ctx context.Context, userID string) (ed25519.PublicKey, error) {
	return f(ctx, userID)
}

// Middleware bundles the signing-key cache, nonce cache and configuration
// shared across authenticated REST endpoints. A single instance should be
// created at startup and shared between handlers.
type Middleware struct {
	lookup      UserKeyLookup
	keys        *signingKeyCache
	nonces      *nonceCache
	bodyIngress *RateLimit
	bodySlots   chan struct{}

	bodyAdmissionMu      sync.Mutex
	bodyClientSlotsInUse map[string]uint8

	stop chan struct{}
}

// New constructs a Middleware. All authenticated REST endpoints require a
// valid Ed25519 signature triplet (X-Veil-User, X-Veil-Timestamp,
// X-Veil-Signature); the legacy unsigned bypass that previously honoured a
// bare X-User-ID header has been removed (W3 / SECURITY).
//
// The returned middleware spawns a background goroutine that periodically
// evicts expired entries from its internal caches; call Close to stop it.
func New(lookup UserKeyLookup) *Middleware {
	m := &Middleware{
		lookup:               lookup,
		keys:                 newSigningKeyCache(),
		nonces:               newNonceCache(),
		bodyIngress:          NewRateLimit(signedBodyRequestsPerMin, time.Minute),
		bodySlots:            make(chan struct{}, signedBodyReadConcurrency),
		bodyClientSlotsInUse: make(map[string]uint8),
		stop:                 make(chan struct{}),
	}
	go m.gcLoop()
	return m
}

// Close stops the background GC goroutine. Safe to call only once.
func (m *Middleware) Close() {
	close(m.stop)
	m.bodyIngress.Close()
}

func (m *Middleware) gcLoop() {
	t := time.NewTicker(gcInterval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case now := <-t.C:
			m.keys.sweep(now)
			m.nonces.sweep(now)
		}
	}
}

// RequireSigned wraps an http.HandlerFunc with Ed25519 signature
// verification. On success the verified user ID is propagated via the
// X-User-ID header so existing downstream handlers continue to work
// unchanged.
func (m *Middleware) RequireSigned(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("X-Veil-User")
		tsStr := r.Header.Get("X-Veil-Timestamp")
		sigB64 := r.Header.Get("X-Veil-Signature")

		if userID == "" || tsStr == "" || sigB64 == "" {
			writeError(w, http.StatusUnauthorized, "signed request required (X-Veil-User, X-Veil-Timestamp, X-Veil-Signature)")
			return
		}
		parsedUserID, err := uuid.Parse(userID)
		if err != nil || parsedUserID == uuid.Nil || parsedUserID.String() != userID {
			writeError(w, http.StatusUnauthorized, "invalid canonical user id")
			return
		}

		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid timestamp")
			return
		}
		nowMs := time.Now().UnixMilli()
		maxSkewMs := int64(SignatureMaxSkew / time.Millisecond)
		if ts < nowMs-maxSkewMs || ts > nowMs+maxSkewMs {
			writeError(w, http.StatusUnauthorized, "timestamp out of acceptable range")
			return
		}

		sig, err := base64.StdEncoding.Strict().DecodeString(sigB64)
		if err != nil || len(sig) != ed25519.SignatureSize {
			writeError(w, http.StatusUnauthorized, "invalid signature encoding")
			return
		}
		if r.ContentLength > maxSignedBodyBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}

		// Reject unknown/non-signing accounts before reading an attacker-sized
		// body. UUID syntax alone is public and never authorizes memory use.
		pub, ok := m.keys.get(userID)
		if !ok {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			key, lookupErr := m.lookup.GetSigningKey(ctx, userID)
			cancel()
			if lookupErr != nil {
				writeError(w, http.StatusUnauthorized, "unknown user")
				return
			}
			// Copy lookup-owned memory before validation and caching so a mutable
			// database buffer cannot change the key between validation and Verify.
			key = append(ed25519.PublicKey(nil), key...)
			if !cryptokey.ValidEd25519PublicKey(key) {
				writeError(w, http.StatusUnauthorized, "user has invalid signing key")
				return
			}
			pub = key
			m.keys.put(userID, pub)
		}

		// Bound body read for both signing-cost and DoS protection.
		var bodyBytes []byte
		hasBody := r.Body != nil && r.Body != http.NoBody
		if hasBody {
			client := clientIP(r)
			if !m.bodyIngress.allow("ip:" + client) {
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusTooManyRequests, "signed body ingress rate limit exceeded")
				return
			}
			switch m.acquireBodySlot(client) {
			case bodyAdmissionAccepted:
				// Keep the slot until the downstream handler releases its retained
				// body too; releasing immediately after ReadAll would not bound peak
				// memory when several valid handlers are slow.
				defer m.releaseBodySlot(client)
			case bodyAdmissionClientBusy:
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusTooManyRequests, "signed body client capacity is busy")
				return
			case bodyAdmissionGlobalBusy:
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusTooManyRequests, "signed body capacity is busy")
				return
			}
			limited := io.LimitReader(r.Body, maxSignedBodyBytes+1)
			bodyBytes, err = io.ReadAll(limited)
			if err != nil {
				writeError(w, http.StatusBadRequest, "could not read request body")
				return
			}
			if len(bodyBytes) > maxSignedBodyBytes {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		requestTarget := r.URL.EscapedPath()
		if requestTarget == "" {
			requestTarget = "/"
		}
		if r.URL.ForceQuery || r.URL.RawQuery != "" {
			requestTarget += "?" + r.URL.RawQuery
		}
		canonical, err := CanonicalRequest(r.Method, r.Host, requestTarget, tsStr, bodyBytes)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid signed request metadata")
			return
		}

		if !ed25519.Verify(pub, canonical, sig) {
			writeError(w, http.StatusUnauthorized, "signature verification failed")
			return
		}

		// Replay protection: a verified signature may be used at most once
		// within the acceptance window. The nonce key binds user + timestamp +
		// signature so legitimate retries with a fresh timestamp are unaffected.
		canonicalSignature := base64.StdEncoding.EncodeToString(sig)
		nonceKey := userID + "|" + tsStr + "|" + canonicalSignature
		expiresAt := time.UnixMilli(ts).Add(SignatureMaxSkew + time.Second)
		switch m.nonces.add(nonceKey, expiresAt) {
		case nonceAccepted:
		case nonceReplay:
			writeError(w, http.StatusUnauthorized, "signature already used")
			return
		case nonceCapacityBusy:
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusServiceUnavailable, "replay protection capacity is busy")
			return
		}

		// Propagate verified identity to downstream handlers. The context value
		// is authoritative; X-User-ID remains only for compatibility with
		// existing handlers and is set after signature verification.
		r.Header.Set("X-User-ID", userID)
		ctx := context.WithValue(r.Context(), verifiedPrincipalContextKey{}, userID)
		next(w, r.WithContext(ctx))
	}
}

// acquireBodySlot atomically applies the per-client cap before taking global
// retained-body capacity. Keeping both decisions under one short mutex avoids
// transient, unbounded client bookkeeping when the global pool is saturated.
func (m *Middleware) acquireBodySlot(client string) bodyAdmissionStatus {
	m.bodyAdmissionMu.Lock()
	defer m.bodyAdmissionMu.Unlock()

	if m.bodyClientSlotsInUse[client] >= signedBodyReadPerClientConcurrency {
		return bodyAdmissionClientBusy
	}
	select {
	case m.bodySlots <- struct{}{}:
		m.bodyClientSlotsInUse[client]++
		return bodyAdmissionAccepted
	default:
		return bodyAdmissionGlobalBusy
	}
}

func (m *Middleware) releaseBodySlot(client string) {
	m.bodyAdmissionMu.Lock()
	defer m.bodyAdmissionMu.Unlock()

	<-m.bodySlots
	if m.bodyClientSlotsInUse[client] <= 1 {
		delete(m.bodyClientSlotsInUse, client)
		return
	}
	m.bodyClientSlotsInUse[client]--
}

// CanonicalRequest returns the exact domain-separated bytes signed by REST
// clients:
//
//	veil-rest-v1\n
//	UPPERCASE_METHOD\n
//	normalized_authority\n
//	escaped_path[?raw_query]\n
//	decimal_timestamp_ms\n
//	lowercase_hex_sha256(body)
//
// Query ordering and escaping are preserved exactly. Explicit ports remain
// present (including default ports) and are normalized to canonical decimal;
// an absent port is never synthesized.
func CanonicalRequest(method, authority, requestTarget, timestamp string, body []byte) ([]byte, error) {
	if method == "" || method != strings.ToUpper(method) || !validHTTPToken(method) {
		return nil, errors.New("invalid HTTP method")
	}
	normalizedAuthority, err := normalizeAuthority(authority)
	if err != nil {
		return nil, err
	}
	if requestTarget == "" || requestTarget[0] != '/' || strings.ContainsRune(requestTarget, '#') ||
		strings.ContainsAny(requestTarget, "\r\n") {
		return nil, errors.New("invalid request target")
	}
	for i := 0; i < len(requestTarget); i++ {
		if requestTarget[i] <= 0x20 || requestTarget[i] >= 0x7f {
			return nil, errors.New("request target must be printable ASCII with percent-encoding")
		}
	}
	if timestamp == "" {
		return nil, errors.New("timestamp required")
	}
	if _, err := strconv.ParseInt(timestamp, 10, 64); err != nil {
		return nil, errors.New("invalid timestamp")
	}

	bodyHash := sha256.Sum256(body)
	canonical := restSignatureDomain + "\n" + method + "\n" + normalizedAuthority + "\n" +
		requestTarget + "\n" + timestamp + "\n" + hex.EncodeToString(bodyHash[:])
	return []byte(canonical), nil
}

func validHTTPToken(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}

func normalizeAuthority(authority string) (string, error) {
	if authority == "" || strings.TrimSpace(authority) != authority || strings.Contains(authority, "@") {
		return "", errors.New("invalid authority")
	}
	for i := 0; i < len(authority); i++ {
		if authority[i] <= 0x20 || authority[i] >= 0x7f {
			return "", errors.New("authority must be printable ASCII (use IDNA/punycode)")
		}
	}

	var host, port string
	hasPort := false
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return "", errors.New("invalid bracketed IPv6 authority")
		}
		parsed := net.ParseIP(authority[1:end])
		if parsed == nil || parsed.To4() != nil {
			return "", errors.New("invalid IPv6 authority")
		}
		host = "[" + strings.ToLower(parsed.String()) + "]"
		rest := authority[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") || len(rest) == 1 {
				return "", errors.New("invalid IPv6 port")
			}
			port = rest[1:]
			hasPort = true
		}
	} else {
		if strings.Count(authority, ":") > 1 {
			return "", errors.New("IPv6 authority must be bracketed")
		}
		host = authority
		if colon := strings.LastIndexByte(authority, ':'); colon >= 0 {
			if colon == 0 || colon == len(authority)-1 {
				return "", errors.New("invalid authority port")
			}
			host, port, hasPort = authority[:colon], authority[colon+1:], true
		}

		if parsed := net.ParseIP(host); parsed != nil {
			if parsed.To4() == nil {
				return "", errors.New("IPv6 authority must be bracketed")
			}
			host = parsed.To4().String()
		} else {
			var err error
			host, err = normalizeHostname(host)
			if err != nil {
				return "", err
			}
		}
	}

	if hasPort {
		for i := 0; i < len(port); i++ {
			if port[i] < '0' || port[i] > '9' {
				return "", errors.New("invalid authority port")
			}
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", errors.New("authority port out of range")
		}
		return host + ":" + strconv.Itoa(portNumber), nil
	}
	return host, nil
}

func normalizeHostname(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 {
		return "", errors.New("invalid hostname")
	}
	allNumericOrDot := true
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid hostname label")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", errors.New("invalid hostname character")
			}
			if c < '0' || c > '9' {
				allNumericOrDot = false
			}
		}
	}
	if allNumericOrDot {
		return "", errors.New("invalid IPv4 address")
	}
	return host, nil
}

// signingKeyCache caches public signing keys with a TTL.
type signingKeyCache struct {
	mu      sync.RWMutex
	entries map[string]signingKeyEntry
}

type signingKeyEntry struct {
	key       ed25519.PublicKey
	expiresAt time.Time
}

func newSigningKeyCache() *signingKeyCache {
	return &signingKeyCache{entries: make(map[string]signingKeyEntry)}
}

func (c *signingKeyCache) get(userID string) (ed25519.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[userID]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.key, true
}

func (c *signingKeyCache) put(userID string, key ed25519.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[userID] = signingKeyEntry{
		key:       key,
		expiresAt: time.Now().Add(keyCacheTTL),
	}
}

func (c *signingKeyCache) sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
}

// nonceCache stores recently-seen signature nonces and their expiry, so that
// a captured signed request cannot be replayed within the acceptance window.
type nonceCache struct {
	mu         sync.Mutex
	entries    map[string]time.Time
	maxEntries int
}

func newNonceCache() *nonceCache {
	return &nonceCache{
		entries:    make(map[string]time.Time),
		maxEntries: maxNonceCacheEntries,
	}
}

// add records a nonce without ever evicting a live replay marker. At capacity
// it first purges every expired entry, then fails closed if the cache remains
// full.
func (c *nonceCache) add(key string, expiresAt time.Time) nonceAddStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if exp, ok := c.entries[key]; ok {
		if now.Before(exp) {
			return nonceReplay
		}
		delete(c.entries, key)
	}
	if len(c.entries) >= c.maxEntries {
		c.sweepLocked(now)
		if len(c.entries) >= c.maxEntries {
			return nonceCapacityBusy
		}
	}
	c.entries[key] = expiresAt
	return nonceAccepted
}

func (c *nonceCache) sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)
}

func (c *nonceCache) sweepLocked(now time.Time) {
	for k, exp := range c.entries {
		if !now.Before(exp) {
			delete(c.entries, k)
		}
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
