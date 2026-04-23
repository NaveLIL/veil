// Package authmw provides shared HTTP middleware for the veil-server REST
// surface: Ed25519 request-signature verification, replay protection and
// per-user rate limiting.
//
// All authenticated REST endpoints across auth/, chat/ and servers/ wrap
// their handlers via Middleware.RequireSigned. The middleware verifies a
// canonical signature
//
//	METHOD "\n" PATH "\n" TIMESTAMP_MS "\n" hex(sha256(body))
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
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// SignatureMaxSkew is the tolerance for client/server clock skew + network
// delay when validating X-Veil-Timestamp.
const SignatureMaxSkew = 60 * time.Second

// keyCacheTTL controls how long we cache a user's signing public key in
// memory. Short enough that a rotated key takes effect quickly, long enough
// to avoid hitting the DB on every request.
const keyCacheTTL = 5 * time.Minute

// maxBodyBytes caps the request body read for signature verification, both
// to bound memory use and to provide cheap DoS protection. Real handlers
// should still apply their own per-route limits as appropriate.
const maxBodyBytes = 4 << 20 // 4 MiB

// gcInterval is how often background sweepers prune expired cache entries.
const gcInterval = time.Minute

// UserKeyLookup returns the Ed25519 public signing key for a given user UUID.
// Implementations must be safe for concurrent use.
type UserKeyLookup interface {
	GetSigningKey(ctx context.Context, userID string) (ed25519.PublicKey, error)
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
	lookup UserKeyLookup
	keys   *signingKeyCache
	nonces *nonceCache

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
		lookup: lookup,
		keys:   newSigningKeyCache(),
		nonces: newNonceCache(),
		stop:   make(chan struct{}),
	}
	go m.gcLoop()
	return m
}

// Close stops the background GC goroutine. Safe to call only once.
func (m *Middleware) Close() { close(m.stop) }

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

		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid timestamp")
			return
		}
		nowMs := time.Now().UnixMilli()
		skew := nowMs - ts
		if skew < 0 {
			skew = -skew
		}
		if skew > int64(SignatureMaxSkew/time.Millisecond) {
			writeError(w, http.StatusUnauthorized, "timestamp out of acceptable range")
			return
		}

		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil || len(sig) != ed25519.SignatureSize {
			writeError(w, http.StatusUnauthorized, "invalid signature encoding")
			return
		}

		// Bound body read for both signing-cost and DoS protection.
		var bodyBytes []byte
		if r.Body != nil {
			limited := io.LimitReader(r.Body, maxBodyBytes+1)
			bodyBytes, _ = io.ReadAll(limited)
			if len(bodyBytes) > maxBodyBytes {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		bodyHash := sha256.Sum256(bodyBytes)
		canonical := r.Method + "\n" + r.URL.Path + "\n" + tsStr + "\n" + hex.EncodeToString(bodyHash[:])

		pub, ok := m.keys.get(userID)
		if !ok {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			key, err := m.lookup.GetSigningKey(ctx, userID)
			cancel()
			if err != nil {
				writeError(w, http.StatusUnauthorized, "unknown user")
				return
			}
			if len(key) != ed25519.PublicKeySize {
				writeError(w, http.StatusUnauthorized, "user has no signing key")
				return
			}
			pub = key
			m.keys.put(userID, pub)
		}

		if !ed25519.Verify(pub, []byte(canonical), sig) {
			writeError(w, http.StatusUnauthorized, "signature verification failed")
			return
		}

		// Replay protection: a verified signature may be used at most once
		// within the acceptance window. The nonce key binds user + timestamp +
		// signature so legitimate retries with a fresh timestamp are unaffected.
		nonceKey := userID + "|" + tsStr + "|" + sigB64
		expiresAt := time.UnixMilli(ts).Add(SignatureMaxSkew + time.Second)
		if !m.nonces.add(nonceKey, expiresAt) {
			writeError(w, http.StatusUnauthorized, "signature already used")
			return
		}

		// Propagate verified identity to downstream handlers.
		r.Header.Set("X-User-ID", userID)
		next(w, r)
	}
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
	mu      sync.Mutex
	entries map[string]time.Time
}

func newNonceCache() *nonceCache {
	return &nonceCache{entries: make(map[string]time.Time)}
}

// add records a nonce. Returns false if it already exists (replay) and true
// when it is freshly recorded.
func (c *nonceCache) add(key string, expiresAt time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.entries[key]; ok && time.Now().Before(exp) {
		return false
	}
	c.entries[key] = expiresAt
	return true
}

func (c *nonceCache) sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.entries {
		if now.After(exp) {
			delete(c.entries, k)
		}
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
