// W10 — Per-(user, kind) WS message rate limiting.
//
// REST already has authmw.RateLimit, but once a client is authenticated the
// WS pipe lets it flood any payload kind at line speed. A compromised
// account or a malicious client mod can therefore DoS the gateway with
// `typing` events, presence churn, or send_message spam.
//
// This file adds a per-(userID, kind) token-bucket limiter consulted in
// handleEnvelope before each payload is dispatched. Tighter buckets for the
// cheap-to-spam kinds (typing, presence) than for send_message and friend-
// ops. Misses increment veil_ws_messages_rejected_total{kind,reason} and
// drop the envelope; sustained offenders aren't disconnected automatically
// (a single hiccup shouldn't kill a long-lived connection), but the metric
// makes them visible for ops.
package gateway

import (
	"strings"
	"sync"
	"time"

	"github.com/AegisSec/veil-server/internal/metrics"
)

// wsBucketLimits is the table of per-kind capacity / refill-window pairs.
// Cap = burst; refill window = how long it takes to fully refill `cap`
// tokens. For example {cap: 60, window: 60s} ≈ 1 msg/sec sustained, burst
// 60.
//
// Values are tuned for a single user across all their devices; if a power
// user runs 4 devices on one account they'll share the bucket. That's
// intentional — the limit defends the gateway, not the device.
var wsBucketLimits = map[string]wsLimit{
	"send_message":    {cap: 120, window: time.Minute}, // 2 msg/s sustained
	"edit_message":    {cap: 60, window: time.Minute},
	"delete_message":  {cap: 60, window: time.Minute},
	"reaction":        {cap: 240, window: time.Minute},
	"typing":          {cap: 120, window: time.Minute},
	"presence":        {cap: 60, window: time.Minute},
	"sender_key_dist": {cap: 60, window: time.Minute},
	"prekey_request":  {cap: 60, window: time.Minute},
	// Friend ops: rare enough that we cap aggressively to make brute-force
	// scraping cost prohibitive.
	"friend_request":      {cap: 30, window: time.Minute},
	"friend_respond":      {cap: 60, window: time.Minute},
	"friend_remove":       {cap: 30, window: time.Minute},
	"friend_list_request": {cap: 30, window: time.Minute},
}

// defaultWSLimit applies to any kind not in the table above. Set
// conservatively so a typo in the dispatch switch doesn't open a flood
// vector.
var defaultWSLimit = wsLimit{cap: 60, window: time.Minute}

type wsLimit struct {
	cap    int
	window time.Duration
}

// wsRateLimiter is a process-wide map of (userID, kind) → token bucket.
// Buckets are lazily created on first use and evicted by an idle GC.
type wsRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*wsBucket
	stop    chan struct{}
}

type wsBucket struct {
	tokens     float64
	cap        float64
	refillStep time.Duration // time to gain one token
	lastRefill time.Time
}

// idleEvictAfter drops buckets that haven't been touched in this long.
// Keeps map size bounded on long-running processes with high churn.
const wsIdleEvictAfter = 10 * time.Minute

var globalWSLimiter = newWSRateLimiter()

func newWSRateLimiter() *wsRateLimiter {
	rl := &wsRateLimiter{
		buckets: make(map[string]*wsBucket),
		stop:    make(chan struct{}),
	}
	go rl.gcLoop()
	return rl
}

func (rl *wsRateLimiter) gcLoop() {
	t := time.NewTicker(wsIdleEvictAfter)
	defer t.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case now := <-t.C:
			rl.mu.Lock()
			for k, b := range rl.buckets {
				if now.Sub(b.lastRefill) > wsIdleEvictAfter {
					delete(rl.buckets, k)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// allow returns true if the user may send one more message of `kind`.
// Updates the bucket as a side effect.
func (rl *wsRateLimiter) allow(userID, kind string) bool {
	if userID == "" {
		// Pre-auth envelopes are handled separately (auth_response); refuse
		// to rate-limit by an empty key (would collapse all unknown users
		// into one bucket).
		return true
	}
	limit, ok := wsBucketLimits[kind]
	if !ok {
		limit = defaultWSLimit
	}
	if limit.cap <= 0 || limit.window <= 0 {
		return true
	}
	key := userID + "\x00" + kind

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		b = &wsBucket{
			tokens:     float64(limit.cap - 1),
			cap:        float64(limit.cap),
			refillStep: limit.window / time.Duration(limit.cap),
			lastRefill: now,
		}
		rl.buckets[key] = b
		return true
	}
	if elapsed := now.Sub(b.lastRefill); elapsed > 0 && b.refillStep > 0 {
		b.tokens += float64(elapsed) / float64(b.refillStep)
		if b.tokens > b.cap {
			b.tokens = b.cap
		}
		b.lastRefill = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// allowEnvelope checks the per-(user, kind) bucket and increments the
// rejected counter on miss. Returns true when the envelope may proceed.
//
// Tests inject custom limits via SetWSLimitsForTest; production callers
// pass the canonical kind label produced by envelopeKind().
func allowEnvelope(userID, kind string) bool {
	if globalWSLimiter.allow(userID, kind) {
		return true
	}
	metrics.WSMessagesRejectedTotal.WithLabelValues(kind, "rate_limit").Inc()
	return false
}

// SetWSLimitsForTest replaces the per-kind table; the previous map is
// returned so tests can restore it. Not safe for concurrent use; call from
// a single test goroutine before driving the limiter.
func SetWSLimitsForTest(custom map[string]wsLimit) map[string]wsLimit {
	prev := wsBucketLimits
	if custom == nil {
		wsBucketLimits = map[string]wsLimit{}
	} else {
		wsBucketLimits = custom
	}
	// Drop any lingering buckets so the new limits take effect immediately.
	globalWSLimiter.mu.Lock()
	globalWSLimiter.buckets = make(map[string]*wsBucket)
	globalWSLimiter.mu.Unlock()
	return prev
}

// kindForUserBucket normalises a kind label produced by envelopeKind() into
// the bucket key. Currently identity, but kept as a chokepoint so we can
// alias kinds (e.g. fold edit/delete into one budget) without touching the
// dispatch site.
func kindForUserBucket(kind string) string {
	return strings.ToLower(kind)
}
