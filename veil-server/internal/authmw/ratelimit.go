package authmw

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimit is a per-user (or per-IP) token-bucket limiter for REST
// endpoints. It identifies the caller via the X-User-ID header (set by
// RequireSigned on success) and falls back to the client IP when no user is
// associated. Buckets are kept in memory; this is a single-process
// best-effort defence and does not coordinate across multiple gateway
// replicas.
//
// Idle buckets are evicted by a background goroutine to bound memory use on
// long-lived processes.
type RateLimit struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	capacity int
	refill   time.Duration // per-token refill interval
	idleTTL  time.Duration

	stop chan struct{}
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

// NewRateLimit builds a limiter that allows up to `capacity` requests with a
// steady refill of `capacity` tokens per `window`. For example,
// NewRateLimit(120, time.Minute) ≈ 2 req/sec sustained, with bursts up to 120.
//
// A background goroutine evicts buckets that have been idle for longer than
// 10× window. Call Close to stop it.
func NewRateLimit(capacity int, window time.Duration) *RateLimit {
	if capacity <= 0 {
		capacity = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	rl := &RateLimit{
		buckets:  make(map[string]*tokenBucket),
		capacity: capacity,
		refill:   window / time.Duration(capacity),
		idleTTL:  window * 10,
		stop:     make(chan struct{}),
	}
	go rl.gcLoop()
	return rl
}

// Close stops the background eviction goroutine.
func (rl *RateLimit) Close() { close(rl.stop) }

func (rl *RateLimit) gcLoop() {
	t := time.NewTicker(rl.idleTTL)
	defer t.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case now := <-t.C:
			rl.evictIdle(now)
		}
	}
}

func (rl *RateLimit) evictIdle(now time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for k, b := range rl.buckets {
		if now.Sub(b.lastRefill) > rl.idleTTL {
			delete(rl.buckets, k)
		}
	}
}

// Wrap returns a handler that consumes one token per request. When the
// bucket is empty the request is rejected with 429 Too Many Requests.
func (rl *RateLimit) Wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-User-ID")
		if key == "" {
			key = "ip:" + clientIP(r)
		}
		if !rl.allow(key) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next(w, r)
	}
}

func (rl *RateLimit) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &tokenBucket{tokens: float64(rl.capacity - 1), lastRefill: now}
		return true
	}
	elapsed := now.Sub(b.lastRefill)
	if elapsed > 0 && rl.refill > 0 {
		add := float64(elapsed) / float64(rl.refill)
		b.tokens += add
		if b.tokens > float64(rl.capacity) {
			b.tokens = float64(rl.capacity)
		}
		b.lastRefill = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Trust only the first IP in the chain (closest to the client).
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
