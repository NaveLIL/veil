package push

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
	"google.golang.org/protobuf/proto"
)

// Subscription is the projection of a row used by the dispatcher. Kept
// independent from db.PushSubscription so the push package does not
// import the db package directly.
type Subscription struct {
	ID          int64
	UserID      string
	EndpointURL string
	PushKind    string
}

// Store is the persistence surface the dispatcher needs. db.DB
// satisfies this through a thin adapter (see db_adapter.go).
type Store interface {
	ListPushSubscriptions(ctx context.Context, userID string) ([]Subscription, error)
	DeletePushSubscriptionByEndpoint(ctx context.Context, userID, endpointURL string) error
	TouchPushSubscription(ctx context.Context, id int64) error
}

// Dispatcher is goroutine-safe. Construct with New and pass to the
// gateway via SetPushNotifier.
type Dispatcher struct {
	store        Store
	httpClient   *http.Client
	transportKey []byte
	salt         []byte
	maxJitter    time.Duration
	counter      atomic.Uint64
	enabled      bool
	log          *slog.Logger
}

// Options is the construction record. All fields are optional except
// Store; defaults are filled in by New when zero.
type Options struct {
	Store        Store
	TransportKey []byte
	Salt         []byte
	HTTPClient   *http.Client
	MaxJitter    time.Duration
	Logger       *slog.Logger
}

// New builds a Dispatcher. When TransportKey is nil, the dispatcher
// runs in *disabled* mode: NotifyOffline becomes a no-op so the
// gateway can ship even when no push backend is configured.
func New(opts Options) *Dispatcher {
	if opts.Store == nil {
		panic("push.New: Store is required")
	}
	d := &Dispatcher{
		store:        opts.Store,
		httpClient:   opts.HTTPClient,
		transportKey: opts.TransportKey,
		salt:         opts.Salt,
		maxJitter:    opts.MaxJitter,
		log:          opts.Logger,
	}
	if d.httpClient == nil {
		d.httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if d.log == nil {
		d.log = slog.Default()
	}
	if d.maxJitter < 0 {
		d.maxJitter = 0
	}
	d.enabled = len(d.transportKey) >= MinTransportKeyLen
	if !d.enabled {
		d.log.Info("push dispatcher disabled (no transport key configured)")
	}
	return d
}

// Enabled reports whether the dispatcher will actually deliver
// notifications. Useful for /health-style introspection.
func (d *Dispatcher) Enabled() bool { return d.enabled }

// NotifyOffline POSTs an encrypted envelope to every subscription the
// user has registered. Safe to call from a hot path: it spawns its own
// goroutine and never blocks the caller.
func (d *Dispatcher) NotifyOffline(ctx context.Context, userID string, env *pb.Envelope) {
	if !d.enabled || env == nil {
		return
	}
	go d.deliver(context.Background(), userID, env)
}

func (d *Dispatcher) deliver(ctx context.Context, userID string, env *pb.Envelope) {
	subs, err := d.store.ListPushSubscriptions(ctx, userID)
	if err != nil {
		d.log.Warn("push: list subscriptions failed", "user", userID, "err", err)
		return
	}
	if len(subs) == 0 {
		return
	}

	// Apply random jitter [0, maxJitter) before dispatch to defeat
	// trivial timing correlation between WS-send and ntfy-POST.
	if d.maxJitter > 0 {
		time.Sleep(jitter(d.maxJitter))
	}

	convID, senderID, msgID, kind := summarise(env)
	for _, sub := range subs {
		envelope := NewEnvelope(
			d.salt,
			kind,
			convID,
			senderID,
			msgID,
			d.counter.Add(1),
			nil, // server-side push carries metadata only; client-side preview encryption is a v2 item
		)
		sealed, err := EncodeAndSeal(d.transportKey, envelope)
		if err != nil {
			d.log.Warn("push: seal failed", "err", err)
			continue
		}
		if err := d.post(ctx, sub, sealed); err != nil {
			d.log.Warn("push: dispatch failed", "endpoint", redact(sub.EndpointURL), "err", err)
			continue
		}
		_ = d.store.TouchPushSubscription(ctx, sub.ID)
	}
}

func (d *Dispatcher) post(ctx context.Context, sub Subscription, sealed []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.EndpointURL, strings.NewReader(base64.StdEncoding.EncodeToString(sealed)))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	// UnifiedPush distributors (incl. ntfy) accept arbitrary opaque
	// bodies; ntfy in particular forwards Content-Type to the device.
	// We use base64 in the body so any distributor that mishandles
	// raw bytes (e.g. CR/LF stripping) still delivers safely.
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Veil-Push-Version", "1")
	req.Header.Set("X-Veil-Push-Length", strconv.Itoa(len(sealed)))

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusNotFound:
		// Endpoint is dead — drop the subscription so we stop
		// hammering ntfy. The user's *other* devices are unaffected.
		if err := d.store.DeletePushSubscriptionByEndpoint(ctx, sub.UserID, sub.EndpointURL); err != nil {
			d.log.Warn("push: prune dead subscription failed", "err", err)
		}
		return fmt.Errorf("endpoint gone (HTTP %d)", resp.StatusCode)
	default:
		return fmt.Errorf("dispatch HTTP %d", resp.StatusCode)
	}
}

// summarise extracts the conversation_id, sender_id, message_id, and
// push kind from a Veil Envelope. Only MessageEvent.NEW currently
// produces pushes; other event types return zero values, which the
// caller handles by sending a generic "wakeup" notification.
func summarise(env *pb.Envelope) (convID, senderID, msgID string, kind EnvelopeKind) {
	kind = KindMessage
	if env == nil {
		return
	}
	if me := env.GetMessageEvent(); me != nil {
		convID = me.ConversationId
		msgID = me.MessageId
		// SenderIdentityKey is bytes — render hex for hashing input.
		if len(me.SenderIdentityKey) > 0 {
			senderID = fmt.Sprintf("%x", me.SenderIdentityKey)
		}
	}
	return
}

// jitter returns a random duration in [0, max).
func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	n := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	return time.Duration(n % uint64(max))
}

// redact strips the path of an endpoint URL for safe logging — ntfy
// topic IDs are sometimes secret.
func redact(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		host := u[i+3:]
		if j := strings.Index(host, "/"); j >= 0 {
			return u[:i+3] + host[:j] + "/…"
		}
		return u
	}
	return "[invalid]"
}

// LoadTransportKey reads VEIL_PUSH_TRANSPORT_KEY (base64 of >=32 raw
// bytes) from the environment. Returns (nil, nil) when unset so the
// dispatcher boots in disabled mode.
func LoadTransportKey() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("VEIL_PUSH_TRANSPORT_KEY"))
	if raw == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("VEIL_PUSH_TRANSPORT_KEY is not valid base64: %w", err)
	}
	if len(key) < MinTransportKeyLen {
		return nil, fmt.Errorf("VEIL_PUSH_TRANSPORT_KEY decoded to %d bytes; need >= %d", len(key), MinTransportKeyLen)
	}
	return key, nil
}

// LoadSalt reads VEIL_PUSH_HASH_SALT (any non-empty string). Defaults
// to a fixed string when unset; operators are STRONGLY encouraged to
// override per-deployment so conversation_id hashes are unique to this
// installation (mitigates rainbow-table attacks against the metadata
// hash field).
func LoadSalt() []byte {
	raw := strings.TrimSpace(os.Getenv("VEIL_PUSH_HASH_SALT"))
	if raw == "" {
		return []byte("veil/push/v1")
	}
	return []byte(raw)
}

// LoadJitter parses VEIL_PUSH_JITTER_MS (default 2000ms). A negative
// value disables jitter entirely.
func LoadJitter() time.Duration {
	raw := strings.TrimSpace(os.Getenv("VEIL_PUSH_JITTER_MS"))
	if raw == "" {
		return 2 * time.Second
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 2 * time.Second
	}
	return time.Duration(n) * time.Millisecond
}

// MarshalEnvelopeForTest is exposed only so integration tests can
// re-encode a pb.Envelope through the dispatcher's path. Production
// code should not call this.
func MarshalEnvelopeForTest(env *pb.Envelope) ([]byte, error) {
	if env == nil {
		return nil, errors.New("nil envelope")
	}
	return proto.Marshal(env)
}
