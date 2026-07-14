package push

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AegisSec/veil-server/internal/logsafe"
	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
	webpush "github.com/ergochat/webpush-go/v2"
)

const defaultMaxConcurrentDeliveries = 32

type Subscription struct {
	ID          int64
	UserID      string
	EndpointURL string
	PublicKey   string
	AuthSecret  string
	PushKind    string
}

type Store interface {
	ListActivePushSubscriptions(ctx context.Context, userID string) ([]Subscription, error)
	DeletePushSubscriptionByEndpoint(ctx context.Context, userID, endpointURL string) error
	TouchPushSubscription(ctx context.Context, id int64) error
}

type VAPIDConfig struct {
	Keys       *webpush.VAPIDKeys
	Subscriber string
}

type unifiedPushHTTPClient struct{ base webpush.HTTPClient }

func (c unifiedPushHTTPClient) Do(request *http.Request) (*http.Response, error) {
	request.Header.Set("X-UnifiedPush", "1")
	return c.base.Do(request)
}

type Dispatcher struct {
	store          Store
	httpClient     *http.Client
	endpointPolicy *EndpointPolicy
	vapid          VAPIDConfig
	maxJitter      time.Duration
	deliverySlots  chan struct{}
	enabled        bool
	log            *slog.Logger
}

type Options struct {
	Store                   Store
	VAPID                   VAPIDConfig
	HTTPClient              *http.Client
	EndpointPolicy          *EndpointPolicy
	MaxJitter               time.Duration
	MaxConcurrentDeliveries int
	Logger                  *slog.Logger
}

func New(opts Options) *Dispatcher {
	if opts.Store == nil {
		panic("push.New: Store is required")
	}
	maxConcurrent := opts.MaxConcurrentDeliveries
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentDeliveries
	}
	d := &Dispatcher{
		store: opts.Store, httpClient: opts.HTTPClient, endpointPolicy: opts.EndpointPolicy,
		vapid: opts.VAPID, maxJitter: opts.MaxJitter,
		deliverySlots: make(chan struct{}, maxConcurrent), log: opts.Logger,
	}
	if d.endpointPolicy == nil {
		d.endpointPolicy = defaultEndpointPolicy()
	}
	if d.httpClient == nil {
		d.httpClient = d.endpointPolicy.newHTTPClient()
	} else {
		clientCopy := *d.httpClient
		clientCopy.CheckRedirect = d.endpointPolicy.checkRedirect
		if clientCopy.Timeout <= 0 || clientCopy.Timeout > defaultPushHTTPTimeout {
			clientCopy.Timeout = defaultPushHTTPTimeout
		}
		d.httpClient = &clientCopy
	}
	if d.log == nil {
		d.log = slog.Default()
	}
	if d.maxJitter < 0 {
		d.maxJitter = 0
	}
	d.enabled = d.vapid.Keys != nil && d.vapid.Subscriber != ""
	if !d.enabled {
		d.log.Info("push dispatcher disabled (VAPID is not configured)")
	}
	return d
}

func (d *Dispatcher) Enabled() bool { return d.enabled }

func (d *Dispatcher) VAPIDPublicKey() string {
	if !d.enabled {
		return ""
	}
	return d.vapid.Keys.PublicKeyString()
}

func (d *Dispatcher) NotifyOffline(_ context.Context, userID string, env *pb.Envelope) {
	if !d.enabled || env == nil {
		return
	}
	select {
	case d.deliverySlots <- struct{}{}:
		go func() {
			defer func() { <-d.deliverySlots }()
			d.deliver(context.Background(), userID)
		}()
	default:
		d.log.Warn("push: delivery queue saturated", "user_ref", logsafe.Ref("user", userID))
	}
}

func (d *Dispatcher) deliver(ctx context.Context, userID string) {
	subs, err := d.store.ListActivePushSubscriptions(ctx, userID)
	if err != nil {
		d.log.Warn("push: list subscriptions failed", "user_ref", logsafe.Ref("user", userID), "error_class", logsafe.ErrorClass(err))
		return
	}
	if len(subs) == 0 {
		return
	}
	if d.maxJitter > 0 {
		time.Sleep(jitter(d.maxJitter))
	}
	for _, sub := range subs {
		if err := d.post(ctx, sub, wakePayload(), WakeTTLSeconds); err != nil {
			d.log.Warn("push: dispatch failed", "endpoint_ref", logsafe.Ref("push_endpoint", sub.EndpointURL), "error_class", logsafe.ErrorClass(err))
			continue
		}
		_ = d.store.TouchPushSubscription(ctx, sub.ID)
	}
}

func (d *Dispatcher) SendValidationChallenge(ctx context.Context, sub Subscription, token string) error {
	if !d.enabled {
		return errors.New("push delivery is not configured")
	}
	body, err := challengePayload(sub.ID, token)
	if err != nil {
		return err
	}
	return d.post(ctx, sub, body, ChallengeTTLSeconds)
}

func (d *Dispatcher) post(ctx context.Context, sub Subscription, payload []byte, ttl int) error {
	if sub.PushKind != "unifiedpush" {
		return errors.New("unsupported push kind")
	}
	endpoint, err := d.endpointPolicy.ValidateEndpoint(ctx, sub.EndpointURL)
	if err != nil {
		return fmt.Errorf("unsafe endpoint: %w", err)
	}
	keys, err := webpush.DecodeSubscriptionKeys(sub.AuthSecret, sub.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid subscription keys: %w", err)
	}
	resp, err := webpush.SendNotification(ctx, payload, &webpush.Subscription{
		Endpoint: endpoint.String(), Keys: keys,
	}, &webpush.Options{
		HTTPClient: unifiedPushHTTPClient{base: d.httpClient}, RecordSize: WebPushRecordSize,
		Subscriber: d.vapid.Subscriber, TTL: ttl, Urgency: webpush.UrgencyNormal,
		VAPIDKeys: d.vapid.Keys,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	const maxResponseBytes = 4 << 10
	read, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read push response: %w", err)
	}
	if read > maxResponseBytes {
		return errors.New("push response body too large")
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusNotFound {
		if err := d.store.DeletePushSubscriptionByEndpoint(ctx, sub.UserID, sub.EndpointURL); err != nil {
			d.log.Warn("push: prune dead subscription failed", "error_class", logsafe.ErrorClass(err))
		}
		return fmt.Errorf("endpoint gone (HTTP %d)", resp.StatusCode)
	}
	return fmt.Errorf("dispatch HTTP %d", resp.StatusCode)
}

func LoadVAPIDConfig() (VAPIDConfig, error) {
	rawKey := strings.TrimSpace(os.Getenv("VEIL_PUSH_VAPID_PRIVATE_KEY"))
	subscriber := strings.TrimSpace(os.Getenv("VEIL_PUSH_VAPID_SUBJECT"))
	if rawKey == "" && subscriber == "" {
		return VAPIDConfig{}, nil
	}
	if rawKey == "" || subscriber == "" {
		return VAPIDConfig{}, errors.New("VEIL_PUSH_VAPID_PRIVATE_KEY and VEIL_PUSH_VAPID_SUBJECT must be configured together")
	}
	if err := validateVAPIDSubject(subscriber); err != nil {
		return VAPIDConfig{}, err
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(rawKey, "="))
	if err != nil || len(keyBytes) != 32 {
		return VAPIDConfig{}, errors.New("VEIL_PUSH_VAPID_PRIVATE_KEY must be an unpadded base64url 32-byte P-256 scalar")
	}
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(keyBytes)
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return VAPIDConfig{}, errors.New("VEIL_PUSH_VAPID_PRIVATE_KEY is outside the P-256 scalar range")
	}
	x, y := curve.ScalarBaseMult(keyBytes)
	keys, err := webpush.ECDSAToVAPIDKeys(&ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d,
	})
	if err != nil {
		return VAPIDConfig{}, fmt.Errorf("load VAPID key: %w", err)
	}
	return VAPIDConfig{Keys: keys, Subscriber: subscriber}, nil
}

func validateVAPIDSubject(subject string) error {
	if strings.HasPrefix(subject, "mailto:") {
		address := strings.TrimPrefix(subject, "mailto:")
		parsed, err := mail.ParseAddress(address)
		if err == nil && parsed.Address == address {
			return nil
		}
		return errors.New("VEIL_PUSH_VAPID_SUBJECT mailto address is invalid")
	}
	u, err := url.Parse(subject)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("VEIL_PUSH_VAPID_SUBJECT must be a mailto address or HTTPS URL")
	}
	return nil
}

func GenerateVAPIDPrivateKey() (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	raw := key.D.FillBytes(make([]byte, 32))
	keys, err := webpush.ECDSAToVAPIDKeys(key)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), keys.PublicKeyString(), nil
}

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

func redact(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		host := raw[i+3:]
		if j := strings.Index(host, "/"); j >= 0 {
			return raw[:i+3] + host[:j] + "/…"
		}
		return raw
	}
	return "[invalid]"
}

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
