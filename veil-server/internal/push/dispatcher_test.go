package push

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
)

type fakeStore struct {
	mu      sync.Mutex
	subs    []Subscription
	deleted []string
	touched []int64
	listErr error
}

func (f *fakeStore) ListActivePushSubscriptions(ctx context.Context, userID string) ([]Subscription, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]Subscription, len(f.subs))
	copy(out, f.subs)
	return out, nil
}

func (f *fakeStore) DeletePushSubscriptionByEndpoint(ctx context.Context, userID, endpointURL string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, endpointURL)
	return nil
}

func (f *fakeStore) TouchPushSubscription(ctx context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touched = append(f.touched, id)
	return nil
}

func TestDispatcher_DisabledWithoutKey(t *testing.T) {
	d := New(Options{Store: &fakeStore{}})
	if d.Enabled() {
		t.Fatal("dispatcher must boot disabled without a transport key")
	}
	// Should be a no-op, no panic.
	d.NotifyOffline(context.Background(), "user", &pb.Envelope{})
}

func TestDispatcher_DispatchesToAllSubscriptions(t *testing.T) {
	var hits atomic.Int32
	var bodies atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("X-Veil-Push-Version") == "1" {
			bodies.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := &fakeStore{
		subs: []Subscription{
			{ID: 1, UserID: "u1", EndpointURL: srv.URL + "/topic-a", PushKind: "unifiedpush"},
			{ID: 2, UserID: "u1", EndpointURL: srv.URL + "/topic-b", PushKind: "unifiedpush"},
		},
	}
	policy, err := NewEndpointPolicy(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	d := New(Options{
		Store:          store,
		TransportKey:   make([]byte, MinTransportKeyLen),
		Salt:           []byte("salt"),
		HTTPClient:     srv.Client(),
		EndpointPolicy: policy,
	})
	if !d.Enabled() {
		t.Fatal("expected enabled dispatcher")
	}

	env := &pb.Envelope{
		Payload: &pb.Envelope_MessageEvent{MessageEvent: &pb.MessageEvent{
			MessageId:      "msg-x",
			ConversationId: "conv-y",
		}},
	}
	d.NotifyOffline(context.Background(), "u1", env)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		store.mu.Lock()
		touched := len(store.touched)
		store.mu.Unlock()
		if hits.Load() == 2 && touched == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() != 2 {
		t.Fatalf("expected 2 dispatches, got %d", hits.Load())
	}
	if bodies.Load() != 2 {
		t.Fatalf("expected version header on every request, got %d", bodies.Load())
	}

	// Touch was called for each successful dispatch.
	store.mu.Lock()
	touched := len(store.touched)
	store.mu.Unlock()
	if touched != 2 {
		t.Fatalf("expected 2 touch calls, got %d", touched)
	}
}

func TestDispatcher_PrunesGoneEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()

	store := &fakeStore{
		subs: []Subscription{
			{ID: 1, UserID: "u1", EndpointURL: srv.URL + "/dead", PushKind: "unifiedpush"},
		},
	}
	policy, err := NewEndpointPolicy(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	d := New(Options{
		Store:          store,
		TransportKey:   make([]byte, MinTransportKeyLen),
		HTTPClient:     srv.Client(),
		EndpointPolicy: policy,
	})
	d.NotifyOffline(context.Background(), "u1", &pb.Envelope{
		Payload: &pb.Envelope_MessageEvent{MessageEvent: &pb.MessageEvent{
			MessageId: "m", ConversationId: "c",
		}},
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		store.mu.Lock()
		n := len(store.deleted)
		store.mu.Unlock()
		if n == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected dead endpoint to be pruned, deleted=%v", store.deleted)
}

func TestDispatcher_BoundsConcurrentDeliveryJobs(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		started <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	policy, err := NewEndpointPolicy(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	d := New(Options{
		Store: &fakeStore{subs: []Subscription{{
			ID: 1, UserID: "u1", EndpointURL: srv.URL + "/topic", PushKind: "unifiedpush",
		}}},
		TransportKey:            make([]byte, MinTransportKeyLen),
		HTTPClient:              srv.Client(),
		EndpointPolicy:          policy,
		MaxConcurrentDeliveries: 1,
	})
	d.NotifyOffline(context.Background(), "u1", &pb.Envelope{})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first delivery did not start")
	}
	// The only slot is occupied, so this event must be dropped synchronously.
	d.NotifyOffline(context.Background(), "u1", &pb.Envelope{})
	time.Sleep(25 * time.Millisecond)
	if got := hits.Load(); got != 1 {
		t.Fatalf("concurrent outbound jobs = %d, want 1", got)
	}
	close(release)
}

func TestDispatcher_WarningsNeverLogRawUserID(t *testing.T) {
	const rawUserID = "0a751249-4dc5-45d7-aa17-d91cdbeb9cec"
	var output bytes.Buffer
	d := New(Options{
		Store:                   &fakeStore{listErr: errors.New("database unavailable")},
		TransportKey:            make([]byte, MinTransportKeyLen),
		MaxConcurrentDeliveries: 1,
		Logger:                  slog.New(slog.NewTextHandler(&output, nil)),
	})

	// The storage-error warning and the overload warning are separate paths.
	d.deliver(context.Background(), rawUserID, &pb.Envelope{})
	d.deliverySlots <- struct{}{}
	d.NotifyOffline(context.Background(), rawUserID, &pb.Envelope{})
	<-d.deliverySlots

	logged := output.String()
	if strings.Contains(logged, rawUserID) {
		t.Fatalf("push warning leaked raw user id: %s", logged)
	}
	if got := strings.Count(logged, "user_ref=v1_"); got != 2 {
		t.Fatalf("push warnings contain %d pseudonymous user refs, want 2: %s", got, logged)
	}
}

func TestRedact_StripsPath(t *testing.T) {
	cases := map[string]string{
		"https://ntfy.sh/topic-secret": "https://ntfy.sh/…",
		"http://localhost:9081/abc":    "http://localhost:9081/…",
		"http://no-path":               "http://no-path",
	}
	for in, want := range cases {
		if got := redact(in); got != want {
			t.Errorf("redact(%q): got %q, want %q", in, got, want)
		}
	}
}
