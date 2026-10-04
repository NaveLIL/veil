package push

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

type blockedPushStore struct {
	started chan struct{}
	calls   atomic.Int32
}

func (s *blockedPushStore) ListActivePushSubscriptions(ctx context.Context, _ string) ([]Subscription, error) {
	s.calls.Add(1)
	close(s.started)
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*blockedPushStore) DeletePushSubscriptionByEndpoint(context.Context, string, string) error {
	return nil
}
func (*blockedPushStore) TouchPushSubscription(context.Context, int64) error { return nil }

func TestDispatcherShutdownCancelsDatabaseWaitAndRejectsNewWake(t *testing.T) {
	s := &blockedPushStore{started: make(chan struct{})}
	d := New(Options{Store: s, VAPID: testVAPID(t)})
	// Sender cancellation must not abandon a wake already scheduled after a
	// committed message. Dispatcher shutdown does cancel its separate owner.
	senderCtx, senderCancel := context.WithCancel(context.Background())
	senderCancel()
	d.NotifyOffline(senderCtx, "user", &pb.Envelope{})
	select {
	case <-s.started:
	case <-time.After(time.Second):
		t.Fatal("wake lost with sender context")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := d.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	d.NotifyOffline(context.Background(), "user", &pb.Envelope{})
	if calls := s.calls.Load(); calls != 1 {
		t.Fatalf("%d calls after shutdown", calls)
	}
	if len(d.deliverySlots) != 0 {
		t.Fatal("worker still owns delivery slot")
	}
}
