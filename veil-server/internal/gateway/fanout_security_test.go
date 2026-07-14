package gateway

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

func TestClassifySendMessageErrorRequiresRosterRefresh(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
		wantText   string
	}{
		{
			name: "roster changed", err: db.ErrMessageRosterChanged,
			wantStatus: 409, wantText: errMessageRosterRefresh,
		},
		{
			name: "sender device changed", err: db.ErrMessageSecurityContext,
			wantStatus: 409, wantText: errMessageDeviceRefresh,
		},
		{
			name: "ordinary validation", err: errors.New("invalid message"),
			wantStatus: 400, wantText: "message rejected",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, text := classifySendMessageError(tc.err)
			if status != tc.wantStatus || text != tc.wantText {
				t.Fatalf("classification=(%d, %q), want (%d, %q)", status, text, tc.wantStatus, tc.wantText)
			}
		})
	}
}

// Regression for the disconnect/fan-out race: Hub.Run removes a client and
// closes its send channel under h.mu, while broadcasts enqueue concurrently.
// Run this test with -race as well as normally; the pre-fix implementation
// either panicked by sending on a closed channel or raced while iterating the
// userClients map outside the lock.
func TestConcurrentFanoutAndDisconnectIsSafe(t *testing.T) {
	hub := NewHub(nil, nil)
	const userID = "fanout-user"
	data := []byte("event")
	envelope := &pb.Envelope{}

	stop := make(chan struct{})
	var fanout sync.WaitGroup
	for range 4 {
		fanout.Add(1)
		go func() {
			defer fanout.Done()
			for {
				select {
				case <-stop:
					return
				default:
					hub.sendToUser(userID, data)
					hub.fanoutMessageEvent(context.Background(), []string{userID}, data, envelope)
				}
			}
		}()
	}

	for range 2_000 {
		client := &Client{send: make(chan []byte, 1)}
		hub.mu.Lock()
		hub.clients[client] = true
		hub.userClients[userID] = map[*Client]bool{client: true}
		hub.mu.Unlock()

		// Increase overlap between map iteration/enqueue and disconnect without
		// relying on sleeps or scheduler timing assumptions.
		runtime.Gosched()

		hub.mu.Lock()
		delete(hub.clients, client)
		delete(hub.userClients, userID)
		close(client.send)
		hub.mu.Unlock()
	}

	close(stop)
	fanout.Wait()
}

func TestFullQueuesDoNotSuppressPushFallback(t *testing.T) {
	hub := NewHub(nil, nil)
	client := &Client{send: make(chan []byte, 1)}
	client.send <- []byte("already queued")
	hub.userClients["online"] = map[*Client]bool{client: true}
	hub.deviceClients["device-db-id"] = map[*Client]bool{client: true}
	recorder := &recordingPushNotifier{}
	hub.pushNotifier = recorder

	if enqueued := hub.enqueueToUser("online", []byte("dropped")); enqueued {
		t.Fatal("a full user queue falsely reported successful enqueue")
	}
	if enqueued := hub.enqueueToDevice("device-db-id", []byte("dropped")); enqueued {
		t.Fatal("a full device queue falsely reported successful enqueue")
	}
	if enqueued := hub.enqueueToUser("offline", []byte("event")); enqueued {
		t.Fatal("missing user unexpectedly reported as online")
	}

	envelope := &pb.Envelope{Payload: &pb.Envelope_MessageEvent{MessageEvent: &pb.MessageEvent{}}}
	hub.fanoutMessageEvent(context.Background(), []string{"online"}, []byte("dm"), envelope)
	hub.fanoutMessageEventToDevices(context.Background(), []deviceFanoutRecipient{{
		UserID: "online", DeviceID: "device-db-id", DeviceKey: make([]byte, 16),
	}}, envelope)
	if recorder.calls != 2 {
		t.Fatalf("push calls = %d, want one user and one device fallback", recorder.calls)
	}
}

type recordingPushNotifier struct {
	mu    sync.Mutex
	calls int
}

func (n *recordingPushNotifier) NotifyOffline(_ context.Context, _ string, _ *pb.Envelope) {
	n.mu.Lock()
	n.calls++
	n.mu.Unlock()
}

type recordingAuthorizedMemberStore struct {
	required uint64
	ids      []string
}

func (s *recordingAuthorizedMemberStore) GetAuthorizedConversationMembers(_ context.Context, _ string, required uint64) ([]string, error) {
	s.required = required
	return append([]string(nil), s.ids...), nil
}

func TestTypingRecipientsUseMessageReadACL(t *testing.T) {
	store := &recordingAuthorizedMemberStore{ids: []string{"allowed-user"}}
	recipients, err := authorizedTypingRecipients(context.Background(), store, "conversation")
	if err != nil {
		t.Fatal(err)
	}
	if store.required != db.ChannelReadPermissions {
		t.Fatalf("typing permission mask = %#x, want %#x", store.required, db.ChannelReadPermissions)
	}
	if len(recipients) != 1 || recipients[0] != "allowed-user" {
		t.Fatalf("typing recipients = %v, want only the permission-filtered member", recipients)
	}
}
