package gateway

import (
	"context"
	"runtime"
	"sync"
	"testing"

	"github.com/AegisSec/veil-server/internal/db"
	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
)

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

func TestEnqueueToUserReportsLiveClientWhenQueueIsFull(t *testing.T) {
	hub := NewHub(nil, nil)
	client := &Client{send: make(chan []byte, 1)}
	client.send <- []byte("already queued")
	hub.userClients["online"] = map[*Client]bool{client: true}

	if online := hub.enqueueToUser("online", []byte("dropped")); !online {
		t.Fatal("a connected client with a full queue must still count as online")
	}
	if online := hub.enqueueToUser("offline", []byte("event")); online {
		t.Fatal("missing user unexpectedly reported as online")
	}
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
