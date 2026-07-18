package gateway

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

func TestAuthenticatedSenderSnapshotIsCompleteAndImmutable(t *testing.T) {
	t.Parallel()

	identityKey := bytes.Repeat([]byte{0x2a}, 32)
	client := &Client{
		authenticated: true,
		userID:        "authenticated-user",
		username:      "authenticated-name",
		identityKey:   identityKey,
	}
	snapshot, ok := client.snapshotAuthenticatedSender()
	if !ok {
		t.Fatal("complete authenticated sender was rejected")
	}
	client.identityKey[0] ^= 0xff
	client.username = "changed-after-snapshot"
	if !bytes.Equal(snapshot.identityKey, bytes.Repeat([]byte{0x2a}, 32)) ||
		snapshot.username != "authenticated-name" {
		t.Fatalf("snapshot changed with client state: key=%x username=%q", snapshot.identityKey, snapshot.username)
	}

	for name, invalid := range map[string]*Client{
		"unauthenticated": {
			userID: "user", username: "name", identityKey: bytes.Repeat([]byte{1}, 32),
		},
		"missing user": {
			authenticated: true, username: "name", identityKey: bytes.Repeat([]byte{1}, 32),
		},
		"missing username": {
			authenticated: true, userID: "user", identityKey: bytes.Repeat([]byte{1}, 32),
		},
		"short identity": {
			authenticated: true, userID: "user", username: "name", identityKey: bytes.Repeat([]byte{1}, 31),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if snapshot, ok := invalid.snapshotAuthenticatedSender(); ok {
				t.Fatalf("invalid sender produced snapshot: %+v", snapshot)
			}
		})
	}
}

func TestSealedMessageIsRejectedBeforeGatewayDependencies(t *testing.T) {
	t.Parallel()

	// A nil hub is an intentional poison dependency: reaching ACL, type, or
	// roster preflight would panic. The unsupported shape must fail first.
	client := &Client{
		authenticated: true,
		userID:        "authenticated-user",
		username:      "authenticated-name",
		identityKey:   bytes.Repeat([]byte{0x44}, 32),
		send:          make(chan outboundBatch, 1),
	}
	client.handleSendMessage(context.Background(), 41, &pb.SendMessage{
		ConversationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Ciphertext:     []byte("must-not-reach-dependencies"),
		Sealed:         true,
	})

	envelope := decodePublicErrorEnvelope(t, <-client.send)
	got := envelope.GetError()
	if got == nil || got.GetCode() != http.StatusBadRequest ||
		got.GetMessage() != "message rejected" || got.GetRefSeq() != 41 ||
		envelope.GetMessageAck() != nil {
		t.Fatalf("sealed gateway response = %#v, want generic 400 without ACK", envelope)
	}
}

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
		client := &Client{send: make(chan outboundBatch, 1)}
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
	var closeMu sync.Mutex
	closeCalls := 0
	client := &Client{
		send: make(chan outboundBatch, 1),
		closeFn: func() error {
			closeMu.Lock()
			closeCalls++
			closeMu.Unlock()
			return nil
		},
	}
	client.send <- singleOutbound([]byte("already queued"))
	hub.userClients["online"] = map[*Client]bool{client: true}
	hub.deviceClients["device-db-id"] = map[*Client]bool{client: true}
	recorder := &recordingPushNotifier{}
	hub.pushNotifier = recorder

	if enqueued := hub.enqueueToUser("online", []byte("dropped")); enqueued {
		t.Fatal("a full user queue falsely reported successful enqueue")
	}
	if !client.closing.Load() {
		t.Fatal("a saturated session was not marked closing")
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
	closeMu.Lock()
	defer closeMu.Unlock()
	if closeCalls != 1 {
		t.Fatalf("transport close calls = %d, want exactly 1", closeCalls)
	}
}

func TestAuthenticatedPublicationGatesFIFOUntilBothIndexesExist(t *testing.T) {
	hub := NewHub(nil, nil)
	client := &Client{
		hub:      hub,
		send:     make(chan outboundBatch, 4),
		userID:   "published-user",
		deviceID: "published-device",
	}
	hub.clients[client] = true

	gate := newPublicationGate()
	client.send <- outboundBatch{
		frames:      [][]byte{[]byte("retained-control"), []byte("auth-result")},
		publication: gate,
	}

	dequeued := make(chan struct{})
	written := make(chan string, 3)
	go func() {
		first := <-client.send
		close(dequeued)
		if first.publication.wait() {
			for _, frame := range first.frames {
				written <- string(frame)
			}
		}
		live := <-client.send
		if live.publication.wait() {
			for _, frame := range live.frames {
				written <- string(frame)
			}
		}
	}()

	<-dequeued
	select {
	case frame := <-written:
		t.Fatalf("publication frame became visible before indexing: %q", frame)
	default:
	}
	if client.authenticated {
		t.Fatal("client authenticated before publication")
	}

	if !hub.publishAuthenticatedClient(client, gate) {
		t.Fatal("authenticated publication failed")
	}
	hub.mu.RLock()
	indexedByUser := hub.userClients[client.userID][client]
	indexedByDevice := hub.deviceClients[client.deviceID][client]
	hub.mu.RUnlock()
	if !client.authenticated || !indexedByUser || !indexedByDevice {
		t.Fatalf("incomplete publication: authenticated=%v user=%v device=%v",
			client.authenticated, indexedByUser, indexedByDevice)
	}
	if !hub.enqueueToUser(client.userID, []byte("live-event")) {
		t.Fatal("published client did not accept live fan-out")
	}

	for index, want := range []string{"retained-control", "auth-result", "live-event"} {
		select {
		case got := <-written:
			if got != want {
				t.Fatalf("frame %d = %q, want %q", index, got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for frame %d (%q)", index, want)
		}
	}
}

func TestRejectedPublicationNeverExposesSuccessBatch(t *testing.T) {
	hub := NewHub(nil, nil)
	client := &Client{
		send:     make(chan outboundBatch, 1),
		userID:   "missing-user",
		deviceID: "missing-device",
	}
	gate := newPublicationGate()
	batch := outboundBatch{frames: [][]byte{[]byte("auth-result")}, publication: gate}
	client.send <- batch

	written := make(chan []byte, 1)
	go func() {
		queued := <-client.send
		if queued.publication.wait() {
			written <- queued.frames[0]
		}
	}()
	if hub.publishAuthenticatedClient(client, gate) {
		t.Fatal("unregistered client was published")
	}
	select {
	case frame := <-written:
		t.Fatalf("rejected success batch became visible: %q", frame)
	case <-time.After(25 * time.Millisecond):
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
