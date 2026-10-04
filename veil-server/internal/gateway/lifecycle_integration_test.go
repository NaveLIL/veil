//go:build integration

package gateway

import (
	"context"
	"testing"
	"time"

	integrationtest "github.com/NaveLIL/veil/veil-server/internal/integration"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

func TestWSCommandDeadlineInterruptsPostgresLockWait(t *testing.T) {
	h := integrationtest.New(t)
	ctx := context.Background()
	alice := h.CreateUser("deadline-alice")
	bob := h.CreateUser("deadline-bob")
	conversationID, _, err := h.DB.FindOrCreateDM(ctx, alice.ID, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := h.DB.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(ctx)
	if _, err := lock.Exec(ctx, "LOCK TABLE message_send_idempotency IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	hub := NewHub(nil, h.Chat)
	hub.SetCommandBudgets(CommandBudgets{Auth: time.Second, Read: time.Second, Mutation: 100 * time.Millisecond, Ephemeral: time.Second})
	c := &Client{hub: hub, send: make(chan outboundBatch, 4), authenticated: true, userID: alice.ID, username: alice.Username, identityKey: alice.IdentityKey}
	msg := &pb.SendMessage{ClientMessageId: "11111111-1111-4111-8111-111111111111", ConversationId: conversationID, Ciphertext: []byte("opaque"), Header: append([]byte{0x02}, make([]byte, 41)...), MsgType: pb.MessageType_MESSAGE_TYPE_TEXT}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		c.handleEnvelope(&pb.Envelope{Seq: 1, Payload: &pb.Envelope_SendMessage{SendMessage: msg}})
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("SQL lock wait ignored command deadline")
	}
	if !c.closing.Load() {
		t.Fatal("deadline did not close uncertain transport")
	}
	if len(c.send) != 0 {
		t.Fatal("deadline published a rejection instead of uncertain transport closure")
	}
	if err := lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := h.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM messages WHERE conversation_id = $1::uuid", conversationID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("timed-out blocked request persisted a message")
	}
	// The cancelled query must release its checkout; this bound also prevents
	// a false-positive where only the gateway goroutine returned.
	deadline := time.Now().Add(time.Second)
	for h.DB.Pool.Stat().AcquiredConns() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("cancelled lock wait retained a pool connection")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCommittedSendSurvivesCancelledTransportAndExactReplay(t *testing.T) {
	h := integrationtest.New(t)
	ctx := context.Background()
	alice := h.CreateUser("cancelled-ack-alice")
	bob := h.CreateUser("cancelled-ack-bob")
	conversationID, _, err := h.DB.FindOrCreateDM(ctx, alice.ID, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	msg := &pb.SendMessage{ClientMessageId: "22222222-2222-4222-8222-222222222222", ConversationId: conversationID, Ciphertext: []byte("opaque"), Header: append([]byte{0x02}, make([]byte, 41)...), MsgType: pb.MessageType_MESSAGE_TYPE_TEXT}
	committed, err := h.Chat.HandleSendMessageResult(ctx, alice.ID, msg)
	if err != nil {
		t.Fatal(err)
	}
	hub := NewHub(nil, h.Chat)
	connectionCtx, cancel := context.WithCancel(hub.lifecycleContext())
	old := &Client{hub: hub, ctx: connectionCtx, cancel: cancel, send: make(chan outboundBatch, 4), authenticated: true, userID: alice.ID, username: alice.Username, identityKey: alice.IdentityKey}
	old.failClosed() // committed ACK was lost at disconnect
	old.sendMessageAck(1, msg.ClientMessageId, committed)
	if len(old.send) != 0 {
		t.Fatal("closed connection published an ACK")
	}
	current := &Client{hub: hub, send: make(chan outboundBatch, 4), authenticated: true, userID: alice.ID, username: alice.Username, identityKey: alice.IdentityKey}
	current.handleEnvelope(&pb.Envelope{Seq: 2, Payload: &pb.Envelope_SendMessage{SendMessage: msg}})
	ack := receiveGatewayEnvelope(t, current.send).GetMessageAck()
	if ack == nil || ack.GetMessageId() != committed.MessageID || ack.GetClientMessageId() != msg.ClientMessageId || ack.GetServerTimestamp() != uint64(committed.ServerTimestamp.UnixNano()) {
		t.Fatalf("replay lost committed outcome: %v", ack)
	}
	var count int
	if err := h.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM messages WHERE conversation_id = $1::uuid", conversationID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("replay produced %d messages", count)
	}
}
