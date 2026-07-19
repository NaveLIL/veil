//go:build integration

package integration

import (
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/chat"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestMessageSendIdempotencySequentialConcurrentAndAccountScoped(t *testing.T) {
	h := New(t)
	alice := h.CreateUser("send-idempotency-alice")
	bob := h.CreateUser("send-idempotency-bob")
	status, _, body := h.Do(alice, http.MethodPost, "/v1/conversations/dm", map[string]string{
		"peer_user_id": bob.ID,
	})
	if status != http.StatusOK {
		t.Fatalf("create DM status=%d body=%v", status, body)
	}
	conversationID := body["conversation_id"].(string)

	message := &pb.SendMessage{
		ConversationId:  conversationID,
		ClientMessageId: uuid.NewString(),
		Ciphertext:      []byte("exact sequential ciphertext"),
		Header:          []byte("exact sequential header"),
	}
	first, err := h.Chat.HandleSendMessageResult(t.Context(), alice.ID, message)
	if err != nil {
		t.Fatal(err)
	}
	if first.Replayed || len(first.Recipients) != 1 || first.Recipients[0] != bob.ID ||
		first.MessageID == "" || first.ServerTimestamp.IsZero() || first.AckRosterVersion != nil {
		t.Fatalf("first result=%#v", first)
	}

	replay, err := h.Chat.HandleSendMessageResult(t.Context(), alice.ID, proto.Clone(message).(*pb.SendMessage))
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || replay.MessageID != first.MessageID ||
		!replay.ServerTimestamp.Equal(first.ServerTimestamp) || replay.Recipients != nil ||
		replay.AckRosterVersion != nil {
		t.Fatalf("sequential replay=%#v first=%#v", replay, first)
	}

	mismatch := proto.Clone(message).(*pb.SendMessage)
	mismatch.Ciphertext = []byte("different ciphertext")
	if _, err := h.Chat.HandleSendMessageResult(t.Context(), alice.ID, mismatch); !errors.Is(err, chat.ErrClientMessageIDConflict) {
		t.Fatalf("mismatch error=%v, want ErrClientMessageIDConflict", err)
	}

	// The key is account-scoped: another authenticated sender may use the same
	// client UUID for its own exact protobuf request.
	bobMessage := proto.Clone(message).(*pb.SendMessage)
	bobMessage.Ciphertext = []byte("bob account-scoped ciphertext")
	bobResult, err := h.Chat.HandleSendMessageResult(t.Context(), bob.ID, bobMessage)
	if err != nil {
		t.Fatal(err)
	}
	if bobResult.Replayed || bobResult.MessageID == first.MessageID {
		t.Fatalf("bob account-scoped result=%#v first=%#v", bobResult, first)
	}

	concurrent := &pb.SendMessage{
		ConversationId:  conversationID,
		ClientMessageId: uuid.NewString(),
		Ciphertext:      []byte("exact concurrent ciphertext"),
		Header:          []byte("exact concurrent header"),
	}
	const workers = 12
	start := make(chan struct{})
	results := make(chan *chat.SendMessageResult, workers)
	errorsSeen := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			result, sendErr := h.Chat.HandleSendMessageResult(
				t.Context(), alice.ID, proto.Clone(concurrent).(*pb.SendMessage),
			)
			if sendErr != nil {
				errorsSeen <- sendErr
				return
			}
			results <- result
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsSeen)
	for sendErr := range errorsSeen {
		t.Errorf("concurrent send: %v", sendErr)
	}
	if t.Failed() {
		return
	}
	var (
		canonicalID   string
		canonicalTime time.Time
		newCount      int
		replayCount   int
	)
	for result := range results {
		if canonicalID == "" {
			canonicalID = result.MessageID
			canonicalTime = result.ServerTimestamp
		}
		if result.MessageID != canonicalID || !result.ServerTimestamp.Equal(canonicalTime) {
			t.Fatalf("concurrent tuple=%#v, want id=%s time=%s", result, canonicalID, canonicalTime)
		}
		if result.Replayed {
			replayCount++
			if result.Recipients != nil {
				t.Fatalf("replay recipients=%v, want nil", result.Recipients)
			}
		} else {
			newCount++
			if len(result.Recipients) != 1 || result.Recipients[0] != bob.ID {
				t.Fatalf("new result recipients=%v", result.Recipients)
			}
		}
	}
	if newCount != 1 || replayCount != workers-1 {
		t.Fatalf("new=%d replay=%d, want 1,%d", newCount, replayCount, workers-1)
	}

	var ledgerRows, messageRows int
	if err := h.DB.Pool.QueryRow(t.Context(),
		`SELECT count(*) FROM message_send_idempotency
		 WHERE sender_id=$1::uuid AND client_message_id=$2::uuid`,
		alice.ID, concurrent.ClientMessageId,
	).Scan(&ledgerRows); err != nil {
		t.Fatal(err)
	}
	if err := h.DB.Pool.QueryRow(t.Context(),
		`SELECT count(*) FROM messages WHERE id=$1::uuid`, canonicalID,
	).Scan(&messageRows); err != nil {
		t.Fatal(err)
	}
	if ledgerRows != 1 || messageRows != 1 {
		t.Fatalf("concurrent durable rows ledger=%d messages=%d, want 1,1", ledgerRows, messageRows)
	}

	conflictingClientID := uuid.NewString()
	conflictingMessages := []*pb.SendMessage{
		{
			ConversationId: conversationID, ClientMessageId: conflictingClientID,
			Ciphertext: []byte("concurrent conflict A"), Header: []byte("header A"),
		},
		{
			ConversationId: conversationID, ClientMessageId: conflictingClientID,
			Ciphertext: []byte("concurrent conflict B"), Header: []byte("header B"),
		},
	}
	conflictStart := make(chan struct{})
	conflictResults := make(chan *chat.SendMessageResult, len(conflictingMessages))
	conflictErrors := make(chan error, len(conflictingMessages))
	group = sync.WaitGroup{}
	for _, request := range conflictingMessages {
		request := request
		group.Add(1)
		go func() {
			defer group.Done()
			<-conflictStart
			result, sendErr := h.Chat.HandleSendMessageResult(t.Context(), alice.ID, request)
			if sendErr != nil {
				conflictErrors <- sendErr
				return
			}
			conflictResults <- result
		}()
	}
	close(conflictStart)
	group.Wait()
	close(conflictResults)
	close(conflictErrors)
	if got := len(conflictResults); got != 1 {
		t.Fatalf("concurrent mismatch successful results=%d, want 1", got)
	}
	if got := len(conflictErrors); got != 1 {
		t.Fatalf("concurrent mismatch errors=%d, want 1", got)
	}
	conflictWinner := <-conflictResults
	for conflictErr := range conflictErrors {
		if !errors.Is(conflictErr, chat.ErrClientMessageIDConflict) {
			t.Fatalf("concurrent mismatch error=%v, want ErrClientMessageIDConflict", conflictErr)
		}
	}
	if err := h.DB.Pool.QueryRow(t.Context(),
		`SELECT count(*) FROM message_send_idempotency
		 WHERE sender_id=$1::uuid AND client_message_id=$2::uuid`,
		alice.ID, conflictingClientID,
	).Scan(&ledgerRows); err != nil {
		t.Fatal(err)
	}
	if ledgerRows != 1 {
		t.Fatalf("concurrent mismatch ledger rows=%d, want 1", ledgerRows)
	}
	if err := h.DB.Pool.QueryRow(t.Context(),
		`SELECT count(*) FROM messages WHERE id=$1::uuid`, conflictWinner.MessageID,
	).Scan(&messageRows); err != nil {
		t.Fatal(err)
	}
	if messageRows != 1 {
		t.Fatalf("concurrent mismatch message rows=%d, want 1", messageRows)
	}

	// The ledger has no message FK and remains authoritative after a hard
	// cleanup, so a lost ACK is still recoverable without re-insertion.
	if _, err := h.DB.Pool.Exec(t.Context(), `DELETE FROM messages WHERE id=$1::uuid`, first.MessageID); err != nil {
		t.Fatal(err)
	}
	tombstoneReplay, err := h.Chat.LookupSendMessageReplay(t.Context(), alice.ID, message)
	if err != nil {
		t.Fatal(err)
	}
	if tombstoneReplay == nil || !tombstoneReplay.Replayed ||
		tombstoneReplay.MessageID != first.MessageID ||
		!tombstoneReplay.ServerTimestamp.Equal(first.ServerTimestamp) {
		t.Fatalf("tombstone replay=%#v first=%#v", tombstoneReplay, first)
	}
}
