package chat

import (
	"context"
	"errors"
	"testing"

	"github.com/NaveLIL/veil/veil-server/internal/config"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

func TestHandleSendMessageRejectsSealedBeforeDatabaseAccess(t *testing.T) {
	t.Parallel()

	service := &Service{cfg: &config.Config{MaxMessageSize: 1024}}
	message := &pb.SendMessage{
		ConversationId:  "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ClientMessageId: "11111111-1111-4111-8111-111111111111",
		Ciphertext:      []byte("ciphertext"),
		Sealed:          true,
	}

	for name, send := range map[string]func() error{
		"direct": func() error {
			_, _, _, err := service.HandleSendMessage(context.Background(), "sender", message)
			return err
		},
		"sender key": func() error {
			_, _, _, err := service.HandleSecureSendMessage(
				context.Background(), "sender", message, &db.MessageSecurityContext{},
			)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := send(); !errors.Is(err, ErrSealedMessageUnsupported) {
				t.Fatalf("sealed message error = %v, want ErrSealedMessageUnsupported", err)
			}
		})
	}
}

type recordingCommittedChatLookup struct {
	members        []string
	err            error
	conversationID string
	required       uint64
}

func (s *recordingCommittedChatLookup) GetAuthorizedConversationMembers(
	_ context.Context,
	conversationID string,
	required uint64,
) ([]string, error) {
	s.conversationID = conversationID
	s.required = required
	return append([]string(nil), s.members...), s.err
}

func TestCommittedChatRecipientLookupFailureIsSafeNoFanout(t *testing.T) {
	t.Parallel()

	store := &recordingCommittedChatLookup{err: errors.New("forced post-commit lookup failure")}
	recipients := committedChatRecipients(
		context.Background(),
		store,
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"sender",
	)

	if recipients != nil {
		t.Fatalf("recipients = %v, want nil safe no-live-fanout result", recipients)
	}
	if store.conversationID != "cccccccc-cccc-4ccc-8ccc-cccccccccccc" {
		t.Fatalf("conversation lookup = %q", store.conversationID)
	}
	if store.required != db.ChannelReadPermissions {
		t.Fatalf("recipient permission mask = %#x, want %#x", store.required, db.ChannelReadPermissions)
	}
}

func TestCommittedChatRecipientsPreserveReadACLAndExcludeSender(t *testing.T) {
	t.Parallel()

	store := &recordingCommittedChatLookup{
		members: []string{"sender", "reader-one", "reader-two"},
	}
	recipients := committedChatRecipients(
		context.Background(), store, "message", "conversation", "sender",
	)

	if len(recipients) != 2 || recipients[0] != "reader-one" || recipients[1] != "reader-two" {
		t.Fatalf("recipients = %v, want authorized readers without sender", recipients)
	}
}
