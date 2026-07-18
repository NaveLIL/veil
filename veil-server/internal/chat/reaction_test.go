package chat

import (
	"context"
	"errors"
	"testing"

	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

func TestHandleReactionRejectsMalformedUUIDsBeforeDatabaseAccess(t *testing.T) {
	t.Parallel()
	service := &Service{}
	validMessageID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	validConversationID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	for name, update := range map[string]*pb.ReactionUpdate{
		"message id": {
			MessageId: "not-a-uuid", ConversationId: validConversationID,
			Emoji: "ok", Add: true,
		},
		"conversation id": {
			MessageId: validMessageID, ConversationId: "not-a-uuid",
			Emoji: "ok", Add: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			recipients, changed, err := service.HandleReaction(
				context.Background(), validMessageID, update,
			)
			if !errors.Is(err, ErrInvalidReaction) || changed || recipients != nil {
				t.Fatalf(
					"malformed request recipients=%v changed=%v err=%v",
					recipients, changed, err,
				)
			}
		})
	}
}
