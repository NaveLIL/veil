package chat

import (
	"testing"

	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

type capturedConversationBroadcast struct {
	users []string
	env   *pb.Envelope
}

func (capture *capturedConversationBroadcast) BroadcastToUsers(users []string, env *pb.Envelope) {
	capture.users = append([]string(nil), users...)
	capture.env = env
}

func TestConversationAvailableHintContainsOnlyExactUUID(t *testing.T) {
	capture := &capturedConversationBroadcast{}
	service := &Service{bcast: capture}
	conversationID := "70be554c-b5ad-4cdd-b6f4-cc7b79563690"
	service.notifyConversationAvailable([]string{"invitee"}, conversationID)

	if len(capture.users) != 1 || capture.users[0] != "invitee" {
		t.Fatalf("recipients = %v, want invitee", capture.users)
	}
	available := capture.env.GetConversationAvailable()
	if available == nil || available.ConversationId != conversationID {
		t.Fatalf("conversation hint = %#v, want exact UUID", available)
	}
	if capture.env.Seq != 0 || capture.env.Timestamp != 0 {
		t.Fatalf("discovery hint unexpectedly carried mutable transport metadata: %#v", capture.env)
	}
}
