package chat

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
	"google.golang.org/protobuf/proto"
)

func TestCanonicalClientMessageID(t *testing.T) {
	t.Parallel()

	valid := "11111111-1111-4111-8111-111111111111"
	for name, message := range map[string]*pb.SendMessage{
		"nil message":  nil,
		"missing":      {},
		"nil UUID":     {ClientMessageId: "00000000-0000-0000-0000-000000000000"},
		"uppercase":    {ClientMessageId: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},
		"noncanonical": {ClientMessageId: "{11111111-1111-4111-8111-111111111111}"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got, ok := CanonicalClientMessageID(message); ok || got != "" {
				t.Fatalf("CanonicalClientMessageID() = %q,%v; want empty,false", got, ok)
			}
		})
	}
	if got, ok := CanonicalClientMessageID(&pb.SendMessage{ClientMessageId: valid}); !ok || got != valid {
		t.Fatalf("CanonicalClientMessageID(valid) = %q,%v", got, ok)
	}
}

func TestSendMessageDigestUsesExactDomainAndDeterministicProtobuf(t *testing.T) {
	t.Parallel()

	message := &pb.SendMessage{
		ConversationId:  "22222222-2222-4222-8222-222222222222",
		Ciphertext:      []byte("ciphertext"),
		Header:          []byte("header"),
		ClientMessageId: "11111111-1111-4111-8111-111111111111",
	}
	clientMessageID, got, err := validateAndDigestSendMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	if clientMessageID != message.ClientMessageId {
		t.Fatalf("client ID = %q", clientMessageID)
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(append([]byte("veil.message.send.v1\x00"), encoded...))
	if got != want {
		t.Fatalf("digest = %x, want %x", got, want)
	}

	clone := proto.Clone(message).(*pb.SendMessage)
	_, clonedDigest, err := validateAndDigestSendMessage(clone)
	if err != nil || clonedDigest != got {
		t.Fatalf("cloned digest = %x err=%v, want %x", clonedDigest, err, got)
	}
	clone.Ciphertext = []byte("different")
	_, changedDigest, err := validateAndDigestSendMessage(clone)
	if err != nil {
		t.Fatal(err)
	}
	if changedDigest == got {
		t.Fatal("different exact SendMessage bytes produced the same digest")
	}
}

func TestSendMessageUnknownFieldsRejectedBeforeDigest(t *testing.T) {
	t.Parallel()

	message := &pb.SendMessage{ClientMessageId: "11111111-1111-4111-8111-111111111111"}
	message.ProtoReflect().SetUnknown([]byte{0x60, 0x01})
	if _, _, err := validateAndDigestSendMessage(message); !errors.Is(err, ErrSendMessageUnknownFields) {
		t.Fatalf("unknown-field error = %v, want ErrSendMessageUnknownFields", err)
	}
}

func TestMessageSendConflictMapsToStableChatError(t *testing.T) {
	t.Parallel()

	if err := mapSendMessageStoreError(db.ErrMessageSendIDConflict); !errors.Is(err, ErrClientMessageIDConflict) {
		t.Fatalf("mapped conflict = %v", err)
	}
}
