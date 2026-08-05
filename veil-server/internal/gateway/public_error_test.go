package gateway

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

const transportSecretCanary = "constraint sender_keys_owner_target_key C:\\veil\\secrets.db 199a866e-8591-4546-9edb-00381bfeb55b https://token.example/private"

func TestSendPublicErrorDoesNotExposeCause(t *testing.T) {
	t.Parallel()
	client := &Client{send: make(chan outboundBatch, 1)}
	client.sendPublicError(71, http.StatusInternalServerError, errors.New(transportSecretCanary))
	envelope := decodePublicErrorEnvelope(t, <-client.send)
	got := envelope.GetError()
	if got == nil || got.GetCode() != http.StatusInternalServerError || got.GetMessage() != "internal server error" {
		t.Fatalf("unexpected WS error: %#v", got)
	}
	if strings.Contains(got.GetMessage(), transportSecretCanary) {
		t.Fatal("private cause leaked through WS error")
	}
}

func TestReactionLimitErrorIsStaticAndUnderstandable(t *testing.T) {
	t.Parallel()
	client := &Client{send: make(chan outboundBatch, 1)}
	client.sendPublicError(74, http.StatusConflict, publicerr.New(
		http.StatusConflict,
		"reaction_limit_reached",
		"message reaction limit reached",
		errors.New(transportSecretCanary),
	))
	errorEnvelope := decodePublicErrorEnvelope(t, <-client.send).GetError()
	if errorEnvelope == nil ||
		errorEnvelope.GetCode() != http.StatusConflict ||
		errorEnvelope.GetMessage() != "message reaction limit reached" {
		t.Fatalf("unexpected reaction-limit error: %#v", errorEnvelope)
	}
	if strings.Contains(errorEnvelope.GetMessage(), transportSecretCanary) {
		t.Fatal("private reaction-limit cause leaked through WS error")
	}
}

func decodePublicErrorEnvelope(t *testing.T, batch outboundBatch) *pb.Envelope {
	t.Helper()
	var envelope pb.Envelope
	if err := proto.Unmarshal(requireSingleOutboundFrame(t, batch), &envelope); err != nil {
		t.Fatalf("decode WS error: %v", err)
	}
	return &envelope
}

func requireSingleOutboundFrame(t *testing.T, batch outboundBatch) []byte {
	t.Helper()
	if batch.publication != nil {
		t.Fatal("ordinary response unexpectedly has a publication gate")
	}
	if len(batch.frames) != 1 {
		t.Fatalf("outbound frames = %d, want 1", len(batch.frames))
	}
	return batch.frames[0]
}
