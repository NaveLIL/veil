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
	client := &Client{send: make(chan []byte, 1)}
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

func TestSendPublicAuthFailureDoesNotExposeCause(t *testing.T) {
	t.Parallel()
	client := &Client{send: make(chan []byte, 1)}
	err := publicerr.New(http.StatusUnauthorized, "authentication_failed", "authentication failed", errors.New(transportSecretCanary))
	if queueErr := client.sendPublicAuthFailure(72, err); queueErr != nil {
		t.Fatalf("queue auth failure: %v", queueErr)
	}
	var envelope pb.Envelope
	if unmarshalErr := proto.Unmarshal(<-client.send, &envelope); unmarshalErr != nil {
		t.Fatalf("decode auth failure: %v", unmarshalErr)
	}
	result := envelope.GetAuthResult()
	if result == nil || result.GetSuccess() || result.GetErrorMessage() != "authentication failed" {
		t.Fatalf("unexpected auth result: %#v", result)
	}
	if strings.Contains(result.GetErrorMessage(), transportSecretCanary) {
		t.Fatal("private cause leaked through unauthenticated handshake")
	}
}

func decodePublicErrorEnvelope(t *testing.T, data []byte) *pb.Envelope {
	t.Helper()
	var envelope pb.Envelope
	if err := proto.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode WS error: %v", err)
	}
	return &envelope
}
