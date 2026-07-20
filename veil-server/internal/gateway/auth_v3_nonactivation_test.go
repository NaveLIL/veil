package gateway

import (
	"bytes"
	"net/http"
	"testing"

	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

func TestAuthResponseV3IsNotRoutedByLegacyWebSocket(t *testing.T) {
	t.Parallel()

	client := &Client{send: make(chan outboundBatch, 1)}
	nodeAccessPass := bytes.Repeat([]byte{0xa5}, 32)
	client.handleEnvelope(&pb.Envelope{
		Seq: 73,
		Payload: &pb.Envelope_AuthResponseV3{AuthResponseV3: &pb.AuthResponseV3{
			ProtocolVersion: 3,
			NodeAccessPass:  nodeAccessPass,
		}},
	})

	got := decodePublicErrorEnvelope(t, <-client.send).GetError()
	if got == nil || got.GetCode() != http.StatusUnauthorized || got.GetRefSeq() != 73 {
		t.Fatalf("unactivated auth v3 response = %#v, want generic pre-auth 401", got)
	}
	if client.authAttempts != 0 || client.authenticated {
		t.Fatalf(
			"unactivated auth v3 reached legacy auth state: attempts=%d authenticated=%v",
			client.authAttempts,
			client.authenticated,
		)
	}
	if !bytes.Equal(nodeAccessPass, make([]byte, len(nodeAccessPass))) {
		t.Fatal("unactivated auth v3 left the decoded Node Access Pass in memory")
	}
}
