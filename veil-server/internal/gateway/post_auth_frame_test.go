package gateway

import (
	"bytes"
	"testing"

	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

func TestPostHandshakeAuthFramesFailClosedAndClearBearers(t *testing.T) {
	t.Parallel()

	for name, testCase := range map[string]struct {
		bearer   []byte
		envelope func([]byte) *pb.Envelope
	}{
		"v3 replay": {
			bearer: bytes.Repeat([]byte{0xa5}, 32),
			envelope: func(bearer []byte) *pb.Envelope {
				return &pb.Envelope{Payload: &pb.Envelope_AuthResponseV3{AuthResponseV3: &pb.AuthResponseV3{NodeAccessPass: bearer}}}
			},
		},
		"v2 downgrade": {
			bearer: bytes.Repeat([]byte{0x5a}, 32),
			envelope: func(bearer []byte) *pb.Envelope {
				return &pb.Envelope{Payload: &pb.Envelope_AuthResponse{AuthResponse: &pb.AuthResponse{NodeAccessInvite: bearer}}}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			closed := false
			client := &Client{authenticated: true, closeFn: func() error { closed = true; return nil }}
			client.handleEnvelope(testCase.envelope(testCase.bearer))
			if !closed || !client.closing.Load() {
				t.Fatal("post-handshake auth frame did not fail closed")
			}
			if !bytes.Equal(testCase.bearer, make([]byte, len(testCase.bearer))) {
				t.Fatal("post-handshake auth frame left a decoded bearer in memory")
			}
		})
	}
}
