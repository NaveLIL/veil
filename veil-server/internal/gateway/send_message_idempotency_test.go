package gateway

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/chat"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

const gatewayTestClientMessageID = "abcdefab-cdef-4abc-8def-abcdefabcdef"

func TestSendMessageEnvelopeContextOnlyReflectsCanonicalIDs(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name       string
		envelope   *pb.Envelope
		wantID     string
		wantReason string
	}{
		{
			name: "canonical",
			envelope: &pb.Envelope{Payload: &pb.Envelope_SendMessage{SendMessage: &pb.SendMessage{
				ClientMessageId: gatewayTestClientMessageID,
			}}},
			wantID: gatewayTestClientMessageID,
		},
		{
			name:       "missing",
			envelope:   &pb.Envelope{Payload: &pb.Envelope_SendMessage{SendMessage: &pb.SendMessage{}}},
			wantReason: sendMessageReasonInvalidClientMessageID,
		},
		{
			name: "uppercase is not canonical",
			envelope: &pb.Envelope{Payload: &pb.Envelope_SendMessage{SendMessage: &pb.SendMessage{
				ClientMessageId: "ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF",
			}}},
			wantReason: sendMessageReasonInvalidClientMessageID,
		},
		{
			name:       "nil send payload",
			envelope:   &pb.Envelope{Payload: &pb.Envelope_SendMessage{}},
			wantReason: sendMessageReasonInvalidClientMessageID,
		},
		{
			name:     "unrelated payload",
			envelope: &pb.Envelope{Payload: &pb.Envelope_FriendListRequest{}},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			gotID, gotReason := sendMessageEnvelopeContext(testCase.envelope)
			if gotID != testCase.wantID || gotReason != testCase.wantReason {
				t.Fatalf("context=(%q, %q), want (%q, %q)", gotID, gotReason, testCase.wantID, testCase.wantReason)
			}
		})
	}
}

func TestSendMessageErrorCorrelationAndReason(t *testing.T) {
	t.Parallel()

	client := &Client{send: make(chan outboundBatch, 1)}
	client.sendErrorWithSendMessageContext(
		91, http.StatusConflict, "conflict", gatewayTestClientMessageID, sendMessageReasonClientMessageIDConflict,
	)
	got := decodePublicErrorEnvelope(t, <-client.send).GetError()
	if got == nil || got.GetRefSeq() != 91 || got.GetCode() != http.StatusConflict ||
		got.GetClientMessageId() != gatewayTestClientMessageID ||
		got.GetReason() != sendMessageReasonClientMessageIDConflict {
		t.Fatalf("correlated error = %#v", got)
	}

	client.sendErrorWithSendMessageContext(92, http.StatusInternalServerError, "internal error", gatewayTestClientMessageID, "")
	got = decodePublicErrorEnvelope(t, <-client.send).GetError()
	if got == nil || got.GetClientMessageId() != gatewayTestClientMessageID ||
		got.GetReason() != sendMessageReasonInternalError {
		t.Fatalf("defensively classified correlated error = %#v", got)
	}

	client.sendError(93, http.StatusBadRequest, "generic")
	got = decodePublicErrorEnvelope(t, <-client.send).GetError()
	if got == nil || got.ClientMessageId != nil || got.Reason != nil {
		t.Fatalf("generic error unexpectedly carried send correlation: %#v", got)
	}
}

func TestInvalidSendMessageIDIsRejectedWithoutReflection(t *testing.T) {
	t.Parallel()

	client := &Client{
		authenticated: true,
		userID:        "authenticated-user",
		username:      "authenticated-name",
		identityKey:   bytes.Repeat([]byte{0x41}, 32),
		send:          make(chan outboundBatch, 1),
	}
	client.handleSendMessage(nil, 93, &pb.SendMessage{
		ClientMessageId: "ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF",
	})
	got := decodePublicErrorEnvelope(t, <-client.send).GetError()
	if got == nil || got.GetCode() != http.StatusBadRequest || got.GetRefSeq() != 93 ||
		got.ClientMessageId != nil || got.GetReason() != sendMessageReasonInvalidClientMessageID {
		t.Fatalf("invalid-id error = %#v", got)
	}
}

func TestUnauthenticatedSendErrorEchoesOnlyCanonicalID(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name       string
		id         string
		wantID     string
		wantReason string
	}{
		{
			name: "canonical", id: gatewayTestClientMessageID, wantID: gatewayTestClientMessageID,
			wantReason: sendMessageReasonNotAuthenticated,
		},
		{name: "invalid", id: "not-a-uuid", wantReason: sendMessageReasonInvalidClientMessageID},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			client := &Client{send: make(chan outboundBatch, 1)}
			client.handleEnvelope(&pb.Envelope{
				Seq: 94,
				Payload: &pb.Envelope_SendMessage{SendMessage: &pb.SendMessage{
					ClientMessageId: testCase.id,
				}},
			})
			got := decodePublicErrorEnvelope(t, <-client.send).GetError()
			if got == nil || got.GetCode() != http.StatusUnauthorized || got.GetRefSeq() != 94 ||
				got.GetClientMessageId() != testCase.wantID || got.GetReason() != testCase.wantReason {
				t.Fatalf("unauthenticated error = %#v", got)
			}
		})
	}
}

func TestRateLimitedSendErrorEchoesCanonicalID(t *testing.T) {
	previous := SetWSLimitsForTest(map[string]wsLimit{
		"send_message": {cap: 1, window: time.Hour},
	})
	defer SetWSLimitsForTest(previous)

	const userID = "correlation-rate-limit-user"
	if !allowEnvelope(userID, "send_message") {
		t.Fatal("first limiter token unexpectedly rejected")
	}
	client := &Client{
		authenticated: true,
		userID:        userID,
		send:          make(chan outboundBatch, 1),
	}
	client.handleEnvelope(&pb.Envelope{
		Seq: 95,
		Payload: &pb.Envelope_SendMessage{SendMessage: &pb.SendMessage{
			ClientMessageId: gatewayTestClientMessageID,
		}},
	})
	got := decodePublicErrorEnvelope(t, <-client.send).GetError()
	if got == nil || got.GetCode() != http.StatusTooManyRequests || got.GetRefSeq() != 95 ||
		got.GetClientMessageId() != gatewayTestClientMessageID || got.GetReason() != sendMessageReasonRateLimited {
		t.Fatalf("rate-limit error = %#v", got)
	}
}

func TestSendMessageAckUsesDurableResultCorrelation(t *testing.T) {
	t.Parallel()

	serverTimestamp := time.Unix(1_725_000_000, 123_456_789)
	rosterVersion := uint64(17)
	client := &Client{send: make(chan outboundBatch, 1)}
	if !client.sendMessageAck(96, gatewayTestClientMessageID, &chat.SendMessageResult{
		MessageID:        "99999999-9999-4999-8999-999999999999",
		ServerTimestamp:  serverTimestamp,
		AckRosterVersion: &rosterVersion,
		Replayed:         true,
	}) {
		t.Fatal("valid durable result was rejected")
	}
	envelope := decodePublicErrorEnvelope(t, <-client.send)
	got := envelope.GetMessageAck()
	if got == nil || got.GetRefSeq() != 96 || got.GetMessageId() != "99999999-9999-4999-8999-999999999999" ||
		got.GetServerTimestamp() != uint64(serverTimestamp.UnixNano()) ||
		got.GetClientMessageId() != gatewayTestClientMessageID || got.GetRosterVersion() != rosterVersion {
		t.Fatalf("message ACK = %#v", got)
	}
}

func TestSendMessageAckRejectsNilResultWithCorrelatedInternalError(t *testing.T) {
	t.Parallel()

	client := &Client{send: make(chan outboundBatch, 1)}
	if client.sendMessageAck(97, gatewayTestClientMessageID, nil) {
		t.Fatal("nil durable result unexpectedly produced an ACK")
	}
	envelope := decodePublicErrorEnvelope(t, <-client.send)
	got := envelope.GetError()
	if got == nil || envelope.GetMessageAck() != nil || got.GetCode() != http.StatusInternalServerError ||
		got.GetRefSeq() != 97 || got.GetClientMessageId() != gatewayTestClientMessageID ||
		got.GetReason() != sendMessageReasonInternalError {
		t.Fatalf("nil-result response = %#v", envelope)
	}
}
