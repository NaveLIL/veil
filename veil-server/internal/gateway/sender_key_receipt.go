package gateway

import (
	"bytes"
	"context"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

// handleSenderKeyReceipt collects only the retained row installed by this
// exact authenticated target device. The stream head remains as the monotonic
// replay barrier after collection.
func (c *Client) handleSenderKeyReceipt(ctx context.Context, seq uint64, receipt *pb.SenderKeyReceipt) {
	if receipt == nil || receipt.ConversationId == "" || len(receipt.OwnerDeviceId) != 16 ||
		len(receipt.TargetDeviceId) != 16 || receipt.Generation == 0 ||
		receipt.RosterVersion == 0 || len(receipt.EnvelopeCommitment) != 32 ||
		!c.perDeviceSecure || c.deviceBindingStatus != db.DeviceBindingActive ||
		len(c.deviceKey) != 16 || !bytes.Equal(receipt.TargetDeviceId, c.deviceKey) {
		c.sendError(seq, 400, "invalid sender key receipt")
		return
	}
	owner, err := c.hub.chatSvc.DB().FindDevice(ctx, receipt.OwnerDeviceId)
	if err != nil {
		c.sendError(seq, 404, "sender device not found")
		return
	}
	if err := c.hub.chatSvc.DB().AcknowledgeSenderKey(
		ctx, receipt.ConversationId, owner.ID, c.deviceID,
		receipt.Generation, receipt.RosterVersion, receipt.EnvelopeCommitment,
	); err != nil {
		c.sendPublicError(seq, 409, publicerr.New(
			409, "sender_key_receipt_mismatch", "sender key receipt does not match retained distribution", err,
		))
		return
	}
	conversationID := receipt.ConversationId
	generation := receipt.Generation
	rosterVersion := receipt.RosterVersion
	c.sendEnvelope(&pb.Envelope{
		Seq: seq,
		Payload: &pb.Envelope_MessageAck{MessageAck: &pb.MessageAck{
			RefSeq:              seq,
			TargetDeviceId:      append([]byte(nil), c.deviceKey...),
			ConversationId:      &conversationID,
			SenderKeyGeneration: &generation,
			RosterVersion:       &rosterVersion,
			EnvelopeCommitment:  append([]byte(nil), receipt.EnvelopeCommitment...),
		}},
	})
}
