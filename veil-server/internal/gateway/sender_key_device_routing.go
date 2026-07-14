package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/logsafe"
	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

func (c *Client) handleSenderKeyDist(ctx context.Context, seq uint64, skd *pb.SenderKeyDistribution) {
	c.handleDeviceSenderKeyDist(ctx, seq, skd)
}

func (c *Client) pendingSenderKeyEnvelopes(ctx context.Context) ([][]byte, error) {
	return c.buildPendingDeviceSenderKeyEnvelopes(ctx)
}

func (c *Client) handleDeviceSenderKeyDist(ctx context.Context, seq uint64, skd *pb.SenderKeyDistribution) {
	if skd == nil || skd.ConversationId == "" || skd.Generation == 0 ||
		len(skd.SenderKeyMessage) == 0 || len(skd.TargetIdentityKey) != 32 ||
		len(skd.TargetDeviceId) != 16 || len(skd.TargetDeviceIdentityKey) != 32 ||
		len(skd.SenderDeviceId) != 16 || skd.RosterVersion == 0 ||
		len(skd.RosterCommitment) != 32 || skd.SenderBindingVersion == 0 ||
		skd.TargetBindingVersion == 0 {
		c.sendError(seq, 400, "invalid sender key distribution")
		return
	}
	if !c.perDeviceSecure || c.deviceBindingStatus != db.DeviceBindingActive ||
		c.deviceBindingVersion == 0 || len(c.deviceKey) != 16 {
		c.sendPublicError(seq, 409, publicerr.New(
			409, "device_not_eligible", "device is not eligible for secure channel traffic", errDeviceNotEligible,
		))
		return
	}
	isMember, err := c.hub.chatSvc.DB().CanAccessConversation(
		ctx, skd.ConversationId, c.userID,
		db.ChannelReadPermissions|db.PermSendMessages,
	)
	if err != nil || !isMember {
		c.sendError(seq, 403, "not a group member")
		return
	}
	conversationType, err := c.hub.chatSvc.DB().GetConversationType(ctx, skd.ConversationId)
	if err != nil || (conversationType != 1 && conversationType != 2) {
		c.sendError(seq, 400, "sender key distributions require a group or channel conversation")
		return
	}

	roster, err := resolveExactReadyRoster(
		ctx, c.hub.chatSvc.DB(), skd.ConversationId,
		skd.RosterVersion, skd.RosterCommitment,
	)
	if err != nil {
		c.sendPublicError(seq, 409, publicerr.New(
			409, "secure_roster_changed", "secure device roster changed; rotate and redistribute", err,
		))
		return
	}
	source, err := findRosterDeviceByDatabaseID(roster, c.deviceID)
	if err != nil || !bytes.Equal(source.device.DeviceKey, c.deviceKey) ||
		!bytes.Equal(skd.SenderDeviceId, source.device.DeviceKey) ||
		skd.SenderBindingVersion != source.device.Binding.Version ||
		c.deviceBindingVersion != source.device.Binding.Version {
		c.sendPublicError(seq, 409, publicerr.New(
			409, "device_not_eligible", "device is not eligible for secure channel traffic", errDeviceNotEligible,
		))
		return
	}
	target, err := findRosterDeviceByProtocolID(roster, skd.TargetIdentityKey, skd.TargetDeviceId)
	if err != nil || target.device.DeviceID == c.deviceID ||
		!bytes.Equal(skd.TargetDeviceIdentityKey, target.device.Binding.DeviceIdentityKey) ||
		skd.TargetBindingVersion != target.device.Binding.Version {
		c.sendPublicError(seq, 409, publicerr.New(
			409, "device_not_eligible", "device is not eligible for secure channel traffic", errDeviceNotEligible,
		))
		return
	}

	// The v3 bytes remain unchanged, but every identity in them is now a
	// cryptographic DEVICE identity. The account key is routing/membership
	// metadata only and is never an encryption fallback.
	if err := validateSenderKeyEnvelope(
		skd.SenderKeyMessage, skd.ConversationId, skd.Generation,
		source.device.Binding.DeviceIdentityKey,
		source.device.Binding.DeviceSigningKey,
		target.device.Binding.DeviceIdentityKey,
	); err != nil {
		c.sendError(seq, 403, "invalid authenticated sender key distribution")
		return
	}

	if err := c.hub.chatSvc.DB().StoreDeviceSenderKey(
		ctx, skd.ConversationId, c.deviceID, target.device.DeviceID,
		skd.SenderKeyMessage, skd.Generation,
		roster.Version, roster.Commitment[:],
		source.device.Binding.Version, target.device.Binding.Version,
	); err != nil {
		switch {
		case errors.Is(err, db.ErrSenderKeyConversationType):
			c.sendPublicError(seq, 400, publicerr.New(
				400, "invalid_sender_key_conversation", "sender key distribution requires a group or channel conversation", err,
			))
		case errors.Is(err, db.ErrStaleSenderKeyGeneration):
			c.sendError(seq, 409, "stale sender key generation")
		case errors.Is(err, db.ErrSenderKeyGenerationConflict):
			c.sendError(seq, 409, "sender key generation already committed")
		case errors.Is(err, db.ErrSenderKeyRosterChanged):
			c.sendPublicError(seq, 409, publicerr.New(
				409, "secure_roster_changed", "secure device roster changed; rotate and redistribute", err,
			))
		case errors.Is(err, db.ErrSenderKeyRetentionFull),
			errors.Is(err, db.ErrSenderKeyRetentionExpired),
			errors.Is(err, db.ErrSenderKeyTargetBacklogFull):
			// No transport ACK: the client's outgoing generation remains blocked
			// until an exact receipt arrives or the device is explicitly excluded.
			c.sendPublicError(seq, 409, publicerr.New(
				409, "sender_key_delivery_unavailable", "sender-key delivery requires recovery or target-device exclusion", err,
			))
		default:
			log.Printf(
				"sender-key durable device store failed: owner_device_ref=%s target_device_ref=%s",
				logsafe.Ref("device", c.deviceID), logsafe.Ref("device", target.device.DeviceID),
			)
			c.sendError(seq, 500, "failed to store sender key distribution")
		}
		return
	}

	// Never clone an untrusted protobuf into the recipient envelope. Besides
	// caller-controlled proof fields, proto.Clone would preserve unknown wire
	// fields and turn this gateway into a future-field injection oracle. Build
	// the complete wire object from the validated ciphertext and authoritative
	// directory snapshot, exactly as the retained-delivery path does.
	forwarded := &pb.SenderKeyDistribution{
		ConversationId:            skd.ConversationId,
		SenderKeyMessage:          append([]byte(nil), skd.SenderKeyMessage...),
		Generation:                skd.Generation,
		TargetIdentityKey:         append([]byte(nil), target.member.IdentityKey...),
		TargetDeviceId:            append([]byte(nil), target.device.DeviceKey...),
		TargetDeviceIdentityKey:   append([]byte(nil), target.device.Binding.DeviceIdentityKey...),
		SenderDeviceId:            append([]byte(nil), source.device.DeviceKey...),
		RosterVersion:             roster.Version,
		RosterCommitment:          append([]byte(nil), roster.Commitment[:]...),
		SenderBindingVersion:      source.device.Binding.Version,
		TargetBindingVersion:      target.device.Binding.Version,
		SenderAccountIdentityKey:  append([]byte(nil), source.member.IdentityKey...),
		SenderAccountSigningKey:   append([]byte(nil), source.member.SigningKey...),
		SenderDeviceIdentityKey:   append([]byte(nil), source.device.Binding.DeviceIdentityKey...),
		SenderDeviceSigningKey:    append([]byte(nil), source.device.Binding.DeviceSigningKey...),
		SenderDeviceCapabilities:  source.device.Binding.Capabilities,
		SenderDeviceBindingStatus: uint32(source.device.Binding.Status),
		SenderAccountSignature:    append([]byte(nil), source.device.Binding.AccountSignature...),
	}
	fwd := &pb.Envelope{
		Timestamp: uint64(time.Now().UnixNano()),
		Payload:   &pb.Envelope_SenderKeyDist{SenderKeyDist: forwarded},
	}
	data, err := proto.Marshal(fwd)
	if err != nil {
		c.sendError(seq, 500, "failed to encode sender key distribution")
		return
	}

	envelopeCommitment := sha256.Sum256(skd.SenderKeyMessage)
	if err := c.hub.chatSvc.DB().WithCurrentSenderKeyRoute(
		ctx, skd.ConversationId, c.deviceID, target.device.DeviceID,
		roster.Version, roster.Commitment[:],
		source.device.Binding.Version, target.device.Binding.Version,
		func() error {
			c.hub.enqueueToDevice(target.device.DeviceID, data)
			return nil
		},
	); err != nil {
		if errors.Is(err, db.ErrSenderKeyRosterChanged) {
			if discardErr := c.hub.chatSvc.DB().DiscardDeviceSenderKey(
				ctx, skd.ConversationId, c.deviceID, target.device.DeviceID,
				skd.Generation, roster.Version, envelopeCommitment[:],
			); discardErr != nil {
				log.Printf(
					"sender-key stale route cleanup failed: owner_device_ref=%s target_device_ref=%s",
					logsafe.Ref("device", c.deviceID), logsafe.Ref("device", target.device.DeviceID),
				)
			}
			c.sendPublicError(seq, 409, publicerr.New(
				409, "secure_roster_changed", "secure device roster changed; rotate and redistribute", err,
			))
		} else {
			log.Printf(
				"sender-key publication authorization failed: owner_device_ref=%s target_device_ref=%s",
				logsafe.Ref("device", c.deviceID), logsafe.Ref("device", target.device.DeviceID),
			)
			c.sendError(seq, 500, "failed to authorize sender key publication")
		}
		return
	}

	conversationID := skd.ConversationId
	generation := skd.Generation
	rosterVersion := roster.Version
	c.sendEnvelope(&pb.Envelope{
		Seq: seq,
		Payload: &pb.Envelope_MessageAck{MessageAck: &pb.MessageAck{
			RefSeq:              seq,
			TargetDeviceId:      append([]byte(nil), target.device.DeviceKey...),
			ConversationId:      &conversationID,
			SenderKeyGeneration: &generation,
			RosterVersion:       &rosterVersion,
			EnvelopeCommitment:  append([]byte(nil), envelopeCommitment[:]...),
		}},
	})
}

// buildPendingDeviceSenderKeyEnvelopes restores each conversation as an
// all-or-nothing unit. One expired, malformed, oversized or currently
// not-ready group is isolated without preventing authentication, DM sync, or
// healthy group restore. Its rows remain untouched and cannot be ACKed as a
// partial suffix; new generations remain blocked by the durable DB policy.
func (c *Client) buildPendingDeviceSenderKeyEnvelopes(ctx context.Context) ([][]byte, error) {
	if !c.perDeviceSecure || c.deviceBindingStatus != db.DeviceBindingActive {
		return nil, nil
	}
	if c.deviceID == "" || len(c.deviceKey) != 16 {
		return nil, errors.New("authenticated cryptographic device required")
	}
	backlogs, err := c.hub.chatSvc.DB().ListPendingSenderKeyConversations(ctx, c.deviceID)
	if err != nil {
		return nil, err
	}
	encoded := make([][]byte, 0)
	ownerAccounts := make(map[string]*db.User)
	var acceptedRows, acceptedEncryptedBytes, acceptedWireBytes int64
	for _, backlog := range backlogs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if backlog.ConversationID == "" || backlog.TargetUserID == "" ||
			backlog.Rows <= 0 || backlog.Bytes <= 0 ||
			backlog.LegacyOrPartial || backlog.Expired {
			c.logIsolatedSenderKeyConversation(backlog.ConversationID, "invalid_or_expired")
			continue
		}
		remainingRows := int64(db.MaxPendingSenderKeyRowsPerTarget) - acceptedRows
		remainingEncryptedBytes := int64(db.MaxPendingSenderKeyBytesPerTarget) - acceptedEncryptedBytes
		remainingWireBytes := int64(db.MaxPendingSenderKeyBytesPerTarget) - acceptedWireBytes
		if remainingRows <= 0 || remainingEncryptedBytes <= 0 || remainingWireBytes <= 0 ||
			backlog.Rows > remainingRows || backlog.Bytes > remainingEncryptedBytes {
			c.logIsolatedSenderKeyConversation(backlog.ConversationID, "restore_budget")
			continue
		}

		// Current roster readiness, exact authenticated target binding, and the
		// retained ciphertext read share one SERIALIZABLE transaction. A revoke
		// or legacy-device insertion cannot land between those decisions.
		restore, loadErr := c.hub.chatSvc.DB().LoadPendingSenderKeyConversation(
			ctx, c.deviceID, c.deviceKey, c.deviceBindingVersion,
			backlog.ConversationID,
			remainingRows, remainingEncryptedBytes,
		)
		if loadErr != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			c.logIsolatedSenderKeyConversation(
				backlog.ConversationID, senderKeyRestoreErrorLabel(loadErr),
			)
			continue
		}
		if restore == nil || len(restore.Rows) == 0 {
			continue
		}
		target, targetErr := findRosterDeviceByDatabaseID(restore.Roster, c.deviceID)
		if targetErr != nil {
			c.logIsolatedSenderKeyConversation(backlog.ConversationID, "target_not_ready")
			continue
		}
		conversationEncoded, encryptedBytes, encodeErr := c.encodePendingSenderKeyConversation(
			ctx, restore.Rows, target, ownerAccounts, remainingWireBytes,
		)
		if encodeErr != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			c.logIsolatedSenderKeyConversation(
				backlog.ConversationID, senderKeyRestoreErrorLabel(encodeErr),
			)
			continue
		}
		var wireBytes int64
		for _, wire := range conversationEncoded {
			wireBytes += int64(len(wire))
		}
		encoded = append(encoded, conversationEncoded...)
		acceptedRows += int64(len(restore.Rows))
		acceptedEncryptedBytes += encryptedBytes
		acceptedWireBytes += wireBytes
	}
	return encoded, nil
}

func (c *Client) encodePendingSenderKeyConversation(ctx context.Context, rows []db.SenderKeyRow, target *rosterDeviceRef, ownerAccounts map[string]*db.User, maxWireBytes int64) ([][]byte, int64, error) {
	if len(rows) == 0 || target == nil || target.member == nil || target.device == nil || maxWireBytes <= 0 {
		return nil, 0, errors.New("invalid retained sender key conversation")
	}
	conversationID := rows[0].ConversationID
	encoded := make([][]byte, 0, len(rows))
	var encryptedBytes, wireBytes int64
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if row.ConversationID != conversationID || row.ConversationID == "" ||
			row.Generation == 0 || len(row.EncryptedKey) == 0 ||
			row.RosterVersion == 0 || len(row.RosterCommitment) != 32 ||
			row.OwnerBindingVersion == 0 || row.TargetBindingVersion == 0 ||
			len(row.EnvelopeCommitment) != 32 {
			return nil, 0, db.ErrSenderKeyLegacyState
		}
		envelopeCommitment := sha256.Sum256(row.EncryptedKey)
		if !bytes.Equal(envelopeCommitment[:], row.EnvelopeCommitment) {
			return nil, 0, errors.New("invalid retained sender key row")
		}
		ownerBinding, ownerErr := c.hub.chatSvc.DB().GetDeviceBindingVersion(
			ctx, row.OwnerDeviceID, row.OwnerBindingVersion,
		)
		targetBinding, targetBindingErr := c.hub.chatSvc.DB().GetDeviceBindingVersion(
			ctx, row.TargetDeviceID, row.TargetBindingVersion,
		)
		if ownerErr != nil || targetBindingErr != nil ||
			ownerBinding.Status != db.DeviceBindingActive ||
			ownerBinding.Capabilities&db.RequiredChannelCapabilities != db.RequiredChannelCapabilities ||
			targetBinding.Status != db.DeviceBindingActive ||
			targetBinding.Capabilities&db.RequiredChannelCapabilities != db.RequiredChannelCapabilities ||
			!bytes.Equal(targetBinding.DeviceKey, c.deviceKey) {
			return nil, 0, errors.New("retained sender key binding history is unavailable")
		}
		ownerAccount := ownerAccounts[ownerBinding.UserID]
		if ownerAccount == nil {
			ownerAccount, ownerErr = c.hub.chatSvc.DB().FindUserByID(ctx, ownerBinding.UserID)
			if ownerErr != nil || ownerAccount == nil {
				return nil, 0, errors.New("retained sender account binding history is unavailable")
			}
			ownerAccounts[ownerBinding.UserID] = ownerAccount
		}
		if len(ownerAccount.IdentityKey) != 32 || len(ownerAccount.SigningKey) != 32 ||
			len(ownerBinding.DeviceIdentityKey) != 32 || len(ownerBinding.DeviceSigningKey) != 32 ||
			len(ownerBinding.AccountSignature) != 64 {
			return nil, 0, errors.New("retained sender account binding proof is invalid")
		}
		if err := validateSenderKeyEnvelope(
			row.EncryptedKey, row.ConversationID, row.Generation,
			ownerBinding.DeviceIdentityKey,
			ownerBinding.DeviceSigningKey,
			targetBinding.DeviceIdentityKey,
		); err != nil {
			return nil, 0, errors.New("invalid retained sender key envelope")
		}
		env := &pb.Envelope{
			Timestamp: uint64(time.Now().UnixNano()),
			Payload: &pb.Envelope_SenderKeyDist{SenderKeyDist: &pb.SenderKeyDistribution{
				ConversationId:            row.ConversationID,
				SenderKeyMessage:          append([]byte(nil), row.EncryptedKey...),
				Generation:                row.Generation,
				TargetIdentityKey:         append([]byte(nil), target.member.IdentityKey...),
				TargetDeviceId:            append([]byte(nil), target.device.DeviceKey...),
				TargetDeviceIdentityKey:   append([]byte(nil), targetBinding.DeviceIdentityKey...),
				SenderDeviceId:            append([]byte(nil), ownerBinding.DeviceKey...),
				RosterVersion:             row.RosterVersion,
				RosterCommitment:          append([]byte(nil), row.RosterCommitment...),
				SenderBindingVersion:      row.OwnerBindingVersion,
				TargetBindingVersion:      row.TargetBindingVersion,
				SenderAccountIdentityKey:  append([]byte(nil), ownerAccount.IdentityKey...),
				SenderAccountSigningKey:   append([]byte(nil), ownerAccount.SigningKey...),
				SenderDeviceIdentityKey:   append([]byte(nil), ownerBinding.DeviceIdentityKey...),
				SenderDeviceSigningKey:    append([]byte(nil), ownerBinding.DeviceSigningKey...),
				SenderDeviceCapabilities:  ownerBinding.Capabilities,
				SenderDeviceBindingStatus: uint32(ownerBinding.Status),
				SenderAccountSignature:    append([]byte(nil), ownerBinding.AccountSignature...),
			}},
		}
		data, err := proto.Marshal(env)
		if err != nil {
			return nil, 0, fmt.Errorf("encode retained sender key: %w", err)
		}
		wireBytes += int64(len(data))
		if wireBytes > maxWireBytes {
			return nil, 0, db.ErrSenderKeyRestoreBacklogExceeded
		}
		encryptedBytes += int64(len(row.EncryptedKey))
		encoded = append(encoded, data)
	}
	return encoded, encryptedBytes, nil
}

func (c *Client) logIsolatedSenderKeyConversation(conversationID, reason string) {
	if reason == "" {
		reason = "internal"
	}
	log.Printf(
		"sender-key restore conversation isolated: conversation_ref=%s reason=%s",
		logsafe.Ref("conversation", conversationID), reason,
	)
}
