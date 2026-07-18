package gateway

import (
	"bytes"
	"context"
	"errors"

	"github.com/NaveLIL/veil/veil-server/internal/chat"
	"github.com/NaveLIL/veil/veil-server/internal/db"
)

var (
	errDeviceRosterUnavailable = errors.New("secure device roster is unavailable")
	errDeviceRosterChanged     = errors.New("secure device roster changed; rotate and redistribute")
	errDeviceNotEligible       = errors.New("device is not eligible for secure channel traffic")
)

const (
	errMessageRosterRefresh = "secure device roster changed; refresh the device directory and retry"
	errMessageDeviceRefresh = "secure sender device context changed; re-authenticate and retry"

	sendMessageReasonInvalidClientMessageID  = "invalid_client_message_id"
	sendMessageReasonClientMessageIDConflict = "client_message_id_conflict"
	sendMessageReasonSecureRosterChanged     = "secure_roster_changed"
	sendMessageReasonDeviceNotEligible       = "device_not_eligible"
	sendMessageReasonNotAuthenticated        = "not_authenticated"
	sendMessageReasonRateLimited             = "rate_limited"
	sendMessageReasonNotMember               = "not_member"
	sendMessageReasonConversationNotFound    = "conversation_not_found"
	sendMessageReasonSealedUnsupported       = "sealed_unsupported"
	sendMessageReasonInvalidMessage          = "invalid_message"
	sendMessageReasonInternalError           = "internal_error"
)

func classifySendMessageError(err error) (int, string, string) {
	switch {
	case errors.Is(err, chat.ErrInvalidClientMessageID):
		return 400, "invalid client message id", sendMessageReasonInvalidClientMessageID
	case errors.Is(err, chat.ErrClientMessageIDConflict):
		return 409, "client message id already used for a different request", sendMessageReasonClientMessageIDConflict
	case errors.Is(err, chat.ErrSealedMessageUnsupported):
		return 400, "message rejected", sendMessageReasonSealedUnsupported
	case errors.Is(err, chat.ErrNotMember), errors.Is(err, chat.ErrInsufficientPermissions):
		return 403, "not a conversation member", sendMessageReasonNotMember
	case errors.Is(err, chat.ErrSendMessageUnknownFields),
		errors.Is(err, chat.ErrInvalidSendMessage),
		errors.Is(err, chat.ErrMessageTooBig),
		errors.Is(err, chat.ErrMessageConversationMismatch),
		errors.Is(err, chat.ErrAttachmentAccess):
		return 400, "message rejected", sendMessageReasonInvalidMessage
	case errors.Is(err, db.ErrMessageRosterChanged):
		return 409, errMessageRosterRefresh, sendMessageReasonSecureRosterChanged
	case errors.Is(err, db.ErrMessageSecurityContext):
		return 409, errMessageDeviceRefresh, sendMessageReasonDeviceNotEligible
	case errors.Is(err, errDeviceRosterUnavailable), errors.Is(err, errDeviceRosterChanged):
		return 409, errMessageRosterRefresh, sendMessageReasonSecureRosterChanged
	case errors.Is(err, errDeviceNotEligible):
		return 409, errMessageDeviceRefresh, sendMessageReasonDeviceNotEligible
	default:
		return 500, "internal error", sendMessageReasonInternalError
	}
}

// The early ledger lookup has only three public outcomes: invalid wire bytes,
// a digest conflict, or an exact replay. Every other error is infrastructure
// failure and must not be presented as client validation.
func classifySendMessageLookupError(err error) (int, string, string) {
	if errors.Is(err, chat.ErrInvalidClientMessageID) ||
		errors.Is(err, chat.ErrSendMessageUnknownFields) ||
		errors.Is(err, chat.ErrClientMessageIDConflict) {
		return classifySendMessageError(err)
	}
	return 500, "internal error", sendMessageReasonInternalError
}

func senderKeyRestoreErrorLabel(err error) string {
	switch {
	case errors.Is(err, db.ErrSenderKeyRetentionExpired):
		return "retention_expired"
	case errors.Is(err, db.ErrSenderKeyRestoreBacklogExceeded):
		return "backlog_exceeded"
	case errors.Is(err, db.ErrSenderKeyLegacyState):
		return "legacy_state"
	case errors.Is(err, db.ErrSenderKeyConversationUnavailable),
		errors.Is(err, db.ErrConversationAccessDenied):
		return "roster_not_ready"
	default:
		return "invalid_or_unavailable_state"
	}
}

type rosterDeviceRef struct {
	member *db.ConversationDirectoryMember
	device *db.ConversationDirectoryDevice
}

type deviceFanoutRecipient struct {
	UserID    string
	DeviceID  string // database UUID, used only for exact live routing
	DeviceKey []byte // signed 16-byte protocol device ID
}

func resolveExactReadyRoster(ctx context.Context, database *db.DB, conversationID string, version uint64, commitment []byte) (*db.ConversationDeviceRoster, error) {
	if database == nil || conversationID == "" || version == 0 || len(commitment) != 32 {
		return nil, errDeviceRosterUnavailable
	}
	roster, err := database.ResolveConversationDeviceRoster(
		ctx, conversationID, db.RequiredChannelCapabilities,
	)
	if err != nil {
		return nil, errDeviceRosterUnavailable
	}
	if !roster.Ready {
		return nil, errDeviceRosterUnavailable
	}
	if roster.Version != version || !bytes.Equal(roster.Commitment[:], commitment) {
		return nil, errDeviceRosterChanged
	}
	return roster, nil
}

func secureRosterDevice(device *db.ConversationDirectoryDevice) bool {
	return device != nil && device.Eligible && device.Binding != nil &&
		device.Binding.Status == db.DeviceBindingActive &&
		device.Binding.Capabilities&db.RequiredChannelCapabilities == db.RequiredChannelCapabilities &&
		len(device.DeviceKey) == 16 && len(device.Binding.DeviceIdentityKey) == 32 &&
		len(device.Binding.DeviceSigningKey) == 32 && device.Binding.Version > 0
}

func findRosterDeviceByDatabaseID(roster *db.ConversationDeviceRoster, deviceID string) (*rosterDeviceRef, error) {
	if roster == nil || deviceID == "" {
		return nil, errDeviceNotEligible
	}
	for memberIndex := range roster.Members {
		member := &roster.Members[memberIndex]
		for deviceIndex := range member.Devices {
			device := &member.Devices[deviceIndex]
			if device.DeviceID == deviceID {
				if !secureRosterDevice(device) {
					return nil, errDeviceNotEligible
				}
				return &rosterDeviceRef{member: member, device: device}, nil
			}
		}
	}
	return nil, errDeviceNotEligible
}

func findRosterDeviceByProtocolID(roster *db.ConversationDeviceRoster, accountIdentityKey, deviceKey []byte) (*rosterDeviceRef, error) {
	if roster == nil || len(accountIdentityKey) != 32 || len(deviceKey) != 16 {
		return nil, errDeviceNotEligible
	}
	for memberIndex := range roster.Members {
		member := &roster.Members[memberIndex]
		if !bytes.Equal(member.IdentityKey, accountIdentityKey) {
			continue
		}
		for deviceIndex := range member.Devices {
			device := &member.Devices[deviceIndex]
			if bytes.Equal(device.DeviceKey, deviceKey) {
				if !secureRosterDevice(device) {
					return nil, errDeviceNotEligible
				}
				return &rosterDeviceRef{member: member, device: device}, nil
			}
		}
	}
	return nil, errDeviceNotEligible
}

func eligibleRosterRecipients(roster *db.ConversationDeviceRoster, sourceDeviceID string) []deviceFanoutRecipient {
	if roster == nil {
		return nil
	}
	recipients := make([]deviceFanoutRecipient, 0)
	for memberIndex := range roster.Members {
		member := &roster.Members[memberIndex]
		for deviceIndex := range member.Devices {
			device := &member.Devices[deviceIndex]
			if device.DeviceID == sourceDeviceID || !secureRosterDevice(device) {
				continue
			}
			recipients = append(recipients, deviceFanoutRecipient{
				UserID:    member.UserID,
				DeviceID:  device.DeviceID,
				DeviceKey: append([]byte(nil), device.DeviceKey...),
			})
		}
	}
	return recipients
}
