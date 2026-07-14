package chat

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
)

type directoryBindingJSON struct {
	DeviceID          string                 `json:"device_id"`
	DeviceIdentityKey string                 `json:"device_identity_key"`
	DeviceSigningKey  string                 `json:"device_signing_key"`
	Version           string                 `json:"version"`
	Capabilities      string                 `json:"capabilities"`
	Status            db.DeviceBindingStatus `json:"status"`
	AccountSignature  string                 `json:"account_signature"`
	CreatedAt         string                 `json:"created_at"`
}

type directoryDeviceJSON struct {
	UserID             string                 `json:"user_id"`
	Username           string                 `json:"username"`
	AccountIdentityKey string                 `json:"account_identity_key"`
	AccountSigningKey  string                 `json:"account_signing_key"`
	DeviceID           string                 `json:"device_id"`
	DeviceName         string                 `json:"device_name"`
	Binding            *directoryBindingJSON  `json:"binding,omitempty"`
	Status             db.DeviceBindingStatus `json:"status"`
	Eligible           bool                   `json:"eligible"`
	ExclusionReason    string                 `json:"exclusion_reason,omitempty"`
}

type deviceDirectoryJSON struct {
	ConversationID       string                `json:"conversation_id"`
	RosterVersion        string                `json:"roster_version"`
	RosterCommitment     string                `json:"roster_commitment"`
	Ready                bool                  `json:"ready"`
	Reason               string                `json:"reason,omitempty"`
	RequiredCapabilities string                `json:"required_capabilities"`
	MemberUserIDs        []string              `json:"member_user_ids"`
	Devices              []directoryDeviceJSON `json:"devices"`
}

func (h *Handler) GetDeviceDirectory(w http.ResponseWriter, r *http.Request) {
	requesterID := r.Header.Get("X-User-ID")
	if requesterID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}
	conversationID := r.PathValue("conversationID")
	roster, err := h.svc.db.ResolveConversationDeviceRosterForRequester(
		r.Context(), conversationID, requesterID, db.RequiredChannelCapabilities,
	)
	if err != nil {
		if errors.Is(err, db.ErrConversationAccessDenied) {
			writeJSON(w, http.StatusForbidden, errorResp("not authorized for conversation"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to resolve device directory"))
		return
	}
	response := deviceDirectoryJSON{
		ConversationID:       roster.ConversationID,
		RosterVersion:        strconv.FormatUint(roster.Version, 10),
		RosterCommitment:     hex.EncodeToString(roster.Commitment[:]),
		Ready:                roster.Ready,
		Reason:               roster.Reason,
		RequiredCapabilities: strconv.FormatUint(roster.RequiredCapabilities, 10),
		MemberUserIDs:        make([]string, 0, len(roster.Members)),
		Devices:              []directoryDeviceJSON{},
	}
	for _, member := range roster.Members {
		response.MemberUserIDs = append(response.MemberUserIDs, member.UserID)
		for _, device := range member.Devices {
			entry := directoryDeviceJSON{
				UserID:             member.UserID,
				Username:           member.Username,
				AccountIdentityKey: base64.StdEncoding.EncodeToString(member.IdentityKey),
				AccountSigningKey:  base64.StdEncoding.EncodeToString(member.SigningKey),
				DeviceID:           hex.EncodeToString(device.DeviceKey),
				DeviceName:         device.DeviceName,
				Status:             db.DeviceLegacyUnbound,
				Eligible:           device.Eligible,
				ExclusionReason:    device.Reason,
			}
			if binding := device.Binding; binding != nil {
				entry.Status = binding.Status
				entry.Binding = &directoryBindingJSON{
					DeviceID:          hex.EncodeToString(binding.DeviceKey),
					DeviceIdentityKey: base64.StdEncoding.EncodeToString(binding.DeviceIdentityKey),
					DeviceSigningKey:  base64.StdEncoding.EncodeToString(binding.DeviceSigningKey),
					Version:           strconv.FormatUint(binding.Version, 10),
					Capabilities:      strconv.FormatUint(binding.Capabilities, 10),
					Status:            binding.Status,
					AccountSignature:  base64.StdEncoding.EncodeToString(binding.AccountSignature),
					CreatedAt:         binding.CreatedAt.UTC().Format(time.RFC3339Nano),
				}
			}
			response.Devices = append(response.Devices, entry)
		}
	}
	writeJSON(w, http.StatusOK, response)
}
