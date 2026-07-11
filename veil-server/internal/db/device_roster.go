package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const conversationDeviceRosterDomainV1 = "veil-conversation-device-roster-v1\x00"

type ConversationDirectoryDevice struct {
	DeviceID   string
	DeviceKey  []byte
	DeviceName string
	Binding    *DeviceBinding
	Eligible   bool
	Reason     string
}

type ConversationDirectoryMember struct {
	UserID      string
	Username    string
	IdentityKey []byte
	SigningKey  []byte
	Devices     []ConversationDirectoryDevice
}

type ConversationDeviceRoster struct {
	ConversationID       string
	Version              uint64
	Commitment           [32]byte
	Ready                bool
	Reason               string
	RequiredCapabilities uint64
	Members              []ConversationDirectoryMember
}

// ResolveConversationDeviceRoster builds the exact current device directory
// from the same overwrite-aware user ACL as message fan-out. It does not turn
// on a new send mode; callers must inspect Ready and fail closed.
func (db *DB) ResolveConversationDeviceRoster(ctx context.Context, conversationID string, requiredCapabilities uint64) (*ConversationDeviceRoster, error) {
	if requiredCapabilities == 0 || requiredCapabilities > math.MaxInt64 {
		return nil, errors.New("invalid required device capability mask")
	}
	memberIDs, err := db.GetAuthorizedConversationMembers(
		ctx, conversationID, ChannelReadPermissions,
	)
	if err != nil {
		return nil, err
	}
	if len(memberIDs) == 0 {
		return nil, errors.New("conversation has no authorized members")
	}

	roster := &ConversationDeviceRoster{
		ConversationID:       conversationID,
		Ready:                true,
		RequiredCapabilities: requiredCapabilities,
		Members:              make([]ConversationDirectoryMember, 0, len(memberIDs)),
	}
	for _, userID := range memberIDs {
		user, err := db.FindUserByID(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("load roster member: %w", err)
		}
		member := ConversationDirectoryMember{
			UserID:      user.ID,
			Username:    user.Username,
			IdentityKey: append([]byte(nil), user.IdentityKey...),
			SigningKey:  append([]byte(nil), user.SigningKey...),
		}
		devices, err := db.GetDevicesByUser(ctx, user.ID)
		if err != nil {
			return nil, fmt.Errorf("load roster devices: %w", err)
		}
		for _, device := range devices {
			entry := ConversationDirectoryDevice{
				DeviceID:   device.ID,
				DeviceKey:  append([]byte(nil), device.DeviceKey...),
				DeviceName: device.DeviceName,
			}
			binding, bindingErr := db.GetLatestDeviceBinding(ctx, device.ID)
			switch {
			case errors.Is(bindingErr, ErrDeviceBindingUnavailable):
				entry.Reason = "legacy_unbound"
			case bindingErr != nil:
				return nil, bindingErr
			default:
				entry.Binding = binding
				switch binding.Status {
				case DeviceBindingActive:
					if binding.Capabilities&requiredCapabilities == requiredCapabilities {
						entry.Eligible = true
					} else {
						entry.Reason = "missing_required_capabilities"
					}
				case DeviceBindingExcluded:
					entry.Reason = "explicitly_excluded"
				case DeviceBindingRevoked:
					entry.Reason = "revoked"
				default:
					return nil, errors.New("invalid stored device binding status")
				}
			}
			member.Devices = append(member.Devices, entry)
		}
		roster.Members = append(roster.Members, member)
	}

	// Return the same canonical order that is committed below. Readiness is
	// derived only after sorting so both the response and its reason remain
	// deterministic even when PostgreSQL returns equal sets in a new order.
	sort.Slice(roster.Members, func(i, j int) bool {
		return roster.Members[i].UserID < roster.Members[j].UserID
	})
	hasLegacy, hasMissingCapabilities, memberWithoutEligibleDevice := false, false, false
	for memberIndex := range roster.Members {
		member := &roster.Members[memberIndex]
		sort.Slice(member.Devices, func(i, j int) bool {
			return bytes.Compare(member.Devices[i].DeviceKey, member.Devices[j].DeviceKey) < 0
		})
		eligibleCount := 0
		for _, device := range member.Devices {
			if device.Eligible {
				eligibleCount++
			}
			switch device.Reason {
			case "legacy_unbound":
				hasLegacy = true
			case "missing_required_capabilities":
				hasMissingCapabilities = true
			}
		}
		if eligibleCount == 0 {
			memberWithoutEligibleDevice = true
		}
	}
	switch {
	case hasLegacy:
		roster.Ready = false
		roster.Reason = "legacy_unbound_device"
	case hasMissingCapabilities:
		roster.Ready = false
		roster.Reason = "active_device_missing_required_capabilities"
	case memberWithoutEligibleDevice:
		roster.Ready = false
		roster.Reason = "member_has_no_eligible_active_device"
	}

	commitment, err := ConversationDeviceRosterCommitment(
		conversationID, requiredCapabilities, roster.Members,
	)
	if err != nil {
		return nil, err
	}
	roster.Commitment = commitment
	roster.Version, err = db.recordConversationRosterCommitment(ctx, conversationID, commitment)
	if err != nil {
		return nil, err
	}
	return roster, nil
}

// ConversationDeviceRosterCommitment hashes a deterministic fixed-width
// canonical form. Variable collections use u32 big-endian length prefixes;
// members sort by UUID bytes and devices sort by their signed 16-byte IDs.
func ConversationDeviceRosterCommitment(conversationID string, requiredCapabilities uint64, members []ConversationDirectoryMember) ([32]byte, error) {
	var empty [32]byte
	conversationUUID, err := uuid.Parse(conversationID)
	if err != nil || requiredCapabilities == 0 || requiredCapabilities > math.MaxInt64 {
		return empty, errors.New("invalid roster commitment scope")
	}
	if len(members) == 0 || len(members) > math.MaxUint32 {
		return empty, errors.New("invalid roster member count")
	}
	canonicalMembers := append([]ConversationDirectoryMember(nil), members...)
	sort.Slice(canonicalMembers, func(i, j int) bool {
		left, leftErr := uuid.Parse(canonicalMembers[i].UserID)
		right, rightErr := uuid.Parse(canonicalMembers[j].UserID)
		if leftErr != nil || rightErr != nil {
			return canonicalMembers[i].UserID < canonicalMembers[j].UserID
		}
		return bytes.Compare(left[:], right[:]) < 0
	})

	message := make([]byte, 0, len(conversationDeviceRosterDomainV1)+16+8+4+len(members)*24)
	message = append(message, conversationDeviceRosterDomainV1...)
	message = append(message, conversationUUID[:]...)
	var integer8 [8]byte
	binary.BigEndian.PutUint64(integer8[:], requiredCapabilities)
	message = append(message, integer8[:]...)
	var integer4 [4]byte
	binary.BigEndian.PutUint32(integer4[:], uint32(len(canonicalMembers)))
	message = append(message, integer4[:]...)
	var previousUser [16]byte
	for memberIndex, member := range canonicalMembers {
		userUUID, err := uuid.Parse(member.UserID)
		if err != nil || (memberIndex > 0 && bytes.Equal(previousUser[:], userUUID[:])) {
			return empty, errors.New("invalid or duplicate roster member id")
		}
		previousUser = userUUID
		message = append(message, userUUID[:]...)
		if len(member.Devices) > math.MaxUint32 {
			return empty, errors.New("invalid roster device count")
		}
		devices := append([]ConversationDirectoryDevice(nil), member.Devices...)
		sort.Slice(devices, func(i, j int) bool {
			return bytes.Compare(devices[i].DeviceKey, devices[j].DeviceKey) < 0
		})
		binary.BigEndian.PutUint32(integer4[:], uint32(len(devices)))
		message = append(message, integer4[:]...)
		var previousDevice []byte
		for _, device := range devices {
			if len(device.DeviceKey) != 16 || (previousDevice != nil && bytes.Equal(previousDevice, device.DeviceKey)) {
				return empty, errors.New("invalid or duplicate roster device id")
			}
			previousDevice = device.DeviceKey
			message = append(message, device.DeviceKey...)
			status := DeviceLegacyUnbound
			var version, capabilities uint64
			var identityKey, signingKey [32]byte
			var signature [64]byte
			if device.Binding != nil {
				binding := device.Binding
				if !bytes.Equal(binding.DeviceKey, device.DeviceKey) ||
					len(binding.DeviceIdentityKey) != 32 || len(binding.DeviceSigningKey) != 32 ||
					len(binding.AccountSignature) != 64 || binding.Version == 0 || binding.Version > math.MaxInt64 ||
					binding.Capabilities > math.MaxInt64 ||
					(binding.Status != DeviceBindingActive && binding.Status != DeviceBindingExcluded && binding.Status != DeviceBindingRevoked) {
					return empty, errors.New("invalid roster device binding")
				}
				status = binding.Status
				version = binding.Version
				capabilities = binding.Capabilities
				copy(identityKey[:], binding.DeviceIdentityKey)
				copy(signingKey[:], binding.DeviceSigningKey)
				copy(signature[:], binding.AccountSignature)
			}
			message = append(message, byte(status))
			binary.BigEndian.PutUint64(integer8[:], version)
			message = append(message, integer8[:]...)
			binary.BigEndian.PutUint64(integer8[:], capabilities)
			message = append(message, integer8[:]...)
			message = append(message, identityKey[:]...)
			message = append(message, signingKey[:]...)
			message = append(message, signature[:]...)
		}
	}
	return sha256.Sum256(message), nil
}

func (db *DB) recordConversationRosterCommitment(ctx context.Context, conversationID string, commitment [32]byte) (uint64, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`SELECT id FROM conversations WHERE id = $1::uuid FOR UPDATE`, conversationID,
	); err != nil {
		return 0, fmt.Errorf("lock conversation roster: %w", err)
	}
	var currentVersion int64
	var currentCommitment []byte
	err = tx.QueryRow(ctx,
		`SELECT roster_version, roster_commitment
		 FROM conversation_device_rosters
		 WHERE conversation_id = $1::uuid FOR UPDATE`, conversationID,
	).Scan(&currentVersion, &currentCommitment)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO conversation_device_rosters
			   (conversation_id, roster_version, roster_commitment)
			 VALUES ($1::uuid, 1, $2)`, conversationID, commitment[:],
		); err != nil {
			return 0, fmt.Errorf("create conversation roster head: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return 0, err
		}
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("load conversation roster head: %w", err)
	}
	if bytes.Equal(currentCommitment, commitment[:]) {
		if err := tx.Commit(ctx); err != nil {
			return 0, err
		}
		return uint64(currentVersion), nil
	}
	if currentVersion == math.MaxInt64 {
		return 0, errors.New("conversation roster version exhausted")
	}
	next := currentVersion + 1
	if _, err := tx.Exec(ctx,
		`UPDATE conversation_device_rosters
		 SET roster_version = $2, roster_commitment = $3, updated_at = now()
		 WHERE conversation_id = $1::uuid`, conversationID, next, commitment[:],
	); err != nil {
		return 0, fmt.Errorf("advance conversation roster head: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return uint64(next), nil
}
