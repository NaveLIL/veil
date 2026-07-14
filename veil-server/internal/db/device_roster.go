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

type rosterQuerier interface {
	bindingQuerier
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// ResolveConversationDeviceRoster builds the exact current device directory
// from the same overwrite-aware user ACL as message fan-out. It does not turn
// on a new send mode; callers must inspect Ready and fail closed.
func (db *DB) ResolveConversationDeviceRoster(ctx context.Context, conversationID string, requiredCapabilities uint64) (*ConversationDeviceRoster, error) {
	return db.resolveConversationDeviceRoster(ctx, conversationID, "", requiredCapabilities)
}

// ResolveConversationDeviceRosterForRequester binds directory authorization
// and roster materialization to the same SERIALIZABLE transaction. A caller
// revoked before the transaction snapshot cannot receive device key material.
func (db *DB) ResolveConversationDeviceRosterForRequester(ctx context.Context, conversationID, requesterID string, requiredCapabilities uint64) (*ConversationDeviceRoster, error) {
	if requesterID == "" {
		return nil, ErrConversationAccessDenied
	}
	return db.resolveConversationDeviceRoster(
		ctx, conversationID, requesterID, requiredCapabilities,
	)
}

func (db *DB) resolveConversationDeviceRoster(ctx context.Context, conversationID, requesterID string, requiredCapabilities uint64) (*ConversationDeviceRoster, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		roster, err := db.resolveConversationDeviceRosterOnce(
			ctx, conversationID, requesterID, requiredCapabilities,
		)
		if err == nil {
			return roster, nil
		}
		lastErr = err
		if !isSenderKeySerializationFailure(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("resolve conversation roster after serialization retries: %w", lastErr)
}

func (db *DB) resolveConversationDeviceRosterOnce(ctx context.Context, conversationID, requesterID string, requiredCapabilities uint64) (*ConversationDeviceRoster, error) {
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`SELECT id FROM conversations WHERE id = $1::uuid FOR UPDATE`, conversationID,
	); err != nil {
		return nil, fmt.Errorf("lock conversation roster: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO conversation_roster_revisions (conversation_id)
		 VALUES ($1::uuid) ON CONFLICT (conversation_id) DO NOTHING`,
		conversationID,
	); err != nil {
		return nil, fmt.Errorf("ensure conversation roster revision: %w", err)
	}
	var mutationRevision int64
	if err := tx.QueryRow(ctx,
		`SELECT mutation_revision
		 FROM conversation_roster_revisions
		 WHERE conversation_id = $1::uuid FOR UPDATE`,
		conversationID,
	).Scan(&mutationRevision); err != nil {
		return nil, fmt.Errorf("lock conversation roster revision: %w", err)
	}
	if requesterID != "" {
		allowed, err := canAccessConversationWithQuery(
			ctx, tx, conversationID, requesterID, ChannelReadPermissions,
		)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, ErrConversationAccessDenied
		}
	}
	roster, err := buildConversationDeviceRoster(ctx, tx, conversationID, requiredCapabilities)
	if err != nil {
		return nil, err
	}
	if err := pruneUnauthorizedSenderKeyTargetsForRoster(ctx, tx, roster); err != nil {
		return nil, err
	}
	roster.Version, err = recordConversationRosterCommitmentTx(
		ctx, tx, conversationID, roster.Commitment, mutationRevision,
	)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return roster, nil
}

// resolveConversationDeviceRosterSnapshot recomputes the authoritative roster
// through the caller's transaction and accepts it only when the persisted head
// already commits to that exact state. Sender-key durable admission uses this
// helper under SERIALIZABLE isolation, closing the validate-then-store window.
func resolveConversationDeviceRosterSnapshot(ctx context.Context, tx pgx.Tx, conversationID string, requiredCapabilities uint64) (*ConversationDeviceRoster, error) {
	var mutationRevision int64
	if err := tx.QueryRow(ctx,
		`SELECT mutation_revision
		 FROM conversation_roster_revisions
		 WHERE conversation_id = $1::uuid FOR UPDATE`,
		conversationID,
	).Scan(&mutationRevision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSenderKeyRosterChanged
		}
		return nil, err
	}
	var version, resolvedRevision int64
	var commitment []byte
	var dirty bool
	err := tx.QueryRow(ctx,
		`SELECT roster_version, roster_commitment, dirty, resolved_mutation_revision
		 FROM conversation_device_rosters
		 WHERE conversation_id = $1::uuid
		 FOR UPDATE`,
		conversationID,
	).Scan(&version, &commitment, &dirty, &resolvedRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSenderKeyRosterChanged
	}
	if err != nil {
		return nil, err
	}
	if version <= 0 || len(commitment) != 32 || dirty || resolvedRevision != mutationRevision {
		return nil, ErrSenderKeyRosterChanged
	}
	roster, err := buildConversationDeviceRoster(ctx, tx, conversationID, requiredCapabilities)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(commitment, roster.Commitment[:]) {
		return nil, ErrSenderKeyRosterChanged
	}
	if err := pruneUnauthorizedSenderKeyTargetsForRoster(ctx, tx, roster); err != nil {
		return nil, err
	}
	roster.Version = uint64(version)
	return roster, nil
}

func pruneUnauthorizedSenderKeyTargetsForRoster(ctx context.Context, tx pgx.Tx, roster *ConversationDeviceRoster) error {
	if roster == nil || roster.ConversationID == "" || len(roster.Members) == 0 {
		return errors.New("invalid roster for sender-key target pruning")
	}
	authorizedUsers := make([]string, 0, len(roster.Members))
	for _, member := range roster.Members {
		if member.UserID == "" {
			return errors.New("invalid authorized roster member")
		}
		authorizedUsers = append(authorizedUsers, member.UserID)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM sender_keys AS sender_key
		 USING devices AS target_device
		 WHERE sender_key.conversation_id = $1::uuid
		   AND target_device.id = sender_key.target_device_id
		   AND NOT (target_device.user_id = ANY($2::uuid[]))`,
		roster.ConversationID, authorizedUsers,
	); err != nil {
		return fmt.Errorf("prune sender-key targets outside current roster: %w", err)
	}
	return nil
}

func buildConversationDeviceRoster(ctx context.Context, query rosterQuerier, conversationID string, requiredCapabilities uint64) (*ConversationDeviceRoster, error) {
	if requiredCapabilities == 0 || requiredCapabilities > math.MaxInt64 {
		return nil, errors.New("invalid required device capability mask")
	}
	memberIDs, err := authorizedConversationMemberIDs(ctx, query, conversationID, ChannelReadPermissions)
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
		var member ConversationDirectoryMember
		if err := query.QueryRow(ctx,
			`SELECT id::text, username, identity_key, signing_key
			 FROM users WHERE id = $1::uuid`,
			userID,
		).Scan(&member.UserID, &member.Username, &member.IdentityKey, &member.SigningKey); err != nil {
			return nil, fmt.Errorf("load roster member: %w", err)
		}
		deviceRows, err := query.Query(ctx,
			`SELECT id::text, user_id::text, device_key, device_name, last_seen, created_at
			 FROM devices WHERE user_id = $1::uuid ORDER BY device_key`,
			userID,
		)
		if err != nil {
			return nil, fmt.Errorf("load roster devices: %w", err)
		}
		devices := make([]Device, 0)
		for deviceRows.Next() {
			var device Device
			if err := deviceRows.Scan(
				&device.ID, &device.UserID, &device.DeviceKey, &device.DeviceName,
				&device.LastSeen, &device.CreatedAt,
			); err != nil {
				deviceRows.Close()
				return nil, fmt.Errorf("scan roster device: %w", err)
			}
			devices = append(devices, device)
		}
		if err := deviceRows.Err(); err != nil {
			deviceRows.Close()
			return nil, fmt.Errorf("load roster devices: %w", err)
		}
		deviceRows.Close()
		for _, device := range devices {
			entry := ConversationDirectoryDevice{
				DeviceID:   device.ID,
				DeviceKey:  append([]byte(nil), device.DeviceKey...),
				DeviceName: device.DeviceName,
			}
			binding, bindingErr := scanLatestDeviceBinding(ctx, query, device.ID, false)
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
	return roster, nil
}

func authorizedConversationMemberIDs(ctx context.Context, query rosterQuerier, conversationID string, required uint64) ([]string, error) {
	var conversationType int16
	var channelID *string
	if err := query.QueryRow(ctx,
		`SELECT conversation.conv_type, channel.id::text
		 FROM conversations conversation
		 LEFT JOIN channels channel ON channel.conversation_id = conversation.id
		 WHERE conversation.id = $1::uuid`,
		conversationID,
	).Scan(&conversationType, &channelID); err != nil {
		return nil, err
	}
	rows, err := query.Query(ctx,
		`SELECT user_id::text
		 FROM conversation_members
		 WHERE conversation_id = $1::uuid
		 ORDER BY user_id`,
		conversationID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := make([]string, 0)
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}
		candidates = append(candidates, userID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if conversationType != 2 {
		return candidates, nil
	}
	if channelID == nil {
		return nil, errors.New("channel conversation has no channel")
	}
	authorized := make([]string, 0, len(candidates))
	for _, userID := range candidates {
		permissions, err := getChannelPermissions(ctx, query, *channelID, userID)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if permissions&PermAdministrator != 0 || permissions&required == required {
			authorized = append(authorized, userID)
		}
	}
	return authorized, nil
}

func canAccessConversationWithQuery(ctx context.Context, query rosterQuerier, conversationID, userID string, required uint64) (bool, error) {
	memberIDs, err := authorizedConversationMemberIDs(ctx, query, conversationID, required)
	if err != nil {
		return false, err
	}
	for _, memberID := range memberIDs {
		if memberID == userID {
			return true, nil
		}
	}
	return false, nil
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

func recordConversationRosterCommitmentTx(ctx context.Context, tx pgx.Tx, conversationID string, commitment [32]byte, mutationRevision int64) (uint64, error) {
	if mutationRevision < 0 {
		return 0, errors.New("invalid conversation roster mutation revision")
	}
	var currentVersion, resolvedRevision int64
	var currentCommitment []byte
	var dirty bool
	err := tx.QueryRow(ctx,
		`SELECT roster_version, roster_commitment, dirty, resolved_mutation_revision
		 FROM conversation_device_rosters
		 WHERE conversation_id = $1::uuid FOR UPDATE`, conversationID,
	).Scan(&currentVersion, &currentCommitment, &dirty, &resolvedRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO conversation_device_rosters
			   (conversation_id, roster_version, roster_commitment,
			    dirty, resolved_mutation_revision)
			 VALUES ($1::uuid, 1, $2, FALSE, $3)`,
			conversationID, commitment[:], mutationRevision,
		); err != nil {
			return 0, fmt.Errorf("create conversation roster head: %w", err)
		}
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("load conversation roster head: %w", err)
	}
	if !dirty && resolvedRevision == mutationRevision && bytes.Equal(currentCommitment, commitment[:]) {
		return uint64(currentVersion), nil
	}
	if currentVersion == math.MaxInt64 {
		return 0, errors.New("conversation roster version exhausted")
	}
	next := currentVersion + 1
	if _, err := tx.Exec(ctx,
		`UPDATE conversation_device_rosters
		 SET roster_version = $2, roster_commitment = $3,
		     dirty = FALSE, resolved_mutation_revision = $4,
		     updated_at = now()
		 WHERE conversation_id = $1::uuid`, conversationID, next, commitment[:],
		mutationRevision,
	); err != nil {
		return 0, fmt.Errorf("advance conversation roster head: %w", err)
	}
	return uint64(next), nil
}
