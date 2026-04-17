package chat

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/AegisSec/veil-server/internal/config"
	"github.com/AegisSec/veil-server/internal/db"
	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
)

var (
	ErrNotMember     = errors.New("not a conversation member")
	ErrMessageTooBig = errors.New("message ciphertext too large")
	ErrNoPreKeys     = errors.New("no signed prekey available for target")
)

// Service handles message routing and prekey distribution.
type Service struct {
	db  *db.DB
	cfg *config.Config
}

func NewService(database *db.DB, cfg *config.Config) *Service {
	return &Service{db: database, cfg: cfg}
}

// DB returns the underlying database handle.
func (s *Service) DB() *db.DB {
	return s.db
}

// HandleSendMessage processes a client's send_message request.
// Returns: message ID, server timestamp, list of recipient user IDs for fan-out.
func (s *Service) HandleSendMessage(ctx context.Context, senderUserID string, msg *pb.SendMessage) (string, time.Time, []string, error) {
	// --- Validate ---
	if len(msg.Ciphertext) == 0 {
		return "", time.Time{}, nil, errors.New("empty ciphertext")
	}
	if len(msg.Ciphertext) > s.cfg.MaxMessageSize {
		return "", time.Time{}, nil, ErrMessageTooBig
	}

	// --- Check membership ---
	isMember, err := s.db.IsConversationMember(ctx, msg.ConversationId, senderUserID)
	if err != nil {
		return "", time.Time{}, nil, fmt.Errorf("check membership: %w", err)
	}
	if !isMember {
		return "", time.Time{}, nil, ErrNotMember
	}

	// --- Compute TTL ---
	var expiresAt *time.Time
	if msg.TtlSeconds != nil && *msg.TtlSeconds > 0 {
		t := time.Now().Add(time.Duration(*msg.TtlSeconds) * time.Second)
		expiresAt = &t
	}

	// --- Store message ---
	dbMsg := &db.Message{
		ConversationID: msg.ConversationId,
		SenderID:       senderUserID,
		Ciphertext:     msg.Ciphertext,
		Header:         msg.Header,
		MsgType:        int16(msg.MsgType),
		ExpiresAt:      expiresAt,
	}
	if msg.ReplyToId != nil {
		dbMsg.ReplyToID = msg.ReplyToId
	}

	if err := s.db.StoreMessage(ctx, dbMsg); err != nil {
		return "", time.Time{}, nil, fmt.Errorf("store message: %w", err)
	}

	// --- Get recipients for fan-out ---
	members, err := s.db.GetConversationMembers(ctx, msg.ConversationId)
	if err != nil {
		return "", time.Time{}, nil, fmt.Errorf("get members: %w", err)
	}

	// Filter out sender
	var recipients []string
	for _, uid := range members {
		if uid != senderUserID {
			recipients = append(recipients, uid)
		}
	}

	return dbMsg.ID, dbMsg.CreatedAt, recipients, nil
}

// HandleEditMessage processes a client's edit_message request.
// Returns: edit timestamp, list of recipient user IDs for fan-out.
func (s *Service) HandleEditMessage(ctx context.Context, senderUserID string, msg *pb.EditMessage) (time.Time, []string, error) {
	if len(msg.NewCiphertext) == 0 {
		return time.Time{}, nil, errors.New("empty ciphertext")
	}
	if len(msg.NewCiphertext) > s.cfg.MaxMessageSize {
		return time.Time{}, nil, ErrMessageTooBig
	}

	convID, editedAt, err := s.db.UpdateMessageCiphertext(ctx, msg.MessageId, senderUserID, msg.NewCiphertext, msg.NewHeader)
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("edit message: %w", err)
	}

	members, err := s.db.GetConversationMembers(ctx, convID)
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("get members: %w", err)
	}

	var recipients []string
	for _, uid := range members {
		if uid != senderUserID {
			recipients = append(recipients, uid)
		}
	}
	return editedAt, recipients, nil
}

// HandleDeleteMessage processes a client's delete_message request.
// Returns: list of recipient user IDs for fan-out.
func (s *Service) HandleDeleteMessage(ctx context.Context, senderUserID string, msg *pb.DeleteMessage) ([]string, error) {
	convID, err := s.db.SoftDeleteMessage(ctx, msg.MessageId, senderUserID)
	if err != nil {
		return nil, fmt.Errorf("delete message: %w", err)
	}

	members, err := s.db.GetConversationMembers(ctx, convID)
	if err != nil {
		return nil, fmt.Errorf("get members: %w", err)
	}

	var recipients []string
	for _, uid := range members {
		if uid != senderUserID {
			recipients = append(recipients, uid)
		}
	}
	return recipients, nil
}

// HandleReaction processes a client's reaction_update request.
// Returns: list of recipient user IDs for fan-out.
func (s *Service) HandleReaction(ctx context.Context, senderUserID string, msg *pb.ReactionUpdate) ([]string, error) {
	if msg.Add {
		if err := s.db.AddReaction(ctx, msg.MessageId, msg.ConversationId, senderUserID, msg.Emoji); err != nil {
			return nil, fmt.Errorf("add reaction: %w", err)
		}
	} else {
		if err := s.db.RemoveReaction(ctx, msg.MessageId, senderUserID, msg.Emoji); err != nil {
			return nil, fmt.Errorf("remove reaction: %w", err)
		}
	}

	members, err := s.db.GetConversationMembers(ctx, msg.ConversationId)
	if err != nil {
		return nil, fmt.Errorf("get members: %w", err)
	}

	var recipients []string
	for _, uid := range members {
		if uid != senderUserID {
			recipients = append(recipients, uid)
		}
	}
	return recipients, nil
}

// HandlePreKeyRequest fetches a prekey bundle for establishing an X3DH session.
func (s *Service) HandlePreKeyRequest(ctx context.Context, targetIdentityKey []byte) (*pb.PreKeyBundle, error) {
	// Find user
	user, err := s.db.FindUserByIdentityKey(ctx, targetIdentityKey)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// For now, get the first device (multi-device fan-out is Phase 6)
	// TODO: iterate over all devices

	// We need the device's signed prekey
	// First, find devices for this user
	// For simplicity in Phase 1, we find device by user
	devices, err := s.findUserDevices(ctx, user.ID)
	if err != nil || len(devices) == 0 {
		return nil, errors.New("no devices registered for target user")
	}

	device := devices[0]

	// Get signed prekey
	spk, err := s.db.GetSignedPreKey(ctx, device.ID)
	if err != nil {
		return nil, ErrNoPreKeys
	}

	bundle := &pb.PreKeyBundle{
		IdentityKey:           user.IdentityKey,
		SignedPrekey:          spk.PublicKey,
		SignedPrekeySignature: spk.Signature,
		SignedPrekeyId:        uint32(spk.ID),
	}

	// Try to claim a one-time prekey
	opk, err := s.db.ClaimOneTimePreKey(ctx, device.ID)
	if err == nil && opk != nil {
		bundle.OneTimePrekey = opk.PublicKey
		opkID := uint32(opk.ID)
		bundle.OneTimePrekeyId = &opkID
	}

	// Check OPK count and warn
	remaining, _ := s.db.CountUnusedOPKs(ctx, device.ID)
	if remaining < s.cfg.PreKeyLowWarning {
		log.Printf("WARNING: device %s has only %d OPKs remaining", device.ID, remaining)
	}

	return bundle, nil
}

// findUserDevices returns all devices belonging to a user.
func (s *Service) findUserDevices(ctx context.Context, userID string) ([]db.Device, error) {
	return s.db.GetDevicesByUser(ctx, userID)
}

// LookupUser returns a user by ID (for enriching message events).
func (s *Service) LookupUser(ctx context.Context, userID string) (*db.User, error) {
	return s.db.FindUserByID(ctx, userID)
}

// GetConversationMembers returns user IDs for fan-out.
func (s *Service) GetConversationMembers(ctx context.Context, convID string) ([]string, error) {
	return s.db.GetConversationMembers(ctx, convID)
}

// CreateGroup creates a group conversation and returns the conversation ID.
func (s *Service) CreateGroup(ctx context.Context, name string, creatorUserID string) (string, error) {
	if name == "" {
		return "", errors.New("group name required")
	}
	if len(name) > 100 {
		return "", errors.New("group name too long")
	}
	return s.db.CreateGroup(ctx, name, creatorUserID)
}

// AddGroupMember adds a user to a group. Only admins/owners can add.
func (s *Service) AddGroupMember(ctx context.Context, convID, requesterID, targetUserID string) error {
	// Check requester is a member with admin or owner role
	role, err := s.db.GetMemberRole(ctx, convID, requesterID)
	if err != nil {
		return ErrNotMember
	}
	if role < 1 { // must be admin(1) or owner(2)
		return errors.New("insufficient permissions")
	}

	// Verify target user exists
	_, err = s.db.FindUserByID(ctx, targetUserID)
	if err != nil {
		return fmt.Errorf("target user not found: %w", err)
	}

	return s.db.AddGroupMember(ctx, convID, targetUserID, 0) // role=0 member
}

// RemoveGroupMember removes a user from a group.
func (s *Service) RemoveGroupMember(ctx context.Context, convID, requesterID, targetUserID string) error {
	// Self-leave is always allowed
	if requesterID == targetUserID {
		return s.db.RemoveGroupMember(ctx, convID, targetUserID)
	}

	// Otherwise, check permissions
	requesterRole, err := s.db.GetMemberRole(ctx, convID, requesterID)
	if err != nil {
		return ErrNotMember
	}

	targetRole, err := s.db.GetMemberRole(ctx, convID, targetUserID)
	if err != nil {
		return errors.New("target not a member")
	}

	// Cannot kick someone with equal or higher role
	if requesterRole <= targetRole {
		return errors.New("insufficient permissions")
	}

	return s.db.RemoveGroupMember(ctx, convID, targetUserID)
}

// GetGroupMembers returns detailed member info for a group.
func (s *Service) GetGroupMembers(ctx context.Context, convID, requesterID string) ([]db.GroupMember, error) {
	isMember, err := s.db.IsConversationMember(ctx, convID, requesterID)
	if err != nil || !isMember {
		return nil, ErrNotMember
	}
	return s.db.GetGroupMembersDetailed(ctx, convID)
}
