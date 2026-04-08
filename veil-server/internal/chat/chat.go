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
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, user_id, device_key, device_name, last_seen, created_at
		 FROM devices WHERE user_id = $1::uuid ORDER BY last_seen DESC NULLS LAST`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []db.Device
	for rows.Next() {
		var d db.Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.DeviceKey, &d.DeviceName, &d.LastSeen, &d.CreatedAt); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// LookupUser returns a user by ID (for enriching message events).
func (s *Service) LookupUser(ctx context.Context, userID string) (*db.User, error) {
	return s.db.FindUserByID(ctx, userID)
}

// GetConversationMembers returns user IDs for fan-out.
func (s *Service) GetConversationMembers(ctx context.Context, convID string) ([]string, error) {
	return s.db.GetConversationMembers(ctx, convID)
}
