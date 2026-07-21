package chat

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/config"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/logsafe"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

var (
	ErrNotMember                    = errors.New("not a conversation member")
	ErrInsufficientPermissions      = errors.New("insufficient permissions")
	ErrMessageTooBig                = errors.New("message ciphertext too large")
	ErrNoPreKeys                    = errors.New("no signed prekey available for target")
	ErrPreKeyAccessDenied           = errors.New("prekey access requires a shared conversation")
	ErrMessageConversationMismatch  = errors.New("message does not belong to conversation")
	ErrAttachmentAccess             = errors.New("attachment is unavailable or not owned by sender")
	ErrSealedMessageUnsupported     = errors.New("sealed messages are unavailable until live and history storage have matching semantics")
	ErrSecureMessageEditUnsupported = errors.New("editing Sender-Key group/channel messages requires an exact device-routed edit protocol")
	ErrInvalidReaction              = errors.New("invalid reaction request")
	ErrReactionLimitReached         = errors.New("message reaction limit reached")
	ErrInvalidClientMessageID       = errors.New("client_message_id must be a canonical lowercase non-nil UUID")
	ErrClientMessageIDConflict      = errors.New("client_message_id already identifies different send bytes")
	ErrSendMessageUnknownFields     = errors.New("send_message contains unsupported protobuf fields")
	ErrInvalidSendMessage           = errors.New("invalid send_message")
)

const sendMessageDigestDomain = "veil.message.send.v1\x00"

// Broadcaster delivers non-authoritative conversation discovery hints to
// online accounts. The exact directory is always resolved again through the
// signed membership-scoped REST endpoint.
type Broadcaster interface {
	BroadcastToUsers(userIDs []string, env *pb.Envelope)
}

// Service handles message routing and prekey distribution.
type Service struct {
	db    *db.DB
	cfg   *config.Config
	bcast Broadcaster
}

func NewService(database *db.DB, cfg *config.Config) *Service {
	return &Service{db: database, cfg: cfg}
}

// SetBroadcaster wires the gateway after both mutually-referencing services
// have been constructed. It is intended for startup use before serving calls.
func (s *Service) SetBroadcaster(bcast Broadcaster) { s.bcast = bcast }

func (s *Service) notifyConversationAvailable(userIDs []string, conversationID string) {
	if s.bcast == nil || len(userIDs) == 0 || conversationID == "" {
		return
	}
	s.bcast.BroadcastToUsers(userIDs, &pb.Envelope{
		Payload: &pb.Envelope_ConversationAvailable{
			ConversationAvailable: &pb.ConversationAvailable{ConversationId: conversationID},
		},
	})
}

// DB returns the underlying database handle.
func (s *Service) DB() *db.DB {
	return s.db
}

// SendMessageResult is the durable result of one account-scoped send intent.
// Replayed results are ACK-only and never eligible for a second live fan-out.
type SendMessageResult struct {
	MessageID        string
	ServerTimestamp  time.Time
	Recipients       []string
	Replayed         bool
	AckRosterVersion *uint64
}

// CanonicalClientMessageID returns the wire correlation key only when it is a
// canonical lowercase non-nil UUID. Invalid values must never be reflected.
func CanonicalClientMessageID(msg *pb.SendMessage) (string, bool) {
	if msg == nil || msg.ClientMessageId == "" {
		return "", false
	}
	parsed, err := uuid.Parse(msg.ClientMessageId)
	if err != nil || parsed == uuid.Nil || parsed.String() != msg.ClientMessageId {
		return "", false
	}
	return msg.ClientMessageId, true
}

func validateAndDigestSendMessage(msg *pb.SendMessage) (string, [sha256.Size]byte, error) {
	clientMessageID, valid := CanonicalClientMessageID(msg)
	if !valid {
		return "", [sha256.Size]byte{}, ErrInvalidClientMessageID
	}
	if len(msg.ProtoReflect().GetUnknown()) != 0 {
		return "", [sha256.Size]byte{}, ErrSendMessageUnknownFields
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(msg)
	if err != nil {
		return "", [sha256.Size]byte{}, fmt.Errorf("marshal send_message digest: %w", err)
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(sendMessageDigestDomain))
	_, _ = hasher.Write(encoded)
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return clientMessageID, digest, nil
}

func sendMessageResultFromDB(outcome *db.MessageSendOutcome) *SendMessageResult {
	if outcome == nil {
		return nil
	}
	return &SendMessageResult{
		MessageID:        outcome.MessageID,
		ServerTimestamp:  outcome.ServerTimestamp,
		Replayed:         outcome.Replayed,
		AckRosterVersion: outcome.AckRosterVersion,
	}
}

func mapSendMessageStoreError(err error) error {
	if errors.Is(err, db.ErrMessageSendIDConflict) {
		return ErrClientMessageIDConflict
	}
	return err
}

func (s *Service) lookupSendMessageReplay(
	ctx context.Context,
	senderUserID string,
	clientMessageID string,
	digest [sha256.Size]byte,
) (*SendMessageResult, error) {
	outcome, err := s.db.LookupMessageSendOutcome(
		ctx, senderUserID, clientMessageID, digest[:],
	)
	if err != nil {
		return nil, mapSendMessageStoreError(err)
	}
	return sendMessageResultFromDB(outcome), nil
}

// LookupSendMessageReplay performs the authenticated early replay check. It
// intentionally needs no current membership or roster state: the ledger is
// the authority for an already accepted exact request.
func (s *Service) LookupSendMessageReplay(ctx context.Context, senderUserID string, msg *pb.SendMessage) (*SendMessageResult, error) {
	clientMessageID, digest, err := validateAndDigestSendMessage(msg)
	if err != nil {
		return nil, err
	}
	return s.lookupSendMessageReplay(ctx, senderUserID, clientMessageID, digest)
}

// HandleSendMessage processes a client's send_message request.
// Returns: message ID, server timestamp, list of recipient user IDs for fan-out.
func (s *Service) HandleSendMessage(ctx context.Context, senderUserID string, msg *pb.SendMessage) (string, time.Time, []string, error) {
	result, err := s.HandleSendMessageResult(ctx, senderUserID, msg)
	if err != nil {
		return "", time.Time{}, nil, err
	}
	return result.MessageID, result.ServerTimestamp, result.Recipients, nil
}

func (s *Service) HandleSendMessageResult(ctx context.Context, senderUserID string, msg *pb.SendMessage) (*SendMessageResult, error) {
	return s.handleSendMessage(ctx, senderUserID, msg, nil)
}

// HandleSecureSendMessage supplies the authenticated device/roster snapshot
// required for every new group/channel row. DM callers continue through
// HandleSendMessage with no Sender-Key context.
func (s *Service) HandleSecureSendMessage(ctx context.Context, senderUserID string, msg *pb.SendMessage, security *db.MessageSecurityContext) (string, time.Time, []string, error) {
	result, err := s.HandleSecureSendMessageResult(ctx, senderUserID, msg, security)
	if err != nil {
		return "", time.Time{}, nil, err
	}
	return result.MessageID, result.ServerTimestamp, result.Recipients, nil
}

func (s *Service) HandleSecureSendMessageResult(ctx context.Context, senderUserID string, msg *pb.SendMessage, security *db.MessageSecurityContext) (*SendMessageResult, error) {
	return s.handleSendMessage(ctx, senderUserID, msg, security)
}

func (s *Service) handleSendMessage(ctx context.Context, senderUserID string, msg *pb.SendMessage, security *db.MessageSecurityContext) (*SendMessageResult, error) {
	clientMessageID, digest, err := validateAndDigestSendMessage(msg)
	if err != nil {
		return nil, err
	}
	// No sealed message has ever been accepted, so this static rejection can
	// remain before the DB lookup and preserves the fail-closed no-storage path.
	if msg.Sealed {
		return nil, ErrSealedMessageUnsupported
	}
	replay, err := s.lookupSendMessageReplay(ctx, senderUserID, clientMessageID, digest)
	if err != nil || replay != nil {
		return replay, err
	}

	// --- Validate a new send ---
	if msg.ConversationId == "" {
		return nil, fmt.Errorf("%w: conversation_id required", ErrInvalidSendMessage)
	}
	if len(msg.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: empty ciphertext", ErrInvalidSendMessage)
	}
	if len(msg.Ciphertext) > s.cfg.MaxMessageSize {
		return nil, ErrMessageTooBig
	}

	// --- Check membership ---
	isMember, err := s.db.CanAccessConversation(
		ctx,
		msg.ConversationId,
		senderUserID,
		db.PermViewChannel|db.PermSendMessages,
	)
	if err != nil {
		return nil, fmt.Errorf("check membership: %w", err)
	}
	if !isMember {
		return nil, ErrNotMember
	}

	// --- Compute TTL ---
	var expiresAt *time.Time
	if msg.TtlSeconds != nil && *msg.TtlSeconds > 0 {
		t := time.Now().Add(time.Duration(*msg.TtlSeconds) * time.Second)
		expiresAt = &t
	}

	// --- Store message ---
	dbMsg := &db.Message{
		ConversationID:  msg.ConversationId,
		SenderID:        senderUserID,
		Ciphertext:      msg.Ciphertext,
		Header:          msg.Header,
		MsgType:         int16(msg.MsgType),
		ExpiresAt:       expiresAt,
		SecurityContext: security,
	}
	if len(msg.Attachments) > 32 {
		return nil, fmt.Errorf("%w: too many attachments", ErrInvalidSendMessage)
	}
	seenAttachments := make(map[string]struct{}, len(msg.Attachments))
	for position, attachment := range msg.Attachments {
		if attachment == nil || !validAttachmentFileID(attachment.MediaId) {
			return nil, fmt.Errorf("%w: invalid attachment media_id", ErrInvalidSendMessage)
		}
		if _, duplicate := seenAttachments[attachment.MediaId]; duplicate {
			return nil, fmt.Errorf("%w: duplicate attachment media_id", ErrInvalidSendMessage)
		}
		seenAttachments[attachment.MediaId] = struct{}{}
		if len(attachment.EncryptedKey) == 0 || len(attachment.EncryptedKey) > 4096 ||
			len(attachment.Nonce) == 0 || len(attachment.Nonce) > 64 ||
			attachment.ContentType != "application/octet-stream" ||
			attachment.Size > uint64(1<<63-1) {
			return nil, fmt.Errorf("%w: invalid encrypted attachment metadata", ErrInvalidSendMessage)
		}
		dbMsg.Attachments = append(dbMsg.Attachments, db.MessageAttachment{
			FileID:       attachment.MediaId,
			Position:     int16(position),
			EncryptedKey: append([]byte(nil), attachment.EncryptedKey...),
			Nonce:        append([]byte(nil), attachment.Nonce...),
			SizeBytes:    int64(attachment.Size),
			ContentType:  attachment.ContentType,
		})
	}
	if msg.ReplyToId != nil {
		if *msg.ReplyToId == "" {
			return nil, fmt.Errorf("%w: reply_to_id cannot be empty", ErrInvalidSendMessage)
		}
		dbMsg.ReplyToID = msg.ReplyToId
	}

	outcome, err := s.db.StoreMessageIdempotent(ctx, dbMsg, clientMessageID, digest[:])
	if err != nil {
		if errors.Is(err, db.ErrReplyTargetMismatch) {
			return nil, ErrMessageConversationMismatch
		}
		if errors.Is(err, db.ErrAttachmentScope) {
			return nil, ErrAttachmentAccess
		}
		if errors.Is(err, db.ErrMessageSendIDConflict) {
			return nil, ErrClientMessageIDConflict
		}
		if errors.Is(err, db.ErrMessageSecurityContext) || errors.Is(err, db.ErrMessageRosterChanged) {
			return nil, err
		}
		return nil, fmt.Errorf("store message: %w", err)
	}
	result := sendMessageResultFromDB(outcome)
	if result.Replayed {
		return result, nil
	}

	// Recipient resolution happens after StoreMessage commits. It is therefore
	// deliberately best-effort: returning an error here would tell the sender
	// that a durable message failed and could cause a duplicate retry. On a
	// lookup failure the caller still ACKs the committed row, while live fan-out
	// is skipped and reconnect/history remains the source of truth.
	result.Recipients = committedChatRecipients(
		ctx, s.db, dbMsg.ID, msg.ConversationId, senderUserID,
	)
	return result, nil
}

type authorizedConversationMemberLookup interface {
	GetAuthorizedConversationMembers(context.Context, string, uint64) ([]string, error)
}

// committedChatRecipients cannot report an error by design. Its caller is
// already past a durable send/edit/delete/reaction commit boundary and must
// never turn a fan-out lookup failure into a mutation failure visible to the
// client.
func committedChatRecipients(
	ctx context.Context,
	store authorizedConversationMemberLookup,
	messageID string,
	conversationID string,
	senderUserID string,
) []string {
	members, err := store.GetAuthorizedConversationMembers(
		ctx, conversationID, db.ChannelReadPermissions,
	)
	if err != nil {
		log.Printf(
			"committed chat mutation recipient lookup failed: message_ref=%s conversation_ref=%s class=%s",
			logsafe.Ref("message", messageID),
			logsafe.Ref("conversation", conversationID),
			logsafe.ErrorClass(err),
		)
		return nil
	}

	recipients := make([]string, 0, len(members))
	for _, uid := range members {
		if uid != senderUserID {
			recipients = append(recipients, uid)
		}
	}
	return recipients
}

func validAttachmentFileID(fileID string) bool {
	if len(fileID) != 32 {
		return false
	}
	for _, character := range fileID {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

// HandleEditMessage processes a client's edit_message request.
// Returns: edit timestamp, list of recipient user IDs for fan-out.

func (s *Service) HandleEditMessage(ctx context.Context, senderUserID string, msg *pb.EditMessage) (string, time.Time, []string, error) {
	if msg == nil || msg.MessageId == "" || msg.ConversationId == "" {
		return "", time.Time{}, nil, errors.New("message_id and conversation_id required")
	}
	if len(msg.NewCiphertext) == 0 {
		return "", time.Time{}, nil, errors.New("empty ciphertext")
	}
	if len(msg.NewCiphertext) > s.cfg.MaxMessageSize {
		return "", time.Time{}, nil, ErrMessageTooBig
	}
	allowed, err := s.db.CanAccessConversation(
		ctx,
		msg.ConversationId,
		senderUserID,
		db.PermViewChannel|db.PermSendMessages,
	)
	if err != nil {
		return "", time.Time{}, nil, fmt.Errorf("check conversation access: %w", err)
	}
	if !allowed {
		return "", time.Time{}, nil, ErrNotMember
	}
	matches, err := s.db.MessageBelongsToConversation(ctx, msg.MessageId, msg.ConversationId)
	if err != nil {
		return "", time.Time{}, nil, fmt.Errorf("check edit message scope: %w", err)
	}
	if !matches {
		return "", time.Time{}, nil, ErrMessageConversationMismatch
	}
	conversationType, err := s.db.GetConversationType(ctx, msg.ConversationId)
	if err != nil {
		return "", time.Time{}, nil, fmt.Errorf("lookup edit conversation type: %w", err)
	}
	if conversationType == 1 || conversationType == 2 {
		return "", time.Time{}, nil, ErrSecureMessageEditUnsupported
	}

	convID, editedAt, err := s.db.UpdateMessageCiphertext(ctx, msg.MessageId, senderUserID, msg.ConversationId, msg.NewCiphertext, msg.NewHeader)
	if err != nil {
		if errors.Is(err, db.ErrMessageMutationScope) {
			return "", time.Time{}, nil, ErrMessageConversationMismatch
		}
		return "", time.Time{}, nil, fmt.Errorf("edit message: %w", err)
	}

	recipients := committedChatRecipients(
		ctx, s.db, msg.MessageId, convID, senderUserID,
	)
	return convID, editedAt, recipients, nil
}

// HandleDeleteMessage processes a client's delete_message request. Returns
// the authoritative conversation/revision and recipient IDs for fan-out.
func (s *Service) HandleDeleteMessage(ctx context.Context, senderUserID string, msg *pb.DeleteMessage) (string, time.Time, []string, error) {
	if msg == nil || msg.MessageId == "" || msg.ConversationId == "" {
		return "", time.Time{}, nil, errors.New("message_id and conversation_id required")
	}
	matches, err := s.db.MessageBelongsToConversation(ctx, msg.MessageId, msg.ConversationId)
	if err != nil {
		return "", time.Time{}, nil, fmt.Errorf("check delete message scope: %w", err)
	}
	if !matches {
		return "", time.Time{}, nil, ErrMessageConversationMismatch
	}
	allowed, err := s.db.CanAccessConversation(ctx, msg.ConversationId, senderUserID, db.PermViewChannel)
	if err != nil {
		return "", time.Time{}, nil, fmt.Errorf("check conversation access: %w", err)
	}
	if !allowed {
		return "", time.Time{}, nil, ErrNotMember
	}
	convID, deletedAt, err := s.db.SoftDeleteMessage(ctx, msg.MessageId, senderUserID, msg.ConversationId)
	if err != nil {
		if errors.Is(err, db.ErrMessageMutationScope) {
			return "", time.Time{}, nil, ErrMessageConversationMismatch
		}
		return "", time.Time{}, nil, fmt.Errorf("delete message: %w", err)
	}

	recipients := committedChatRecipients(
		ctx, s.db, msg.MessageId, convID, senderUserID,
	)
	return convID, deletedAt, recipients, nil
}

// HandleReaction processes a client's reaction_update request.
// Returns the recipient user IDs and whether durable state changed. Exact
// retries are acknowledged but must not produce a duplicate fan-out event.
func (s *Service) HandleReaction(ctx context.Context, senderUserID string, msg *pb.ReactionUpdate) ([]string, bool, error) {
	if msg == nil || msg.MessageId == "" || msg.ConversationId == "" {
		return nil, false, fmt.Errorf("%w: message_id and conversation_id required", ErrInvalidReaction)
	}
	if msg.Emoji == "" || len(msg.Emoji) > 64 {
		return nil, false, fmt.Errorf("%w: emoji must be between 1 and 64 bytes", ErrInvalidReaction)
	}
	if _, err := uuid.Parse(msg.MessageId); err != nil {
		return nil, false, fmt.Errorf("%w: malformed message_id", ErrInvalidReaction)
	}
	if _, err := uuid.Parse(msg.ConversationId); err != nil {
		return nil, false, fmt.Errorf("%w: malformed conversation_id", ErrInvalidReaction)
	}

	var changed bool
	var err error
	if msg.Add {
		changed, err = s.db.AddReaction(ctx, msg.MessageId, msg.ConversationId, senderUserID, msg.Emoji)
	} else {
		changed, err = s.db.RemoveReaction(ctx, msg.MessageId, msg.ConversationId, senderUserID, msg.Emoji)
	}
	if err != nil {
		switch {
		case errors.Is(err, db.ErrConversationAccessDenied):
			return nil, false, ErrNotMember
		case errors.Is(err, db.ErrMessageMutationScope):
			return nil, false, ErrMessageConversationMismatch
		case errors.Is(err, db.ErrReactionLimitReached):
			return nil, false, ErrReactionLimitReached
		default:
			return nil, false, fmt.Errorf("mutate reaction: %w", err)
		}
	}
	if !changed {
		return nil, false, nil
	}

	recipients := committedChatRecipients(
		ctx, s.db, msg.MessageId, msg.ConversationId, senderUserID,
	)
	return recipients, true, nil
}

// HandlePreKeyRequest fetches a prekey bundle for establishing an X3DH session.
func (s *Service) HandlePreKeyRequest(ctx context.Context, requesterUserID string, targetIdentityKey []byte) (*pb.PreKeyBundle, error) {
	// Find user
	user, err := s.db.FindUserByIdentityKey(ctx, targetIdentityKey)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	if requesterUserID == "" {
		return nil, ErrPreKeyAccessDenied
	}
	if requesterUserID != user.ID {
		allowed, relationErr := s.db.UsersShareConversation(ctx, requesterUserID, user.ID)
		if relationErr != nil || !allowed {
			return nil, ErrPreKeyAccessDenied
		}
	}

	// Known limitation: this protobuf bundle represents one device only.
	// Multi-device X3DH needs a versioned per-device bundle/session protocol;
	// iterating here would be ambiguous and could bind an OPK to the wrong
	// device. The REST endpoint documents the same constraint.

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
		SignedPrekeyId:        spk.ProtocolKeyID,
	}

	// Try to claim a one-time prekey
	opk, err := s.db.ClaimOneTimePreKey(ctx, device.ID)
	if err == nil && opk != nil {
		bundle.OneTimePrekey = opk.PublicKey
		opkID := opk.ProtocolKeyID
		bundle.OneTimePrekeyId = &opkID
	}

	// Check OPK count and warn
	remaining, _ := s.db.CountUnusedOPKs(ctx, device.ID)
	if remaining < s.cfg.PreKeyLowWarning {
		log.Printf("WARNING: device_ref=%s has only %d OPKs remaining", logsafe.Ref("device", device.ID), remaining)
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
	return s.db.GetAuthorizedConversationMembers(ctx, convID, db.ChannelReadPermissions)
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

func (s *Service) CreateCircle(ctx context.Context, name, creatorUserID string, members []db.GroupMemberLocator) (string, error) {
	if name == "" {
		return "", errors.New("circle name required")
	}
	if len(name) > 100 {
		return "", errors.New("circle name too long")
	}
	if len(members) < 1 || len(members) > 32 {
		return "", errors.New("circle requires between 1 and 32 selected members")
	}
	seen := map[string]struct{}{creatorUserID: {}}
	for _, member := range members {
		if member.UserID == "" || len(member.IdentityKey) != 32 {
			return "", errors.New("invalid initial Circle member locator")
		}
		if _, exists := seen[member.UserID]; exists {
			return "", errors.New("duplicate initial Circle member")
		}
		seen[member.UserID] = struct{}{}
	}
	conversationID, err := s.db.CreateGroupWithMembers(ctx, name, creatorUserID, members)
	if err != nil {
		return "", err
	}
	recipients := make([]string, 0, len(members)+1)
	recipients = append(recipients, creatorUserID)
	for _, member := range members {
		recipients = append(recipients, member.UserID)
	}
	// The DB transaction is committed before this hint. The creator can now
	// safely distribute Sender-Key state knowing every online invitee receives
	// and hydrates the directory hint first on its ordered WS queue.
	s.notifyConversationAvailable(recipients, conversationID)
	return conversationID, nil
}

// AddGroupMember adds a user to a group. Only admins/owners can add.
func (s *Service) AddGroupMember(ctx context.Context, convID, requesterID, targetUserID string) error {
	conversationType, err := s.db.GetConversationType(ctx, convID)
	if err != nil || conversationType != 1 {
		return errors.New("group conversation not found")
	}
	// Check requester is a member with admin or owner role
	role, err := s.db.GetMemberRole(ctx, convID, requesterID)
	if err != nil {
		return ErrNotMember
	}
	if role < 1 { // must be admin(1) or owner(2)
		return ErrInsufficientPermissions
	}

	// Verify target user exists
	_, err = s.db.FindUserByID(ctx, targetUserID)
	if err != nil {
		return fmt.Errorf("target user not found: %w", err)
	}

	if err := s.db.AddGroupMember(ctx, convID, targetUserID, 0); err != nil {
		return err
	}
	s.notifyConversationAvailable([]string{targetUserID}, convID)
	return nil
}

// RemoveGroupMember removes a user from a group.
func (s *Service) RemoveGroupMember(ctx context.Context, convID, requesterID, targetUserID string) error {
	conversationType, err := s.db.GetConversationType(ctx, convID)
	if err != nil || conversationType != 1 {
		return errors.New("group conversation not found")
	}
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
		return ErrInsufficientPermissions
	}

	return s.db.RemoveGroupMember(ctx, convID, targetUserID)
}

// GetGroupMembers returns detailed member info for a group.
func (s *Service) GetGroupMembers(ctx context.Context, convID, requesterID string) ([]db.GroupMember, error) {
	conversationType, err := s.db.GetConversationType(ctx, convID)
	if err != nil || conversationType != 1 {
		return nil, errors.New("group conversation not found")
	}
	isMember, err := s.db.IsConversationMember(ctx, convID, requesterID)
	if err != nil || !isMember {
		return nil, ErrNotMember
	}
	return s.db.GetGroupMembersDetailed(ctx, convID)
}
