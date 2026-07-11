package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrStaleSenderKeyGeneration    = errors.New("stale sender key generation")
	ErrSenderKeyGenerationConflict = errors.New("sender key generation already has a different commitment")
	ErrSenderKeyConversationType   = errors.New("sender keys require a group or channel conversation")
	ErrSenderKeyReceiptMismatch    = errors.New("sender key receipt does not match an exact pending device distribution")
	ErrReplyTargetMismatch         = errors.New("reply target does not belong to conversation")
	ErrMessageMutationScope        = errors.New("message mutation scope mismatch")
	ErrAttachmentScope             = errors.New("attachment is unavailable or not owned by sender")
)

const maxUnusedOneTimePreKeysPerDevice = 100

// --- Users ---

type User struct {
	ID          string
	IdentityKey []byte
	SigningKey  []byte
	Username    string
	CreatedAt   time.Time
}

// FindUserByIdentityKey looks up a user by their X25519 public key.
func (db *DB) FindUserByIdentityKey(ctx context.Context, identityKey []byte) (*User, error) {
	var u User
	err := db.Pool.QueryRow(ctx,
		`SELECT id, identity_key, signing_key, username, created_at
		 FROM users WHERE identity_key = $1`, identityKey,
	).Scan(&u.ID, &u.IdentityKey, &u.SigningKey, &u.Username, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// CreateUser registers a new user with their public keys.
func (db *DB) CreateUser(ctx context.Context, identityKey, signingKey []byte, username string) (*User, error) {
	var u User
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO users (identity_key, signing_key, username)
		 VALUES ($1, $2, $3)
		 RETURNING id, identity_key, signing_key, username, created_at`,
		identityKey, signingKey, username,
	).Scan(&u.ID, &u.IdentityKey, &u.SigningKey, &u.Username, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return &u, nil
}

// --- Devices ---

type Device struct {
	ID         string
	UserID     string
	DeviceKey  []byte
	DeviceName string
	LastSeen   *time.Time
	CreatedAt  time.Time
}

// FindDevice looks up a device by its unique device key.
func (db *DB) FindDevice(ctx context.Context, deviceKey []byte) (*Device, error) {
	var d Device
	err := db.Pool.QueryRow(ctx,
		`SELECT id, user_id, device_key, device_name, last_seen, created_at
		 FROM devices WHERE device_key = $1`, deviceKey,
	).Scan(&d.ID, &d.UserID, &d.DeviceKey, &d.DeviceName, &d.LastSeen, &d.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// CreateDevice registers a new device for a user.
func (db *DB) CreateDevice(ctx context.Context, userID string, deviceKey []byte, deviceName string) (*Device, error) {
	var d Device
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO devices (user_id, device_key, device_name, last_seen)
		 VALUES ($1, $2, $3, now())
		 RETURNING id, user_id, device_key, device_name, last_seen, created_at`,
		userID, deviceKey, deviceName,
	).Scan(&d.ID, &d.UserID, &d.DeviceKey, &d.DeviceName, &d.LastSeen, &d.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create device: %w", err)
	}
	return &d, nil
}

// TouchDevice updates last_seen timestamp.
func (db *DB) TouchDevice(ctx context.Context, deviceID string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE devices SET last_seen = now() WHERE id = $1`, deviceID)
	return err
}

// --- PreKeys ---

type PreKey struct {
	ID            int64
	DeviceID      string
	KeyType       int16 // 0=signed, 1=one-time
	ProtocolKeyID uint32
	PublicKey     []byte
	Signature     []byte
	Used          bool
}

// StorePreKeys bulk-inserts prekeys for a device.
func (db *DB) StorePreKeys(ctx context.Context, deviceID string, keys []PreKey) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, k := range keys {
		// A protocol key id is chosen by the device and refers to local secret
		// material.  The database BIGSERIAL id is only an internal row id and
		// must never be sent in an X3DH header.  Re-uploading an SPK updates it;
		// an already-known OPK is deliberately not resurrected after use.
		var statement string
		if k.KeyType == 0 {
			statement = `INSERT INTO prekeys (device_id, key_type, protocol_key_id, public_key, signature)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (device_id, key_type, protocol_key_id)
			 DO UPDATE SET public_key = EXCLUDED.public_key,
			               signature = EXCLUDED.signature,
			               used = false`
		} else {
			statement = `INSERT INTO prekeys (device_id, key_type, protocol_key_id, public_key, signature)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (device_id, key_type, protocol_key_id) DO NOTHING`
		}
		_, err := tx.Exec(ctx, statement,
			deviceID, k.KeyType, k.ProtocolKeyID, k.PublicKey, k.Signature)
		if err != nil {
			return fmt.Errorf("insert prekey: %w", err)
		}
	}

	// Clients replenish opportunistically on reconnect. Bound only UNUSED
	// OPKs so repeated uploads cannot grow the table indefinitely; claimed
	// rows are preserved because they may still be referenced by an in-flight
	// X3DH initial message and are useful for audit/retention policy.
	if _, err := tx.Exec(ctx,
		`DELETE FROM prekeys
		 WHERE device_id = $1::uuid AND key_type = 1 AND used = false
		   AND id NOT IN (
		     SELECT id FROM prekeys
		     WHERE device_id = $1::uuid AND key_type = 1 AND used = false
		     ORDER BY id DESC
		     LIMIT $2
		   )`,
		deviceID, maxUnusedOneTimePreKeysPerDevice,
	); err != nil {
		return fmt.Errorf("prune old unused prekeys: %w", err)
	}

	return tx.Commit(ctx)
}

// ClaimOneTimePreKey atomically claims an unused one-time prekey for a device.
// Returns nil if no OPK available (falls back to signed-only X3DH).
func (db *DB) ClaimOneTimePreKey(ctx context.Context, deviceID string) (*PreKey, error) {
	var pk PreKey
	err := db.Pool.QueryRow(ctx,
		`UPDATE prekeys SET used = true
		 WHERE id = (
		   SELECT id FROM prekeys
		   WHERE device_id = $1 AND key_type = 1 AND used = false
		   ORDER BY id ASC LIMIT 1
		   FOR UPDATE SKIP LOCKED
		 )
		 RETURNING id, device_id, key_type, protocol_key_id, public_key, signature, used`,
		deviceID,
	).Scan(&pk.ID, &pk.DeviceID, &pk.KeyType, &pk.ProtocolKeyID, &pk.PublicKey, &pk.Signature, &pk.Used)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // No OPK available, not an error
		}
		return nil, fmt.Errorf("claim opk: %w", err)
	}
	return &pk, nil
}

// GetSignedPreKey returns the current signed prekey for a device.
func (db *DB) GetSignedPreKey(ctx context.Context, deviceID string) (*PreKey, error) {
	var pk PreKey
	err := db.Pool.QueryRow(ctx,
		`SELECT id, device_id, key_type, protocol_key_id, public_key, signature, used
		 FROM prekeys
		 WHERE device_id = $1 AND key_type = 0
		 ORDER BY id DESC LIMIT 1`,
		deviceID,
	).Scan(&pk.ID, &pk.DeviceID, &pk.KeyType, &pk.ProtocolKeyID, &pk.PublicKey, &pk.Signature, &pk.Used)
	if err != nil {
		return nil, err
	}
	return &pk, nil
}

// CountUnusedOPKs returns how many one-time prekeys remain for a device.
func (db *DB) CountUnusedOPKs(ctx context.Context, deviceID string) (int, error) {
	var count int
	err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM prekeys
		 WHERE device_id = $1 AND key_type = 1 AND used = false`,
		deviceID,
	).Scan(&count)
	return count, err
}

// --- Messages ---

type Message struct {
	ID             string
	ConversationID string
	SenderID       string
	// SenderIdentityKey and SenderSigningKey are the server-pinned public
	// identity binding for SenderID at read time.  They let a client safely
	// rebuild its local directory before attempting to decrypt an offline
	// message.
	SenderIdentityKey []byte
	SenderSigningKey  []byte
	Ciphertext        []byte
	Header            []byte
	MsgType           int16
	ReplyToID         *string
	ExpiresAt         *time.Time
	EditedAt          *time.Time
	IsDeleted         bool
	CreatedAt         time.Time
	Attachments       []MessageAttachment
}

type MessageAttachment struct {
	MessageID    string
	FileID       string
	Position     int16
	EncryptedKey []byte
	Nonce        []byte
	SizeBytes    int64
	ContentType  string
}

// StoreMessage persists an encrypted message.
func (db *DB) StoreMessage(ctx context.Context, m *Message) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	err = tx.QueryRow(ctx,
		`INSERT INTO messages (conversation_id, sender_id, ciphertext, header, msg_type, reply_to_id, expires_at)
		 SELECT $1::uuid, $2::uuid, $3, $4, $5, $6::uuid, $7
		 WHERE $6::uuid IS NULL OR EXISTS (
		   SELECT 1 FROM messages reply
		   WHERE reply.id = $6::uuid
		     AND reply.conversation_id = $1::uuid
		     AND reply.is_deleted = false
		 )
		 RETURNING id, created_at`,
		m.ConversationID, m.SenderID, m.Ciphertext, m.Header, m.MsgType, m.ReplyToID, m.ExpiresAt,
	).Scan(&m.ID, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) && m.ReplyToID != nil {
		return ErrReplyTargetMismatch
	}
	if err != nil {
		return err
	}
	for _, attachment := range m.Attachments {
		var inserted string
		err = tx.QueryRow(ctx,
			`INSERT INTO message_attachments
			   (message_id, file_id, position, encrypted_key, nonce, size_bytes, content_type)
			 SELECT $1::uuid, upload.file_id, $3, $4, $5, $6, $7
			 FROM tus_uploads upload
			 WHERE upload.file_id = $2
			   AND upload.user_id = $8::uuid
			   AND upload.finished_at IS NOT NULL
			   AND upload.received_bytes = upload.size_bytes
			   AND upload.size_bytes = $6
			   AND upload.expires_at > now()
			 RETURNING file_id`,
			m.ID, attachment.FileID, attachment.Position, attachment.EncryptedKey,
			attachment.Nonce, attachment.SizeBytes, attachment.ContentType, m.SenderID,
		).Scan(&inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAttachmentScope
		}
		if err != nil {
			return fmt.Errorf("store message attachment: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// GetPendingMessages returns the authoritative current rows from one
// conversation for a member since a creation-time keyset boundary. It
// intentionally includes caller-owned, edited, deleted and expired rows so a
// full replay can reconcile local state after being offline. The REST handler
// redacts ciphertext for deleted/expired tombstones. Both IDs are part of the
// query so rows from another conversation can never cross the BOLA boundary.
func (db *DB) GetPendingMessages(ctx context.Context, conversationID, userID string, after time.Time, afterID string, limit int) ([]Message, error) {
	predicate := `m.created_at > $3`
	args := []any{userID, conversationID, after, limit}
	limitPlaceholder := "$4"
	if afterID != "" {
		// Keyset pagination must include the UUID tie-breaker.  Timestamp-only
		// pagination can skip messages created in the same database clock tick.
		predicate = `(m.created_at, m.id) > ($3, $4::uuid)`
		args = []any{userID, conversationID, after, afterID, limit}
		limitPlaceholder = "$5"
	}

	rows, err := db.Pool.Query(ctx,
		`SELECT m.id, m.conversation_id, m.sender_id,
		        u.identity_key, u.signing_key,
		        m.ciphertext, m.header, m.msg_type, m.reply_to_id, m.expires_at,
		        m.edited_at, m.is_deleted, m.created_at
		 FROM messages m
		 JOIN conversation_members cm ON cm.conversation_id = m.conversation_id
		 JOIN users u ON u.id = m.sender_id
		 WHERE cm.user_id = $1::uuid AND m.conversation_id = $2::uuid AND `+predicate+`
		 ORDER BY m.created_at ASC, m.id ASC
		 LIMIT `+limitPlaceholder,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.SenderID,
			&m.SenderIdentityKey, &m.SenderSigningKey, &m.Ciphertext, &m.Header,
			&m.MsgType, &m.ReplyToID, &m.ExpiresAt, &m.EditedAt, &m.IsDeleted, &m.CreatedAt); err != nil {
			return nil, err
		}
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// GetAttachmentsForMessages returns encrypted attachment descriptors in their
// sender-declared order. The referenced tus row must still exist; retention
// deletion cascades the stale descriptor.
func (db *DB) GetAttachmentsForMessages(ctx context.Context, messageIDs []string) ([]MessageAttachment, error) {
	if len(messageIDs) == 0 {
		return []MessageAttachment{}, nil
	}
	rows, err := db.Pool.Query(ctx,
		`SELECT attachment.message_id, attachment.file_id, attachment.position,
		        attachment.encrypted_key, attachment.nonce, attachment.size_bytes,
		        attachment.content_type
		 FROM message_attachments attachment
		 JOIN tus_uploads upload ON upload.file_id = attachment.file_id
		 WHERE attachment.message_id = ANY($1::uuid[])
		 ORDER BY attachment.message_id, attachment.position`,
		messageIDs,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	attachments := make([]MessageAttachment, 0)
	for rows.Next() {
		var attachment MessageAttachment
		if err := rows.Scan(
			&attachment.MessageID, &attachment.FileID, &attachment.Position,
			&attachment.EncryptedKey, &attachment.Nonce, &attachment.SizeBytes,
			&attachment.ContentType,
		); err != nil {
			return nil, err
		}
		attachments = append(attachments, attachment)
	}
	return attachments, rows.Err()
}

// UpdateMessageCiphertext updates the ciphertext of a message (edit).
// Only the original sender can edit. Returns conversation_id for fan-out.
func (db *DB) UpdateMessageCiphertext(ctx context.Context, messageID, senderID, conversationID string, newCiphertext, newHeader []byte) (string, time.Time, error) {
	var convID string
	var editedAt time.Time
	err := db.Pool.QueryRow(ctx,
		`UPDATE messages SET ciphertext = $1, header = $2, edited_at = now()
		 WHERE id = $3::uuid AND sender_id = $4::uuid AND conversation_id = $5::uuid AND is_deleted = false
		 RETURNING conversation_id, edited_at`,
		newCiphertext, newHeader, messageID, senderID, conversationID,
	).Scan(&convID, &editedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", time.Time{}, ErrMessageMutationScope
		}
		return "", time.Time{}, fmt.Errorf("update message: %w", err)
	}
	return convID, editedAt, nil
}

// SoftDeleteMessage marks a message as deleted (wipes ciphertext). Only the
// original sender can delete. It returns the authoritative database revision
// timestamp used by both WS fan-out and REST reconciliation.
func (db *DB) SoftDeleteMessage(ctx context.Context, messageID, senderID, conversationID string) (string, time.Time, error) {
	var convID string
	var deletedAt time.Time
	err := db.Pool.QueryRow(ctx,
		`UPDATE messages SET is_deleted = true, ciphertext = '\x00', header = NULL, edited_at = now()
		 WHERE id = $1::uuid AND sender_id = $2::uuid AND conversation_id = $3::uuid AND is_deleted = false
		 RETURNING conversation_id, edited_at`,
		messageID, senderID, conversationID,
	).Scan(&convID, &deletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", time.Time{}, ErrMessageMutationScope
		}
		return "", time.Time{}, fmt.Errorf("delete message: %w", err)
	}
	return convID, deletedAt, nil
}

// --- Conversations ---

// ConversationMemberBinding is server-pinned public directory information
// for one conversation member.  No private or device-local key material is
// returned by the discovery API.
type ConversationMemberBinding struct {
	UserID      string
	Username    string
	IdentityKey []byte
	SigningKey  []byte
	Role        int16
	JoinedAt    time.Time
}

// ConversationDiscovery is one member-visible conversation and the complete
// public identity directory needed to authenticate its encrypted traffic.
type ConversationDiscovery struct {
	ID        string
	ConvType  int16
	Name      *string
	ServerID  *string
	CreatedAt time.Time
	Members   []ConversationMemberBinding
}

// ListUserConversations returns a keyset page of conversations belonging to
// userID. Channel candidates and their member directories are passed through
// the same overwrite-aware ACL used by sync, live fan-out and sender keys.
func (db *DB) ListUserConversations(ctx context.Context, userID string, after time.Time, afterID string, limit int) ([]ConversationDiscovery, error) {
	if limit <= 0 {
		return []ConversationDiscovery{}, nil
	}
	batchSize := limit * 2
	if batchSize < 32 {
		batchSize = 32
	}

	conversations := make([]ConversationDiscovery, 0, limit)
	scanAfter, scanAfterID := after, afterID
	for len(conversations) < limit {
		predicate := ""
		args := []any{userID, batchSize}
		limitPlaceholder := "$2"
		if scanAfterID != "" {
			predicate = `AND (conversation.created_at, conversation.id) > ($2, $3::uuid)`
			args = []any{userID, scanAfter, scanAfterID, batchSize}
			limitPlaceholder = "$4"
		}

		rows, err := db.Pool.Query(ctx,
			`SELECT conversation.id, conversation.conv_type, conversation.name,
			        conversation.server_id, conversation.created_at
			 FROM conversation_members mine
			 JOIN conversations conversation ON conversation.id = mine.conversation_id
			 WHERE mine.user_id = $1::uuid `+predicate+`
			 ORDER BY conversation.created_at ASC, conversation.id ASC
			 LIMIT `+limitPlaceholder,
			args...,
		)
		if err != nil {
			return nil, err
		}

		candidates := make([]ConversationDiscovery, 0, batchSize)
		for rows.Next() {
			var candidate ConversationDiscovery
			if err := rows.Scan(
				&candidate.ID, &candidate.ConvType, &candidate.Name,
				&candidate.ServerID, &candidate.CreatedAt,
			); err != nil {
				rows.Close()
				return nil, err
			}
			candidates = append(candidates, candidate)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
		if len(candidates) == 0 {
			break
		}

		for _, candidate := range candidates {
			scanAfter, scanAfterID = candidate.CreatedAt, candidate.ID
			allowed, err := db.CanAccessConversation(ctx, candidate.ID, userID, ChannelReadPermissions)
			if err != nil {
				return nil, err
			}
			if !allowed {
				continue
			}
			candidate.Members, err = db.GetAuthorizedConversationMemberBindings(
				ctx, candidate.ID, ChannelReadPermissions,
			)
			if err != nil {
				return nil, err
			}
			conversations = append(conversations, candidate)
			if len(conversations) == limit {
				break
			}
		}
		if len(candidates) < batchSize {
			break
		}
	}
	return conversations, nil
}

// FindOrCreateDM finds an existing DM conversation between two users, or
// creates one. A transaction-scoped advisory lock serializes the canonical
// user pair, including calls with reversed argument order, so concurrent X3DH
// establishment can never fork into duplicate DM conversation IDs.
func (db *DB) FindOrCreateDM(ctx context.Context, userID1, userID2 string) (string, bool, error) {
	if userID1 == "" || userID2 == "" || userID1 == userID2 {
		return "", false, errors.New("two distinct user IDs are required")
	}
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback(ctx)

	// hashtextextended yields the signed bigint key expected by PostgreSQL's
	// advisory lock. UUID -> text canonicalization plus LEAST/GREATEST makes
	// (A,B) and (B,A) exactly the same lock domain. Hash collisions only
	// serialize unrelated creations; they cannot weaken correctness.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended(
		   LEAST($1::uuid::text, $2::uuid::text) || ':' ||
		   GREATEST($1::uuid::text, $2::uuid::text), 0
		 ))`,
		userID1, userID2,
	); err != nil {
		return "", false, fmt.Errorf("lock DM participant pair: %w", err)
	}

	// Re-check only after acquiring the pair lock. At READ COMMITTED, a
	// waiter sees the conversation committed by the previous lock owner.
	var convID string
	err = tx.QueryRow(ctx,
		`SELECT cm1.conversation_id
		 FROM conversation_members cm1
		 JOIN conversation_members cm2 ON cm1.conversation_id = cm2.conversation_id
		 JOIN conversations c ON c.id = cm1.conversation_id
		 WHERE cm1.user_id = $1::uuid AND cm2.user_id = $2::uuid AND c.conv_type = 0
		 LIMIT 1`,
		userID1, userID2,
	).Scan(&convID)
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return "", false, err
		}
		return convID, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", false, fmt.Errorf("find existing DM: %w", err)
	}

	err = tx.QueryRow(ctx,
		`INSERT INTO conversations (conv_type) VALUES (0) RETURNING id`,
	).Scan(&convID)
	if err != nil {
		return "", false, err
	}

	for _, uid := range []string{userID1, userID2} {
		_, err = tx.Exec(ctx,
			`INSERT INTO conversation_members (conversation_id, user_id) VALUES ($1, $2::uuid)`,
			convID, uid)
		if err != nil {
			return "", false, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", false, err
	}
	return convID, true, nil
}

// IsConversationMember checks if a user is a member of a conversation.
func (db *DB) IsConversationMember(ctx context.Context, convID, userID string) (bool, error) {
	var exists bool
	err := db.Pool.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM conversation_members
		   WHERE conversation_id = $1::uuid AND user_id = $2::uuid
		 )`, convID, userID,
	).Scan(&exists)
	return exists, err
}

// UsersShareConversation reports whether both users are current members of
// at least one conversation. It is used to authorize scarce one-time prekey
// claims after DM/group membership has been established.
func (db *DB) UsersShareConversation(ctx context.Context, userID1, userID2 string) (bool, error) {
	var exists bool
	err := db.Pool.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1
		   FROM conversation_members first_member
		   JOIN conversation_members second_member
		     ON second_member.conversation_id = first_member.conversation_id
		   WHERE first_member.user_id = $1::uuid AND second_member.user_id = $2::uuid
		 )`,
		userID1, userID2,
	).Scan(&exists)
	return exists, err
}

// GetConversationMembers returns user IDs of all members in a conversation.
func (db *DB) GetConversationMembers(ctx context.Context, convID string) ([]string, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT user_id::text FROM conversation_members WHERE conversation_id = $1::uuid`,
		convID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		members = append(members, uid)
	}
	return members, rows.Err()
}

// FindUserByID finds a user by their UUID.
func (db *DB) FindUserByID(ctx context.Context, userID string) (*User, error) {
	var u User
	err := db.Pool.QueryRow(ctx,
		`SELECT id, identity_key, signing_key, username, created_at
		 FROM users WHERE id = $1::uuid`, userID,
	).Scan(&u.ID, &u.IdentityKey, &u.SigningKey, &u.Username, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetDevicesByUser returns all devices belonging to a user, ordered by last_seen.
func (db *DB) GetDevicesByUser(ctx context.Context, userID string) ([]Device, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, user_id, device_key, device_name, last_seen, created_at
		 FROM devices WHERE user_id = $1::uuid ORDER BY last_seen DESC NULLS LAST`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.DeviceKey, &d.DeviceName, &d.LastSeen, &d.CreatedAt); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// --- Groups ---

type GroupInfo struct {
	ConversationID string
	Name           string
	CreatedAt      time.Time
}

type GroupMember struct {
	UserID      string
	IdentityKey []byte
	SigningKey  []byte
	Username    string
	Role        int16
	JoinedAt    time.Time
}

// CreateGroup creates a group conversation and adds the creator as owner.
func (db *DB) CreateGroup(ctx context.Context, name string, creatorUserID string) (string, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var convID string
	err = tx.QueryRow(ctx,
		`INSERT INTO conversations (conv_type, name) VALUES (1, $1) RETURNING id`,
		name,
	).Scan(&convID)
	if err != nil {
		return "", fmt.Errorf("create group conversation: %w", err)
	}

	// Add creator as owner (role=2)
	_, err = tx.Exec(ctx,
		`INSERT INTO conversation_members (conversation_id, user_id, role) VALUES ($1, $2::uuid, 2)`,
		convID, creatorUserID)
	if err != nil {
		return "", fmt.Errorf("add group owner: %w", err)
	}

	return convID, tx.Commit(ctx)
}

// AddGroupMember adds a user to a group conversation.
func (db *DB) AddGroupMember(ctx context.Context, convID, userID string, role int16) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO conversation_members (conversation_id, user_id, role)
		 VALUES ($1::uuid, $2::uuid, $3)
		 ON CONFLICT (conversation_id, user_id) DO NOTHING`,
		convID, userID, role,
	)
	return err
}

// RemoveGroupMember removes a user from a group.
func (db *DB) RemoveGroupMember(ctx context.Context, convID, userID string) error {
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM conversation_members WHERE conversation_id = $1::uuid AND user_id = $2::uuid`,
		convID, userID,
	)
	return err
}

// GetGroupMembersDetailed returns all group members with user info.
func (db *DB) GetGroupMembersDetailed(ctx context.Context, convID string) ([]GroupMember, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT u.id, u.identity_key, u.signing_key, u.username, cm.role, cm.joined_at
		 FROM conversation_members cm
		 JOIN users u ON u.id = cm.user_id
		 WHERE cm.conversation_id = $1::uuid
		 ORDER BY cm.role DESC, cm.joined_at ASC`,
		convID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []GroupMember
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.UserID, &m.IdentityKey, &m.SigningKey, &m.Username, &m.Role, &m.JoinedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

// GetConversationType returns the conv_type of a conversation.
func (db *DB) GetConversationType(ctx context.Context, convID string) (int16, error) {
	var convType int16
	err := db.Pool.QueryRow(ctx,
		`SELECT conv_type FROM conversations WHERE id = $1::uuid`, convID,
	).Scan(&convType)
	return convType, err
}

// GetMemberRole returns the role of a user in a conversation.
func (db *DB) GetMemberRole(ctx context.Context, convID, userID string) (int16, error) {
	var role int16
	err := db.Pool.QueryRow(ctx,
		`SELECT role FROM conversation_members
		 WHERE conversation_id = $1::uuid AND user_id = $2::uuid`,
		convID, userID,
	).Scan(&role)
	return role, err
}

// StoreSenderKey persists an encrypted sender key distribution for one target
// device. See StoreSenderKeys for atomic multi-device fan-out.
func (db *DB) StoreSenderKey(ctx context.Context, convID, ownerDeviceID, targetDeviceID string, encryptedKey []byte, generation uint32) error {
	return db.StoreSenderKeys(ctx, convID, ownerDeviceID, []string{targetDeviceID}, encryptedKey, generation)
}

type senderKeyWrite struct {
	targetDeviceID       string
	encryptedKey         []byte
	rosterVersion        uint64
	rosterCommitment     []byte
	ownerBindingVersion  uint64
	targetBindingVersion uint64
	deviceRouted         bool
}

const senderKeyDeviceRouteDomainV1 = "veil-sender-key-device-route-v1\x00"

func senderKeyDeviceRouteCommitment(envelopeCommitment [32]byte, write senderKeyWrite) [32]byte {
	message := make([]byte, 0, len(senderKeyDeviceRouteDomainV1)+32+8+32+8+8)
	message = append(message, senderKeyDeviceRouteDomainV1...)
	message = append(message, envelopeCommitment[:]...)
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], write.rosterVersion)
	message = append(message, integer[:]...)
	message = append(message, write.rosterCommitment...)
	binary.BigEndian.PutUint64(integer[:], write.ownerBindingVersion)
	message = append(message, integer[:]...)
	binary.BigEndian.PutUint64(integer[:], write.targetBindingVersion)
	message = append(message, integer[:]...)
	return sha256.Sum256(message)
}

// StoreDeviceSenderKey appends one independently encrypted SKDM for one exact
// eligible device and binds the retained row to the roster and both immutable
// binding versions that authorized it.
func (db *DB) StoreDeviceSenderKey(ctx context.Context, convID, ownerDeviceID, targetDeviceID string, encryptedKey []byte, generation uint32, rosterVersion uint64, rosterCommitment []byte, ownerBindingVersion, targetBindingVersion uint64) error {
	if rosterVersion == 0 || rosterVersion > math.MaxInt64 || len(rosterCommitment) != 32 ||
		ownerBindingVersion == 0 || ownerBindingVersion > math.MaxInt64 ||
		targetBindingVersion == 0 || targetBindingVersion > math.MaxInt64 {
		return errors.New("invalid sender key device route")
	}
	return db.storeSenderKeyWrites(ctx, convID, ownerDeviceID, generation, []senderKeyWrite{{
		targetDeviceID:       targetDeviceID,
		encryptedKey:         append([]byte(nil), encryptedKey...),
		rosterVersion:        rosterVersion,
		rosterCommitment:     append([]byte(nil), rosterCommitment...),
		ownerBindingVersion:  ownerBindingVersion,
		targetBindingVersion: targetBindingVersion,
		deviceRouted:         true,
	}})
}

// StoreSenderKeys atomically appends an authenticated distribution for every
// target device. All unacknowledged generations remain retained for offline
// delivery. A stream's high-water mark prevents rollback, and the first
// envelope accepted for a generation is immutable: an equal-generation retry
// succeeds only when both its commitment and bytes are exactly identical.
func (db *DB) StoreSenderKeys(ctx context.Context, convID, ownerDeviceID string, targetDeviceIDs []string, encryptedKey []byte, generation uint32) error {
	if len(targetDeviceIDs) == 0 {
		return errors.New("at least one target device required")
	}
	writes := make([]senderKeyWrite, 0, len(targetDeviceIDs))
	for _, targetDeviceID := range targetDeviceIDs {
		writes = append(writes, senderKeyWrite{
			targetDeviceID: targetDeviceID,
			encryptedKey:   append([]byte(nil), encryptedKey...),
		})
	}
	return db.storeSenderKeyWrites(ctx, convID, ownerDeviceID, generation, writes)
}

func (db *DB) storeSenderKeyWrites(ctx context.Context, convID, ownerDeviceID string, generation uint32, writes []senderKeyWrite) error {
	if convID == "" || ownerDeviceID == "" || len(writes) == 0 || generation == 0 {
		return errors.New("invalid sender key distribution")
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin sender key transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	var conversationType int16
	if err := tx.QueryRow(ctx,
		`SELECT conv_type FROM conversations WHERE id = $1::uuid FOR UPDATE`, convID,
	).Scan(&conversationType); err != nil {
		return fmt.Errorf("lookup sender key conversation: %w", err)
	}
	if conversationType != 1 && conversationType != 2 {
		return ErrSenderKeyConversationType
	}
	seen := make(map[string]struct{}, len(writes))
	for _, write := range writes {
		targetDeviceID := write.targetDeviceID
		if targetDeviceID == "" || len(write.encryptedKey) == 0 || len(write.encryptedKey) > 4*1024 {
			return errors.New("target device id required")
		}
		if write.deviceRouted {
			if write.rosterVersion == 0 || write.rosterVersion > math.MaxInt64 ||
				len(write.rosterCommitment) != 32 || write.ownerBindingVersion == 0 ||
				write.ownerBindingVersion > math.MaxInt64 || write.targetBindingVersion == 0 ||
				write.targetBindingVersion > math.MaxInt64 {
				return errors.New("invalid sender key device route")
			}
		} else if write.rosterVersion != 0 || len(write.rosterCommitment) != 0 ||
			write.ownerBindingVersion != 0 || write.targetBindingVersion != 0 {
			return errors.New("partial sender key device route")
		}
		if _, duplicate := seen[targetDeviceID]; duplicate {
			continue
		}
		seen[targetDeviceID] = struct{}{}
		envelopeCommitment := sha256.Sum256(write.encryptedKey)
		headCommitment := envelopeCommitment
		if write.deviceRouted {
			headCommitment = senderKeyDeviceRouteCommitment(envelopeCommitment, write)
		}

		var currentGeneration int64
		var currentCommitment []byte
		err := tx.QueryRow(ctx,
			`SELECT max_generation, max_commitment
			 FROM sender_key_heads
			 WHERE conversation_id = $1::uuid
			   AND owner_device_id = $2::uuid
			   AND target_device_id = $3::uuid
			 FOR UPDATE`,
			convID, ownerDeviceID, targetDeviceID,
		).Scan(&currentGeneration, &currentCommitment)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if _, err := tx.Exec(ctx,
				`INSERT INTO sender_key_heads (
				   conversation_id, owner_device_id, target_device_id,
				   max_generation, max_commitment
				 ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5)`,
				convID, ownerDeviceID, targetDeviceID, int64(generation), headCommitment[:],
			); err != nil {
				return fmt.Errorf("create sender key head for device %s: %w", targetDeviceID, err)
			}
		case err != nil:
			return fmt.Errorf("lookup sender key head for device %s: %w", targetDeviceID, err)
		case int64(generation) < currentGeneration:
			return ErrStaleSenderKeyGeneration
		case int64(generation) == currentGeneration:
			if !bytes.Equal(currentCommitment, headCommitment[:]) {
				return ErrSenderKeyGenerationConflict
			}
			var retainedKey, retainedCommitment, retainedRosterCommitment []byte
			var retainedRosterVersion, retainedOwnerBindingVersion, retainedTargetBindingVersion int64
			err := tx.QueryRow(ctx,
				`SELECT encrypted_key, envelope_commitment,
				        COALESCE(roster_version, 0), COALESCE(roster_commitment, ''::bytea),
				        COALESCE(owner_binding_version, 0), COALESCE(target_binding_version, 0)
				 FROM sender_keys
				 WHERE conversation_id = $1::uuid
				   AND owner_device_id = $2::uuid
				   AND target_device_id = $3::uuid
				   AND generation = $4`,
				convID, ownerDeviceID, targetDeviceID, int64(generation),
			).Scan(&retainedKey, &retainedCommitment, &retainedRosterVersion,
				&retainedRosterCommitment, &retainedOwnerBindingVersion, &retainedTargetBindingVersion)
			if errors.Is(err, pgx.ErrNoRows) {
				// The row was explicitly collected after its stream head was
				// committed. An exact retry remains idempotent but must not
				// resurrect control state already acknowledged or expired.
				continue
			}
			if err != nil {
				return fmt.Errorf("verify sender key for device %s: %w", targetDeviceID, err)
			}
			if !senderKeyWriteMatches(write, retainedKey, retainedCommitment,
				retainedRosterVersion, retainedRosterCommitment,
				retainedOwnerBindingVersion, retainedTargetBindingVersion) {
				return ErrSenderKeyGenerationConflict
			}
			continue
		default:
			if _, err := tx.Exec(ctx,
				`UPDATE sender_key_heads
				 SET max_generation = $4, max_commitment = $5, updated_at = now()
				 WHERE conversation_id = $1::uuid
				   AND owner_device_id = $2::uuid
				   AND target_device_id = $3::uuid`,
				convID, ownerDeviceID, targetDeviceID, int64(generation), headCommitment[:],
			); err != nil {
				return fmt.Errorf("advance sender key head for device %s: %w", targetDeviceID, err)
			}
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO sender_keys (
			   conversation_id, owner_device_id, target_device_id,
			   encrypted_key, generation, envelope_commitment, roster_version,
			   roster_commitment, owner_binding_version, target_binding_version
			 ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9, $10)
			 ON CONFLICT (conversation_id, owner_device_id, target_device_id, generation)
			 DO NOTHING`,
			convID, ownerDeviceID, targetDeviceID, write.encryptedKey, int64(generation),
			envelopeCommitment[:], nullableSenderKeyRoute(write.rosterVersion, write.deviceRouted),
			nullableSenderKeyBytes(write.rosterCommitment, write.deviceRouted),
			nullableSenderKeyRoute(write.ownerBindingVersion, write.deviceRouted),
			nullableSenderKeyRoute(write.targetBindingVersion, write.deviceRouted),
		); err != nil {
			return fmt.Errorf("store sender key for device %s: %w", targetDeviceID, err)
		}

		// ON CONFLICT is intentionally non-mutating. Verify the retained row so
		// an inconsistent legacy row, or even a theoretical commitment collision,
		// cannot make a generation replace authenticated state.
		var retainedKey, retainedCommitment, retainedRosterCommitment []byte
		var retainedRosterVersion, retainedOwnerBindingVersion, retainedTargetBindingVersion int64
		if err := tx.QueryRow(ctx,
			`SELECT encrypted_key, envelope_commitment,
			        COALESCE(roster_version, 0), COALESCE(roster_commitment, ''::bytea),
			        COALESCE(owner_binding_version, 0), COALESCE(target_binding_version, 0)
			 FROM sender_keys
			 WHERE conversation_id = $1::uuid
			   AND owner_device_id = $2::uuid
			   AND target_device_id = $3::uuid
			   AND generation = $4`,
			convID, ownerDeviceID, targetDeviceID, int64(generation),
		).Scan(&retainedKey, &retainedCommitment, &retainedRosterVersion,
			&retainedRosterCommitment, &retainedOwnerBindingVersion, &retainedTargetBindingVersion); err != nil {
			return fmt.Errorf("verify sender key for device %s: %w", targetDeviceID, err)
		}
		if !senderKeyWriteMatches(write, retainedKey, retainedCommitment,
			retainedRosterVersion, retainedRosterCommitment,
			retainedOwnerBindingVersion, retainedTargetBindingVersion) {
			return ErrSenderKeyGenerationConflict
		}
	}
	return tx.Commit(ctx)
}

func nullableSenderKeyRoute(value uint64, present bool) any {
	if !present {
		return nil
	}
	return int64(value)
}

func nullableSenderKeyBytes(value []byte, present bool) any {
	if !present {
		return nil
	}
	return value
}

func senderKeyWriteMatches(write senderKeyWrite, retainedKey, retainedCommitment []byte, rosterVersion int64, rosterCommitment []byte, ownerBindingVersion, targetBindingVersion int64) bool {
	envelopeCommitment := sha256.Sum256(write.encryptedKey)
	if !bytes.Equal(retainedKey, write.encryptedKey) ||
		!bytes.Equal(retainedCommitment, envelopeCommitment[:]) {
		return false
	}
	if !write.deviceRouted {
		return rosterVersion == 0 && len(rosterCommitment) == 0 &&
			ownerBindingVersion == 0 && targetBindingVersion == 0
	}
	return rosterVersion == int64(write.rosterVersion) &&
		bytes.Equal(rosterCommitment, write.rosterCommitment) &&
		ownerBindingVersion == int64(write.ownerBindingVersion) &&
		targetBindingVersion == int64(write.targetBindingVersion)
}

// GetPendingSenderKeys returns sender keys addressed to a specific device.
func (db *DB) GetPendingSenderKeys(ctx context.Context, targetDeviceID string) ([]SenderKeyRow, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT sk.conversation_id, sk.owner_device_id, sk.target_device_id,
		        target_device.user_id, sk.encrypted_key, sk.generation,
		        COALESCE(sk.roster_version, 0), COALESCE(sk.roster_commitment, ''::bytea),
		        COALESCE(sk.owner_binding_version, 0), COALESCE(sk.target_binding_version, 0),
		        sk.envelope_commitment
		 FROM sender_keys sk
		 JOIN conversations conversation ON conversation.id = sk.conversation_id AND conversation.conv_type IN (1, 2)
		 JOIN devices target_device ON target_device.id = sk.target_device_id
		 JOIN devices owner_device ON owner_device.id = sk.owner_device_id
		 JOIN conversation_members target_member
		   ON target_member.conversation_id = sk.conversation_id
		  AND target_member.user_id = target_device.user_id
		 JOIN conversation_members owner_member
		   ON owner_member.conversation_id = sk.conversation_id
		  AND owner_member.user_id = owner_device.user_id
		 WHERE sk.target_device_id = $1::uuid
		 ORDER BY sk.conversation_id, sk.owner_device_id, sk.generation`,
		targetDeviceID,
	)
	if err != nil {
		return nil, err
	}

	var keys []SenderKeyRow
	for rows.Next() {
		var k SenderKeyRow
		var rosterVersion, ownerBindingVersion, targetBindingVersion int64
		if err := rows.Scan(&k.ConversationID, &k.OwnerDeviceID, &k.TargetDeviceID,
			&k.TargetUserID, &k.EncryptedKey, &k.Generation, &rosterVersion,
			&k.RosterCommitment, &ownerBindingVersion, &targetBindingVersion,
			&k.EnvelopeCommitment); err != nil {
			rows.Close()
			return nil, err
		}
		k.RosterVersion = uint64(rosterVersion)
		k.OwnerBindingVersion = uint64(ownerBindingVersion)
		k.TargetBindingVersion = uint64(targetBindingVersion)
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	authorized := keys[:0]
	for _, key := range keys {
		allowed, err := db.CanAccessConversation(ctx, key.ConversationID, key.TargetUserID, ChannelReadPermissions)
		if err != nil {
			return nil, err
		}
		if allowed {
			authorized = append(authorized, key)
		}
	}
	return authorized, nil
}

type SenderKeyRow struct {
	ConversationID       string
	OwnerDeviceID        string
	TargetDeviceID       string
	TargetUserID         string
	EncryptedKey         []byte
	Generation           uint32
	RosterVersion        uint64
	RosterCommitment     []byte
	OwnerBindingVersion  uint64
	TargetBindingVersion uint64
	EnvelopeCommitment   []byte
}

// AcknowledgeSenderKey removes only the exact pending row installed by the
// authenticated target device. The stream head is deliberately retained so a
// replay cannot resurrect or replace an acknowledged generation.
func (db *DB) AcknowledgeSenderKey(ctx context.Context, conversationID, ownerDeviceID, targetDeviceID string, generation uint32, rosterVersion uint64, envelopeCommitment []byte) error {
	if conversationID == "" || ownerDeviceID == "" || targetDeviceID == "" ||
		generation == 0 || rosterVersion == 0 || rosterVersion > math.MaxInt64 ||
		len(envelopeCommitment) != 32 {
		return ErrSenderKeyReceiptMismatch
	}
	tag, err := db.Pool.Exec(ctx,
		`DELETE FROM sender_keys
		 WHERE conversation_id = $1::uuid
		   AND owner_device_id = $2::uuid
		   AND target_device_id = $3::uuid
		   AND generation = $4
		   AND roster_version = $5
		   AND envelope_commitment = $6`,
		conversationID, ownerDeviceID, targetDeviceID, int64(generation),
		int64(rosterVersion), envelopeCommitment,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrSenderKeyReceiptMismatch
	}
	return nil
}

// --- Reactions ---

// MessageBelongsToConversation validates a message/conversation object
// relationship. Keeping this check in the database avoids accepting a
// message UUID from one conversation while broadcasting an event to another.
func (db *DB) MessageBelongsToConversation(ctx context.Context, messageID, conversationID string) (bool, error) {
	var exists bool
	err := db.Pool.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM messages
		   WHERE id = $1::uuid AND conversation_id = $2::uuid AND is_deleted = false
		 )`,
		messageID, conversationID,
	).Scan(&exists)
	return exists, err
}

// AddReaction inserts a reaction (idempotent — ignores conflict).
func (db *DB) AddReaction(ctx context.Context, messageID, conversationID, userID, emoji string) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO reactions (message_id, conversation_id, user_id, emoji)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4)
		 ON CONFLICT DO NOTHING`,
		messageID, conversationID, userID, emoji,
	)
	return err
}

// RemoveReaction deletes a specific reaction.
func (db *DB) RemoveReaction(ctx context.Context, messageID, conversationID, userID, emoji string) error {
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM reactions
		 WHERE message_id = $1::uuid AND conversation_id = $2::uuid
		   AND user_id = $3::uuid AND emoji = $4`,
		messageID, conversationID, userID, emoji,
	)
	return err
}

// Reaction represents a single stored reaction.
type Reaction struct {
	MessageID      string
	ConversationID string
	UserID         string
	Username       string
	Emoji          string
}

// GetReactionsForMessages returns all reactions for the given message IDs.
func (db *DB) GetReactionsForMessages(ctx context.Context, messageIDs []string) ([]Reaction, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT reaction.message_id, reaction.conversation_id, reaction.user_id,
		        user_account.username, reaction.emoji
		 FROM reactions reaction
		 JOIN users user_account ON user_account.id = reaction.user_id
		 WHERE reaction.message_id = ANY($1::uuid[])
		 ORDER BY reaction.message_id, reaction.emoji, reaction.user_id`,
		messageIDs,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Reaction
	for rows.Next() {
		var r Reaction
		if err := rows.Scan(&r.MessageID, &r.ConversationID, &r.UserID, &r.Username, &r.Emoji); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Friends ---

type FriendRequest struct {
	ID         string
	FromUserID string
	ToUserID   string
	Message    *string
	Status     int16 // 0=pending, 1=accepted, 2=rejected
	CreatedAt  time.Time
}

type Friendship struct {
	UserID    string
	Username  string
	CreatedAt time.Time
}

// CreateFriendRequest sends a new friend request. Returns the request ID.
func (db *DB) CreateFriendRequest(ctx context.Context, fromUserID, toUserID string, message *string) (string, time.Time, error) {
	var id string
	var createdAt time.Time
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO friend_requests (from_user_id, to_user_id, message)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (from_user_id, to_user_id) DO UPDATE SET status = 0, message = $3, created_at = now()
		 RETURNING id, created_at`,
		fromUserID, toUserID, message,
	).Scan(&id, &createdAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("create friend request: %w", err)
	}
	return id, createdAt, nil
}

// HasPendingFriendRequest checks if there is already a pending request between two users (in either direction).
func (db *DB) HasPendingFriendRequest(ctx context.Context, fromUserID, toUserID string) (bool, error) {
	var exists bool
	err := db.Pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM friend_requests
			WHERE ((from_user_id = $1 AND to_user_id = $2) OR (from_user_id = $2 AND to_user_id = $1))
			AND status = 0
		)`,
		fromUserID, toUserID,
	).Scan(&exists)
	return exists, err
}

// GetPendingFriendRequests returns all pending requests for a user (both incoming and outgoing).
func (db *DB) GetPendingFriendRequests(ctx context.Context, userID string) ([]FriendRequest, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, from_user_id, to_user_id, message, status, created_at
		 FROM friend_requests
		 WHERE (to_user_id = $1 OR from_user_id = $1) AND status = 0
		 ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FriendRequest
	for rows.Next() {
		var r FriendRequest
		if err := rows.Scan(&r.ID, &r.FromUserID, &r.ToUserID, &r.Message, &r.Status, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AcceptFriendRequest marks request as accepted and creates a friendship. Returns the other user's ID.
func (db *DB) AcceptFriendRequest(ctx context.Context, requestID, acceptingUserID string) (string, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var fromUserID, toUserID string
	err = tx.QueryRow(ctx,
		`UPDATE friend_requests SET status = 1
		 WHERE id = $1 AND to_user_id = $2 AND status = 0
		 RETURNING from_user_id, to_user_id`, requestID, acceptingUserID,
	).Scan(&fromUserID, &toUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("friend request not found or already handled")
		}
		return "", err
	}

	// Insert friendship with canonical ordering (user_id_1 < user_id_2)
	uid1, uid2 := fromUserID, toUserID
	if uid1 > uid2 {
		uid1, uid2 = uid2, uid1
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO friendships (user_id_1, user_id_2) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		uid1, uid2,
	)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return fromUserID, nil
}

// RejectFriendRequest marks request as rejected.
func (db *DB) RejectFriendRequest(ctx context.Context, requestID, rejectingUserID string) error {
	tag, err := db.Pool.Exec(ctx,
		`UPDATE friend_requests SET status = 2
		 WHERE id = $1 AND to_user_id = $2 AND status = 0`, requestID, rejectingUserID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("friend request not found or already handled")
	}
	return nil
}

// RemoveFriend deletes a friendship between two users.
func (db *DB) RemoveFriend(ctx context.Context, userID1, userID2 string) error {
	uid1, uid2 := userID1, userID2
	if uid1 > uid2 {
		uid1, uid2 = uid2, uid1
	}
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM friendships WHERE user_id_1 = $1 AND user_id_2 = $2`,
		uid1, uid2,
	)
	return err
}

// GetFriends returns all friends for a user.
func (db *DB) GetFriends(ctx context.Context, userID string) ([]Friendship, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT u.id, u.username, f.created_at
		 FROM friendships f
		 JOIN users u ON u.id = CASE
		     WHEN f.user_id_1 = $1 THEN f.user_id_2
		     ELSE f.user_id_1
		 END
		 WHERE f.user_id_1 = $1 OR f.user_id_2 = $1
		 ORDER BY u.username`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Friendship
	for rows.Next() {
		var f Friendship
		if err := rows.Scan(&f.UserID, &f.Username, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetFriendIDs returns just friend user IDs for a user (for presence filtering).
func (db *DB) GetFriendIDs(ctx context.Context, userID string) ([]string, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT CASE WHEN user_id_1 = $1 THEN user_id_2 ELSE user_id_1 END
		 FROM friendships
		 WHERE user_id_1 = $1 OR user_id_2 = $1`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// AreFriends checks if two users are friends.
func (db *DB) AreFriends(ctx context.Context, userID1, userID2 string) (bool, error) {
	uid1, uid2 := userID1, userID2
	if uid1 > uid2 {
		uid1, uid2 = uid2, uid1
	}
	var exists bool
	err := db.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM friendships WHERE user_id_1 = $1 AND user_id_2 = $2)`,
		uid1, uid2,
	).Scan(&exists)
	return exists, err
}

// FindUserByUsername looks up a user by username.
func (db *DB) FindUserByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	err := db.Pool.QueryRow(ctx,
		`SELECT id, identity_key, signing_key, username, created_at
		 FROM users WHERE username = $1`, username,
	).Scan(&u.ID, &u.IdentityKey, &u.SigningKey, &u.Username, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}
