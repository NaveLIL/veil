package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

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
	ID        int64
	DeviceID  string
	KeyType   int16 // 0=signed, 1=one-time
	PublicKey []byte
	Signature []byte
	Used      bool
}

// StorePreKeys bulk-inserts prekeys for a device.
func (db *DB) StorePreKeys(ctx context.Context, deviceID string, keys []PreKey) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, k := range keys {
		_, err := tx.Exec(ctx,
			`INSERT INTO prekeys (device_id, key_type, public_key, signature)
			 VALUES ($1, $2, $3, $4)`,
			deviceID, k.KeyType, k.PublicKey, k.Signature)
		if err != nil {
			return fmt.Errorf("insert prekey: %w", err)
		}
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
		 RETURNING id, device_id, key_type, public_key, signature, used`,
		deviceID,
	).Scan(&pk.ID, &pk.DeviceID, &pk.KeyType, &pk.PublicKey, &pk.Signature, &pk.Used)
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
		`SELECT id, device_id, key_type, public_key, signature, used
		 FROM prekeys
		 WHERE device_id = $1 AND key_type = 0
		 ORDER BY id DESC LIMIT 1`,
		deviceID,
	).Scan(&pk.ID, &pk.DeviceID, &pk.KeyType, &pk.PublicKey, &pk.Signature, &pk.Used)
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
	Ciphertext     []byte
	Header         []byte
	MsgType        int16
	ReplyToID      *string
	ExpiresAt      *time.Time
	CreatedAt      time.Time
}

// StoreMessage persists an encrypted message.
func (db *DB) StoreMessage(ctx context.Context, m *Message) error {
	return db.Pool.QueryRow(ctx,
		`INSERT INTO messages (conversation_id, sender_id, ciphertext, header, msg_type, reply_to_id, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, created_at`,
		m.ConversationID, m.SenderID, m.Ciphertext, m.Header, m.MsgType, m.ReplyToID, m.ExpiresAt,
	).Scan(&m.ID, &m.CreatedAt)
}

// GetPendingMessages returns undelivered messages for a user since a timestamp.
func (db *DB) GetPendingMessages(ctx context.Context, userID string, since time.Time, limit int) ([]Message, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT m.id, m.conversation_id, m.sender_id, m.ciphertext, m.header,
		        m.msg_type, m.reply_to_id, m.expires_at, m.created_at
		 FROM messages m
		 JOIN conversation_members cm ON cm.conversation_id = m.conversation_id
		 WHERE cm.user_id = $1::uuid AND m.created_at > $2
		   AND (m.expires_at IS NULL OR m.expires_at > now())
		 ORDER BY m.created_at ASC
		 LIMIT $3`,
		userID, since, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.SenderID, &m.Ciphertext, &m.Header,
			&m.MsgType, &m.ReplyToID, &m.ExpiresAt, &m.CreatedAt); err != nil {
			return nil, err
		}
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// UpdateMessageCiphertext updates the ciphertext of a message (edit).
// Only the original sender can edit. Returns conversation_id for fan-out.
func (db *DB) UpdateMessageCiphertext(ctx context.Context, messageID, senderID string, newCiphertext, newHeader []byte) (string, time.Time, error) {
	var convID string
	var editedAt time.Time
	err := db.Pool.QueryRow(ctx,
		`UPDATE messages SET ciphertext = $1, header = $2, edited_at = now()
		 WHERE id = $3::uuid AND sender_id = $4::uuid AND is_deleted = false
		 RETURNING conversation_id, edited_at`,
		newCiphertext, newHeader, messageID, senderID,
	).Scan(&convID, &editedAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("update message: %w", err)
	}
	return convID, editedAt, nil
}

// SoftDeleteMessage marks a message as deleted (wipes ciphertext).
// Only the original sender can delete. Returns conversation_id for fan-out.
func (db *DB) SoftDeleteMessage(ctx context.Context, messageID, senderID string) (string, error) {
	var convID string
	err := db.Pool.QueryRow(ctx,
		`UPDATE messages SET is_deleted = true, ciphertext = '\x00', header = NULL, edited_at = now()
		 WHERE id = $1::uuid AND sender_id = $2::uuid AND is_deleted = false
		 RETURNING conversation_id`,
		messageID, senderID,
	).Scan(&convID)
	if err != nil {
		return "", fmt.Errorf("delete message: %w", err)
	}
	return convID, nil
}

// --- Conversations ---

// FindOrCreateDM finds an existing DM conversation between two users, or creates one.
func (db *DB) FindOrCreateDM(ctx context.Context, userID1, userID2 string) (string, error) {
	// Check if DM already exists
	var convID string
	err := db.Pool.QueryRow(ctx,
		`SELECT cm1.conversation_id
		 FROM conversation_members cm1
		 JOIN conversation_members cm2 ON cm1.conversation_id = cm2.conversation_id
		 JOIN conversations c ON c.id = cm1.conversation_id
		 WHERE cm1.user_id = $1::uuid AND cm2.user_id = $2::uuid AND c.conv_type = 0
		 LIMIT 1`,
		userID1, userID2,
	).Scan(&convID)
	if err == nil {
		return convID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("find existing DM: %w", err)
	}

	// Create new DM conversation
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	err = tx.QueryRow(ctx,
		`INSERT INTO conversations (conv_type) VALUES (0) RETURNING id`,
	).Scan(&convID)
	if err != nil {
		return "", err
	}

	for _, uid := range []string{userID1, userID2} {
		_, err = tx.Exec(ctx,
			`INSERT INTO conversation_members (conversation_id, user_id) VALUES ($1, $2::uuid)`,
			convID, uid)
		if err != nil {
			return "", err
		}
	}

	return convID, tx.Commit(ctx)
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
		`SELECT u.id, u.identity_key, u.username, cm.role, cm.joined_at
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
		if err := rows.Scan(&m.UserID, &m.IdentityKey, &m.Username, &m.Role, &m.JoinedAt); err != nil {
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

// StoreSenderKey persists an encrypted sender key distribution.
func (db *DB) StoreSenderKey(ctx context.Context, convID, ownerDeviceID, targetDeviceID string, encryptedKey []byte, generation int) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO sender_keys (conversation_id, owner_device_id, target_device_id, encrypted_key, generation)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5)
		 ON CONFLICT (conversation_id, owner_device_id, target_device_id)
		 DO UPDATE SET encrypted_key = $4, generation = $5`,
		convID, ownerDeviceID, targetDeviceID, encryptedKey, generation,
	)
	return err
}

// GetPendingSenderKeys returns sender keys addressed to a specific device.
func (db *DB) GetPendingSenderKeys(ctx context.Context, targetDeviceID string) ([]SenderKeyRow, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT conversation_id, owner_device_id, target_device_id, encrypted_key, generation
		 FROM sender_keys WHERE target_device_id = $1::uuid`,
		targetDeviceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []SenderKeyRow
	for rows.Next() {
		var k SenderKeyRow
		if err := rows.Scan(&k.ConversationID, &k.OwnerDeviceID, &k.TargetDeviceID, &k.EncryptedKey, &k.Generation); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

type SenderKeyRow struct {
	ConversationID string
	OwnerDeviceID  string
	TargetDeviceID string
	EncryptedKey   []byte
	Generation     int
}

// --- Reactions ---

// AddReaction inserts a reaction (idempotent — ignores conflict).
func (db *DB) AddReaction(ctx context.Context, messageID, conversationID, userID, emoji string) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO reactions (message_id, conversation_id, user_id, emoji)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT DO NOTHING`,
		messageID, conversationID, userID, emoji,
	)
	return err
}

// RemoveReaction deletes a specific reaction.
func (db *DB) RemoveReaction(ctx context.Context, messageID, userID, emoji string) error {
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3`,
		messageID, userID, emoji,
	)
	return err
}

// Reaction represents a single stored reaction.
type Reaction struct {
	MessageID      string
	ConversationID string
	UserID         string
	Emoji          string
}

// GetReactionsForMessages returns all reactions for the given message IDs.
func (db *DB) GetReactionsForMessages(ctx context.Context, messageIDs []string) ([]Reaction, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT message_id, conversation_id, user_id, emoji
		 FROM reactions WHERE message_id = ANY($1)`,
		messageIDs,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Reaction
	for rows.Next() {
		var r Reaction
		if err := rows.Scan(&r.MessageID, &r.ConversationID, &r.UserID, &r.Emoji); err != nil {
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
