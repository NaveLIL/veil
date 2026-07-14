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
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrStaleSenderKeyGeneration         = errors.New("stale sender key generation")
	ErrSenderKeyGenerationConflict      = errors.New("sender key generation already has a different commitment")
	ErrSenderKeyConversationType        = errors.New("sender keys require a group or channel conversation")
	ErrSenderKeyReceiptMismatch         = errors.New("sender key receipt does not match an exact pending device distribution")
	ErrSenderKeyRetentionFull           = errors.New("sender key retention limit reached for target device")
	ErrSenderKeyRetentionExpired        = errors.New("sender key receipt deadline expired for target device")
	ErrSenderKeyTargetBacklogFull       = errors.New("sender key target backlog limit reached")
	ErrSenderKeyRestoreBacklogExceeded  = errors.New("sender key restore backlog exceeds the safe login bound")
	ErrSenderKeyConversationUnavailable = errors.New("sender key conversation is not ready for restore")
	ErrSenderKeyLegacyState             = errors.New("legacy account-routed sender key state is unsupported")
	ErrSenderKeyRosterChanged           = errors.New("sender key device roster changed before durable admission")
	ErrReplyTargetMismatch              = errors.New("reply target does not belong to conversation")
	ErrMessageMutationScope             = errors.New("message mutation scope mismatch")
	ErrAttachmentScope                  = errors.New("attachment is unavailable or not owned by sender")
	ErrMessageSecurityContext           = errors.New("message security context does not match the conversation")
	ErrMessageRosterChanged             = errors.New("message roster changed before durable admission")
	ErrConversationAccessDenied         = errors.New("conversation access denied")
)

const maxUnusedOneTimePreKeysPerDevice = 100

const (
	MaxPendingSenderKeyGenerationsPerStream = 128
	SenderKeyReceiptTTL                     = 90 * 24 * time.Hour
	MaxPendingSenderKeyRowsPerTarget        = 2048
	MaxPendingSenderKeyBytesPerTarget       = 4 * 1024 * 1024
)

const (
	MessageCryptoProfileSenderKeyV5 = "sender_key_v5"
	MessageCryptoEraSenderKeyV5     = uint64(1)
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
	if len(identityKey) != 32 || !cryptokey.ValidEd25519PublicKey(signingKey) {
		return nil, errors.New("invalid account cryptographic public keys")
	}
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
	SecurityContext   *MessageSecurityContext
}

// MessageSecurityContext is the immutable, persisted authorization snapshot
// for a Sender-Key group/channel ciphertext. SenderDeviceDatabaseID is used
// only while admitting a new row and is never returned on the wire.
type MessageSecurityContext struct {
	CryptoProfile          string
	CryptoEra              uint64
	RosterVersion          uint64
	RosterCommitment       []byte
	SenderDeviceID         []byte
	SenderBindingVersion   uint64
	SenderDeviceDatabaseID string
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
	if m == nil || m.ConversationID == "" || m.SenderID == "" || len(m.Ciphertext) == 0 {
		return errors.New("invalid message")
	}
	attempts := 1
	if m.SecurityContext != nil {
		attempts = 3
	}
	for attempt := 0; attempt < attempts; attempt++ {
		err := db.storeMessageOnce(ctx, m)
		if !isSenderKeySerializationFailure(err) {
			return err
		}
	}
	return ErrMessageRosterChanged
}

func (db *DB) storeMessageOnce(ctx context.Context, m *Message) error {
	txOptions := pgx.TxOptions{}
	if m.SecurityContext != nil {
		txOptions.IsoLevel = pgx.Serializable
	}
	tx, err := db.Pool.BeginTx(ctx, txOptions)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var conversationType int16
	if err := tx.QueryRow(ctx,
		`SELECT conv_type FROM conversations WHERE id = $1::uuid FOR UPDATE`,
		m.ConversationID,
	).Scan(&conversationType); err != nil {
		return err
	}
	if conversationType == 1 || conversationType == 2 {
		if err := validateMessageSecurityContext(m.SecurityContext); err != nil {
			return err
		}
		var lockedDeviceID string
		if err := tx.QueryRow(ctx,
			`SELECT id::text FROM devices
			 WHERE id = $1::uuid AND user_id = $2::uuid FOR UPDATE`,
			m.SecurityContext.SenderDeviceDatabaseID, m.SenderID,
		).Scan(&lockedDeviceID); err != nil {
			return ErrMessageSecurityContext
		}
		roster, err := resolveConversationDeviceRosterSnapshot(
			ctx, tx, m.ConversationID, RequiredChannelCapabilities,
		)
		if err != nil {
			if errors.Is(err, ErrSenderKeyRosterChanged) {
				return ErrMessageRosterChanged
			}
			return err
		}
		if err := validateMessageRosterSnapshot(
			ctx, tx, roster, m.ConversationID, m.SenderID, m.SecurityContext,
		); err != nil {
			return err
		}
	} else if m.SecurityContext != nil {
		return ErrMessageSecurityContext
	}

	var securityProfile, rosterCommitment, senderDeviceID any
	var securityEra, rosterVersion, senderBindingVersion any
	if m.SecurityContext != nil {
		securityProfile = m.SecurityContext.CryptoProfile
		securityEra = int64(m.SecurityContext.CryptoEra)
		rosterVersion = int64(m.SecurityContext.RosterVersion)
		rosterCommitment = m.SecurityContext.RosterCommitment
		senderDeviceID = m.SecurityContext.SenderDeviceID
		senderBindingVersion = int64(m.SecurityContext.SenderBindingVersion)
	}

	err = tx.QueryRow(ctx,
		`INSERT INTO messages (
		   conversation_id, sender_id, ciphertext, header, msg_type, reply_to_id, expires_at,
		   crypto_profile, crypto_era, roster_version, roster_commitment,
		   sender_device_id, sender_binding_version
		 )
		 SELECT $1::uuid, $2::uuid, $3, $4, $5, $6::uuid, $7,
		        $8, $9, $10, $11, $12, $13
		 WHERE $6::uuid IS NULL OR EXISTS (
		   SELECT 1 FROM messages reply
		   WHERE reply.id = $6::uuid
		     AND reply.conversation_id = $1::uuid
		     AND reply.is_deleted = false
		 )
		 RETURNING id, created_at`,
		m.ConversationID, m.SenderID, m.Ciphertext, m.Header, m.MsgType, m.ReplyToID, m.ExpiresAt,
		securityProfile, securityEra, rosterVersion, rosterCommitment, senderDeviceID, senderBindingVersion,
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

func validateMessageSecurityContext(security *MessageSecurityContext) error {
	if security == nil || security.CryptoProfile != MessageCryptoProfileSenderKeyV5 ||
		security.CryptoEra != MessageCryptoEraSenderKeyV5 ||
		security.RosterVersion == 0 || security.RosterVersion > math.MaxInt64 ||
		len(security.RosterCommitment) != 32 || len(security.SenderDeviceID) != 16 ||
		security.SenderBindingVersion == 0 || security.SenderBindingVersion > math.MaxInt64 ||
		security.SenderDeviceDatabaseID == "" {
		return ErrMessageSecurityContext
	}
	return nil
}

func validateMessageRosterSnapshot(ctx context.Context, tx pgx.Tx, roster *ConversationDeviceRoster, conversationID, senderUserID string, security *MessageSecurityContext) error {
	if roster == nil || !roster.Ready || security == nil ||
		roster.Version != security.RosterVersion ||
		!bytes.Equal(roster.Commitment[:], security.RosterCommitment) {
		return ErrMessageRosterChanged
	}
	senderFound := false
	for memberIndex := range roster.Members {
		member := &roster.Members[memberIndex]
		if member.UserID != senderUserID {
			continue
		}
		for deviceIndex := range member.Devices {
			device := &member.Devices[deviceIndex]
			if device.DeviceID != security.SenderDeviceDatabaseID {
				continue
			}
			if !device.Eligible || device.Binding == nil ||
				device.Binding.Status != DeviceBindingActive ||
				device.Binding.Capabilities&RequiredChannelCapabilities != RequiredChannelCapabilities ||
				device.Binding.Version != security.SenderBindingVersion ||
				!bytes.Equal(device.DeviceKey, security.SenderDeviceID) {
				return ErrMessageRosterChanged
			}
			senderFound = true
		}
	}
	if !senderFound {
		return ErrMessageRosterChanged
	}
	canSend, err := canAccessConversationWithQuery(
		ctx, tx, conversationID, senderUserID,
		ChannelReadPermissions|PermSendMessages,
	)
	if err != nil {
		return err
	}
	if !canSend {
		return ErrMessageRosterChanged
	}
	return nil
}

type ConversationHistoryPage struct {
	Messages    []Message
	Reactions   []Reaction
	Attachments []MessageAttachment
}

// GetPendingMessages is the narrow sync API used by non-HTTP callers. It uses
// the same all-or-nothing authorized snapshot as the REST history page.
func (db *DB) GetPendingMessages(ctx context.Context, conversationID, userID string, after time.Time, afterID string, limit int) ([]Message, error) {
	page, err := db.GetConversationHistoryPage(
		ctx, conversationID, userID, after, afterID, limit,
	)
	if err != nil {
		return nil, err
	}
	return page.Messages, nil
}

// GetConversationHistoryPage authorizes and reads ciphertext, reactions and
// encrypted attachment descriptors from one repeatable-read snapshot. A
// committed revoke cannot land between a handler precheck and any related
// read, and an error returns no partial page.
func (db *DB) GetConversationHistoryPage(ctx context.Context, conversationID, userID string, after time.Time, afterID string, limit int) (*ConversationHistoryPage, error) {
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// Authorization and ciphertext are read from one MVCC snapshot. A role or
	// history revocation that committed before this transaction's first read is
	// therefore authoritative; a request that won the snapshot first is
	// explicitly linearized before that revocation.
	allowed, err := canAccessConversationWithQuery(
		ctx, tx, conversationID, userID, ChannelReadPermissions,
	)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrConversationAccessDenied
	}
	messages, err := getPendingMessagesWithQuery(
		ctx, tx, conversationID, userID, after, afterID, limit,
	)
	if err != nil {
		return nil, err
	}
	messageIDs := make([]string, 0, len(messages))
	for _, message := range messages {
		messageIDs = append(messageIDs, message.ID)
	}
	reactions, err := getReactionsForMessagesWithQuery(ctx, tx, messageIDs)
	if err != nil {
		return nil, err
	}
	attachments, err := getAttachmentsForMessagesWithQuery(ctx, tx, messageIDs)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &ConversationHistoryPage{
		Messages: messages, Reactions: reactions, Attachments: attachments,
	}, nil
}

// getPendingMessagesWithQuery returns authoritative current rows since a
// creation-time keyset boundary through the caller's authorized snapshot.
// Deleted/expired rows are included so clients can reconcile tombstones.
func getPendingMessagesWithQuery(ctx context.Context, query rosterQuerier, conversationID, userID string, after time.Time, afterID string, limit int) ([]Message, error) {
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

	rows, err := query.Query(ctx,
		`SELECT m.id, m.conversation_id, m.sender_id,
		        u.identity_key, u.signing_key,
		        m.ciphertext, m.header, m.msg_type, m.reply_to_id, m.expires_at,
		        m.edited_at, m.is_deleted, m.created_at,
		        m.crypto_profile, m.crypto_era, m.roster_version,
		        m.roster_commitment, m.sender_device_id, m.sender_binding_version
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

	var msgs []Message
	for rows.Next() {
		var m Message
		var profile *string
		var era, rosterVersion, senderBindingVersion *int64
		var rosterCommitment, senderDeviceID []byte
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.SenderID,
			&m.SenderIdentityKey, &m.SenderSigningKey, &m.Ciphertext, &m.Header,
			&m.MsgType, &m.ReplyToID, &m.ExpiresAt, &m.EditedAt, &m.IsDeleted, &m.CreatedAt,
			&profile, &era, &rosterVersion, &rosterCommitment, &senderDeviceID, &senderBindingVersion,
		); err != nil {
			rows.Close()
			return nil, err
		}
		if profile != nil || era != nil || rosterVersion != nil || rosterCommitment != nil ||
			senderDeviceID != nil || senderBindingVersion != nil {
			if profile == nil || era == nil || rosterVersion == nil || len(rosterCommitment) != 32 ||
				len(senderDeviceID) != 16 || senderBindingVersion == nil || *era <= 0 ||
				*rosterVersion <= 0 || *senderBindingVersion <= 0 {
				return nil, ErrMessageSecurityContext
			}
			m.SecurityContext = &MessageSecurityContext{
				CryptoProfile:        *profile,
				CryptoEra:            uint64(*era),
				RosterVersion:        uint64(*rosterVersion),
				RosterCommitment:     append([]byte(nil), rosterCommitment...),
				SenderDeviceID:       append([]byte(nil), senderDeviceID...),
				SenderBindingVersion: uint64(*senderBindingVersion),
			}
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	return msgs, nil
}

// getAttachmentsForMessagesWithQuery is intentionally transaction-scoped;
// callers cannot fetch wrapped attachment keys without an authorized history
// snapshot. The referenced tus row must still exist.
func getAttachmentsForMessagesWithQuery(ctx context.Context, query rosterQuerier, messageIDs []string) ([]MessageAttachment, error) {
	if len(messageIDs) == 0 {
		return []MessageAttachment{}, nil
	}
	rows, err := query.Query(ctx,
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
		`UPDATE messages message
		 SET ciphertext = $1, header = $2, edited_at = now()
		 FROM conversations conversation
		 WHERE message.id = $3::uuid
		   AND message.sender_id = $4::uuid
		   AND message.conversation_id = $5::uuid
		   AND message.is_deleted = false
		   AND conversation.id = message.conversation_id
		   AND conversation.conv_type = 0
		 RETURNING message.conversation_id, message.edited_at`,
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
			candidate.Members, err = db.GetConversationMemberBindingsForRequester(
				ctx, candidate.ID, userID, ChannelReadPermissions,
			)
			if errors.Is(err, ErrConversationAccessDenied) {
				continue
			}
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

type GroupMemberLocator struct {
	UserID      string
	IdentityKey []byte
}

// CreateGroup creates a group conversation and adds the creator as owner.
func (db *DB) CreateGroup(ctx context.Context, name string, creatorUserID string) (string, error) {
	return db.CreateGroupWithMembers(ctx, name, creatorUserID, nil)
}

// CreateGroupWithMembers commits the Circle and its complete initial roster as
// one transaction. Every selected account is pinned by user ID + identity key;
// a stale or cross-origin locator aborts instead of creating an orphan Circle.
func (db *DB) CreateGroupWithMembers(ctx context.Context, name string, creatorUserID string, members []GroupMemberLocator) (string, error) {
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
	for _, member := range members {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid AND identity_key=$2)`,
			member.UserID, member.IdentityKey,
		).Scan(&exists); err != nil {
			return "", fmt.Errorf("validate initial Circle member: %w", err)
		}
		if !exists {
			return "", errors.New("initial Circle member locator is not authoritative")
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO conversation_members (conversation_id, user_id, role)
			 VALUES ($1, $2::uuid, 0)`, convID, member.UserID,
		); err != nil {
			return "", fmt.Errorf("add initial Circle member: %w", err)
		}
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

func (db *DB) storeSenderKeyWrites(ctx context.Context, convID, ownerDeviceID string, generation uint32, writes []senderKeyWrite) error {
	if convID == "" || ownerDeviceID == "" || len(writes) == 0 || generation == 0 {
		return errors.New("invalid sender key distribution")
	}
	deviceRouted := writes[0].deviceRouted
	for _, write := range writes[1:] {
		if write.deviceRouted != deviceRouted {
			return errors.New("mixed sender key routing modes")
		}
	}
	if deviceRouted {
		targets := make(map[string]struct{}, len(writes))
		for _, write := range writes {
			if write.targetDeviceID == "" {
				return errors.New("target device id required")
			}
			targets[write.targetDeviceID] = struct{}{}
		}
		orderedTargets := make([]string, 0, len(targets))
		for targetDeviceID := range targets {
			orderedTargets = append(orderedTargets, targetDeviceID)
		}
		sort.Strings(orderedTargets)
		for _, targetDeviceID := range orderedTargets {
			if err := db.pruneUnauthorizedSenderKeyTarget(ctx, targetDeviceID); err != nil {
				return err
			}
		}
	}
	attempts := 1
	if deviceRouted {
		attempts = 3
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		lastErr = db.storeSenderKeyWritesOnce(
			ctx, convID, ownerDeviceID, generation, writes, deviceRouted,
		)
		if !isSenderKeySerializationFailure(lastErr) {
			return lastErr
		}
	}
	return ErrSenderKeyRosterChanged
}

func (db *DB) storeSenderKeyWritesOnce(ctx context.Context, convID, ownerDeviceID string, generation uint32, writes []senderKeyWrite, deviceRouted bool) error {
	txOptions := pgx.TxOptions{}
	if deviceRouted {
		// Predicate reads over membership, devices, bindings, roles, and
		// overwrites must conflict with concurrent roster mutations. Row locks
		// alone cannot protect against a newly inserted device or overwrite.
		txOptions.IsoLevel = pgx.Serializable
	}
	tx, err := db.Pool.BeginTx(ctx, txOptions)
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
	var secureRoster *ConversationDeviceRoster
	if deviceRouted {
		deviceIDs := make([]string, 0, len(writes)+1)
		deviceIDs = append(deviceIDs, ownerDeviceID)
		for _, write := range writes {
			deviceIDs = append(deviceIDs, write.targetDeviceID)
		}
		rows, err := tx.Query(ctx,
			`SELECT id::text FROM devices
			 WHERE id = ANY($1::uuid[])
			 ORDER BY id
			 FOR UPDATE`,
			deviceIDs,
		)
		if err != nil {
			return err
		}
		locked := 0
		for rows.Next() {
			var ignored string
			if err := rows.Scan(&ignored); err != nil {
				rows.Close()
				return err
			}
			locked++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		uniqueDevices := make(map[string]struct{}, len(deviceIDs))
		for _, deviceID := range deviceIDs {
			uniqueDevices[deviceID] = struct{}{}
		}
		if locked != len(uniqueDevices) {
			return ErrSenderKeyRosterChanged
		}
		secureRoster, err = resolveConversationDeviceRosterSnapshot(
			ctx, tx, convID, RequiredChannelCapabilities,
		)
		if err != nil {
			return err
		}
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
		if write.deviceRouted {
			if err := validateSenderKeyRouteSnapshot(
				ctx, tx, secureRoster, convID, ownerDeviceID, targetDeviceID, write,
			); err != nil {
				return err
			}
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
			if write.deviceRouted {
				if err := enforceSenderKeyRetentionAdmission(ctx, tx, convID, ownerDeviceID, targetDeviceID, len(write.encryptedKey)); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO sender_key_heads (
				   conversation_id, owner_device_id, target_device_id,
				   max_generation, max_commitment
				 ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5)`,
				convID, ownerDeviceID, targetDeviceID, int64(generation), headCommitment[:],
			); err != nil {
				return fmt.Errorf("create sender key target head: %w", err)
			}
		case err != nil:
			return fmt.Errorf("lookup sender key target head: %w", err)
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
				// resurrect control state already acknowledged or pruned by an
				// explicit target-device eligibility transition.
				continue
			}
			if err != nil {
				return fmt.Errorf("verify retained sender key target: %w", err)
			}
			if !senderKeyWriteMatches(write, retainedKey, retainedCommitment,
				retainedRosterVersion, retainedRosterCommitment,
				retainedOwnerBindingVersion, retainedTargetBindingVersion) {
				return ErrSenderKeyGenerationConflict
			}
			continue
		default:
			if write.deviceRouted {
				if err := enforceSenderKeyRetentionAdmission(ctx, tx, convID, ownerDeviceID, targetDeviceID, len(write.encryptedKey)); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx,
				`UPDATE sender_key_heads
				 SET max_generation = $4, max_commitment = $5, updated_at = now()
				 WHERE conversation_id = $1::uuid
				   AND owner_device_id = $2::uuid
				   AND target_device_id = $3::uuid`,
				convID, ownerDeviceID, targetDeviceID, int64(generation), headCommitment[:],
			); err != nil {
				return fmt.Errorf("advance sender key target head: %w", err)
			}
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO sender_keys (
			   conversation_id, owner_device_id, target_device_id,
			   encrypted_key, generation, envelope_commitment, roster_version,
			   roster_commitment, owner_binding_version, target_binding_version,
			   expires_at
			 ) VALUES (
			   $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9, $10,
			   now() + ($11 * INTERVAL '1 second')
			 )
			 ON CONFLICT (conversation_id, owner_device_id, target_device_id, generation)
			 DO NOTHING`,
			convID, ownerDeviceID, targetDeviceID, write.encryptedKey, int64(generation),
			envelopeCommitment[:], nullableSenderKeyRoute(write.rosterVersion, write.deviceRouted),
			nullableSenderKeyBytes(write.rosterCommitment, write.deviceRouted),
			nullableSenderKeyRoute(write.ownerBindingVersion, write.deviceRouted),
			nullableSenderKeyRoute(write.targetBindingVersion, write.deviceRouted),
			int64(SenderKeyReceiptTTL/time.Second),
		); err != nil {
			return fmt.Errorf("store sender key target: %w", err)
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
			return fmt.Errorf("verify retained sender key target: %w", err)
		}
		if !senderKeyWriteMatches(write, retainedKey, retainedCommitment,
			retainedRosterVersion, retainedRosterCommitment,
			retainedOwnerBindingVersion, retainedTargetBindingVersion) {
			return ErrSenderKeyGenerationConflict
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func validateSenderKeyRouteSnapshot(ctx context.Context, tx pgx.Tx, roster *ConversationDeviceRoster, conversationID, ownerDeviceID, targetDeviceID string, write senderKeyWrite) error {
	if roster == nil || !roster.Ready || roster.Version != write.rosterVersion ||
		!bytes.Equal(roster.Commitment[:], write.rosterCommitment) ||
		ownerDeviceID == "" || targetDeviceID == "" || ownerDeviceID == targetDeviceID {
		return ErrSenderKeyRosterChanged
	}
	var ownerMemberID string
	ownerFound, targetFound := false, false
	for memberIndex := range roster.Members {
		member := &roster.Members[memberIndex]
		for deviceIndex := range member.Devices {
			device := &member.Devices[deviceIndex]
			if device.DeviceID != ownerDeviceID && device.DeviceID != targetDeviceID {
				continue
			}
			if !device.Eligible || device.Binding == nil ||
				device.Binding.Status != DeviceBindingActive ||
				device.Binding.Capabilities&RequiredChannelCapabilities != RequiredChannelCapabilities {
				return ErrSenderKeyRosterChanged
			}
			switch device.DeviceID {
			case ownerDeviceID:
				if device.Binding.Version != write.ownerBindingVersion {
					return ErrSenderKeyRosterChanged
				}
				ownerMemberID = member.UserID
				ownerFound = true
			case targetDeviceID:
				if device.Binding.Version != write.targetBindingVersion {
					return ErrSenderKeyRosterChanged
				}
				targetFound = true
			}
		}
	}
	if !ownerFound || !targetFound {
		return ErrSenderKeyRosterChanged
	}
	canSend, err := canAccessConversationWithQuery(
		ctx, tx, conversationID, ownerMemberID,
		ChannelReadPermissions|PermSendMessages,
	)
	if err != nil {
		return err
	}
	if !canSend {
		return ErrSenderKeyRosterChanged
	}
	return nil
}

// WithCurrentSenderKeyRoute holds the conversation's common roster revision
// lock while revalidating and publishing one already-durable distribution.
// Roster mutations therefore linearize either before the callback (which is
// skipped) or after it (and may then prune the retained row).
func (db *DB) WithCurrentSenderKeyRoute(ctx context.Context, conversationID, ownerDeviceID, targetDeviceID string, rosterVersion uint64, rosterCommitment []byte, ownerBindingVersion, targetBindingVersion uint64, publish func() error) error {
	if conversationID == "" || ownerDeviceID == "" || targetDeviceID == "" ||
		rosterVersion == 0 || rosterVersion > math.MaxInt64 || len(rosterCommitment) != 32 ||
		ownerBindingVersion == 0 || ownerBindingVersion > math.MaxInt64 ||
		targetBindingVersion == 0 || targetBindingVersion > math.MaxInt64 || publish == nil {
		return ErrSenderKeyRosterChanged
	}
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`SELECT id FROM conversations WHERE id = $1::uuid FOR UPDATE`, conversationID,
	); err != nil {
		return err
	}
	roster, err := resolveConversationDeviceRosterSnapshot(
		ctx, tx, conversationID, RequiredChannelCapabilities,
	)
	if err != nil {
		return err
	}
	if err := validateSenderKeyRouteSnapshot(
		ctx, tx, roster, conversationID, ownerDeviceID, targetDeviceID,
		senderKeyWrite{
			targetDeviceID:       targetDeviceID,
			rosterVersion:        rosterVersion,
			rosterCommitment:     rosterCommitment,
			ownerBindingVersion:  ownerBindingVersion,
			targetBindingVersion: targetBindingVersion,
			deviceRouted:         true,
		},
	); err != nil {
		return err
	}
	if err := publish(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DiscardDeviceSenderKey removes only the stale pending envelope created by a
// route that changed between durable admission and publication. The stream
// head remains the rollback barrier, so the sender must correct with a newer
// generation for the new roster.
func (db *DB) DiscardDeviceSenderKey(ctx context.Context, conversationID, ownerDeviceID, targetDeviceID string, generation uint32, rosterVersion uint64, envelopeCommitment []byte) error {
	if conversationID == "" || ownerDeviceID == "" || targetDeviceID == "" ||
		generation == 0 || rosterVersion == 0 || rosterVersion > math.MaxInt64 ||
		len(envelopeCommitment) != 32 {
		return ErrSenderKeyReceiptMismatch
	}
	_, err := db.Pool.Exec(ctx,
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
	return err
}

func isSenderKeySerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "40001" || pgErr.Code == "40P01")
}

// pruneUnauthorizedSenderKeyTarget removes retained envelopes only after the
// exact target account has lost current channel-read authorization. It locks
// every affected conversation and its common roster revision in canonical
// order, so an ACL mutation linearizes wholly before or after the decision.
// Stream heads are deliberately untouched: re-admission is future-only and
// therefore requires a newer generation for the newer roster commitment.
func (db *DB) pruneUnauthorizedSenderKeyTarget(ctx context.Context, targetDeviceID string) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		lastErr = db.pruneUnauthorizedSenderKeyTargetOnce(ctx, targetDeviceID)
		if !isSenderKeySerializationFailure(lastErr) {
			return lastErr
		}
	}
	return fmt.Errorf("prune unauthorized sender-key target after serialization retries: %w", lastErr)
}

func (db *DB) pruneUnauthorizedSenderKeyTargetOnce(ctx context.Context, targetDeviceID string) error {
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx,
		`SELECT DISTINCT conversation_id::text
		 FROM sender_keys
		 WHERE target_device_id = $1::uuid
		 ORDER BY conversation_id::text
		 LIMIT $2`,
		targetDeviceID, MaxPendingSenderKeyRowsPerTarget+1,
	)
	if err != nil {
		return err
	}
	conversationIDs := make([]string, 0)
	for rows.Next() {
		var conversationID string
		if err := rows.Scan(&conversationID); err != nil {
			rows.Close()
			return err
		}
		conversationIDs = append(conversationIDs, conversationID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(conversationIDs) > MaxPendingSenderKeyRowsPerTarget {
		return ErrSenderKeyRestoreBacklogExceeded
	}
	if len(conversationIDs) == 0 {
		return tx.Commit(ctx)
	}

	rows, err = tx.Query(ctx,
		`SELECT id::text
		 FROM conversations
		 WHERE id = ANY($1::uuid[])
		 ORDER BY id
		 FOR UPDATE`,
		conversationIDs,
	)
	if err != nil {
		return err
	}
	lockedConversations := make([]string, 0, len(conversationIDs))
	for rows.Next() {
		var conversationID string
		if err := rows.Scan(&conversationID); err != nil {
			rows.Close()
			return err
		}
		lockedConversations = append(lockedConversations, conversationID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(lockedConversations) == 0 {
		return tx.Commit(ctx)
	}

	var targetUserID string
	if err := tx.QueryRow(ctx,
		`SELECT user_id::text FROM devices
		 WHERE id = $1::uuid FOR SHARE`,
		targetDeviceID,
	).Scan(&targetUserID); err != nil {
		return err
	}

	rows, err = tx.Query(ctx,
		`SELECT conversation_id::text
		 FROM conversation_roster_revisions
		 WHERE conversation_id = ANY($1::uuid[])
		 ORDER BY conversation_id
		 FOR UPDATE`,
		lockedConversations,
	)
	if err != nil {
		return err
	}
	lockedRevisions := 0
	for rows.Next() {
		var ignored string
		if err := rows.Scan(&ignored); err != nil {
			rows.Close()
			return err
		}
		lockedRevisions++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if lockedRevisions != len(lockedConversations) {
		return ErrSenderKeyRosterChanged
	}

	for _, conversationID := range lockedConversations {
		allowed, err := canAccessConversationWithQuery(
			ctx, tx, conversationID, targetUserID, ChannelReadPermissions,
		)
		if err != nil {
			return err
		}
		if allowed {
			continue
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM sender_keys
			 WHERE conversation_id = $1::uuid
			   AND target_device_id = $2::uuid`,
			conversationID, targetDeviceID,
		); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func enforceSenderKeyRetentionAdmission(ctx context.Context, tx pgx.Tx, conversationID, ownerDeviceID, targetDeviceID string, prospectiveBytes int) error {
	var targetRows, targetBytes int64
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(octet_length(encrypted_key)), 0)
		 FROM sender_keys
		 WHERE target_device_id = $1::uuid`,
		targetDeviceID,
	).Scan(&targetRows, &targetBytes); err != nil {
		return fmt.Errorf("check target sender key backlog: %w", err)
	}
	if prospectiveBytes <= 0 || targetRows >= MaxPendingSenderKeyRowsPerTarget ||
		targetBytes+int64(prospectiveBytes) > MaxPendingSenderKeyBytesPerTarget {
		return ErrSenderKeyTargetBacklogFull
	}
	var pending int64
	var expired bool
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(bool_or(expires_at <= now()), false)
		 FROM sender_keys
		 WHERE conversation_id = $1::uuid
		   AND owner_device_id = $2::uuid
		   AND target_device_id = $3::uuid
		   AND roster_version IS NOT NULL`,
		conversationID, ownerDeviceID, targetDeviceID,
	).Scan(&pending, &expired); err != nil {
		return fmt.Errorf("check sender key retention: %w", err)
	}
	// Never discard an unacknowledged generation to make room. Expiry and the
	// hard cap both keep the sender's durable ACK gate closed until an exact
	// device receipt arrives or the device is explicitly excluded/revoked.
	if expired {
		return ErrSenderKeyRetentionExpired
	}
	if pending >= MaxPendingSenderKeyGenerationsPerStream {
		return ErrSenderKeyRetentionFull
	}
	return nil
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

// SenderKeyConversationBacklog is bounded metadata used by pre-auth restore
// to decide which conversations are safe to materialize. Ciphertext is loaded
// only after the gateway confirms that this conversation's current roster is
// ready, so one expired/not-ready/oversized group cannot consume the global
// restore budget or prevent DMs and healthy groups from starting.
type SenderKeyConversationBacklog struct {
	ConversationID  string
	TargetUserID    string
	Rows            int64
	Bytes           int64
	Expired         bool
	LegacyOrPartial bool
}

// ListPendingSenderKeyConversations returns aggregate metadata only. It never
// acknowledges or removes retained rows; committed target authorization loss
// remains the sole pruning step performed before this snapshot.
func (db *DB) ListPendingSenderKeyConversations(ctx context.Context, targetDeviceID string) ([]SenderKeyConversationBacklog, error) {
	if targetDeviceID == "" {
		return nil, ErrSenderKeyRestoreBacklogExceeded
	}
	if err := db.pruneUnauthorizedSenderKeyTarget(ctx, targetDeviceID); err != nil {
		return nil, err
	}
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var lockedDevice string
	if err := tx.QueryRow(ctx,
		`SELECT id::text FROM devices WHERE id = $1::uuid FOR SHARE`, targetDeviceID,
	).Scan(&lockedDevice); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx,
		`SELECT sender_key.conversation_id::text, target_device.user_id::text,
		        COUNT(*), COALESCE(SUM(octet_length(sender_key.encrypted_key)), 0),
		        COALESCE(bool_or(sender_key.expires_at <= now()), FALSE),
		        COALESCE(bool_or(
		          sender_key.roster_version IS NULL
		          OR sender_key.roster_commitment IS NULL
		          OR sender_key.owner_binding_version IS NULL
		          OR sender_key.target_binding_version IS NULL
		        ), FALSE)
		 FROM sender_keys AS sender_key
		 JOIN conversations AS conversation
		   ON conversation.id = sender_key.conversation_id
		  AND conversation.conv_type IN (1, 2)
		 JOIN devices AS target_device ON target_device.id = sender_key.target_device_id
		 WHERE sender_key.target_device_id = $1::uuid
		 GROUP BY sender_key.conversation_id, target_device.user_id
		 ORDER BY sender_key.conversation_id
		 LIMIT $2`,
		targetDeviceID, MaxPendingSenderKeyRowsPerTarget+1,
	)
	if err != nil {
		return nil, err
	}
	backlogs := make([]SenderKeyConversationBacklog, 0)
	for rows.Next() {
		var backlog SenderKeyConversationBacklog
		if err := rows.Scan(
			&backlog.ConversationID, &backlog.TargetUserID,
			&backlog.Rows, &backlog.Bytes,
			&backlog.Expired, &backlog.LegacyOrPartial,
		); err != nil {
			rows.Close()
			return nil, err
		}
		backlogs = append(backlogs, backlog)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(backlogs) > MaxPendingSenderKeyRowsPerTarget {
		return nil, ErrSenderKeyRestoreBacklogExceeded
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return backlogs, nil
}

type SenderKeyConversationRestore struct {
	Roster *ConversationDeviceRoster
	Rows   []SenderKeyRow
}

// LoadPendingSenderKeyConversation atomically resolves current readiness,
// verifies the exact authenticated target device/head, and only then
// materializes one all-or-nothing retained suffix. Roster or binding mutation
// cannot land between those decisions and the ciphertext read.
func (db *DB) LoadPendingSenderKeyConversation(ctx context.Context, targetDeviceID string, targetDeviceKey []byte, targetBindingVersion uint64, conversationID string, maxRows, maxBytes int64) (*SenderKeyConversationRestore, error) {
	if targetDeviceID == "" || len(targetDeviceKey) != 16 || targetBindingVersion == 0 ||
		targetBindingVersion > math.MaxInt64 || conversationID == "" ||
		maxRows <= 0 || maxBytes <= 0 || maxRows > MaxPendingSenderKeyRowsPerTarget ||
		maxBytes > MaxPendingSenderKeyBytesPerTarget {
		return nil, ErrSenderKeyRestoreBacklogExceeded
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		restore, err := db.loadPendingSenderKeyConversationOnce(
			ctx, targetDeviceID, targetDeviceKey, targetBindingVersion,
			conversationID, maxRows, maxBytes,
		)
		if !isSenderKeySerializationFailure(err) {
			return restore, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("load sender-key conversation after serialization retries: %w", lastErr)
}

func (db *DB) loadPendingSenderKeyConversationOnce(ctx context.Context, targetDeviceID string, targetDeviceKey []byte, targetBindingVersion uint64, conversationID string, maxRows, maxBytes int64) (*SenderKeyConversationRestore, error) {
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var conversationType int16
	if err := tx.QueryRow(ctx,
		`SELECT conv_type FROM conversations
		 WHERE id = $1::uuid FOR UPDATE`, conversationID,
	).Scan(&conversationType); err != nil {
		return nil, err
	}
	if conversationType != 1 && conversationType != 2 {
		return nil, ErrSenderKeyConversationType
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO conversation_roster_revisions (conversation_id)
		 VALUES ($1::uuid) ON CONFLICT (conversation_id) DO NOTHING`, conversationID,
	); err != nil {
		return nil, err
	}
	var mutationRevision int64
	if err := tx.QueryRow(ctx,
		`SELECT mutation_revision FROM conversation_roster_revisions
		 WHERE conversation_id = $1::uuid FOR UPDATE`, conversationID,
	).Scan(&mutationRevision); err != nil {
		return nil, err
	}
	roster, err := buildConversationDeviceRoster(
		ctx, tx, conversationID, RequiredChannelCapabilities,
	)
	if err != nil {
		return nil, err
	}
	roster.Version, err = recordConversationRosterCommitmentTx(
		ctx, tx, conversationID, roster.Commitment, mutationRevision,
	)
	if err != nil {
		return nil, err
	}
	if !roster.Ready || !rosterHasExactRestoreTarget(
		roster, targetDeviceID, targetDeviceKey, targetBindingVersion,
	) {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, ErrSenderKeyConversationUnavailable
	}

	var totalRows, totalBytes int64
	var expired, legacyOrPartial bool
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(octet_length(encrypted_key)), 0),
		        COALESCE(bool_or(expires_at <= now()), FALSE),
		        COALESCE(bool_or(
		          roster_version IS NULL OR roster_commitment IS NULL
		          OR owner_binding_version IS NULL OR target_binding_version IS NULL
		        ), FALSE)
		 FROM sender_keys
		 WHERE target_device_id = $1::uuid
		   AND conversation_id = $2::uuid`,
		targetDeviceID, conversationID,
	).Scan(&totalRows, &totalBytes, &expired, &legacyOrPartial); err != nil {
		return nil, err
	}
	if legacyOrPartial {
		return nil, ErrSenderKeyLegacyState
	}
	if expired {
		return nil, ErrSenderKeyRetentionExpired
	}
	if totalRows == 0 {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &SenderKeyConversationRestore{Roster: roster, Rows: []SenderKeyRow{}}, nil
	}
	if totalRows > maxRows || totalBytes > maxBytes {
		return nil, ErrSenderKeyRestoreBacklogExceeded
	}
	rows, err := tx.Query(ctx,
		`SELECT sender_key.conversation_id, sender_key.owner_device_id,
		        sender_key.target_device_id, target_device.user_id,
		        sender_key.encrypted_key, sender_key.generation,
		        sender_key.roster_version, sender_key.roster_commitment,
		        sender_key.owner_binding_version, sender_key.target_binding_version,
		        sender_key.envelope_commitment,
		        sender_key.created_at, sender_key.expires_at
		 FROM sender_keys AS sender_key
		 JOIN devices AS target_device ON target_device.id = sender_key.target_device_id
		 JOIN devices AS owner_device ON owner_device.id = sender_key.owner_device_id
		 WHERE sender_key.target_device_id = $1::uuid
		   AND sender_key.conversation_id = $2::uuid
		 ORDER BY sender_key.owner_device_id, sender_key.generation
		 LIMIT $3`,
		targetDeviceID, conversationID, maxRows+1,
	)
	if err != nil {
		return nil, err
	}
	keys := make([]SenderKeyRow, 0, int(totalRows))
	for rows.Next() {
		var key SenderKeyRow
		var rosterVersion, ownerBindingVersion, targetBindingVersion int64
		if err := rows.Scan(
			&key.ConversationID, &key.OwnerDeviceID, &key.TargetDeviceID,
			&key.TargetUserID, &key.EncryptedKey, &key.Generation,
			&rosterVersion, &key.RosterCommitment,
			&ownerBindingVersion, &targetBindingVersion,
			&key.EnvelopeCommitment, &key.CreatedAt, &key.ExpiresAt,
		); err != nil {
			rows.Close()
			return nil, err
		}
		if rosterVersion <= 0 || ownerBindingVersion <= 0 || targetBindingVersion <= 0 {
			rows.Close()
			return nil, ErrSenderKeyLegacyState
		}
		key.RosterVersion = uint64(rosterVersion)
		key.OwnerBindingVersion = uint64(ownerBindingVersion)
		key.TargetBindingVersion = uint64(targetBindingVersion)
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if int64(len(keys)) != totalRows || int64(len(keys)) > maxRows {
		return nil, ErrSenderKeyRestoreBacklogExceeded
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &SenderKeyConversationRestore{Roster: roster, Rows: keys}, nil
}

func rosterHasExactRestoreTarget(roster *ConversationDeviceRoster, targetDeviceID string, targetDeviceKey []byte, targetBindingVersion uint64) bool {
	if roster == nil || !roster.Ready {
		return false
	}
	for memberIndex := range roster.Members {
		member := &roster.Members[memberIndex]
		for deviceIndex := range member.Devices {
			device := &member.Devices[deviceIndex]
			if device.DeviceID == targetDeviceID {
				return device.Eligible && device.Binding != nil &&
					device.Binding.Status == DeviceBindingActive &&
					device.Binding.Capabilities&RequiredChannelCapabilities == RequiredChannelCapabilities &&
					device.Binding.Version == targetBindingVersion &&
					bytes.Equal(device.DeviceKey, targetDeviceKey) &&
					bytes.Equal(device.Binding.DeviceKey, targetDeviceKey)
			}
		}
	}
	return false
}

// GetPendingSenderKeys returns sender keys addressed to a specific device.
func (db *DB) GetPendingSenderKeys(ctx context.Context, targetDeviceID string) ([]SenderKeyRow, error) {
	if targetDeviceID == "" {
		return nil, ErrSenderKeyRestoreBacklogExceeded
	}
	if err := db.pruneUnauthorizedSenderKeyTarget(ctx, targetDeviceID); err != nil {
		return nil, err
	}
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var lockedDevice string
	if err := tx.QueryRow(ctx,
		`SELECT id::text FROM devices WHERE id = $1::uuid FOR SHARE`, targetDeviceID,
	).Scan(&lockedDevice); err != nil {
		return nil, err
	}
	var totalRows, totalBytes int64
	var expired, legacyOrPartial bool
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(octet_length(encrypted_key)), 0),
		        COALESCE(bool_or(expires_at <= now()), FALSE),
		        COALESCE(bool_or(
		          roster_version IS NULL OR roster_commitment IS NULL
		          OR owner_binding_version IS NULL OR target_binding_version IS NULL
		        ), FALSE)
		 FROM sender_keys WHERE target_device_id = $1::uuid`,
		targetDeviceID,
	).Scan(&totalRows, &totalBytes, &expired, &legacyOrPartial); err != nil {
		return nil, err
	}
	if legacyOrPartial {
		return nil, ErrSenderKeyLegacyState
	}
	if expired {
		// Expiry is an explicit history-unavailable boundary. Never deliver a
		// partial suffix or silently collect the evidence needed to explain why
		// older ciphertext can no longer be decrypted.
		return nil, ErrSenderKeyRetentionExpired
	}
	if totalRows > MaxPendingSenderKeyRowsPerTarget || totalBytes > MaxPendingSenderKeyBytesPerTarget {
		return nil, ErrSenderKeyRestoreBacklogExceeded
	}
	rows, err := tx.Query(ctx,
		`SELECT sk.conversation_id, sk.owner_device_id, sk.target_device_id,
		        target_device.user_id, sk.encrypted_key, sk.generation,
		        COALESCE(sk.roster_version, 0), COALESCE(sk.roster_commitment, ''::bytea),
		        COALESCE(sk.owner_binding_version, 0), COALESCE(sk.target_binding_version, 0),
		        sk.envelope_commitment, sk.created_at, sk.expires_at
		 FROM sender_keys sk
		 JOIN conversations conversation ON conversation.id = sk.conversation_id AND conversation.conv_type IN (1, 2)
		 JOIN devices target_device ON target_device.id = sk.target_device_id
		 JOIN devices owner_device ON owner_device.id = sk.owner_device_id
		 JOIN conversation_members target_member
		   ON target_member.conversation_id = sk.conversation_id
		  AND target_member.user_id = target_device.user_id
		 WHERE sk.target_device_id = $1::uuid
		 ORDER BY sk.conversation_id, sk.owner_device_id, sk.generation
		 LIMIT $2`,
		targetDeviceID, MaxPendingSenderKeyRowsPerTarget+1,
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
			&k.EnvelopeCommitment, &k.CreatedAt, &k.ExpiresAt); err != nil {
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
	if len(keys) > MaxPendingSenderKeyRowsPerTarget {
		return nil, ErrSenderKeyRestoreBacklogExceeded
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	authorized := keys[:0]
	authorizationByConversation := make(map[string]bool)
	for _, key := range keys {
		allowed, checked := authorizationByConversation[key.ConversationID]
		if !checked {
			var err error
			allowed, err = db.CanAccessConversation(ctx, key.ConversationID, key.TargetUserID, ChannelReadPermissions)
			if err != nil {
				return nil, err
			}
			authorizationByConversation[key.ConversationID] = allowed
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
	CreatedAt            time.Time
	ExpiresAt            time.Time
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

// getReactionsForMessagesWithQuery remains inside the authorized history
// transaction so related metadata cannot cross a committed revoke boundary.
func getReactionsForMessagesWithQuery(ctx context.Context, query rosterQuerier, messageIDs []string) ([]Reaction, error) {
	if len(messageIDs) == 0 {
		return []Reaction{}, nil
	}
	rows, err := query.Query(ctx,
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
