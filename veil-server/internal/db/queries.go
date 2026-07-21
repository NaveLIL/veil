package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
	"github.com/google/uuid"
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
	ErrMessageSendIDConflict            = errors.New("client message id already has different send bytes")
	ErrConversationAccessDenied         = errors.New("conversation access denied")
	ErrReactionLimitReached             = errors.New("message reaction limit reached")
	ErrPreKeyMaterialConflict           = errors.New("prekey protocol id already has different key material")
	ErrPreKeyLiveStateFull              = errors.New("prekey live-state capacity reached")
)

// Publication state is constant per device: one current SPK, at most one
// hundred live OPKs, and one high-watermark/idempotency receipt row. The
// account caps bound malicious device proliferation without imposing a
// lifetime limit on legitimate monotonic rotations of an existing device.
const (
	MaxUnusedOneTimePreKeysPerDevice = 100
	MaxPreKeyDevicesPerAccount       = 128
	MaxPreKeyRowsPerAccount          = MaxPreKeyDevicesPerAccount * (1 + MaxUnusedOneTimePreKeysPerDevice)
)

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

// MaxReactionsPerMessage is the shared server/mobile history bound. Admission
// is serialized per message in AddReaction so a committed row can never make
// the strict mobile history parser observe a larger set.
const MaxReactionsPerMessage = 256

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

// PreKeyUploadReceipt is the bounded acknowledgement persisted for the latest
// accepted canonical batch. Replay is process-local metadata and is not stored.
type PreKeyUploadReceipt struct {
	Stored int
	Replay bool
}

type validatedPreKeyBatch struct {
	keys       []PreKey
	signed     PreKey
	oneTime    []PreKey
	digest     [sha256.Size]byte
	maxOneTime uint32
}

type preKeyPublicationState struct {
	signedHighWatermark  uint32
	oneTimeHighWatermark uint32
	latestDigest         []byte
	latestStored         int
}

// StorePreKeys preserves the pre-receipt API for internal callers.
func (db *DB) StorePreKeys(ctx context.Context, deviceID string, keys []PreKey) error {
	batch, err := validatePreKeyBatch(keys)
	if err != nil {
		return err
	}
	digest := digestInternalPreKeyBatch(deviceID, batch.keys)
	_, err = db.storePreKeysWithReceipt(ctx, deviceID, batch, digest)
	return err
}

// StorePreKeysWithReceipt atomically publishes a monotonic prekey batch.
//
// Only the latest exact validated upload bytes are replayable. Their digest
// remains after the corresponding OPKs are claimed and compacted, so a lost
// HTTP ACK can be retried indefinitely without resurrecting an OPK. Any
// non-latest protocol id at or below its per-type high watermark is
// permanently retired.
func (db *DB) StorePreKeysWithReceipt(
	ctx context.Context,
	deviceID string,
	keys []PreKey,
	exactUploadDigest [sha256.Size]byte,
) (PreKeyUploadReceipt, error) {
	batch, err := validatePreKeyBatch(keys)
	if err != nil {
		return PreKeyUploadReceipt{}, err
	}
	batch.digest = exactUploadDigest
	return db.storePreKeysWithReceipt(ctx, deviceID, batch, exactUploadDigest)
}

func (db *DB) storePreKeysWithReceipt(
	ctx context.Context,
	deviceID string,
	batch validatedPreKeyBatch,
	exactUploadDigest [sha256.Size]byte,
) (PreKeyUploadReceipt, error) {
	batch.digest = exactUploadDigest
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return PreKeyUploadReceipt{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Resolve the owner before taking locks, then serialize every publication
	// for that account by locking the user first and the target device second.
	// A stable user -> device lock order makes the account-wide quota exact
	// even when separate devices publish concurrently, while the device lock
	// preserves one stable view for retries and unused-key pruning.
	var ownerID string
	if err := tx.QueryRow(ctx,
		`SELECT user_id FROM devices WHERE id = $1::uuid`,
		deviceID,
	).Scan(&ownerID); err != nil {
		return PreKeyUploadReceipt{}, fmt.Errorf("resolve prekey device owner: %w", err)
	}
	var lockedOwnerID string
	if err := tx.QueryRow(ctx,
		`SELECT id FROM users WHERE id = $1::uuid FOR UPDATE`,
		ownerID,
	).Scan(&lockedOwnerID); err != nil {
		return PreKeyUploadReceipt{}, fmt.Errorf("lock prekey owner: %w", err)
	}
	var lockedDeviceID, lockedDeviceOwnerID string
	if err := tx.QueryRow(ctx,
		`SELECT id, user_id FROM devices WHERE id = $1::uuid FOR UPDATE`,
		deviceID,
	).Scan(&lockedDeviceID, &lockedDeviceOwnerID); err != nil {
		return PreKeyUploadReceipt{}, fmt.Errorf("lock prekey device: %w", err)
	}
	if lockedDeviceOwnerID != lockedOwnerID {
		return PreKeyUploadReceipt{}, errors.New("prekey device owner changed while acquiring publication locks")
	}

	stateCreated, state, err := lockPreKeyPublicationState(ctx, tx, deviceID)
	if err != nil {
		return PreKeyUploadReceipt{}, err
	}
	if stateCreated {
		var accountStates int
		if err := tx.QueryRow(ctx,
			`SELECT COUNT(*)
			 FROM prekey_publication_state s
			 JOIN devices d ON d.id = s.device_id
			 WHERE d.user_id = $1::uuid`,
			lockedOwnerID,
		).Scan(&accountStates); err != nil {
			return PreKeyUploadReceipt{}, fmt.Errorf("count account prekey states: %w", err)
		}
		if accountStates > MaxPreKeyDevicesPerAccount {
			return PreKeyUploadReceipt{}, fmt.Errorf(
				"%w: account=%s device_states=%d",
				ErrPreKeyLiveStateFull, lockedOwnerID, accountStates,
			)
		}
	}

	if state.latestDigest != nil && bytes.Equal(state.latestDigest, batch.digest[:]) {
		if state.latestStored != len(batch.keys) {
			return PreKeyUploadReceipt{}, errors.New("persisted prekey receipt size does not match its canonical digest")
		}
		if err := tx.Commit(ctx); err != nil {
			return PreKeyUploadReceipt{}, fmt.Errorf("commit prekey replay: %w", err)
		}
		return PreKeyUploadReceipt{Stored: state.latestStored, Replay: true}, nil
	}

	var accountRowsBefore int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*)
		 FROM prekeys p
		 JOIN devices d ON d.id = p.device_id
		 WHERE d.user_id = $1::uuid`,
		lockedOwnerID,
	).Scan(&accountRowsBefore); err != nil {
		return PreKeyUploadReceipt{}, fmt.Errorf("count account prekeys before publication: %w", err)
	}

	allLegacyOneTimeIDs := true
	for _, key := range batch.oneTime {
		if key.ProtocolKeyID > state.oneTimeHighWatermark {
			allLegacyOneTimeIDs = false
			break
		}
	}
	legacyCandidate := state.latestDigest == nil &&
		state.signedHighWatermark > 0 &&
		batch.signed.ProtocolKeyID <= state.signedHighWatermark &&
		allLegacyOneTimeIDs
	if legacyCandidate {
		exact, verifyErr := verifyLegacyPreKeyBatch(ctx, tx, deviceID, batch, state)
		if verifyErr != nil {
			return PreKeyUploadReceipt{}, verifyErr
		}
		if !exact {
			return PreKeyUploadReceipt{}, preKeyConflict(deviceID, batch.signed.KeyType, batch.signed.ProtocolKeyID)
		}
		if err := compactPublishedPreKeys(ctx, tx, deviceID, batch.signed.ProtocolKeyID); err != nil {
			return PreKeyUploadReceipt{}, err
		}
		if err := persistPreKeyReceipt(
			ctx, tx, deviceID, state.signedHighWatermark, state.oneTimeHighWatermark,
			batch.digest, len(batch.keys),
		); err != nil {
			return PreKeyUploadReceipt{}, err
		}
		if err := enforcePreKeyLiveBounds(ctx, tx, deviceID, lockedOwnerID, accountRowsBefore); err != nil {
			return PreKeyUploadReceipt{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return PreKeyUploadReceipt{}, fmt.Errorf("commit legacy prekey receipt: %w", err)
		}
		return PreKeyUploadReceipt{Stored: len(batch.keys)}, nil
	}

	reuseCurrentSignedPreKey := false
	switch {
	case batch.signed.ProtocolKeyID < state.signedHighWatermark:
		return PreKeyUploadReceipt{}, preKeyConflict(deviceID, batch.signed.KeyType, batch.signed.ProtocolKeyID)
	case batch.signed.ProtocolKeyID == state.signedHighWatermark:
		exact, exactErr := currentSignedPreKeyExact(ctx, tx, deviceID, batch.signed)
		if exactErr != nil {
			return PreKeyUploadReceipt{}, exactErr
		}
		if !exact {
			return PreKeyUploadReceipt{}, preKeyConflict(deviceID, batch.signed.KeyType, batch.signed.ProtocolKeyID)
		}
		reuseCurrentSignedPreKey = true
	}
	for _, key := range batch.oneTime {
		if key.ProtocolKeyID <= state.oneTimeHighWatermark {
			return PreKeyUploadReceipt{}, preKeyConflict(deviceID, key.KeyType, key.ProtocolKeyID)
		}
	}
	hasNewProtocolID := batch.signed.ProtocolKeyID > state.signedHighWatermark || len(batch.oneTime) > 0
	if !hasNewProtocolID {
		// A different HTTP body may not replace the sole durable lost-ACK
		// receipt unless it actually advances publication state.
		return PreKeyUploadReceipt{}, preKeyConflict(deviceID, batch.signed.KeyType, batch.signed.ProtocolKeyID)
	}

	for _, key := range batch.keys {
		if key.KeyType == 0 && reuseCurrentSignedPreKey {
			continue
		}
		commandTag, insertErr := tx.Exec(ctx,
			`INSERT INTO prekeys
			    (device_id, key_type, protocol_key_id, public_key, signature)
			 VALUES ($1::uuid, $2, $3, $4, $5)
			 ON CONFLICT (device_id, key_type, protocol_key_id) DO NOTHING`,
			deviceID, key.KeyType, key.ProtocolKeyID, key.PublicKey, key.Signature,
		)
		if insertErr != nil {
			return PreKeyUploadReceipt{}, fmt.Errorf("insert prekey: %w", insertErr)
		}
		if commandTag.RowsAffected() != 1 {
			return PreKeyUploadReceipt{}, preKeyConflict(deviceID, key.KeyType, key.ProtocolKeyID)
		}
	}

	if err := compactPublishedPreKeys(ctx, tx, deviceID, batch.signed.ProtocolKeyID); err != nil {
		return PreKeyUploadReceipt{}, err
	}
	if err := persistPreKeyReceipt(
		ctx, tx, deviceID, max(state.signedHighWatermark, batch.signed.ProtocolKeyID),
		max(state.oneTimeHighWatermark, batch.maxOneTime), batch.digest, len(batch.keys),
	); err != nil {
		return PreKeyUploadReceipt{}, err
	}
	if err := enforcePreKeyLiveBounds(ctx, tx, deviceID, lockedOwnerID, accountRowsBefore); err != nil {
		return PreKeyUploadReceipt{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PreKeyUploadReceipt{}, fmt.Errorf("commit prekey publication: %w", err)
	}
	return PreKeyUploadReceipt{Stored: len(batch.keys)}, nil
}

const internalPreKeyUploadDigestDomain = "veil-internal-prekey-upload-v1\x00"

func validatePreKeyBatch(keys []PreKey) (validatedPreKeyBatch, error) {
	if len(keys) == 0 || len(keys) > 1001 {
		return validatedPreKeyBatch{}, errors.New("invalid prekey publication batch size or scope")
	}
	canonical := make([]PreKey, 0, len(keys))
	for _, key := range keys {
		copyKey := PreKey{
			KeyType:       key.KeyType,
			ProtocolKeyID: key.ProtocolKeyID,
			PublicKey:     bytes.Clone(key.PublicKey),
			Signature:     bytes.Clone(key.Signature),
		}
		if copyKey.ProtocolKeyID == 0 || len(copyKey.PublicKey) != 32 {
			return validatedPreKeyBatch{}, errors.New("invalid prekey protocol id or public key")
		}
		switch copyKey.KeyType {
		case 0:
			if len(copyKey.Signature) != 64 {
				return validatedPreKeyBatch{}, errors.New("invalid signed prekey signature")
			}
		case 1:
			if len(copyKey.Signature) != 0 {
				return validatedPreKeyBatch{}, errors.New("one-time prekey must not have a signature")
			}
		default:
			return validatedPreKeyBatch{}, errors.New("invalid prekey type")
		}
		canonical = append(canonical, copyKey)
	}
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].KeyType != canonical[j].KeyType {
			return canonical[i].KeyType < canonical[j].KeyType
		}
		return canonical[i].ProtocolKeyID < canonical[j].ProtocolKeyID
	})

	batch := validatedPreKeyBatch{keys: canonical}
	for index, key := range canonical {
		if index > 0 && key.KeyType == canonical[index-1].KeyType &&
			key.ProtocolKeyID == canonical[index-1].ProtocolKeyID {
			return validatedPreKeyBatch{}, errors.New("duplicate prekey protocol id in publication batch")
		}
		if key.KeyType == 0 {
			if batch.signed.ProtocolKeyID != 0 {
				return validatedPreKeyBatch{}, errors.New("prekey publication must contain exactly one signed prekey")
			}
			batch.signed = key
		} else {
			batch.oneTime = append(batch.oneTime, key)
			batch.maxOneTime = max(batch.maxOneTime, key.ProtocolKeyID)
		}
	}
	if batch.signed.ProtocolKeyID == 0 || len(batch.oneTime) > 1000 {
		return validatedPreKeyBatch{}, errors.New("prekey publication must contain one signed prekey and at most 1000 one-time prekeys")
	}

	return batch, nil
}

// StorePreKeys is also used by trusted non-HTTP integration paths. They get a
// deterministic domain-separated digest; the REST handler always calls
// StorePreKeysWithReceipt with SHA-256 of the exact validated request bytes.
func digestInternalPreKeyBatch(deviceID string, canonical []PreKey) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(internalPreKeyUploadDigestDomain))
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(len(deviceID)))
	_, _ = hash.Write(encoded[:])
	_, _ = hash.Write([]byte(deviceID))
	binary.BigEndian.PutUint32(encoded[:], uint32(len(canonical)))
	_, _ = hash.Write(encoded[:])
	for _, key := range canonical {
		_, _ = hash.Write([]byte{byte(key.KeyType)})
		binary.BigEndian.PutUint32(encoded[:], key.ProtocolKeyID)
		_, _ = hash.Write(encoded[:])
		_, _ = hash.Write(key.PublicKey)
		if key.Signature == nil {
			_, _ = hash.Write([]byte{0})
		} else {
			_, _ = hash.Write([]byte{1})
			_, _ = hash.Write(key.Signature)
		}
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func lockPreKeyPublicationState(ctx context.Context, tx pgx.Tx, deviceID string) (bool, preKeyPublicationState, error) {
	commandTag, err := tx.Exec(ctx,
		`INSERT INTO prekey_publication_state (
		    device_id, signed_prekey_high_watermark, one_time_prekey_high_watermark
		 )
		 SELECT d.id,
		        COALESCE(MAX(p.protocol_key_id) FILTER (WHERE p.key_type = 0), 0),
		        COALESCE(MAX(p.protocol_key_id) FILTER (WHERE p.key_type = 1), 0)
		 FROM devices d
		 LEFT JOIN prekeys p ON p.device_id = d.id
		 WHERE d.id = $1::uuid
		 GROUP BY d.id
		 ON CONFLICT (device_id) DO NOTHING`,
		deviceID,
	)
	if err != nil {
		return false, preKeyPublicationState{}, fmt.Errorf("initialize prekey publication state: %w", err)
	}
	created := commandTag.RowsAffected() == 1
	var signedHigh, oneTimeHigh int64
	var state preKeyPublicationState
	if err := tx.QueryRow(ctx,
		`SELECT signed_prekey_high_watermark,
		        one_time_prekey_high_watermark,
		        latest_upload_digest,
		        COALESCE(latest_upload_stored, 0)
		 FROM prekey_publication_state
		 WHERE device_id = $1::uuid
		 FOR UPDATE`,
		deviceID,
	).Scan(&signedHigh, &oneTimeHigh, &state.latestDigest, &state.latestStored); err != nil {
		return false, preKeyPublicationState{}, fmt.Errorf("lock prekey publication state: %w", err)
	}
	if signedHigh < 0 || signedHigh > math.MaxUint32 || oneTimeHigh < 0 || oneTimeHigh > math.MaxUint32 {
		return false, preKeyPublicationState{}, errors.New("prekey publication watermark is invalid")
	}
	state.signedHighWatermark = uint32(signedHigh)
	state.oneTimeHighWatermark = uint32(oneTimeHigh)
	if state.latestDigest != nil && (len(state.latestDigest) != sha256.Size || state.latestStored <= 0) {
		return false, preKeyPublicationState{}, errors.New("prekey publication receipt is invalid")
	}
	if state.latestDigest == nil && state.latestStored != 0 {
		return false, preKeyPublicationState{}, errors.New("prekey publication receipt is incomplete")
	}
	return created, state, nil
}

func verifyLegacyPreKeyBatch(
	ctx context.Context,
	tx pgx.Tx,
	deviceID string,
	batch validatedPreKeyBatch,
	state preKeyPublicationState,
) (bool, error) {
	if state.latestDigest != nil || state.signedHighWatermark == 0 {
		return false, nil
	}
	var signedRowID, signedProtocolID int64
	var signedPublic, signedSignature []byte
	if err := tx.QueryRow(ctx,
		`SELECT id, protocol_key_id, public_key, signature
		 FROM prekeys
		 WHERE device_id = $1::uuid AND key_type = 0
		 ORDER BY id DESC LIMIT 1`,
		deviceID,
	).Scan(&signedRowID, &signedProtocolID, &signedPublic, &signedSignature); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("load legacy current signed prekey: %w", err)
	}
	if signedProtocolID != int64(batch.signed.ProtocolKeyID) ||
		!bytes.Equal(signedPublic, batch.signed.PublicKey) ||
		!bytes.Equal(signedSignature, batch.signed.Signature) {
		return false, nil
	}

	rows, err := tx.Query(ctx,
		`SELECT protocol_key_id, public_key, signature
		 FROM prekeys
		 WHERE device_id = $1::uuid AND key_type = 1 AND id > $2
		 ORDER BY protocol_key_id ASC`,
		deviceID, signedRowID,
	)
	if err != nil {
		return false, fmt.Errorf("load legacy latest OPK batch: %w", err)
	}
	defer rows.Close()
	legacyOneTime := make([]PreKey, 0, len(batch.oneTime))
	for rows.Next() {
		var protocolID int64
		var key PreKey
		if err := rows.Scan(&protocolID, &key.PublicKey, &key.Signature); err != nil {
			return false, fmt.Errorf("scan legacy latest OPK batch: %w", err)
		}
		if protocolID <= 0 || protocolID > math.MaxUint32 {
			return false, errors.New("legacy OPK protocol id is invalid")
		}
		key.KeyType = 1
		key.ProtocolKeyID = uint32(protocolID)
		legacyOneTime = append(legacyOneTime, key)
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate legacy latest OPK batch: %w", err)
	}
	if len(legacyOneTime) != len(batch.oneTime) {
		return false, nil
	}
	for index := range legacyOneTime {
		if legacyOneTime[index].ProtocolKeyID != batch.oneTime[index].ProtocolKeyID ||
			!bytes.Equal(legacyOneTime[index].PublicKey, batch.oneTime[index].PublicKey) ||
			!bytes.Equal(legacyOneTime[index].Signature, batch.oneTime[index].Signature) {
			return false, nil
		}
	}
	return true, nil
}

func currentSignedPreKeyExact(ctx context.Context, tx pgx.Tx, deviceID string, expected PreKey) (bool, error) {
	var protocolID int64
	var publicKey, signature []byte
	err := tx.QueryRow(ctx,
		`SELECT protocol_key_id, public_key, signature
		 FROM prekeys
		 WHERE device_id = $1::uuid AND key_type = 0
		 ORDER BY id DESC LIMIT 1`,
		deviceID,
	).Scan(&protocolID, &publicKey, &signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load current signed prekey: %w", err)
	}
	return protocolID == int64(expected.ProtocolKeyID) &&
		bytes.Equal(publicKey, expected.PublicKey) &&
		bytes.Equal(signature, expected.Signature), nil
}

func compactPublishedPreKeys(ctx context.Context, tx pgx.Tx, deviceID string, currentSignedID uint32) error {
	if _, err := tx.Exec(ctx,
		`DELETE FROM prekeys
		 WHERE device_id = $1::uuid AND key_type = 0 AND protocol_key_id <> $2`,
		deviceID, currentSignedID,
	); err != nil {
		return fmt.Errorf("compact prior signed prekeys: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM prekeys
		 WHERE device_id = $1::uuid AND key_type = 1 AND used = true`,
		deviceID,
	); err != nil {
		return fmt.Errorf("compact consumed one-time prekeys: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM prekeys
		 WHERE device_id = $1::uuid AND key_type = 1 AND used = false
		   AND id NOT IN (
		     SELECT id FROM prekeys
		     WHERE device_id = $1::uuid AND key_type = 1 AND used = false
		     ORDER BY protocol_key_id DESC, id DESC
		     LIMIT $2
		   )`,
		deviceID, MaxUnusedOneTimePreKeysPerDevice,
	); err != nil {
		return fmt.Errorf("compact excess unused one-time prekeys: %w", err)
	}
	return nil
}

func persistPreKeyReceipt(
	ctx context.Context,
	tx pgx.Tx,
	deviceID string,
	signedHighWatermark uint32,
	oneTimeHighWatermark uint32,
	digest [sha256.Size]byte,
	stored int,
) error {
	commandTag, err := tx.Exec(ctx,
		`UPDATE prekey_publication_state
		 SET signed_prekey_high_watermark = $2,
		     one_time_prekey_high_watermark = $3,
		     latest_upload_digest = $4,
		     latest_upload_stored = $5,
		     updated_at = now()
		 WHERE device_id = $1::uuid`,
		deviceID, signedHighWatermark, oneTimeHighWatermark, digest[:], stored,
	)
	if err != nil {
		return fmt.Errorf("persist prekey publication receipt: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return errors.New("prekey publication state disappeared while storing receipt")
	}
	return nil
}

func enforcePreKeyLiveBounds(
	ctx context.Context,
	tx pgx.Tx,
	deviceID string,
	ownerID string,
	accountRowsBefore int,
) error {
	var signedRows, unusedRows, consumedRows int
	if err := tx.QueryRow(ctx,
		`SELECT
		   COUNT(*) FILTER (WHERE key_type = 0),
		   COUNT(*) FILTER (WHERE key_type = 1 AND used = false),
		   COUNT(*) FILTER (WHERE key_type = 1 AND used = true)
		 FROM prekeys
		 WHERE device_id = $1::uuid`,
		deviceID,
	).Scan(&signedRows, &unusedRows, &consumedRows); err != nil {
		return fmt.Errorf("count device live prekeys: %w", err)
	}
	if signedRows != 1 || unusedRows > MaxUnusedOneTimePreKeysPerDevice || consumedRows != 0 {
		return errors.New("prekey compaction invariant failed")
	}

	var accountRowsAfter int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*)
		 FROM prekeys p
		 JOIN devices d ON d.id = p.device_id
		 WHERE d.user_id = $1::uuid`,
		ownerID,
	).Scan(&accountRowsAfter); err != nil {
		return fmt.Errorf("count account live prekeys: %w", err)
	}
	if accountRowsAfter > MaxPreKeyRowsPerAccount && accountRowsAfter > accountRowsBefore {
		return fmt.Errorf(
			"%w: account=%s rows=%d",
			ErrPreKeyLiveStateFull, ownerID, accountRowsAfter,
		)
	}
	return nil
}

func preKeyConflict(deviceID string, keyType int16, protocolID uint32) error {
	return fmt.Errorf(
		"%w: device=%s key_type=%d protocol_key_id=%d",
		ErrPreKeyMaterialConflict, deviceID, keyType, protocolID,
	)
}

// ClaimOneTimePreKey atomically claims an unused one-time prekey for a device.
// Returns nil if no OPK available (falls back to signed-only X3DH).
func (db *DB) ClaimOneTimePreKey(ctx context.Context, deviceID string) (*PreKey, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin OPK claim: %w", err)
	}
	defer tx.Rollback(ctx)

	// StorePreKeys takes FOR UPDATE on this row. FOR SHARE lets independent
	// claims proceed concurrently while ensuring a claim observes either the
	// complete legacy mode or the complete receipt/compaction cutover.
	var lockedDeviceID string
	if err := tx.QueryRow(ctx,
		`SELECT id FROM devices WHERE id = $1::uuid FOR SHARE`,
		deviceID,
	).Scan(&lockedDeviceID); err != nil {
		return nil, fmt.Errorf("lock OPK device: %w", err)
	}
	var receiptEstablished bool
	err = tx.QueryRow(ctx,
		`SELECT latest_upload_digest IS NOT NULL
		 FROM prekey_publication_state
		 WHERE device_id = $1::uuid`,
		deviceID,
	).Scan(&receiptEstablished)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("load OPK publication state: %w", err)
	}

	var pk PreKey
	if receiptEstablished {
		err = tx.QueryRow(ctx,
			`WITH candidate AS (
			   SELECT id FROM prekeys
			   WHERE device_id = $1::uuid AND key_type = 1 AND used = false
			   ORDER BY protocol_key_id ASC, id ASC LIMIT 1
			   FOR UPDATE SKIP LOCKED
			 )
			 DELETE FROM prekeys selected
			 USING candidate
			 WHERE selected.id = candidate.id
			 RETURNING selected.id, selected.device_id, selected.key_type,
			           selected.protocol_key_id, selected.public_key,
			           selected.signature, true`,
			deviceID,
		).Scan(&pk.ID, &pk.DeviceID, &pk.KeyType, &pk.ProtocolKeyID, &pk.PublicKey, &pk.Signature, &pk.Used)
	} else {
		err = tx.QueryRow(ctx,
			`UPDATE prekeys SET used = true
			 WHERE id = (
			   SELECT id FROM prekeys
			   WHERE device_id = $1::uuid AND key_type = 1 AND used = false
			   ORDER BY protocol_key_id ASC, id ASC LIMIT 1
			   FOR UPDATE SKIP LOCKED
			 )
			 RETURNING id, device_id, key_type, protocol_key_id, public_key, signature, used`,
			deviceID,
		).Scan(&pk.ID, &pk.DeviceID, &pk.KeyType, &pk.ProtocolKeyID, &pk.PublicKey, &pk.Signature, &pk.Used)
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // No OPK available, not an error
		}
		return nil, fmt.Errorf("claim opk: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit OPK claim: %w", err)
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

// MessageSendOutcome is the immutable server identity assigned to one
// account-scoped client send intent. The ledger deliberately outlives the
// message row so an exact retry can still be acknowledged after TTL cleanup.
type MessageSendOutcome struct {
	MessageID        string
	ServerTimestamp  time.Time
	AckRosterVersion *uint64
	Replayed         bool
}

func isCanonicalNonNilUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

// LookupMessageSendOutcome returns the durable result for an exact request
// digest. A reused client ID with different bytes fails closed.
func (db *DB) LookupMessageSendOutcome(
	ctx context.Context,
	senderID string,
	clientMessageID string,
	requestDigest []byte,
) (*MessageSendOutcome, error) {
	if !isCanonicalNonNilUUID(senderID) || !isCanonicalNonNilUUID(clientMessageID) ||
		len(requestDigest) != sha256.Size {
		return nil, errors.New("invalid message send lookup")
	}
	var (
		storedDigest    []byte
		messageID       string
		serverTimestamp time.Time
		rosterVersion   *int64
	)
	err := db.Pool.QueryRow(ctx,
		`SELECT request_digest, message_id::text, server_timestamp, ack_roster_version
		 FROM message_send_idempotency
		 WHERE sender_id = $1::uuid AND client_message_id = $2::uuid`,
		senderID, clientMessageID,
	).Scan(&storedDigest, &messageID, &serverTimestamp, &rosterVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !isCanonicalNonNilUUID(messageID) {
		return nil, errors.New("invalid stored message send outcome")
	}
	if len(storedDigest) != sha256.Size ||
		subtle.ConstantTimeCompare(storedDigest, requestDigest) != 1 {
		return nil, ErrMessageSendIDConflict
	}
	outcome := &MessageSendOutcome{
		MessageID:       messageID,
		ServerTimestamp: serverTimestamp,
		Replayed:        true,
	}
	if rosterVersion != nil {
		version := uint64(*rosterVersion)
		outcome.AckRosterVersion = &version
	}
	return outcome, nil
}

// StoreMessageIdempotent atomically claims an account-scoped client send ID,
// validates the current conversation/security snapshot, and inserts the
// message and attachments. Exact concurrent retries return the first durable
// result without inserting or fan-out eligibility.
func (db *DB) StoreMessageIdempotent(
	ctx context.Context,
	m *Message,
	clientMessageID string,
	requestDigest []byte,
) (*MessageSendOutcome, error) {
	if m == nil || m.ConversationID == "" || !isCanonicalNonNilUUID(m.SenderID) ||
		len(m.Ciphertext) == 0 || !isCanonicalNonNilUUID(clientMessageID) ||
		len(requestDigest) != sha256.Size {
		return nil, errors.New("invalid idempotent message")
	}
	if m.SecurityContext != nil {
		if err := validateMessageSecurityContext(m.SecurityContext); err != nil {
			return nil, err
		}
	}
	attempts := 1
	if m.SecurityContext != nil {
		attempts = 3
	}
	for attempt := 0; attempt < attempts; attempt++ {
		outcome, err := db.storeMessageIdempotentOnce(ctx, m, clientMessageID, requestDigest)
		if !isSenderKeySerializationFailure(err) {
			return outcome, err
		}
	}
	return nil, ErrMessageRosterChanged
}

func (db *DB) storeMessageIdempotentOnce(
	ctx context.Context,
	m *Message,
	clientMessageID string,
	requestDigest []byte,
) (*MessageSendOutcome, error) {
	txOptions := pgx.TxOptions{}
	if m.SecurityContext != nil {
		txOptions.IsoLevel = pgx.Serializable
	}
	tx, err := db.Pool.BeginTx(ctx, txOptions)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	messageID := uuid.NewString()
	var ackRosterVersion any
	if m.SecurityContext != nil {
		ackRosterVersion = int64(m.SecurityContext.RosterVersion)
	}
	var (
		serverTimestamp     time.Time
		storedRosterVersion *int64
	)
	err = tx.QueryRow(ctx,
		`INSERT INTO message_send_idempotency (
		   sender_id, client_message_id, request_digest, message_id,
		   server_timestamp, ack_roster_version
		 ) VALUES ($1::uuid, $2::uuid, $3, $4::uuid, now(), $5)
		 ON CONFLICT (sender_id, client_message_id) DO NOTHING
		 RETURNING message_id::text, server_timestamp, ack_roster_version`,
		m.SenderID, clientMessageID, requestDigest, messageID, ackRosterVersion,
	).Scan(&messageID, &serverTimestamp, &storedRosterVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		var storedDigest []byte
		err = tx.QueryRow(ctx,
			`SELECT request_digest, message_id::text, server_timestamp, ack_roster_version
			 FROM message_send_idempotency
			 WHERE sender_id = $1::uuid AND client_message_id = $2::uuid`,
			m.SenderID, clientMessageID,
		).Scan(&storedDigest, &messageID, &serverTimestamp, &storedRosterVersion)
		if err != nil {
			return nil, err
		}
		if !isCanonicalNonNilUUID(messageID) {
			return nil, errors.New("invalid stored message send outcome")
		}
		if len(storedDigest) != sha256.Size ||
			subtle.ConstantTimeCompare(storedDigest, requestDigest) != 1 {
			return nil, ErrMessageSendIDConflict
		}
		m.ID = messageID
		m.CreatedAt = serverTimestamp
		outcome := &MessageSendOutcome{
			MessageID:       messageID,
			ServerTimestamp: serverTimestamp,
			Replayed:        true,
		}
		if storedRosterVersion != nil {
			version := uint64(*storedRosterVersion)
			outcome.AckRosterVersion = &version
		}
		return outcome, nil
	}
	if err != nil {
		return nil, err
	}
	if !isCanonicalNonNilUUID(messageID) {
		return nil, errors.New("invalid stored message send outcome")
	}

	var conversationType int16
	if err := tx.QueryRow(ctx,
		`SELECT conv_type FROM conversations WHERE id = $1::uuid FOR UPDATE`,
		m.ConversationID,
	).Scan(&conversationType); err != nil {
		return nil, err
	}
	if conversationType == 1 || conversationType == 2 {
		if err := validateMessageSecurityContext(m.SecurityContext); err != nil {
			return nil, err
		}
		var lockedDeviceID string
		if err := tx.QueryRow(ctx,
			`SELECT id::text FROM devices
			 WHERE id = $1::uuid AND user_id = $2::uuid FOR UPDATE`,
			m.SecurityContext.SenderDeviceDatabaseID, m.SenderID,
		).Scan(&lockedDeviceID); err != nil {
			return nil, ErrMessageSecurityContext
		}
		roster, err := resolveConversationDeviceRosterSnapshot(
			ctx, tx, m.ConversationID, RequiredChannelCapabilities,
		)
		if err != nil {
			if errors.Is(err, ErrSenderKeyRosterChanged) {
				return nil, ErrMessageRosterChanged
			}
			return nil, err
		}
		if err := validateMessageRosterSnapshot(
			ctx, tx, roster, m.ConversationID, m.SenderID, m.SecurityContext,
		); err != nil {
			return nil, err
		}
	} else if m.SecurityContext != nil {
		return nil, ErrMessageSecurityContext
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

	m.ID = messageID
	m.CreatedAt = serverTimestamp
	err = tx.QueryRow(ctx,
		`INSERT INTO messages (
		   id, conversation_id, sender_id, ciphertext, header, msg_type,
		   reply_to_id, expires_at, crypto_profile, crypto_era,
		   roster_version, roster_commitment, sender_device_id,
		   sender_binding_version, created_at
		 )
		 SELECT $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7::uuid, $8,
		        $9, $10, $11, $12, $13, $14, $15
		 WHERE $7::uuid IS NULL OR EXISTS (
		   SELECT 1 FROM messages reply
		   WHERE reply.id = $7::uuid
		     AND reply.conversation_id = $2::uuid
		     AND reply.is_deleted = false
		 )
		 RETURNING id::text, created_at`,
		m.ID, m.ConversationID, m.SenderID, m.Ciphertext, m.Header, m.MsgType,
		m.ReplyToID, m.ExpiresAt, securityProfile, securityEra, rosterVersion,
		rosterCommitment, senderDeviceID, senderBindingVersion, m.CreatedAt,
	).Scan(&m.ID, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) && m.ReplyToID != nil {
		return nil, ErrReplyTargetMismatch
	}
	if err != nil {
		return nil, err
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
			return nil, ErrAttachmentScope
		}
		if err != nil {
			return nil, fmt.Errorf("store message attachment: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	outcome := &MessageSendOutcome{
		MessageID:       m.ID,
		ServerTimestamp: m.CreatedAt,
	}
	if storedRosterVersion != nil {
		version := uint64(*storedRosterVersion)
		outcome.AckRosterVersion = &version
	}
	return outcome, nil
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

// GetUserConversation returns one exact conversation projection only when the
// requester is still authorized to read it. The membership join deliberately
// makes a missing UUID and an inaccessible UUID indistinguishable to callers.
// The complete member directory is filtered through the same channel ACL as
// list/sync discovery before it crosses the REST boundary.
func (db *DB) GetUserConversation(ctx context.Context, userID, conversationID string) (*ConversationDiscovery, error) {
	var conversation ConversationDiscovery
	err := db.Pool.QueryRow(ctx,
		`SELECT conversation.id, conversation.conv_type, conversation.name,
		        conversation.server_id, conversation.created_at
		 FROM conversations conversation
		 JOIN conversation_members mine ON mine.conversation_id = conversation.id
		 WHERE conversation.id = $1::uuid AND mine.user_id = $2::uuid`,
		conversationID, userID,
	).Scan(
		&conversation.ID, &conversation.ConvType, &conversation.Name,
		&conversation.ServerID, &conversation.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConversationAccessDenied
	}
	if err != nil {
		return nil, err
	}

	conversation.Members, err = db.GetConversationMemberBindingsForRequester(
		ctx, conversation.ID, userID, ChannelReadPermissions,
	)
	if errors.Is(err, ErrConversationAccessDenied) {
		return nil, ErrConversationAccessDenied
	}
	if err != nil {
		return nil, err
	}
	return &conversation, nil
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

// AddReaction inserts a reaction idempotently while enforcing the bounded
// history contract. It returns false for an exact retry. Authorization,
// message scope and admission are linearized in one transaction so a
// committed revoke/delete cannot land between validation and storage.
func (db *DB) AddReaction(ctx context.Context, messageID, conversationID, userID, emoji string) (bool, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	if err := lockAuthorizedReactionAccess(ctx, tx, conversationID, userID); err != nil {
		return false, err
	}

	// The database trigger takes the same lock for raw/future writers. Taking
	// it explicitly here lets us map the cap to a stable domain error before
	// attempting the INSERT. It must precede the message row lock: raw INSERT
	// takes advisory first and later obtains an FK KEY SHARE lock on messages.
	// A hash collision only delays another message.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text, 73))`,
		messageID,
	); err != nil {
		return false, fmt.Errorf("lock message reactions: %w", err)
	}
	if err := lockActiveReactionMessage(ctx, tx, messageID, conversationID); err != nil {
		return false, err
	}

	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM reactions
		   WHERE message_id = $1::uuid AND conversation_id = $2::uuid
		     AND user_id = $3::uuid AND emoji = $4
		 )`,
		messageID, conversationID, userID, emoji,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("check existing reaction: %w", err)
	}
	if exists {
		if err := tx.Commit(ctx); err != nil {
			return false, err
		}
		return false, nil
	}

	var count int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM reactions WHERE message_id = $1::uuid`,
		messageID,
	).Scan(&count); err != nil {
		return false, fmt.Errorf("count message reactions: %w", err)
	}
	if count >= MaxReactionsPerMessage {
		return false, ErrReactionLimitReached
	}

	tag, err := tx.Exec(ctx,
		`INSERT INTO reactions (message_id, conversation_id, user_id, emoji)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4)
		 ON CONFLICT (message_id, user_id, emoji) DO NOTHING`,
		messageID, conversationID, userID, emoji,
	)
	if err != nil {
		if isReactionLimitViolation(err) {
			return false, ErrReactionLimitReached
		}
		return false, fmt.Errorf("insert reaction: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// RemoveReaction deletes a specific reaction and returns false for an
// idempotent no-op. It uses the same authoritative scope transaction as add.
func (db *DB) RemoveReaction(ctx context.Context, messageID, conversationID, userID, emoji string) (bool, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if err := lockAuthorizedReactionAccess(ctx, tx, conversationID, userID); err != nil {
		return false, err
	}
	if err := lockActiveReactionMessage(ctx, tx, messageID, conversationID); err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM reactions
		 WHERE message_id = $1::uuid AND conversation_id = $2::uuid
		   AND user_id = $3::uuid AND emoji = $4`,
		messageID, conversationID, userID, emoji,
	)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// lockAuthorizedReactionAccess linearizes current ACL state against every
// roster-changing trigger. Access is checked before looking up the message so
// an unauthorized caller cannot probe message existence.
func lockAuthorizedReactionAccess(ctx context.Context, tx pgx.Tx, conversationID, userID string) error {
	var revision int64
	if err := tx.QueryRow(ctx,
		`SELECT mutation_revision
		 FROM conversation_roster_revisions
		 WHERE conversation_id = $1::uuid
		 FOR UPDATE`,
		conversationID,
	).Scan(&revision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConversationAccessDenied
		}
		return fmt.Errorf("lock conversation roster revision: %w", err)
	}
	allowed, err := canAccessConversationWithQuery(
		ctx,
		tx,
		conversationID,
		userID,
		PermViewChannel|PermSendMessages,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConversationAccessDenied
	}
	if err != nil {
		return fmt.Errorf("authorize reaction mutation: %w", err)
	}
	if !allowed {
		return ErrConversationAccessDenied
	}
	return nil
}

// lockActiveReactionMessage linearizes against edits and soft deletes. Add
// calls this only after the per-message advisory lock, matching the raw INSERT
// trigger's advisory -> foreign-key parent-lock order and avoiding a cycle.
func lockActiveReactionMessage(ctx context.Context, tx pgx.Tx, messageID, conversationID string) error {
	var active bool
	if err := tx.QueryRow(ctx,
		`SELECT true
		 FROM messages
		 WHERE id = $1::uuid
		   AND conversation_id = $2::uuid
		   AND is_deleted = false
		 FOR UPDATE`,
		messageID,
		conversationID,
	).Scan(&active); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMessageMutationScope
		}
		return fmt.Errorf("lock reaction message: %w", err)
	}
	return nil
}

func isReactionLimitViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) &&
		pgErr.Code == "23514" &&
		pgErr.ConstraintName == "reactions_per_message_limit"
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
