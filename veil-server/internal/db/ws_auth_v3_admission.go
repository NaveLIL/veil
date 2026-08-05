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
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
)

// WSAuthV3AdmissionIntent is the database-side representation of the exact
// registration choice already authenticated by both WebSocket v3 proofs.
type WSAuthV3AdmissionIntent uint8

const (
	WSAuthV3AdmissionExisting WSAuthV3AdmissionIntent = 1
	WSAuthV3AdmissionOpen     WSAuthV3AdmissionIntent = 2
	WSAuthV3AdmissionPass     WSAuthV3AdmissionIntent = 3
)

var (
	// ErrWSAuthV3IdentityAbsent is deliberately not an account-existence oracle.
	// The auth service maps it only after both possession proofs have succeeded.
	ErrWSAuthV3IdentityAbsent = errors.New("WebSocket auth v3 existing identity is absent")
	// ErrWSAuthV3RegistrationClosed is coherent only with an authenticated OPEN
	// intent. Callers must not expose it for any other admission mode.
	ErrWSAuthV3RegistrationClosed = errors.New("WebSocket auth v3 registration is closed")
	// ErrWSAuthV3AdmissionRejected covers deterministic account, device and
	// binding conflicts without exposing which durable constraint rejected the
	// authenticated presentation.
	ErrWSAuthV3AdmissionRejected = errors.New("WebSocket auth v3 admission rejected")
)

// WSAuthV3AdmissionRequest contains only material already strictly verified by
// the auth service. Arrays keep fixed-width security fields unambiguous. The
// raw Pass slice is borrowed for this call and is never retained or copied.
type WSAuthV3AdmissionRequest struct {
	Intent                WSAuthV3AdmissionIntent
	AllowOpenRegistration bool
	AccountIdentityKey    [32]byte
	AccountSigningKey     [32]byte
	DeviceKey             [16]byte
	DeviceName            string
	DeviceIdentityKey     [32]byte
	DeviceSigningKey      [32]byte
	BindingVersion        uint64
	BindingCapabilities   uint64
	BindingStatus         DeviceBindingStatus
	BindingSignature      [64]byte
	BindingCommitment     [32]byte
	NodeAccessPass        []byte
}

// WSAuthV3AdmissionResult is published only after the complete transaction has
// committed. Binding is the exact immutable version accepted by that commit.
type WSAuthV3AdmissionResult struct {
	User    *User
	Device  *Device
	Binding *DeviceBinding
	IsNew   bool
}

// AdmitWSAuthV3 atomically resolves an authenticated v3 identity and installs
// its exact active device binding. For a new PASS identity, account, device,
// cryptographic keys, binding head/version and Pass consumption share one
// transaction. Any failure rolls back every one of those effects.
//
// The identity-scoped transaction lock closes the lookup/insert race. After
// taking it, an existing exact identity always wins before the Pass table is
// consulted. Consequently a retry after an uncertain successful commit can
// present the same now-used Pass and still authenticate idempotently, while an
// unrelated existing identity never consumes a supplied unused Pass.
func (db *DB) AdmitWSAuthV3(ctx context.Context, request WSAuthV3AdmissionRequest) (*WSAuthV3AdmissionResult, error) {
	if ctx == nil {
		return nil, errors.New("WebSocket auth v3 admission context is unavailable")
	}
	if err := validateWSAuthV3AdmissionRequest(request); err != nil {
		return nil, err
	}
	if db == nil || db.Pool == nil {
		return nil, errors.New("WebSocket auth v3 admission store is unavailable")
	}

	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin WebSocket auth v3 admission: %w", err)
	}
	defer func() {
		// Request cancellation must not strand an open transaction, its identity
		// advisory lock, or a borrowed pool connection. Rollback deliberately
		// gets a short cancellation-independent context.
		rollbackContext, cancelRollback := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelRollback()
		_ = tx.Rollback(rollbackContext)
	}()

	identityDigest := sha256.Sum256(request.AccountIdentityKey[:])
	identityLock := int64(binary.BigEndian.Uint64(identityDigest[:8]))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::bigint)`, identityLock); err != nil {
		return nil, fmt.Errorf("lock WebSocket auth v3 identity: %w", err)
	}

	user, err := findWSAuthV3UserTx(ctx, tx, request.AccountIdentityKey[:])
	isNew := false
	var passID string
	switch {
	case err == nil:
		if subtle.ConstantTimeCompare(user.SigningKey, request.AccountSigningKey[:]) != 1 {
			return nil, ErrWSAuthV3AdmissionRejected
		}
		// ADR-0003: do not inspect, lock or consume a Pass for an identity that
		// already exists with the exact pinned account keys.
	case errors.Is(err, pgx.ErrNoRows):
		switch request.Intent {
		case WSAuthV3AdmissionExisting:
			return nil, ErrWSAuthV3IdentityAbsent
		case WSAuthV3AdmissionOpen:
			if !request.AllowOpenRegistration {
				return nil, ErrWSAuthV3RegistrationClosed
			}
		case WSAuthV3AdmissionPass:
			passID, err = lockWSAuthV3Pass(ctx, tx, request.NodeAccessPass)
			if err != nil {
				return nil, err
			}
		default:
			return nil, ErrWSAuthV3AdmissionRejected
		}

		username := fmt.Sprintf("user_%x", request.AccountIdentityKey[:4])
		user, err = createWSAuthV3UserTx(
			ctx, tx, request.AccountIdentityKey[:], request.AccountSigningKey[:], username,
		)
		if err != nil {
			return nil, err
		}
		if err := db.appendIdentityTransparencyAccountTx(ctx, tx, user); err != nil {
			return nil, fmt.Errorf("append WebSocket auth v3 account transparency event: %w", err)
		}
		isNew = true
	default:
		return nil, fmt.Errorf("find WebSocket auth v3 user: %w", err)
	}

	device, err := findWSAuthV3DeviceTx(ctx, tx, request.DeviceKey[:])
	if errors.Is(err, pgx.ErrNoRows) {
		device, err = createWSAuthV3DeviceTx(ctx, tx, user.ID, request.DeviceKey[:], request.DeviceName)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("find WebSocket auth v3 device: %w", err)
	} else {
		if device.UserID != user.ID || !bytes.Equal(device.DeviceKey, request.DeviceKey[:]) {
			return nil, ErrWSAuthV3AdmissionRejected
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET last_seen = clock_timestamp() WHERE id = $1::uuid`, device.ID); err != nil {
			return nil, fmt.Errorf("touch WebSocket auth v3 device: %w", err)
		}
	}

	binding, bindingAppended, err := storeDeviceBindingTx(ctx, tx, &DeviceBinding{
		DeviceID:          device.ID,
		UserID:            user.ID,
		DeviceKey:         request.DeviceKey[:],
		DeviceIdentityKey: request.DeviceIdentityKey[:],
		DeviceSigningKey:  request.DeviceSigningKey[:],
		Version:           request.BindingVersion,
		Capabilities:      request.BindingCapabilities,
		Status:            request.BindingStatus,
		AccountSignature:  request.BindingSignature[:],
		Commitment:        request.BindingCommitment[:],
	})
	if err != nil {
		if wsAuthV3DeterministicBindingRejection(err) {
			return nil, ErrWSAuthV3AdmissionRejected
		}
		return nil, fmt.Errorf("store WebSocket auth v3 binding: %w", err)
	}
	if bindingAppended {
		if err := db.appendIdentityTransparencyDeviceBindingTx(ctx, tx, binding); err != nil {
			return nil, fmt.Errorf("append WebSocket auth v3 device-binding transparency event: %w", err)
		}
	}

	if isNew && request.Intent == WSAuthV3AdmissionPass {
		tag, err := tx.Exec(ctx,
			`UPDATE node_access_invites
			 SET used_at = clock_timestamp(), used_by_user_id = $2::uuid
			 WHERE id = $1::uuid AND used_at IS NULL AND expires_at > clock_timestamp()`,
			passID, user.ID,
		)
		if err != nil {
			return nil, fmt.Errorf("consume WebSocket auth v3 Pass: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return nil, ErrNodeAccessInviteInvalid
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit WebSocket auth v3 admission: %w", err)
	}
	return &WSAuthV3AdmissionResult{
		User: user, Device: device, Binding: binding, IsNew: isNew,
	}, nil
}

func validateWSAuthV3AdmissionRequest(request WSAuthV3AdmissionRequest) error {
	if allZeroWSAuthV3DB(request.AccountIdentityKey[:]) ||
		!cryptokey.ValidEd25519PublicKey(request.AccountSigningKey[:]) ||
		allZeroWSAuthV3DB(request.DeviceKey[:]) ||
		allZeroWSAuthV3DB(request.DeviceIdentityKey[:]) ||
		!cryptokey.ValidEd25519PublicKey(request.DeviceSigningKey[:]) ||
		request.BindingVersion == 0 || request.BindingVersion > math.MaxInt64 ||
		request.BindingCapabilities > math.MaxInt64 ||
		request.BindingCapabilities&RequiredChannelCapabilities != RequiredChannelCapabilities ||
		request.BindingStatus != DeviceBindingActive ||
		allZeroWSAuthV3DB(request.BindingSignature[:]) ||
		allZeroWSAuthV3DB(request.BindingCommitment[:]) ||
		!validWSAuthV3DeviceNameDB(request.DeviceName) {
		return ErrWSAuthV3AdmissionRejected
	}

	switch request.Intent {
	case WSAuthV3AdmissionExisting, WSAuthV3AdmissionOpen:
		if len(request.NodeAccessPass) != 0 {
			return ErrWSAuthV3AdmissionRejected
		}
	case WSAuthV3AdmissionPass:
		if len(request.NodeAccessPass) != NodeAccessInviteTokenSize || allZeroWSAuthV3DB(request.NodeAccessPass) {
			return ErrWSAuthV3AdmissionRejected
		}
	default:
		return ErrWSAuthV3AdmissionRejected
	}
	return nil
}

func validWSAuthV3DeviceNameDB(name string) bool {
	if !utf8.ValidString(name) || name == "" || len(name) > 128 {
		return false
	}
	for _, character := range name {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}

func allZeroWSAuthV3DB(value []byte) bool {
	var aggregate byte
	for _, item := range value {
		aggregate |= item
	}
	return subtle.ConstantTimeByteEq(aggregate, 0) == 1
}

func findWSAuthV3UserTx(ctx context.Context, tx pgx.Tx, identityKey []byte) (*User, error) {
	var user User
	err := tx.QueryRow(ctx,
		`SELECT id::text, identity_key, signing_key, username, created_at
		 FROM users WHERE identity_key = $1`, identityKey,
	).Scan(&user.ID, &user.IdentityKey, &user.SigningKey, &user.Username, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func createWSAuthV3UserTx(ctx context.Context, tx pgx.Tx, identityKey, signingKey []byte, username string) (*User, error) {
	var user User
	err := tx.QueryRow(ctx,
		`INSERT INTO users (identity_key, signing_key, username)
		 VALUES ($1, $2, $3)
		 RETURNING id::text, identity_key, signing_key, username, created_at`,
		identityKey, signingKey, username,
	).Scan(&user.ID, &user.IdentityKey, &user.SigningKey, &user.Username, &user.CreatedAt)
	if err != nil {
		if wsAuthV3UniqueViolation(err) {
			return nil, ErrWSAuthV3AdmissionRejected
		}
		return nil, fmt.Errorf("create WebSocket auth v3 user: %w", err)
	}
	return &user, nil
}

func findWSAuthV3DeviceTx(ctx context.Context, tx pgx.Tx, deviceKey []byte) (*Device, error) {
	var device Device
	err := tx.QueryRow(ctx,
		`SELECT id::text, user_id::text, device_key, device_name, last_seen, created_at
		 FROM devices WHERE device_key = $1`, deviceKey,
	).Scan(
		&device.ID, &device.UserID, &device.DeviceKey, &device.DeviceName,
		&device.LastSeen, &device.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &device, nil
}

func createWSAuthV3DeviceTx(ctx context.Context, tx pgx.Tx, userID string, deviceKey []byte, deviceName string) (*Device, error) {
	var device Device
	err := tx.QueryRow(ctx,
		`INSERT INTO devices (user_id, device_key, device_name, last_seen)
		 VALUES ($1::uuid, $2, $3, clock_timestamp())
		 RETURNING id::text, user_id::text, device_key, device_name, last_seen, created_at`,
		userID, deviceKey, deviceName,
	).Scan(
		&device.ID, &device.UserID, &device.DeviceKey, &device.DeviceName,
		&device.LastSeen, &device.CreatedAt,
	)
	if err != nil {
		if wsAuthV3UniqueViolation(err) {
			return nil, ErrWSAuthV3AdmissionRejected
		}
		return nil, fmt.Errorf("create WebSocket auth v3 device: %w", err)
	}
	return &device, nil
}

func lockWSAuthV3Pass(ctx context.Context, tx pgx.Tx, pass []byte) (string, error) {
	if len(pass) != NodeAccessInviteTokenSize || allZeroWSAuthV3DB(pass) {
		return "", ErrNodeAccessInviteInvalid
	}
	digest := sha256.Sum256(pass)
	var passID string
	err := tx.QueryRow(ctx,
		`SELECT id::text
		 FROM node_access_invites
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > clock_timestamp()
		 FOR UPDATE`,
		digest[:],
	).Scan(&passID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNodeAccessInviteInvalid
	}
	if err != nil {
		return "", fmt.Errorf("lock WebSocket auth v3 Pass: %w", err)
	}
	return passID, nil
}

func wsAuthV3DeterministicBindingRejection(err error) bool {
	return errors.Is(err, ErrDeviceBindingStale) ||
		errors.Is(err, ErrDeviceBindingVersionGap) ||
		errors.Is(err, ErrDeviceKeyReplacement) ||
		errors.Is(err, ErrDeviceBindingConflict) ||
		errors.Is(err, ErrDeviceBindingRevoked) ||
		wsAuthV3UniqueViolation(err)
}

func wsAuthV3UniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}
