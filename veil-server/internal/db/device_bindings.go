package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/AegisSec/veil-server/internal/cryptokey"
	"github.com/jackc/pgx/v5"
)

type DeviceBindingStatus uint8

const (
	DeviceBindingActive   DeviceBindingStatus = 1
	DeviceBindingExcluded DeviceBindingStatus = 2
	DeviceBindingRevoked  DeviceBindingStatus = 3
	DeviceLegacyUnbound   DeviceBindingStatus = 4 // computed response-only state
)

const (
	DeviceCapabilitySenderKeyV5  uint64 = 1 << 0
	DeviceCapabilitySealedSKDMV3 uint64 = 1 << 1
	RequiredChannelCapabilities         = DeviceCapabilitySenderKeyV5 | DeviceCapabilitySealedSKDMV3
)

var (
	ErrDeviceBindingStale       = errors.New("stale device binding version")
	ErrDeviceBindingVersionGap  = errors.New("device binding version must advance exactly by one")
	ErrDeviceKeyReplacement     = errors.New("device cryptographic keys are immutable")
	ErrDeviceBindingConflict    = errors.New("device binding version is already committed to different state")
	ErrDeviceBindingRevoked     = errors.New("device binding is permanently revoked")
	ErrDeviceBindingUnavailable = errors.New("device has no cryptographic binding")
)

// DeviceBinding is one immutable, account-signed version of a device's
// cryptographic identity. DeviceID is the server UUID; DeviceKey is the stable
// 16-byte protocol identifier signed by the account.
type DeviceBinding struct {
	DeviceID          string
	UserID            string
	DeviceKey         []byte
	DeviceIdentityKey []byte
	DeviceSigningKey  []byte
	Version           uint64
	Capabilities      uint64
	Status            DeviceBindingStatus
	AccountSignature  []byte
	Commitment        []byte
	CreatedAt         time.Time
}

func validateDeviceBindingForStore(binding *DeviceBinding) error {
	if binding == nil || binding.DeviceID == "" || binding.UserID == "" ||
		len(binding.DeviceKey) != 16 || len(binding.DeviceIdentityKey) != 32 ||
		len(binding.DeviceSigningKey) != 32 || binding.Version == 0 ||
		binding.Version > math.MaxInt64 || binding.Capabilities > math.MaxInt64 ||
		len(binding.AccountSignature) != 64 || len(binding.Commitment) != 32 {
		return errors.New("invalid device binding")
	}
	if !cryptokey.ValidEd25519PublicKey(binding.DeviceSigningKey) {
		return errors.New("invalid device signing public key")
	}
	if binding.Status != DeviceBindingActive && binding.Status != DeviceBindingExcluded &&
		binding.Status != DeviceBindingRevoked {
		return errors.New("invalid signed device binding status")
	}
	return nil
}

// StoreDeviceBinding appends one immutable binding version. Keys are installed
// only at version 1 and can never be changed for the same device identifier.
func (db *DB) StoreDeviceBinding(ctx context.Context, binding *DeviceBinding) (*DeviceBinding, error) {
	if err := validateDeviceBindingForStore(binding); err != nil {
		return nil, err
	}
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin device binding transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var ownerID string
	var storedDeviceKey []byte
	if err := tx.QueryRow(ctx,
		`SELECT user_id::text, device_key FROM devices WHERE id = $1::uuid FOR UPDATE`,
		binding.DeviceID,
	).Scan(&ownerID, &storedDeviceKey); err != nil {
		return nil, fmt.Errorf("lock device binding owner: %w", err)
	}
	if ownerID != binding.UserID || !bytes.Equal(storedDeviceKey, binding.DeviceKey) {
		return nil, errors.New("device binding owner or protocol id mismatch")
	}

	var storedIdentityKey, storedSigningKey []byte
	err = tx.QueryRow(ctx,
		`SELECT device_identity_key, device_signing_key
		 FROM device_crypto_keys WHERE device_id = $1::uuid`,
		binding.DeviceID,
	).Scan(&storedIdentityKey, &storedSigningKey)
	if errors.Is(err, pgx.ErrNoRows) {
		if binding.Version != 1 {
			return nil, ErrDeviceBindingVersionGap
		}
		if binding.Status == DeviceBindingRevoked {
			return nil, errors.New("initial device binding cannot be revoked")
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO device_crypto_keys
			   (device_id, device_identity_key, device_signing_key)
			 VALUES ($1::uuid, $2, $3)`,
			binding.DeviceID, binding.DeviceIdentityKey, binding.DeviceSigningKey,
		); err != nil {
			return nil, fmt.Errorf("store immutable device keys: %w", err)
		}
		if err := insertDeviceBindingVersion(ctx, tx, binding); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO device_binding_heads (device_id, binding_version)
			 VALUES ($1::uuid, $2)`, binding.DeviceID, int64(binding.Version),
		); err != nil {
			return nil, fmt.Errorf("create device binding head: %w", err)
		}
		if !deviceBindingCanReceiveSecureChannels(binding) {
			if err := pruneDeviceSenderKeyTargets(ctx, tx, binding.DeviceID); err != nil {
				return nil, err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit initial device binding: %w", err)
		}
		return cloneDeviceBinding(binding), nil
	}
	if err != nil {
		return nil, fmt.Errorf("load immutable device keys: %w", err)
	}
	if !bytes.Equal(storedIdentityKey, binding.DeviceIdentityKey) ||
		!bytes.Equal(storedSigningKey, binding.DeviceSigningKey) {
		return nil, ErrDeviceKeyReplacement
	}

	current, err := scanLatestDeviceBinding(ctx, tx, binding.DeviceID, true)
	if err != nil {
		return nil, err
	}
	switch {
	case binding.Version < current.Version:
		return nil, ErrDeviceBindingStale
	case binding.Version == current.Version:
		if bindingEqual(current, binding) {
			if err := tx.Commit(ctx); err != nil {
				return nil, fmt.Errorf("commit idempotent device binding: %w", err)
			}
			return current, nil
		}
		return nil, ErrDeviceBindingConflict
	case current.Status == DeviceBindingRevoked:
		return nil, ErrDeviceBindingRevoked
	case binding.Version != current.Version+1:
		return nil, ErrDeviceBindingVersionGap
	}

	if err := insertDeviceBindingVersion(ctx, tx, binding); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE device_binding_heads
		 SET binding_version = $2, updated_at = now()
		 WHERE device_id = $1::uuid`, binding.DeviceID, int64(binding.Version),
	); err != nil {
		return nil, fmt.Errorf("advance device binding head: %w", err)
	}
	if !deviceBindingCanReceiveSecureChannels(binding) {
		if err := pruneDeviceSenderKeyTargets(ctx, tx, binding.DeviceID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit device binding: %w", err)
	}
	return cloneDeviceBinding(binding), nil
}

func deviceBindingCanReceiveSecureChannels(binding *DeviceBinding) bool {
	return binding != nil && binding.Status == DeviceBindingActive &&
		binding.Capabilities&RequiredChannelCapabilities == RequiredChannelCapabilities
}

func pruneDeviceSenderKeyTargets(ctx context.Context, tx pgx.Tx, deviceID string) error {
	// Preserve sender_key_heads as the permanent rollback barrier. Only queued
	// envelopes addressed TO the now-ineligible device are collected.
	if _, err := tx.Exec(ctx,
		`DELETE FROM sender_keys WHERE target_device_id = $1::uuid`, deviceID,
	); err != nil {
		return fmt.Errorf("prune ineligible device sender keys: %w", err)
	}
	return nil
}

type bindingQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func insertDeviceBindingVersion(ctx context.Context, tx pgx.Tx, binding *DeviceBinding) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO device_binding_versions
		   (device_id, binding_version, capabilities, binding_status,
		    account_signature, binding_commitment)
		 VALUES ($1::uuid, $2, $3, $4, $5, $6)`,
		binding.DeviceID, int64(binding.Version), int64(binding.Capabilities),
		int16(binding.Status), binding.AccountSignature, binding.Commitment,
	)
	if err != nil {
		return fmt.Errorf("append device binding version: %w", err)
	}
	return nil
}

func scanLatestDeviceBinding(ctx context.Context, query bindingQuerier, deviceID string, lock bool) (*DeviceBinding, error) {
	lockClause := ""
	if lock {
		lockClause = " FOR UPDATE OF head"
	}
	var binding DeviceBinding
	var version, capabilities int64
	var status int16
	err := query.QueryRow(ctx,
		`SELECT device.id::text, device.user_id::text, device.device_key,
		        keys.device_identity_key, keys.device_signing_key,
		        version.binding_version, version.capabilities, version.binding_status,
		        version.account_signature, version.binding_commitment, version.created_at
		 FROM device_binding_heads head
		 JOIN devices device ON device.id = head.device_id
		 JOIN device_crypto_keys keys ON keys.device_id = head.device_id
		 JOIN device_binding_versions version
		   ON version.device_id = head.device_id
		  AND version.binding_version = head.binding_version
		 WHERE head.device_id = $1::uuid`+lockClause,
		deviceID,
	).Scan(
		&binding.DeviceID, &binding.UserID, &binding.DeviceKey,
		&binding.DeviceIdentityKey, &binding.DeviceSigningKey,
		&version, &capabilities, &status, &binding.AccountSignature,
		&binding.Commitment, &binding.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDeviceBindingUnavailable
	}
	if err != nil {
		return nil, fmt.Errorf("load latest device binding: %w", err)
	}
	binding.Version = uint64(version)
	binding.Capabilities = uint64(capabilities)
	binding.Status = DeviceBindingStatus(status)
	return &binding, nil
}

func (db *DB) GetLatestDeviceBinding(ctx context.Context, deviceID string) (*DeviceBinding, error) {
	return scanLatestDeviceBinding(ctx, db.Pool, deviceID, false)
}

// GetDeviceBindingVersion loads one immutable historical version. It is used
// to verify a retained SKDM from a sender device whose current status may have
// changed after the distribution was durably accepted.
func (db *DB) GetDeviceBindingVersion(ctx context.Context, deviceID string, version uint64) (*DeviceBinding, error) {
	if deviceID == "" || version == 0 || version > math.MaxInt64 {
		return nil, ErrDeviceBindingUnavailable
	}
	var binding DeviceBinding
	var storedVersion, capabilities int64
	var status int16
	err := db.Pool.QueryRow(ctx,
		`SELECT device.id::text, device.user_id::text, device.device_key,
		        keys.device_identity_key, keys.device_signing_key,
		        binding.binding_version, binding.capabilities, binding.binding_status,
		        binding.account_signature, binding.binding_commitment, binding.created_at
		 FROM device_binding_versions binding
		 JOIN devices device ON device.id = binding.device_id
		 JOIN device_crypto_keys keys ON keys.device_id = binding.device_id
		 WHERE binding.device_id = $1::uuid AND binding.binding_version = $2`,
		deviceID, int64(version),
	).Scan(
		&binding.DeviceID, &binding.UserID, &binding.DeviceKey,
		&binding.DeviceIdentityKey, &binding.DeviceSigningKey,
		&storedVersion, &capabilities, &status, &binding.AccountSignature,
		&binding.Commitment, &binding.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDeviceBindingUnavailable
	}
	if err != nil {
		return nil, fmt.Errorf("load device binding version: %w", err)
	}
	binding.Version = uint64(storedVersion)
	binding.Capabilities = uint64(capabilities)
	binding.Status = DeviceBindingStatus(status)
	return &binding, nil
}

func (db *DB) GetLatestDeviceBindingByKey(ctx context.Context, deviceKey []byte) (*DeviceBinding, error) {
	var deviceID string
	if err := db.Pool.QueryRow(ctx,
		`SELECT id::text FROM devices WHERE device_key = $1`, deviceKey,
	).Scan(&deviceID); err != nil {
		return nil, err
	}
	return db.GetLatestDeviceBinding(ctx, deviceID)
}

func bindingEqual(left, right *DeviceBinding) bool {
	return left != nil && right != nil && left.DeviceID == right.DeviceID &&
		left.UserID == right.UserID && bytes.Equal(left.DeviceKey, right.DeviceKey) &&
		bytes.Equal(left.DeviceIdentityKey, right.DeviceIdentityKey) &&
		bytes.Equal(left.DeviceSigningKey, right.DeviceSigningKey) &&
		left.Version == right.Version && left.Capabilities == right.Capabilities &&
		left.Status == right.Status && bytes.Equal(left.AccountSignature, right.AccountSignature) &&
		bytes.Equal(left.Commitment, right.Commitment)
}

func cloneDeviceBinding(binding *DeviceBinding) *DeviceBinding {
	if binding == nil {
		return nil
	}
	clone := *binding
	clone.DeviceKey = append([]byte(nil), binding.DeviceKey...)
	clone.DeviceIdentityKey = append([]byte(nil), binding.DeviceIdentityKey...)
	clone.DeviceSigningKey = append([]byte(nil), binding.DeviceSigningKey...)
	clone.AccountSignature = append([]byte(nil), binding.AccountSignature...)
	clone.Commitment = append([]byte(nil), binding.Commitment...)
	return &clone
}
