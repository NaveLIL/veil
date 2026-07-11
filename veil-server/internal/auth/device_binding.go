package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"

	"github.com/AegisSec/veil-server/internal/db"
)

const (
	deviceBindingDomainV1 = "veil-device-binding-v1\x00"
	deviceAuthDomainV1    = "veil-device-auth-v1\x00"
)

var (
	ErrBadDeviceBinding      = errors.New("invalid cryptographic device binding")
	ErrBadDeviceBindingSig   = errors.New("invalid account signature on device binding")
	ErrBadDeviceProof        = errors.New("invalid cryptographic device proof")
	ErrDeviceBindingRequired = errors.New("cryptographic device binding required")
)

// DeviceBindingInput is the transport-neutral form shared by protobuf auth
// and signed REST device-management endpoints.
type DeviceBindingInput struct {
	DeviceKey         []byte
	DeviceIdentityKey []byte
	DeviceSigningKey  []byte
	Version           uint64
	Capabilities      uint64
	Status            db.DeviceBindingStatus
	AccountSignature  []byte
}

func validateDeviceBindingInput(binding *DeviceBindingInput, requireSignature bool) error {
	if binding == nil || len(binding.DeviceKey) != 16 ||
		len(binding.DeviceIdentityKey) != 32 || len(binding.DeviceSigningKey) != 32 ||
		binding.Version == 0 || binding.Version > math.MaxInt64 ||
		binding.Capabilities > math.MaxInt64 ||
		(requireSignature && len(binding.AccountSignature) != ed25519.SignatureSize) {
		return ErrBadDeviceBinding
	}
	if binding.Status != db.DeviceBindingActive && binding.Status != db.DeviceBindingExcluded &&
		binding.Status != db.DeviceBindingRevoked {
		return ErrBadDeviceBinding
	}
	return nil
}

func appendBindingFields(message []byte, binding *DeviceBindingInput) []byte {
	message = append(message, binding.DeviceKey...)
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], binding.Version)
	message = append(message, integer[:]...)
	message = append(message, binding.DeviceIdentityKey...)
	message = append(message, binding.DeviceSigningKey...)
	binary.BigEndian.PutUint64(integer[:], binding.Capabilities)
	message = append(message, integer[:]...)
	message = append(message, byte(binding.Status))
	return message
}

// DeviceBindingSigningMessage is the exact account-signed v1 preimage:
//
//	domain || account_x25519 || account_ed25519 || device_id || version_u64be ||
//	device_x25519 || device_ed25519 || capabilities_u64be || status_u8
func DeviceBindingSigningMessage(accountIdentityKey, accountSigningKey []byte, binding *DeviceBindingInput) ([]byte, error) {
	if len(accountIdentityKey) != 32 || len(accountSigningKey) != ed25519.PublicKeySize {
		return nil, ErrBadDeviceBinding
	}
	if err := validateDeviceBindingInput(binding, false); err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(deviceBindingDomainV1)+32+32+16+8+32+32+8+1)
	message = append(message, deviceBindingDomainV1...)
	message = append(message, accountIdentityKey...)
	message = append(message, accountSigningKey...)
	message = appendBindingFields(message, binding)
	return message, nil
}

// DeviceAuthSigningMessage is signed by the bound device Ed25519 key. The
// final DH secret proves possession of the corresponding device X25519 key.
func DeviceAuthSigningMessage(serverPublic, accountIdentityKey, accountSigningKey []byte, binding *DeviceBindingInput, deviceSharedSecret []byte) ([]byte, error) {
	if len(serverPublic) != 32 || len(accountIdentityKey) != 32 ||
		len(accountSigningKey) != ed25519.PublicKeySize || len(deviceSharedSecret) != 32 {
		return nil, ErrBadDeviceProof
	}
	if err := validateDeviceBindingInput(binding, true); err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(deviceAuthDomainV1)+32+32+32+16+8+32+32+8+1+64+32)
	message = append(message, deviceAuthDomainV1...)
	message = append(message, serverPublic...)
	message = append(message, accountIdentityKey...)
	message = append(message, accountSigningKey...)
	message = appendBindingFields(message, binding)
	message = append(message, binding.AccountSignature...)
	message = append(message, deviceSharedSecret...)
	return message, nil
}

func verifyAccountSignedDeviceBinding(user *db.User, binding *DeviceBindingInput) ([32]byte, error) {
	var commitment [32]byte
	if user == nil || len(user.IdentityKey) != 32 || len(user.SigningKey) != ed25519.PublicKeySize {
		return commitment, ErrBadDeviceBinding
	}
	message, err := DeviceBindingSigningMessage(user.IdentityKey, user.SigningKey, binding)
	if err != nil {
		return commitment, err
	}
	if !ed25519.Verify(ed25519.PublicKey(user.SigningKey), message, binding.AccountSignature) {
		return commitment, ErrBadDeviceBindingSig
	}
	return sha256.Sum256(message), nil
}

func bindingIsPerDeviceSecure(binding *db.DeviceBinding) bool {
	return binding != nil && binding.Status == db.DeviceBindingActive &&
		binding.Capabilities&db.RequiredChannelCapabilities == db.RequiredChannelCapabilities
}
