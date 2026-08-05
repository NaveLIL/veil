package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
)

const (
	nodeAccessPassCommitmentDomainV1 = "veil-node-access-pass-commitment-v1\x00"
	wsAuthContextDomainV3            = "veil-ws-auth-v3/context\x00"
	wsAuthAccountProofDomainV3       = "veil-ws-auth-v3/account-proof\x00"
	wsAuthDeviceProofDomainV3        = "veil-ws-auth-v3/device-proof\x00"

	NodeAccessPassSizeV1          = 32
	WSAuthV3SharedSecretSize      = 32
	WSAuthV3BindingCommitmentSize = 32
)

// ErrInvalidWSAuthV3 is returned for every malformed, non-canonical, or
// cryptographically invalid input to the WebSocket auth v3
// contract. Callers must not expose the wrapped diagnostic as a public auth
// oracle.
var ErrInvalidWSAuthV3 = errors.New("invalid WebSocket auth v3 input")

// WSAuthRegistrationIntentV3 makes account creation an authenticated choice.
// Zero and all values not listed here are deliberately invalid.
type WSAuthRegistrationIntentV3 uint8

const (
	WSAuthRegistrationExistingOnlyV3   WSAuthRegistrationIntentV3 = 1
	WSAuthRegistrationCreateOpenV3     WSAuthRegistrationIntentV3 = 2
	WSAuthRegistrationCreateWithPassV3 WSAuthRegistrationIntentV3 = 3
)

// WSAuthContextV3Input contains only the security fields authenticated by both
// v3 proofs. VerifiedBindingCommitment must be the 32-byte commitment returned
// after independently validating the account-signed device binding. The full
// binding, presentation metadata, and raw Node Access Pass intentionally do not
// belong to this transcript.
type WSAuthContextV3Input struct {
	CanonicalOrigin           string
	ServerEphemeral           [32]byte
	AccountIdentityKey        [32]byte
	AccountSigningKey         [ed25519.PublicKeySize]byte
	DeviceID                  [16]byte
	VerifiedBindingCommitment [WSAuthV3BindingCommitmentSize]byte
	RegistrationIntent        WSAuthRegistrationIntentV3
	PassCommitment            [sha256.Size]byte
}

// NodeAccessPassCommitmentV1 returns:
//
//	SHA-256("veil-node-access-pass-commitment-v1\0" ||
//	        u32be(origin_len) || origin || raw_pass_32)
//
// The canonical origin scopes the bearer to exactly one Node. The temporary
// preimage is cleared before this function returns.
func NodeAccessPassCommitmentV1(canonicalOrigin string, rawPass []byte) ([sha256.Size]byte, error) {
	var commitment [sha256.Size]byte
	if err := nodeorigin.ValidateCanonical(canonicalOrigin); err != nil {
		return commitment, wsAuthV3Invalid("canonical origin", err)
	}
	if len(rawPass) != NodeAccessPassSizeV1 || allZeroWSAuthV3(rawPass) {
		return commitment, wsAuthV3Invalid("Node Access Pass must be a non-zero 32-byte value", nil)
	}

	preimage := make([]byte, 0, len(nodeAccessPassCommitmentDomainV1)+4+len(canonicalOrigin)+len(rawPass))
	preimage = append(preimage, nodeAccessPassCommitmentDomainV1...)
	preimage = appendWSAuthV3LengthPrefixed(preimage, canonicalOrigin)
	preimage = append(preimage, rawPass...)
	commitment = sha256.Sum256(preimage)
	clear(preimage)
	if allZeroWSAuthV3(commitment[:]) {
		return [sha256.Size]byte{}, wsAuthV3Invalid("Node Access Pass commitment is zero", nil)
	}
	return commitment, nil
}

// WSAuthV3Context returns the exact origin-bound canonical context:
//
//	domain || u32be(origin_len) || origin || server_ephemeral_32 ||
//	account_x25519_32 || account_ed25519_32 || device_id_16 ||
//	verified_binding_commitment_32 || intent_u8 || pass_commitment_32
func WSAuthV3Context(input WSAuthContextV3Input) ([]byte, error) {
	if err := validateWSAuthContextV3Input(input); err != nil {
		return nil, err
	}

	context := make([]byte, 0, len(wsAuthContextDomainV3)+4+len(input.CanonicalOrigin)+
		32+32+ed25519.PublicKeySize+16+WSAuthV3BindingCommitmentSize+1+sha256.Size)
	context = append(context, wsAuthContextDomainV3...)
	context = appendWSAuthV3LengthPrefixed(context, input.CanonicalOrigin)
	context = append(context, input.ServerEphemeral[:]...)
	context = append(context, input.AccountIdentityKey[:]...)
	context = append(context, input.AccountSigningKey[:]...)
	context = append(context, input.DeviceID[:]...)
	context = append(context, input.VerifiedBindingCommitment[:]...)
	context = append(context, byte(input.RegistrationIntent))
	context = append(context, input.PassCommitment[:]...)
	return context, nil
}

// WSAuthV3AccountProofMessage returns the exact account Ed25519 preimage:
//
//	domain || u32be(context_len) || context || account_shared_32
//
// The returned message contains a DH secret and must be cleared by its caller
// immediately after signing or verification.
func WSAuthV3AccountProofMessage(input WSAuthContextV3Input, accountShared []byte) ([]byte, error) {
	context, err := WSAuthV3Context(input)
	if err != nil {
		return nil, err
	}
	if err := validateWSAuthV3SharedSecret(accountShared); err != nil {
		return nil, err
	}

	message := make([]byte, 0, len(wsAuthAccountProofDomainV3)+4+len(context)+WSAuthV3SharedSecretSize)
	message = append(message, wsAuthAccountProofDomainV3...)
	message = appendWSAuthV3Bytes(message, context)
	message = append(message, accountShared...)
	return message, nil
}

// WSAuthV3DeviceProofMessage returns the exact device Ed25519 preimage:
//
//	domain || u32be(context_len) || context || device_shared_32 ||
//	account_proof_signature_64
//
// Chaining the account proof signature prevents a device proof from being
// detached from the exact account proof accepted for the same handshake. The
// returned message contains a DH secret and must be cleared by its caller. This
// byte builder validates only the signature field's fixed non-zero shape; the
// caller must supply the account proof signature it has already verified
// strictly against the corresponding account proof message.
func WSAuthV3DeviceProofMessage(input WSAuthContextV3Input, deviceShared, accountProofSignature []byte) ([]byte, error) {
	//lint:ignore SA4006 Staticcheck v0.6.1 misreads this Go 1.26 slice; it is length-bound and appended below.
	canonicalContext, contextErr := WSAuthV3Context(input)
	if contextErr != nil {
		return nil, contextErr
	}
	if err := validateWSAuthV3SharedSecret(deviceShared); err != nil {
		return nil, err
	}
	if len(accountProofSignature) != ed25519.SignatureSize || allZeroWSAuthV3(accountProofSignature) {
		return nil, wsAuthV3Invalid("account proof signature", nil)
	}

	message := make([]byte, 0, len(wsAuthDeviceProofDomainV3)+4+len(canonicalContext)+
		WSAuthV3SharedSecretSize+ed25519.SignatureSize)
	message = append(message, wsAuthDeviceProofDomainV3...)
	message = appendWSAuthV3Bytes(message, canonicalContext)
	message = append(message, deviceShared...)
	message = append(message, accountProofSignature...)
	return message, nil
}

func validateWSAuthContextV3Input(input WSAuthContextV3Input) error {
	if err := nodeorigin.ValidateCanonical(input.CanonicalOrigin); err != nil {
		return wsAuthV3Invalid("canonical origin", err)
	}
	if allZeroWSAuthV3(input.ServerEphemeral[:]) {
		return wsAuthV3Invalid("server ephemeral key is zero", nil)
	}
	if allZeroWSAuthV3(input.AccountIdentityKey[:]) {
		return wsAuthV3Invalid("account X25519 key is zero", nil)
	}
	if !cryptokey.ValidEd25519PublicKey(input.AccountSigningKey[:]) {
		return wsAuthV3Invalid("account Ed25519 key", nil)
	}
	if allZeroWSAuthV3(input.DeviceID[:]) {
		return wsAuthV3Invalid("device id is zero", nil)
	}
	if allZeroWSAuthV3(input.VerifiedBindingCommitment[:]) {
		return wsAuthV3Invalid("verified binding commitment is zero", nil)
	}

	commitmentIsZero := allZeroWSAuthV3(input.PassCommitment[:])
	switch input.RegistrationIntent {
	case WSAuthRegistrationExistingOnlyV3, WSAuthRegistrationCreateOpenV3:
		if !commitmentIsZero {
			return wsAuthV3Invalid("non-pass intent carries a Pass commitment", nil)
		}
	case WSAuthRegistrationCreateWithPassV3:
		if commitmentIsZero {
			return wsAuthV3Invalid("Pass intent has a zero Pass commitment", nil)
		}
	default:
		return wsAuthV3Invalid("registration intent", nil)
	}
	return nil
}

func validateWSAuthV3SharedSecret(shared []byte) error {
	if len(shared) != WSAuthV3SharedSecretSize || allZeroWSAuthV3(shared) {
		return wsAuthV3Invalid("X25519 shared secret", nil)
	}
	return nil
}

func appendWSAuthV3LengthPrefixed(output []byte, value string) []byte {
	return appendWSAuthV3Bytes(output, []byte(value))
}

func appendWSAuthV3Bytes(output, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	output = append(output, length[:]...)
	return append(output, value...)
}

func allZeroWSAuthV3(value []byte) bool {
	var aggregate byte
	for _, item := range value {
		aggregate |= item
	}
	return subtle.ConstantTimeByteEq(aggregate, 0) == 1
}

func wsAuthV3Invalid(field string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalidWSAuthV3, field, cause)
	}
	return fmt.Errorf("%w: %s", ErrInvalidWSAuthV3, field)
}
