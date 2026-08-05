// Package membership implements the shared, domain-separated authorization
// grammar for predecessor-linked encrypted-group membership epochs.
package membership

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"

	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
)

const (
	MaxOriginBytes                  = 2048
	MaxPolicySigners                = 1024
	ConversationKindGroup    byte   = 1
	ConversationKindChannel         = 2
	CryptoProfileSenderKeyV6        = 1
	CryptoEraV1              uint16 = 1
)

var (
	epochDomain     = []byte("veil-membership-epoch-v1\x00")
	signatureDomain = []byte("veil-membership-epoch-signature-v1\x00")
)

type Hash [sha256.Size]byte

type PolicySigner struct {
	AccountID         [16]byte
	AccountSigningKey [ed25519.PublicKeySize]byte
}

type Policy struct {
	Threshold uint16
	Signers   []PolicySigner
}

func (policy Policy) Validate() error {
	if len(policy.Signers) == 0 || len(policy.Signers) > MaxPolicySigners ||
		policy.Threshold == 0 || int(policy.Threshold) > len(policy.Signers) {
		return errors.New("membership authorization policy is invalid")
	}
	var prior [16]byte
	hasPrior := false
	signingKeys := make(map[[ed25519.PublicKeySize]byte]struct{}, len(policy.Signers))
	for _, signer := range policy.Signers {
		if signer.AccountID == ([16]byte{}) ||
			(hasPrior && bytes.Compare(prior[:], signer.AccountID[:]) >= 0) ||
			!cryptokey.ValidEd25519PublicKey(signer.AccountSigningKey[:]) {
			return errors.New("membership authorization policy is not canonical")
		}
		if _, exists := signingKeys[signer.AccountSigningKey]; exists {
			return errors.New("membership authorization policy is not canonical")
		}
		signingKeys[signer.AccountSigningKey] = struct{}{}
		prior = signer.AccountID
		hasPrior = true
	}
	return nil
}

func (policy Policy) signer(accountID [16]byte) (PolicySigner, bool) {
	left, right := 0, len(policy.Signers)
	for left < right {
		middle := left + (right-left)/2
		switch comparison := bytes.Compare(policy.Signers[middle].AccountID[:], accountID[:]); {
		case comparison < 0:
			left = middle + 1
		case comparison > 0:
			right = middle
		default:
			return policy.Signers[middle], true
		}
	}
	return PolicySigner{}, false
}

type Epoch struct {
	CanonicalOrigin  string
	ConversationID   [16]byte
	ConversationKind byte
	Number           uint64
	PredecessorHash  Hash
	RosterVersion    uint64
	RosterCommitment [32]byte
	SuccessorPolicy  Policy
	CryptoProfile    byte
	CryptoEra        uint16
	MutationNonce    [32]byte
}

func (epoch Epoch) Validate() error {
	if len(epoch.CanonicalOrigin) == 0 || len(epoch.CanonicalOrigin) > MaxOriginBytes ||
		len(epoch.CanonicalOrigin) > math.MaxUint16 || !isASCII(epoch.CanonicalOrigin) ||
		epoch.ConversationID == ([16]byte{}) ||
		(epoch.ConversationKind != ConversationKindGroup && epoch.ConversationKind != ConversationKindChannel) ||
		epoch.Number == 0 || epoch.Number > math.MaxInt64 ||
		(epoch.Number == 1) != (epoch.PredecessorHash == (Hash{})) ||
		epoch.RosterVersion == 0 || epoch.RosterVersion > math.MaxInt64 ||
		epoch.RosterCommitment == ([32]byte{}) ||
		epoch.CryptoProfile != CryptoProfileSenderKeyV6 || epoch.CryptoEra != CryptoEraV1 ||
		epoch.MutationNonce == ([32]byte{}) {
		return errors.New("membership epoch coordinates are invalid")
	}
	return epoch.SuccessorPolicy.Validate()
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= 0x80 {
			return false
		}
	}
	return true
}

func (epoch Epoch) CanonicalUnsignedBytes() ([]byte, error) {
	if err := epoch.Validate(); err != nil {
		return nil, err
	}
	capacity := len(epochDomain) + 2 + len(epoch.CanonicalOrigin) + 16 + 1 + 8 + 32 + 8 + 32 +
		2 + 2 + len(epoch.SuccessorPolicy.Signers)*48 + 1 + 2 + 32
	encoded := make([]byte, 0, capacity)
	encoded = append(encoded, epochDomain...)
	var integer2 [2]byte
	binary.BigEndian.PutUint16(integer2[:], uint16(len(epoch.CanonicalOrigin)))
	encoded = append(encoded, integer2[:]...)
	encoded = append(encoded, epoch.CanonicalOrigin...)
	encoded = append(encoded, epoch.ConversationID[:]...)
	encoded = append(encoded, epoch.ConversationKind)
	var integer8 [8]byte
	binary.BigEndian.PutUint64(integer8[:], epoch.Number)
	encoded = append(encoded, integer8[:]...)
	encoded = append(encoded, epoch.PredecessorHash[:]...)
	binary.BigEndian.PutUint64(integer8[:], epoch.RosterVersion)
	encoded = append(encoded, integer8[:]...)
	encoded = append(encoded, epoch.RosterCommitment[:]...)
	binary.BigEndian.PutUint16(integer2[:], epoch.SuccessorPolicy.Threshold)
	encoded = append(encoded, integer2[:]...)
	binary.BigEndian.PutUint16(integer2[:], uint16(len(epoch.SuccessorPolicy.Signers)))
	encoded = append(encoded, integer2[:]...)
	for _, signer := range epoch.SuccessorPolicy.Signers {
		encoded = append(encoded, signer.AccountID[:]...)
		encoded = append(encoded, signer.AccountSigningKey[:]...)
	}
	encoded = append(encoded, epoch.CryptoProfile)
	binary.BigEndian.PutUint16(integer2[:], epoch.CryptoEra)
	encoded = append(encoded, integer2[:]...)
	encoded = append(encoded, epoch.MutationNonce[:]...)
	return encoded, nil
}

func (epoch Epoch) Hash() (Hash, error) {
	encoded, err := epoch.CanonicalUnsignedBytes()
	if err != nil {
		return Hash{}, err
	}
	return sha256.Sum256(encoded), nil
}

func (epoch Epoch) SignatureMessage() ([]byte, error) {
	hash, err := epoch.Hash()
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(signatureDomain)+len(hash))
	message = append(message, signatureDomain...)
	message = append(message, hash[:]...)
	return message, nil
}

type Signature struct {
	SignerAccountID [16]byte
	Signature       [ed25519.SignatureSize]byte
}

func validateSignatureOrder(signatures []Signature) error {
	var prior [16]byte
	hasPrior := false
	for _, signature := range signatures {
		if signature.SignerAccountID == ([16]byte{}) || signature.Signature == ([ed25519.SignatureSize]byte{}) ||
			(hasPrior && bytes.Compare(prior[:], signature.SignerAccountID[:]) >= 0) {
			return errors.New("membership epoch signatures are not canonical")
		}
		prior = signature.SignerAccountID
		hasPrior = true
	}
	return nil
}

func VerifyBootstrap(epoch Epoch, expectedOwner PolicySigner, signatures []Signature) error {
	if err := epoch.Validate(); err != nil {
		return err
	}
	if epoch.Number != 1 || expectedOwner.AccountID == ([16]byte{}) ||
		!cryptokey.ValidEd25519PublicKey(expectedOwner.AccountSigningKey[:]) ||
		len(signatures) != 1 || signatures[0].SignerAccountID != expectedOwner.AccountID {
		return errors.New("membership epoch bootstrap authority is invalid")
	}
	if err := validateSignatureOrder(signatures); err != nil {
		return err
	}
	message, err := epoch.SignatureMessage()
	if err != nil {
		return err
	}
	if !ed25519.Verify(expectedOwner.AccountSigningKey[:], message, signatures[0].Signature[:]) {
		return errors.New("membership epoch bootstrap signature is invalid")
	}
	return nil
}

func VerifyTransition(predecessor, successor Epoch, signatures []Signature) error {
	if err := predecessor.Validate(); err != nil {
		return err
	}
	if err := successor.Validate(); err != nil {
		return err
	}
	predecessorHash, err := predecessor.Hash()
	if err != nil {
		return err
	}
	if predecessor.Number == math.MaxUint64 || successor.CanonicalOrigin != predecessor.CanonicalOrigin ||
		successor.ConversationID != predecessor.ConversationID ||
		successor.ConversationKind != predecessor.ConversationKind ||
		successor.Number != predecessor.Number+1 || successor.PredecessorHash != predecessorHash ||
		successor.RosterVersion < predecessor.RosterVersion ||
		(successor.RosterVersion == predecessor.RosterVersion && successor.RosterCommitment != predecessor.RosterCommitment) {
		return errors.New("membership epoch does not exactly extend its predecessor")
	}
	if len(signatures) < int(predecessor.SuccessorPolicy.Threshold) ||
		len(signatures) > len(predecessor.SuccessorPolicy.Signers) {
		return errors.New("membership epoch signature threshold is not satisfied")
	}
	if err := validateSignatureOrder(signatures); err != nil {
		return err
	}
	message, err := successor.SignatureMessage()
	if err != nil {
		return err
	}
	for _, signature := range signatures {
		signer, ok := predecessor.SuccessorPolicy.signer(signature.SignerAccountID)
		if !ok {
			return errors.New("membership epoch signature is outside the predecessor policy")
		}
		if !ed25519.Verify(signer.AccountSigningKey[:], message, signature.Signature[:]) {
			return errors.New("membership epoch transition signature is invalid")
		}
	}
	return nil
}
