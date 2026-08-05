// Package transparency implements the shared, domain-separated proof grammar
// for Veil's append-only identity log. Trust policy, durable pinning and
// witness requirements intentionally live above these pure primitives.
package transparency

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"math/bits"

	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
)

const (
	MaxEventBytes  = 4096
	MaxProofNodes  = 63
	MaxOriginBytes = 2048
	MaxWitnesses   = 32
)

var (
	emptyDomain               = []byte("veil-transparency-empty-v1\x00")
	leafDomain                = []byte("veil-transparency-leaf-v1\x00")
	nodeDomain                = []byte("veil-transparency-node-v1\x00")
	treeHeadDomain            = []byte("veil-transparency-sth-v1\x00")
	logIDDomain               = []byte("veil-transparency-log-id-v1\x00")
	witnessCheckpointDomain   = []byte("veil-transparency-witness-checkpoint-v1\x00")
	witnessPolicyDomain       = []byte("veil-transparency-witness-policy-v1\x00")
	accountRegistrationDomain = []byte("veil-transparency-account-registration-v1\x00")
	deviceBindingDomain       = []byte("veil-transparency-device-binding-v1\x00")
)

type Hash [sha256.Size]byte

func hashParts(parts ...[]byte) Hash {
	digest := sha256.New()
	for _, part := range parts {
		_, _ = digest.Write(part)
	}
	var result Hash
	copy(result[:], digest.Sum(nil))
	return result
}

func EmptyRoot() Hash {
	return hashParts(emptyDomain)
}

func LeafHash(event []byte) (Hash, error) {
	if len(event) == 0 || len(event) > MaxEventBytes {
		return Hash{}, errors.New("transparency event length is invalid")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(event)))
	return hashParts(leafDomain, length[:], event), nil
}

func NodeHash(left, right Hash) Hash {
	return hashParts(nodeDomain, left[:], right[:])
}

func largestPowerOfTwoLessThan(value int) int {
	highest := 1 << (bits.Len(uint(value)) - 1)
	if highest == value {
		return highest >> 1
	}
	return highest
}

func rootFromHashes(hashes []Hash) Hash {
	switch len(hashes) {
	case 0:
		return EmptyRoot()
	case 1:
		return hashes[0]
	default:
		split := largestPowerOfTwoLessThan(len(hashes))
		return NodeHash(rootFromHashes(hashes[:split]), rootFromHashes(hashes[split:]))
	}
}

func checkedLeafHashes(events [][]byte) ([]Hash, error) {
	if uint64(len(events)) > uint64(math.MaxInt64) {
		return nil, errors.New("transparency tree size is invalid")
	}
	hashes := make([]Hash, len(events))
	for index, event := range events {
		hash, err := LeafHash(event)
		if err != nil {
			return nil, err
		}
		hashes[index] = hash
	}
	return hashes, nil
}

func TreeRoot(events [][]byte) (Hash, error) {
	hashes, err := checkedLeafHashes(events)
	if err != nil {
		return Hash{}, err
	}
	return rootFromHashes(hashes), nil
}

func inclusionPath(hashes []Hash, leafIndex int) []Hash {
	if len(hashes) == 1 {
		return nil
	}
	split := largestPowerOfTwoLessThan(len(hashes))
	if leafIndex < split {
		proof := inclusionPath(hashes[:split], leafIndex)
		return append(proof, rootFromHashes(hashes[split:]))
	}
	proof := inclusionPath(hashes[split:], leafIndex-split)
	return append(proof, rootFromHashes(hashes[:split]))
}

func InclusionProof(events [][]byte, leafIndex int) ([]Hash, error) {
	if len(events) == 0 || leafIndex < 0 || leafIndex >= len(events) {
		return nil, errors.New("transparency inclusion coordinates are invalid")
	}
	hashes, err := checkedLeafHashes(events)
	if err != nil {
		return nil, err
	}
	proof := inclusionPath(hashes, leafIndex)
	if len(proof) > MaxProofNodes {
		return nil, errors.New("transparency inclusion proof is oversized")
	}
	return proof, nil
}

func VerifyInclusion(event []byte, leafIndex, treeSize uint64, proof []Hash, expectedRoot Hash) bool {
	if treeSize == 0 || treeSize > math.MaxInt64 || leafIndex >= treeSize || len(proof) > MaxProofNodes {
		return false
	}
	calculated, err := LeafHash(event)
	if err != nil {
		return false
	}
	leaf := leafIndex
	last := treeSize - 1
	for _, sibling := range proof {
		if leaf&1 == 1 || leaf == last {
			calculated = NodeHash(sibling, calculated)
			for leaf != 0 && leaf&1 == 0 {
				leaf >>= 1
				last >>= 1
			}
		} else {
			calculated = NodeHash(calculated, sibling)
		}
		leaf >>= 1
		last >>= 1
	}
	return last == 0 && calculated == expectedRoot
}

func consistencyPath(hashes []Hash, oldSize int, completeSubtree bool) []Hash {
	if oldSize == len(hashes) {
		if completeSubtree {
			return nil
		}
		return []Hash{rootFromHashes(hashes)}
	}
	split := largestPowerOfTwoLessThan(len(hashes))
	if oldSize <= split {
		proof := consistencyPath(hashes[:split], oldSize, completeSubtree)
		return append(proof, rootFromHashes(hashes[split:]))
	}
	proof := consistencyPath(hashes[split:], oldSize-split, false)
	return append(proof, rootFromHashes(hashes[:split]))
}

func ConsistencyProof(events [][]byte, oldSize int) ([]Hash, error) {
	if oldSize <= 0 || oldSize > len(events) {
		return nil, errors.New("transparency consistency coordinates are invalid")
	}
	if oldSize == len(events) {
		return nil, nil
	}
	hashes, err := checkedLeafHashes(events)
	if err != nil {
		return nil, err
	}
	proof := consistencyPath(hashes, oldSize, true)
	if len(proof) > MaxProofNodes {
		return nil, errors.New("transparency consistency proof is oversized")
	}
	return proof, nil
}

func VerifyConsistency(oldSize, newSize uint64, oldRoot, newRoot Hash, proof []Hash) bool {
	if oldSize == 0 || oldSize > newSize || newSize > math.MaxInt64 || len(proof) > MaxProofNodes {
		return false
	}
	if oldSize == newSize {
		return len(proof) == 0 && oldRoot == newRoot
	}

	oldCursor := oldSize - 1
	newCursor := newSize - 1
	for oldCursor&1 == 1 {
		oldCursor >>= 1
		newCursor >>= 1
	}

	var oldHash, newHash Hash
	proofIndex := 0
	if oldCursor == 0 {
		oldHash, newHash = oldRoot, oldRoot
	} else {
		if len(proof) == 0 {
			return false
		}
		oldHash, newHash = proof[0], proof[0]
		proofIndex = 1
	}

	for ; proofIndex < len(proof); proofIndex++ {
		if newCursor == 0 {
			return false
		}
		sibling := proof[proofIndex]
		if oldCursor&1 == 1 || oldCursor == newCursor {
			oldHash = NodeHash(sibling, oldHash)
			newHash = NodeHash(sibling, newHash)
			for oldCursor != 0 && oldCursor&1 == 0 {
				oldCursor >>= 1
				newCursor >>= 1
			}
		} else {
			newHash = NodeHash(newHash, sibling)
		}
		oldCursor >>= 1
		newCursor >>= 1
	}
	return newCursor == 0 && oldHash == oldRoot && newHash == newRoot
}

func validatedOrigin(canonicalOrigin string) ([]byte, error) {
	origin := []byte(canonicalOrigin)
	if len(origin) == 0 || len(origin) > MaxOriginBytes || len(origin) > math.MaxUint16 {
		return nil, errors.New("transparency canonical origin is invalid")
	}
	for _, value := range origin {
		if value >= 0x80 {
			return nil, errors.New("transparency canonical origin is invalid")
		}
	}
	return origin, nil
}

func LogID(canonicalOrigin string, nodeSigningKey []byte) (Hash, error) {
	origin, err := validatedOrigin(canonicalOrigin)
	if err != nil {
		return Hash{}, err
	}
	if !cryptokey.ValidEd25519PublicKey(nodeSigningKey) {
		return Hash{}, errors.New("transparency Node signing key is invalid")
	}
	var originLength [2]byte
	binary.BigEndian.PutUint16(originLength[:], uint16(len(origin)))
	return hashParts(logIDDomain, originLength[:], origin, nodeSigningKey), nil
}

func AccountRegistrationEvent(canonicalOrigin string, accountID, identityKey, signingKey []byte) ([]byte, error) {
	origin, err := validatedOrigin(canonicalOrigin)
	if err != nil {
		return nil, err
	}
	if len(accountID) != 16 || len(identityKey) != 32 || len(signingKey) != ed25519.PublicKeySize ||
		allZero(accountID) || allZero(identityKey) || !cryptokey.ValidEd25519PublicKey(signingKey) {
		return nil, errors.New("transparency account registration is invalid")
	}
	event := make([]byte, 0, len(accountRegistrationDomain)+2+len(origin)+16+32+32)
	event = append(event, accountRegistrationDomain...)
	var originLength [2]byte
	binary.BigEndian.PutUint16(originLength[:], uint16(len(origin)))
	event = append(event, originLength[:]...)
	event = append(event, origin...)
	event = append(event, accountID...)
	event = append(event, identityKey...)
	event = append(event, signingKey...)
	return event, nil
}

func DeviceBindingEvent(
	canonicalOrigin string,
	accountID, deviceKey, deviceIdentityKey, deviceSigningKey []byte,
	version, capabilities uint64,
	status uint8,
	accountSignature, commitment []byte,
) ([]byte, error) {
	origin, err := validatedOrigin(canonicalOrigin)
	if err != nil {
		return nil, err
	}
	if len(accountID) != 16 || len(deviceKey) != 16 || len(deviceIdentityKey) != 32 ||
		len(deviceSigningKey) != ed25519.PublicKeySize || version == 0 || version > math.MaxInt64 ||
		capabilities > math.MaxInt64 || status < 1 || status > 3 ||
		len(accountSignature) != ed25519.SignatureSize || len(commitment) != sha256.Size ||
		allZero(accountID) || allZero(deviceKey) || allZero(deviceIdentityKey) ||
		!cryptokey.ValidEd25519PublicKey(deviceSigningKey) || allZero(accountSignature) ||
		allZero(commitment) {
		return nil, errors.New("transparency device binding is invalid")
	}
	event := make([]byte, 0, len(deviceBindingDomain)+2+len(origin)+16+16+32+32+8+8+1+64+32)
	event = append(event, deviceBindingDomain...)
	var encoded [8]byte
	binary.BigEndian.PutUint16(encoded[:2], uint16(len(origin)))
	event = append(event, encoded[:2]...)
	event = append(event, origin...)
	event = append(event, accountID...)
	event = append(event, deviceKey...)
	event = append(event, deviceIdentityKey...)
	event = append(event, deviceSigningKey...)
	binary.BigEndian.PutUint64(encoded[:], version)
	event = append(event, encoded[:]...)
	binary.BigEndian.PutUint64(encoded[:], capabilities)
	event = append(event, encoded[:]...)
	event = append(event, status)
	event = append(event, accountSignature...)
	event = append(event, commitment...)
	return event, nil
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

type TreeHead struct {
	LogID      Hash
	TreeSize   uint64
	RootHash   Hash
	IssuedAtMs uint64
}

func (head TreeHead) SigningMessage(canonicalOrigin string) ([]byte, error) {
	origin, err := validatedOrigin(canonicalOrigin)
	if err != nil {
		return nil, err
	}
	if head.LogID == (Hash{}) || head.TreeSize > math.MaxInt64 || head.IssuedAtMs == 0 ||
		(head.TreeSize == 0 && head.RootHash != EmptyRoot()) {
		return nil, errors.New("transparency tree head is invalid")
	}
	message := make([]byte, 0, len(treeHeadDomain)+2+len(origin)+32+8+32+8)
	message = append(message, treeHeadDomain...)
	var encoded [8]byte
	binary.BigEndian.PutUint16(encoded[:2], uint16(len(origin)))
	message = append(message, encoded[:2]...)
	message = append(message, origin...)
	message = append(message, head.LogID[:]...)
	binary.BigEndian.PutUint64(encoded[:], head.TreeSize)
	message = append(message, encoded[:]...)
	message = append(message, head.RootHash[:]...)
	binary.BigEndian.PutUint64(encoded[:], head.IssuedAtMs)
	message = append(message, encoded[:]...)
	return message, nil
}

func (head TreeHead) VerifyNodeSignature(canonicalOrigin string, nodeSigningKey, signature []byte) bool {
	if !cryptokey.ValidEd25519PublicKey(nodeSigningKey) || len(signature) != ed25519.SignatureSize {
		return false
	}
	message, err := head.SigningMessage(canonicalOrigin)
	return err == nil && ed25519.Verify(ed25519.PublicKey(nodeSigningKey), message, signature)
}

func WitnessCheckpointMessage(
	canonicalOrigin string,
	nodeSigningKey []byte,
	head TreeHead,
	nodeSignature []byte,
) ([]byte, error) {
	origin, err := validatedOrigin(canonicalOrigin)
	if err != nil {
		return nil, err
	}
	expectedLogID, err := LogID(canonicalOrigin, nodeSigningKey)
	if err != nil || expectedLogID != head.LogID ||
		!head.VerifyNodeSignature(canonicalOrigin, nodeSigningKey, nodeSignature) {
		return nil, errors.New("transparency witness checkpoint is invalid")
	}
	message := make([]byte, 0, len(witnessCheckpointDomain)+2+len(origin)+32+32+8+32+8+64)
	message = append(message, witnessCheckpointDomain...)
	var encoded [8]byte
	binary.BigEndian.PutUint16(encoded[:2], uint16(len(origin)))
	message = append(message, encoded[:2]...)
	message = append(message, origin...)
	message = append(message, nodeSigningKey...)
	message = append(message, head.LogID[:]...)
	binary.BigEndian.PutUint64(encoded[:], head.TreeSize)
	message = append(message, encoded[:]...)
	message = append(message, head.RootHash[:]...)
	binary.BigEndian.PutUint64(encoded[:], head.IssuedAtMs)
	message = append(message, encoded[:]...)
	message = append(message, nodeSignature...)
	return message, nil
}

func WitnessPolicyHash(threshold uint16, witnessSigningKeys [][]byte) (Hash, error) {
	if threshold == 0 || int(threshold) > len(witnessSigningKeys) ||
		len(witnessSigningKeys) == 0 || len(witnessSigningKeys) > MaxWitnesses {
		return Hash{}, errors.New("transparency witness policy is invalid")
	}
	for index, key := range witnessSigningKeys {
		if !cryptokey.ValidEd25519PublicKey(key) ||
			(index > 0 && bytes.Compare(witnessSigningKeys[index-1], key) >= 0) {
			return Hash{}, errors.New("transparency witness policy is not canonical")
		}
	}
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], threshold)
	parts := make([][]byte, 0, len(witnessSigningKeys)+3)
	parts = append(parts, witnessPolicyDomain, append([]byte(nil), encoded[:]...))
	binary.BigEndian.PutUint16(encoded[:], uint16(len(witnessSigningKeys)))
	parts = append(parts, append([]byte(nil), encoded[:]...))
	parts = append(parts, witnessSigningKeys...)
	return hashParts(parts...), nil
}
