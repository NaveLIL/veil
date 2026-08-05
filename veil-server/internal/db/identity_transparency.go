package db

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"math/bits"

	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
	veiltransparency "github.com/NaveLIL/veil/veil-server/internal/transparency"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	identityTransparencyAccountRegistrationV1 int16 = 1
	identityTransparencyDeviceBindingV1       int16 = 2
)

var (
	ErrIdentityTransparencyInactive       = errors.New("identity transparency is not active")
	ErrIdentityTransparencyHeadRegression = errors.New("identity transparency requested head is newer than the Node head")
)

type identityTransparencyRuntime struct {
	canonicalOrigin string
	logID           veiltransparency.Hash
	nodeSigningKey  [ed25519.PublicKeySize]byte
}

type IdentityTransparencyHead struct {
	LogID          veiltransparency.Hash
	NodeSigningKey [ed25519.PublicKeySize]byte
	TreeSize       uint64
	RootHash       veiltransparency.Hash
}

type IdentityTransparencyProof struct {
	CanonicalEvent   []byte
	LeafIndex        uint64
	Head             IdentityTransparencyHead
	InclusionProof   []veiltransparency.Hash
	ConsistencyFrom  uint64
	ConsistencyProof []veiltransparency.Hash
}

type IdentityTransparencyAccountProof = IdentityTransparencyProof
type IdentityTransparencyDeviceBindingProof = IdentityTransparencyProof

func nonzeroTransparencyHash(value veiltransparency.Hash) bool {
	return value != (veiltransparency.Hash{})
}

func exactTransparencyHash(label string, value []byte) (veiltransparency.Hash, error) {
	if len(value) != 32 {
		return veiltransparency.Hash{}, fmt.Errorf("%s has invalid length", label)
	}
	var result veiltransparency.Hash
	copy(result[:], value)
	if !nonzeroTransparencyHash(result) {
		return veiltransparency.Hash{}, fmt.Errorf("%s is zero", label)
	}
	return result, nil
}

// EnableIdentityTransparencyLog activates account-registration logging for a
// fresh Node or reopens an already-active exact log after a complete startup
// audit. Existing unlogged accounts are never silently backfilled or relabeled
// as transparent; they require a separately reviewed bootstrap ceremony.
//
// This method is startup-only and must complete before any service accepts a
// registration request.
func (db *DB) EnableIdentityTransparencyLog(
	ctx context.Context,
	canonicalOrigin nodeorigin.Canonical,
	logID veiltransparency.Hash,
	nodeSigningKey []byte,
) error {
	if db == nil || db.Pool == nil || canonicalOrigin.IsZero() || !nonzeroTransparencyHash(logID) ||
		!cryptokey.ValidEd25519PublicKey(nodeSigningKey) {
		return errors.New("invalid identity transparency configuration")
	}
	expectedLogID, err := veiltransparency.LogID(canonicalOrigin.String(), nodeSigningKey)
	if err != nil || expectedLogID != logID {
		return errors.New("identity transparency log id does not match its exact origin and signing key")
	}
	var signingKey [ed25519.PublicKeySize]byte
	copy(signingKey[:], nodeSigningKey)
	runtimeState := &identityTransparencyRuntime{
		canonicalOrigin: canonicalOrigin.String(),
		logID:           logID,
		nodeSigningKey:  signingKey,
	}

	db.identityTransparencyMu.RLock()
	existingRuntime := db.identityTransparency
	db.identityTransparencyMu.RUnlock()
	if existingRuntime != nil {
		if *existingRuntime == *runtimeState {
			return nil
		}
		return errors.New("identity transparency runtime is already configured differently")
	}

	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin identity transparency startup: %w", err)
	}
	defer tx.Rollback(ctx)

	emptyRoot := veiltransparency.EmptyRoot()
	if _, err := tx.Exec(ctx,
		`INSERT INTO identity_transparency_log_state
		   (singleton, log_id, node_signing_key, tree_size, root_hash)
		 SELECT TRUE, $1, $2, 0, $3
		 WHERE NOT EXISTS (SELECT 1 FROM users)
		 ON CONFLICT (singleton) DO NOTHING`,
		logID[:], nodeSigningKey, emptyRoot[:],
	); err != nil {
		return fmt.Errorf("initialize identity transparency head: %w", err)
	}

	head, err := loadIdentityTransparencyHeadTx(ctx, tx, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("identity transparency activation requires an empty Node or an existing audited log")
	}
	if err != nil {
		return err
	}
	if head.LogID != logID || head.NodeSigningKey != signingKey {
		return errors.New("persisted identity transparency log identity differs from configuration")
	}
	if err := auditIdentityTransparencyTx(ctx, tx, head); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit identity transparency startup: %w", err)
	}

	db.identityTransparencyMu.Lock()
	defer db.identityTransparencyMu.Unlock()
	if db.identityTransparency != nil && *db.identityTransparency != *runtimeState {
		return errors.New("identity transparency runtime changed during startup")
	}
	db.identityTransparency = runtimeState
	return nil
}

func (db *DB) identityTransparencySnapshot() *identityTransparencyRuntime {
	if db == nil {
		return nil
	}
	db.identityTransparencyMu.RLock()
	defer db.identityTransparencyMu.RUnlock()
	if db.identityTransparency == nil {
		return nil
	}
	copyState := *db.identityTransparency
	return &copyState
}

func loadIdentityTransparencyHeadTx(ctx context.Context, tx pgx.Tx, lock bool) (IdentityTransparencyHead, error) {
	lockClause := ""
	if lock {
		lockClause = " FOR UPDATE"
	}
	var logID, signingKey, rootHash []byte
	var treeSize int64
	err := tx.QueryRow(ctx,
		`SELECT log_id, node_signing_key, tree_size, root_hash
		 FROM identity_transparency_log_state
		 WHERE singleton = TRUE`+lockClause,
	).Scan(&logID, &signingKey, &treeSize, &rootHash)
	if err != nil {
		return IdentityTransparencyHead{}, err
	}
	parsedLogID, err := exactTransparencyHash("identity transparency log id", logID)
	if err != nil {
		return IdentityTransparencyHead{}, err
	}
	parsedRoot, err := exactTransparencyHash("identity transparency root", rootHash)
	if err != nil {
		return IdentityTransparencyHead{}, err
	}
	if treeSize < 0 || len(signingKey) != ed25519.PublicKeySize ||
		!cryptokey.ValidEd25519PublicKey(signingKey) {
		return IdentityTransparencyHead{}, errors.New("persisted identity transparency head is invalid")
	}
	var parsedSigningKey [ed25519.PublicKeySize]byte
	copy(parsedSigningKey[:], signingKey)
	return IdentityTransparencyHead{
		LogID:          parsedLogID,
		NodeSigningKey: parsedSigningKey,
		TreeSize:       uint64(treeSize),
		RootHash:       parsedRoot,
	}, nil
}

func largestTransparencyPowerLessThan(value uint64) uint64 {
	highest := uint64(1) << (bits.Len64(value) - 1)
	if highest == value {
		return highest >> 1
	}
	return highest
}

func identityTransparencyRangeHashTx(
	ctx context.Context,
	tx pgx.Tx,
	start uint64,
	length uint64,
) (veiltransparency.Hash, error) {
	if length == 0 || start > math.MaxInt64 || length > math.MaxInt64 ||
		start > math.MaxInt64-length+1 {
		return veiltransparency.Hash{}, errors.New("identity transparency range is invalid")
	}
	if length&(length-1) == 0 && start%length == 0 {
		level := bits.TrailingZeros64(length)
		if level > 62 {
			return veiltransparency.Hash{}, errors.New("identity transparency node level is invalid")
		}
		var encoded []byte
		err := tx.QueryRow(ctx,
			`SELECT node_hash FROM identity_transparency_log_nodes
			 WHERE node_level = $1 AND node_index = $2`,
			int16(level), int64(start/length),
		).Scan(&encoded)
		if err != nil {
			return veiltransparency.Hash{}, fmt.Errorf("load identity transparency node: %w", err)
		}
		return exactTransparencyHash("identity transparency node", encoded)
	}
	split := largestTransparencyPowerLessThan(length)
	left, err := identityTransparencyRangeHashTx(ctx, tx, start, split)
	if err != nil {
		return veiltransparency.Hash{}, err
	}
	right, err := identityTransparencyRangeHashTx(ctx, tx, start+split, length-split)
	if err != nil {
		return veiltransparency.Hash{}, err
	}
	return veiltransparency.NodeHash(left, right), nil
}

func expectedIdentityTransparencyNodeCount(treeSize uint64) (uint64, error) {
	var count uint64
	for width := treeSize; width != 0; width >>= 1 {
		if count > math.MaxInt64-width {
			return 0, errors.New("identity transparency node count overflow")
		}
		count += width
	}
	return count, nil
}

func auditIdentityTransparencyTx(ctx context.Context, tx pgx.Tx, head IdentityTransparencyHead) error {
	if head.TreeSize == 0 {
		if head.RootHash != veiltransparency.EmptyRoot() {
			return errors.New("empty identity transparency log has an invalid root")
		}
	} else {
		root, err := identityTransparencyRangeHashTx(ctx, tx, 0, head.TreeSize)
		if err != nil {
			return err
		}
		if root != head.RootHash {
			return errors.New("identity transparency node tree differs from its head")
		}
	}

	var leafCount, levelZeroCount, nodeCount int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity_transparency_log_leaves`).Scan(&leafCount); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity_transparency_log_nodes WHERE node_level = 0`).Scan(&levelZeroCount); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity_transparency_log_nodes`).Scan(&nodeCount); err != nil {
		return err
	}
	expectedNodes, err := expectedIdentityTransparencyNodeCount(head.TreeSize)
	if err != nil {
		return err
	}
	if leafCount != int64(head.TreeSize) || levelZeroCount != int64(head.TreeSize) ||
		nodeCount != int64(expectedNodes) {
		return errors.New("identity transparency storage cardinality differs from its head")
	}
	var missingAccountLeaf bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM users AS account
		   LEFT JOIN identity_transparency_log_leaves AS leaf
		     ON leaf.event_kind = 1 AND leaf.subject_user_id = account.id
		   WHERE leaf.leaf_index IS NULL
		 )`,
	).Scan(&missingAccountLeaf); err != nil {
		return err
	}
	if missingAccountLeaf {
		return errors.New("identity transparency log is missing an account registration")
	}
	var missingDeviceBindingLeaf bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM device_binding_versions AS binding
		   JOIN devices AS device ON device.id = binding.device_id
		   LEFT JOIN identity_transparency_log_leaves AS leaf
		     ON leaf.event_kind = 2
		    AND leaf.subject_user_id = device.user_id
		    AND leaf.subject_device_id = binding.device_id
		    AND leaf.binding_version = binding.binding_version
		   WHERE leaf.leaf_index IS NULL
		 )`,
	).Scan(&missingDeviceBindingLeaf); err != nil {
		return err
	}
	if missingDeviceBindingLeaf {
		return errors.New("identity transparency log is missing a device binding version")
	}
	return nil
}

func (db *DB) appendIdentityTransparencyAccountTx(ctx context.Context, tx pgx.Tx, user *User) error {
	runtimeState := db.identityTransparencySnapshot()
	if runtimeState == nil {
		return nil
	}
	if user == nil {
		return errors.New("identity transparency account is unavailable")
	}
	accountUUID, err := uuid.Parse(user.ID)
	if err != nil || accountUUID == uuid.Nil {
		return errors.New("identity transparency account id is invalid")
	}
	event, err := veiltransparency.AccountRegistrationEvent(
		runtimeState.canonicalOrigin,
		accountUUID[:],
		user.IdentityKey,
		user.SigningKey,
	)
	if err != nil {
		return err
	}
	return appendIdentityTransparencyLeafTx(
		ctx,
		tx,
		runtimeState,
		identityTransparencyAccountRegistrationV1,
		user.ID,
		"",
		0,
		event,
	)
}

func (db *DB) appendIdentityTransparencyDeviceBindingTx(
	ctx context.Context,
	tx pgx.Tx,
	binding *DeviceBinding,
) error {
	runtimeState := db.identityTransparencySnapshot()
	if runtimeState == nil {
		return nil
	}
	if binding == nil {
		return errors.New("identity transparency device binding is unavailable")
	}
	accountUUID, err := uuid.Parse(binding.UserID)
	if err != nil || accountUUID == uuid.Nil || accountUUID.String() != binding.UserID {
		return errors.New("identity transparency device-binding account id is invalid")
	}
	deviceUUID, err := uuid.Parse(binding.DeviceID)
	if err != nil || deviceUUID == uuid.Nil || deviceUUID.String() != binding.DeviceID {
		return errors.New("identity transparency device id is invalid")
	}
	event, err := veiltransparency.DeviceBindingEvent(
		runtimeState.canonicalOrigin,
		accountUUID[:],
		binding.DeviceKey,
		binding.DeviceIdentityKey,
		binding.DeviceSigningKey,
		binding.Version,
		binding.Capabilities,
		uint8(binding.Status),
		binding.AccountSignature,
		binding.Commitment,
	)
	if err != nil {
		return err
	}
	return appendIdentityTransparencyLeafTx(
		ctx,
		tx,
		runtimeState,
		identityTransparencyDeviceBindingV1,
		binding.UserID,
		binding.DeviceID,
		binding.Version,
		event,
	)
}

func appendIdentityTransparencyLeafTx(
	ctx context.Context,
	tx pgx.Tx,
	runtimeState *identityTransparencyRuntime,
	eventKind int16,
	userID string,
	deviceID string,
	bindingVersion uint64,
	event []byte,
) error {
	validAccount := eventKind == identityTransparencyAccountRegistrationV1 && deviceID == "" && bindingVersion == 0
	validDevice := eventKind == identityTransparencyDeviceBindingV1 && deviceID != "" &&
		bindingVersion > 0 && bindingVersion <= math.MaxInt64
	if runtimeState == nil || userID == "" || (!validAccount && !validDevice) {
		return errors.New("identity transparency append input is invalid")
	}
	head, err := loadIdentityTransparencyHeadTx(ctx, tx, true)
	if err != nil {
		return err
	}
	if head.LogID != runtimeState.logID || head.NodeSigningKey != runtimeState.nodeSigningKey {
		return errors.New("identity transparency runtime differs from the durable log")
	}
	if head.TreeSize == math.MaxInt64 {
		return errors.New("identity transparency log is exhausted")
	}
	if head.TreeSize == 0 {
		if head.RootHash != veiltransparency.EmptyRoot() {
			return errors.New("identity transparency empty root changed")
		}
	} else {
		currentRoot, err := identityTransparencyRangeHashTx(ctx, tx, 0, head.TreeSize)
		if err != nil {
			return err
		}
		if currentRoot != head.RootHash {
			return errors.New("identity transparency head differs from stored nodes")
		}
	}

	leafHash, err := veiltransparency.LeafHash(event)
	if err != nil {
		return err
	}
	var storedDeviceID, storedBindingVersion any
	if validDevice {
		storedDeviceID = deviceID
		storedBindingVersion = int64(bindingVersion)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO identity_transparency_log_leaves
		   (leaf_index, event_kind, subject_user_id, subject_device_id,
		    binding_version, canonical_event, leaf_hash)
		 VALUES ($1, $2, $3::uuid, $4::uuid, $5, $6, $7)`,
		int64(head.TreeSize), eventKind, userID, storedDeviceID,
		storedBindingVersion, event, leafHash[:],
	); err != nil {
		return fmt.Errorf("append identity transparency leaf: %w", err)
	}

	current := leafHash
	nodeIndex := head.TreeSize
	level := uint64(0)
	for {
		if _, err := tx.Exec(ctx,
			`INSERT INTO identity_transparency_log_nodes (node_level, node_index, node_hash)
			 VALUES ($1, $2, $3)`,
			int16(level), int64(nodeIndex), current[:],
		); err != nil {
			return fmt.Errorf("append identity transparency node: %w", err)
		}
		if nodeIndex&1 == 0 {
			break
		}
		var encodedSibling []byte
		if err := tx.QueryRow(ctx,
			`SELECT node_hash FROM identity_transparency_log_nodes
			 WHERE node_level = $1 AND node_index = $2`,
			int16(level), int64(nodeIndex-1),
		).Scan(&encodedSibling); err != nil {
			return fmt.Errorf("load identity transparency append sibling: %w", err)
		}
		sibling, err := exactTransparencyHash("identity transparency append sibling", encodedSibling)
		if err != nil {
			return err
		}
		current = veiltransparency.NodeHash(sibling, current)
		nodeIndex >>= 1
		level++
		if level > 62 {
			return errors.New("identity transparency append level is exhausted")
		}
	}

	newSize := head.TreeSize + 1
	newRoot, err := identityTransparencyRangeHashTx(ctx, tx, 0, newSize)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`UPDATE identity_transparency_log_state
		 SET tree_size = $1, root_hash = $2, updated_at = clock_timestamp()
		 WHERE singleton = TRUE AND tree_size = $3 AND root_hash = $4`,
		int64(newSize), newRoot[:], int64(head.TreeSize), head.RootHash[:],
	)
	if err != nil {
		return fmt.Errorf("advance identity transparency head: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("identity transparency head changed during append")
	}
	return nil
}

func identityTransparencyInclusionProofTx(
	ctx context.Context,
	tx pgx.Tx,
	start uint64,
	length uint64,
	leafIndex uint64,
) ([]veiltransparency.Hash, error) {
	if length == 0 || leafIndex < start || leafIndex >= start+length {
		return nil, errors.New("identity transparency inclusion coordinates are invalid")
	}
	if length == 1 {
		return nil, nil
	}
	split := largestTransparencyPowerLessThan(length)
	if leafIndex < start+split {
		proof, err := identityTransparencyInclusionProofTx(ctx, tx, start, split, leafIndex)
		if err != nil {
			return nil, err
		}
		sibling, err := identityTransparencyRangeHashTx(ctx, tx, start+split, length-split)
		if err != nil {
			return nil, err
		}
		return append(proof, sibling), nil
	}
	proof, err := identityTransparencyInclusionProofTx(
		ctx, tx, start+split, length-split, leafIndex,
	)
	if err != nil {
		return nil, err
	}
	sibling, err := identityTransparencyRangeHashTx(ctx, tx, start, split)
	if err != nil {
		return nil, err
	}
	return append(proof, sibling), nil
}

func identityTransparencyConsistencyProofTx(
	ctx context.Context,
	tx pgx.Tx,
	start uint64,
	newSize uint64,
	oldSize uint64,
	completeSubtree bool,
) ([]veiltransparency.Hash, error) {
	if oldSize == 0 || oldSize > newSize {
		return nil, errors.New("identity transparency consistency coordinates are invalid")
	}
	if oldSize == newSize {
		if completeSubtree {
			return nil, nil
		}
		root, err := identityTransparencyRangeHashTx(ctx, tx, start, newSize)
		if err != nil {
			return nil, err
		}
		return []veiltransparency.Hash{root}, nil
	}
	split := largestTransparencyPowerLessThan(newSize)
	if oldSize <= split {
		proof, err := identityTransparencyConsistencyProofTx(
			ctx, tx, start, split, oldSize, completeSubtree,
		)
		if err != nil {
			return nil, err
		}
		sibling, err := identityTransparencyRangeHashTx(ctx, tx, start+split, newSize-split)
		if err != nil {
			return nil, err
		}
		return append(proof, sibling), nil
	}
	proof, err := identityTransparencyConsistencyProofTx(
		ctx, tx, start+split, newSize-split, oldSize-split, false,
	)
	if err != nil {
		return nil, err
	}
	sibling, err := identityTransparencyRangeHashTx(ctx, tx, start, split)
	if err != nil {
		return nil, err
	}
	return append(proof, sibling), nil
}

// IdentityTransparencyWitnessConsistencyProof returns a proof between two
// exact historical roots for an external witness. Both roots are supplied by
// independently held state and rechecked against the durable Merkle nodes, so
// a stale, forged, or racing witness coordinate cannot be cosigned.
func (db *DB) IdentityTransparencyWitnessConsistencyProof(
	ctx context.Context,
	fromSize uint64,
	toSize uint64,
	expectedFromRoot veiltransparency.Hash,
	expectedToRoot veiltransparency.Hash,
) ([]veiltransparency.Hash, error) {
	if db == nil || db.Pool == nil || fromSize == 0 || fromSize > toSize ||
		toSize > math.MaxInt64 || expectedFromRoot == (veiltransparency.Hash{}) ||
		expectedToRoot == (veiltransparency.Hash{}) {
		return nil, errors.New("identity transparency witness consistency coordinates are invalid")
	}
	runtimeState := db.identityTransparencySnapshot()
	if runtimeState == nil {
		return nil, ErrIdentityTransparencyInactive
	}
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("begin witness consistency proof: %w", err)
	}
	defer tx.Rollback(ctx)
	head, err := loadIdentityTransparencyHeadTx(ctx, tx, false)
	if err != nil {
		return nil, err
	}
	if head.LogID != runtimeState.logID || head.NodeSigningKey != runtimeState.nodeSigningKey ||
		toSize > head.TreeSize {
		return nil, errors.New("identity transparency witness head is unavailable")
	}
	fromRoot, err := identityTransparencyRangeHashTx(ctx, tx, 0, fromSize)
	if err != nil || fromRoot != expectedFromRoot {
		return nil, errors.New("identity transparency witness prior root mismatch")
	}
	toRoot, err := identityTransparencyRangeHashTx(ctx, tx, 0, toSize)
	if err != nil || toRoot != expectedToRoot {
		return nil, errors.New("identity transparency witness target root mismatch")
	}
	proof, err := identityTransparencyConsistencyProofTx(ctx, tx, 0, toSize, fromSize, true)
	if err != nil || len(proof) > veiltransparency.MaxProofNodes ||
		!veiltransparency.VerifyConsistency(fromSize, toSize, fromRoot, toRoot, proof) {
		return nil, errors.New("identity transparency witness consistency proof self-check failed")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("finish witness consistency proof: %w", err)
	}
	return append([]veiltransparency.Hash(nil), proof...), nil
}

func (db *DB) identityTransparencyProofForLeaf(
	ctx context.Context,
	fromSize uint64,
	leafQuery string,
	leafArgs ...any,
) (*IdentityTransparencyProof, error) {
	runtimeState := db.identityTransparencySnapshot()
	if runtimeState == nil {
		return nil, ErrIdentityTransparencyInactive
	}
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("begin identity transparency proof: %w", err)
	}
	defer tx.Rollback(ctx)

	head, err := loadIdentityTransparencyHeadTx(ctx, tx, false)
	if err != nil {
		return nil, err
	}
	if head.LogID != runtimeState.logID || head.NodeSigningKey != runtimeState.nodeSigningKey {
		return nil, errors.New("identity transparency proof head is invalid")
	}
	if fromSize > head.TreeSize {
		return nil, ErrIdentityTransparencyHeadRegression
	}
	var leafIndex int64
	var event, storedLeafHash []byte
	if err := tx.QueryRow(ctx, leafQuery, leafArgs...).Scan(&leafIndex, &event, &storedLeafHash); err != nil {
		return nil, fmt.Errorf("load identity transparency leaf: %w", err)
	}
	if leafIndex < 0 || uint64(leafIndex) >= head.TreeSize {
		return nil, errors.New("identity transparency leaf index is invalid")
	}
	computedLeafHash, err := veiltransparency.LeafHash(event)
	if err != nil {
		return nil, err
	}
	persistedLeafHash, err := exactTransparencyHash("identity transparency leaf", storedLeafHash)
	if err != nil || computedLeafHash != persistedLeafHash {
		return nil, errors.New("identity transparency event differs from its leaf hash")
	}
	levelZeroHash, err := identityTransparencyRangeHashTx(ctx, tx, uint64(leafIndex), 1)
	if err != nil || levelZeroHash != computedLeafHash {
		return nil, errors.New("identity transparency leaf differs from its tree node")
	}

	inclusion, err := identityTransparencyInclusionProofTx(
		ctx, tx, 0, head.TreeSize, uint64(leafIndex),
	)
	if err != nil || len(inclusion) > veiltransparency.MaxProofNodes ||
		!veiltransparency.VerifyInclusion(
			event, uint64(leafIndex), head.TreeSize, inclusion, head.RootHash,
		) {
		return nil, errors.New("identity transparency inclusion proof generation failed")
	}
	var consistency []veiltransparency.Hash
	if fromSize != 0 && fromSize != head.TreeSize {
		consistency, err = identityTransparencyConsistencyProofTx(
			ctx, tx, 0, head.TreeSize, fromSize, true,
		)
		if err != nil || len(consistency) > veiltransparency.MaxProofNodes {
			return nil, errors.New("identity transparency consistency proof generation failed")
		}
		oldRoot, rootErr := identityTransparencyRangeHashTx(ctx, tx, 0, fromSize)
		if rootErr != nil || !veiltransparency.VerifyConsistency(
			fromSize, head.TreeSize, oldRoot, head.RootHash, consistency,
		) {
			return nil, errors.New("identity transparency consistency proof self-check failed")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("finish identity transparency proof snapshot: %w", err)
	}
	return &IdentityTransparencyProof{
		CanonicalEvent:   append([]byte(nil), event...),
		LeafIndex:        uint64(leafIndex),
		Head:             head,
		InclusionProof:   append([]veiltransparency.Hash(nil), inclusion...),
		ConsistencyFrom:  fromSize,
		ConsistencyProof: append([]veiltransparency.Hash(nil), consistency...),
	}, nil
}

// IdentityTransparencyProofForAccount returns one bounded proof snapshot from
// a single repeatable-read transaction. fromSize is the caller's last pinned
// head size; zero requests first-contact inclusion without pretending there is
// a prior consistency anchor.
func (db *DB) IdentityTransparencyProofForAccount(
	ctx context.Context,
	userID string,
	fromSize uint64,
) (*IdentityTransparencyAccountProof, error) {
	parsedUserID, err := uuid.Parse(userID)
	if err != nil || parsedUserID == uuid.Nil || parsedUserID.String() != userID {
		return nil, errors.New("identity transparency account id is invalid")
	}
	return db.identityTransparencyProofForLeaf(
		ctx,
		fromSize,
		`SELECT leaf_index, canonical_event, leaf_hash
		 FROM identity_transparency_log_leaves
		 WHERE event_kind = 1 AND subject_user_id = $1::uuid`,
		userID,
	)
}

// IdentityTransparencyProofForDeviceBinding proves the exact immutable
// binding version returned by device/prekey discovery. A caller must not
// substitute the latest version implicitly because that would make a racing
// directory response unverifiable.
func (db *DB) IdentityTransparencyProofForDeviceBinding(
	ctx context.Context,
	deviceKey []byte,
	bindingVersion uint64,
	fromSize uint64,
) (*IdentityTransparencyDeviceBindingProof, error) {
	if len(deviceKey) != 16 || bindingVersion == 0 || bindingVersion > math.MaxInt64 {
		return nil, errors.New("identity transparency device binding coordinates are invalid")
	}
	return db.identityTransparencyProofForLeaf(
		ctx,
		fromSize,
		`SELECT leaf.leaf_index, leaf.canonical_event, leaf.leaf_hash
		 FROM identity_transparency_log_leaves AS leaf
		 JOIN devices AS device ON device.id = leaf.subject_device_id
		 WHERE leaf.event_kind = 2
		   AND device.device_key = $1
		   AND leaf.binding_version = $2`,
		deviceKey,
		int64(bindingVersion),
	)
}
