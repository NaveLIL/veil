package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
	veilmembership "github.com/NaveLIL/veil/veil-server/internal/membership"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrMembershipEpochConflict     = errors.New("membership epoch conflicts with durable history")
	ErrMembershipEpochRosterStale  = errors.New("membership epoch does not authorize the current ready roster")
	ErrMembershipEpochUnauthorized = errors.New("membership epoch requester is not authorized for the conversation")
)

type MembershipEpochRecordV1 struct {
	Epoch             veilmembership.Epoch
	Hash              veilmembership.Hash
	Signatures        []veilmembership.Signature
	BootstrapOwner    *veilmembership.PolicySigner
	CanonicalUnsigned []byte
	SubmittedBy       string
}

type MembershipEpochPageV1 struct {
	HeadEpoch uint64
	HeadHash  veilmembership.Hash
	Epochs    []MembershipEpochRecordV1
	HasMore   bool
}

type MembershipEpochRosterStatusV1 struct {
	Activated bool
	Ready     bool
	Epoch     uint64
	Hash      veilmembership.Hash
}

type MembershipBootstrapAuthorityV1 struct {
	ConversationKind uint8
	OwnerID          string
	OwnerSigningKey  [32]byte
}

func (db *DB) MembershipBootstrapAuthorityForRequesterV1(
	ctx context.Context,
	conversationID string,
	requesterID string,
) (*MembershipBootstrapAuthorityV1, error) {
	if db == nil || db.Pool == nil {
		return nil, errors.New("membership bootstrap authority is unavailable")
	}
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var conversationKind int16
	if err := tx.QueryRow(ctx,
		`SELECT conv_type FROM conversations WHERE id = $1::uuid`, conversationID,
	).Scan(&conversationKind); err != nil {
		return nil, err
	}
	allowed, err := canAccessConversationWithQuery(
		ctx, tx, conversationID, requesterID, ChannelReadPermissions,
	)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrMembershipEpochUnauthorized
	}
	if conversationKind == 0 {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, nil
	}
	owner, err := conversationMembershipOwnerV1(ctx, tx, conversationID, conversationKind)
	if err != nil {
		return nil, err
	}
	ownerID, err := membershipUUIDString("membership bootstrap owner", owner.AccountID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &MembershipBootstrapAuthorityV1{
		ConversationKind: uint8(conversationKind),
		OwnerID:          ownerID,
		OwnerSigningKey:  owner.AccountSigningKey,
	}, nil
}

func (db *DB) MembershipEpochRosterStatusForRequesterV1(
	ctx context.Context,
	conversationID string,
	requesterID string,
	rosterVersion uint64,
	rosterCommitment [32]byte,
) (MembershipEpochRosterStatusV1, error) {
	if db == nil || db.Pool == nil || rosterVersion == 0 || rosterVersion > math.MaxInt64 {
		return MembershipEpochRosterStatusV1{}, ErrMembershipEpochRosterStale
	}
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return MembershipEpochRosterStatusV1{}, err
	}
	defer tx.Rollback(ctx)
	allowed, err := canAccessConversationWithQuery(
		ctx, tx, conversationID, requesterID, ChannelReadPermissions,
	)
	if err != nil {
		return MembershipEpochRosterStatusV1{}, err
	}
	if !allowed {
		return MembershipEpochRosterStatusV1{}, ErrMembershipEpochUnauthorized
	}
	var number, storedRosterVersion int64
	var hash, storedRosterCommitment []byte
	err = tx.QueryRow(ctx,
		`SELECT epoch_number, epoch_hash, roster_version, roster_commitment
		 FROM conversation_membership_epoch_heads_v1
		 WHERE conversation_id = $1::uuid`, conversationID,
	).Scan(&number, &hash, &storedRosterVersion, &storedRosterCommitment)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return MembershipEpochRosterStatusV1{}, err
		}
		return MembershipEpochRosterStatusV1{Ready: true}, nil
	}
	if err != nil || number <= 0 || len(hash) != 32 {
		return MembershipEpochRosterStatusV1{}, ErrMembershipEpochConflict
	}
	status := MembershipEpochRosterStatusV1{
		Activated: true,
		Ready: storedRosterVersion == int64(rosterVersion) &&
			bytes.Equal(storedRosterCommitment, rosterCommitment[:]),
		Epoch: uint64(number),
	}
	copy(status.Hash[:], hash)
	if err := tx.Commit(ctx); err != nil {
		return MembershipEpochRosterStatusV1{}, err
	}
	return status, nil
}

func validOptionalMembershipCoordinateV1(epoch uint64, hash []byte) bool {
	return epoch == 0 && len(hash) == 0 ||
		epoch > 0 && epoch <= math.MaxInt64 && len(hash) == 32 && !bytes.Equal(hash, make([]byte, 32))
}

// validateMembershipTrafficContextV1 is the one-way compatibility gate for
// live Sender-Key traffic. Before epoch 1, only v5 with no membership
// coordinate is valid. Once a head exists, only v6 bound to that exact head
// and its exact current device roster is valid. There is deliberately no
// fallback from an activated conversation.
func validateMembershipTrafficContextV1(
	ctx context.Context,
	query rosterQuerier,
	conversationID string,
	cryptoProfile string,
	rosterVersion uint64,
	rosterCommitment []byte,
	membershipEpoch uint64,
	membershipEpochHash []byte,
) error {
	if query == nil || conversationID == "" || rosterVersion == 0 ||
		rosterVersion > math.MaxInt64 || len(rosterCommitment) != 32 {
		return ErrMembershipEpochRosterStale
	}
	var epochNumber, storedRosterVersion int64
	var epochHash, storedRosterCommitment []byte
	err := query.QueryRow(ctx,
		`SELECT epoch_number, epoch_hash, roster_version, roster_commitment
		 FROM conversation_membership_epoch_heads_v1
		 WHERE conversation_id = $1::uuid`, conversationID,
	).Scan(&epochNumber, &epochHash, &storedRosterVersion, &storedRosterCommitment)
	if errors.Is(err, pgx.ErrNoRows) {
		if cryptoProfile == MessageCryptoProfileSenderKeyV5 &&
			membershipEpoch == 0 && len(membershipEpochHash) == 0 {
			return nil
		}
		return ErrMembershipEpochRosterStale
	}
	if err != nil {
		return err
	}
	if cryptoProfile != MessageCryptoProfileSenderKeyV6 ||
		membershipEpoch == 0 || membershipEpoch > math.MaxInt64 ||
		epochNumber != int64(membershipEpoch) || len(epochHash) != 32 ||
		!bytes.Equal(epochHash, membershipEpochHash) ||
		storedRosterVersion != int64(rosterVersion) ||
		!bytes.Equal(storedRosterCommitment, rosterCommitment) {
		return ErrMembershipEpochRosterStale
	}
	return nil
}

func exactMembershipBytes(label string, value []byte, size int) ([]byte, error) {
	if len(value) != size {
		return nil, fmt.Errorf("%s has invalid length", label)
	}
	return append([]byte(nil), value...), nil
}

func membershipUUIDBytes(label, value string) ([16]byte, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return [16]byte{}, fmt.Errorf("%s is not a canonical nonzero UUID", label)
	}
	return [16]byte(parsed), nil
}

func membershipUUIDString(label string, value [16]byte) (string, error) {
	parsed := uuid.UUID(value)
	if parsed == uuid.Nil {
		return "", fmt.Errorf("%s is zero", label)
	}
	return parsed.String(), nil
}

func (db *DB) StoreMembershipEpochV1(
	ctx context.Context,
	requesterID string,
	epoch veilmembership.Epoch,
	signatures []veilmembership.Signature,
) (*MembershipEpochRecordV1, bool, error) {
	if db == nil || db.Pool == nil {
		return nil, false, errors.New("membership epoch database is unavailable")
	}
	if _, err := membershipUUIDBytes("membership requester", requesterID); err != nil {
		return nil, false, ErrMembershipEpochUnauthorized
	}
	if err := epoch.Validate(); err != nil {
		return nil, false, err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		record, stored, err := db.storeMembershipEpochOnceV1(ctx, requesterID, epoch, signatures)
		if err == nil {
			return record, stored, nil
		}
		lastErr = err
		if !isSenderKeySerializationFailure(err) {
			return nil, false, err
		}
	}
	return nil, false, fmt.Errorf("store membership epoch after serialization retries: %w", lastErr)
}

func (db *DB) storeMembershipEpochOnceV1(
	ctx context.Context,
	requesterID string,
	epoch veilmembership.Epoch,
	signatures []veilmembership.Signature,
) (*MembershipEpochRecordV1, bool, error) {
	conversationID, err := membershipUUIDString("membership conversation", epoch.ConversationID)
	if err != nil {
		return nil, false, err
	}
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)
	var conversationKind int16
	if err := tx.QueryRow(ctx,
		`SELECT conv_type FROM conversations
		 WHERE id = $1::uuid FOR UPDATE`, conversationID,
	).Scan(&conversationKind); err != nil {
		return nil, false, err
	}
	if conversationKind != int16(epoch.ConversationKind) ||
		(conversationKind != int16(veilmembership.ConversationKindGroup) &&
			conversationKind != int16(veilmembership.ConversationKindChannel)) {
		return nil, false, errors.New("membership epoch conversation kind is invalid")
	}
	allowed, err := canAccessConversationWithQuery(
		ctx, tx, conversationID, requesterID, ChannelReadPermissions,
	)
	if err != nil {
		return nil, false, err
	}
	if !allowed {
		return nil, false, ErrMembershipEpochUnauthorized
	}

	existing, err := loadMembershipEpochTxV1(ctx, tx, conversationID, epoch.Number)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	if err == nil {
		if !membershipRecordMatchesCandidateV1(existing, &epoch, signatures) {
			return nil, false, ErrMembershipEpochConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, false, err
		}
		return existing, false, nil
	}

	roster, err := resolveConversationDeviceRosterSnapshot(
		ctx, tx, conversationID, RequiredChannelCapabilities,
	)
	if err != nil || !roster.Ready || roster.Version != epoch.RosterVersion ||
		roster.Commitment != epoch.RosterCommitment {
		return nil, false, ErrMembershipEpochRosterStale
	}
	if err := validateMembershipPolicyAgainstRosterV1(&epoch.SuccessorPolicy, roster); err != nil {
		return nil, false, err
	}

	var currentNumber *int64
	var currentHash, currentRosterCommitment []byte
	var currentRosterVersion *int64
	headErr := tx.QueryRow(ctx,
		`SELECT epoch_number, epoch_hash, roster_version, roster_commitment
		 FROM conversation_membership_epoch_heads_v1
		 WHERE conversation_id = $1::uuid FOR UPDATE`, conversationID,
	).Scan(&currentNumber, &currentHash, &currentRosterVersion, &currentRosterCommitment)
	var predecessor *MembershipEpochRecordV1
	var bootstrapOwner *veilmembership.PolicySigner
	switch {
	case errors.Is(headErr, pgx.ErrNoRows):
		if epoch.Number != 1 {
			return nil, false, ErrMembershipEpochConflict
		}
		owner, ownerErr := conversationMembershipOwnerV1(ctx, tx, conversationID, conversationKind)
		if ownerErr != nil {
			return nil, false, ownerErr
		}
		if err := veilmembership.VerifyBootstrap(epoch, owner, signatures); err != nil {
			return nil, false, err
		}
		bootstrapOwner = &owner
	case headErr != nil:
		return nil, false, headErr
	default:
		if currentNumber == nil || currentRosterVersion == nil || *currentNumber <= 0 ||
			*currentRosterVersion <= 0 || len(currentHash) != 32 || len(currentRosterCommitment) != 32 ||
			epoch.Number != uint64(*currentNumber)+1 {
			return nil, false, ErrMembershipEpochConflict
		}
		predecessor, err = loadMembershipEpochTxV1(ctx, tx, conversationID, uint64(*currentNumber))
		if err != nil || !bytes.Equal(predecessor.Hash[:], currentHash) ||
			predecessor.Epoch.RosterVersion != uint64(*currentRosterVersion) ||
			!bytes.Equal(predecessor.Epoch.RosterCommitment[:], currentRosterCommitment) {
			return nil, false, ErrMembershipEpochConflict
		}
		if err := veilmembership.VerifyTransition(predecessor.Epoch, epoch, signatures); err != nil {
			return nil, false, err
		}
	}

	hash, err := epoch.Hash()
	if err != nil {
		return nil, false, err
	}
	canonical, err := epoch.CanonicalUnsignedBytes()
	if err != nil {
		return nil, false, err
	}
	var bootstrapOwnerID any
	var bootstrapOwnerKey any
	if bootstrapOwner != nil {
		ownerID, ownerErr := membershipUUIDString("membership bootstrap owner", bootstrapOwner.AccountID)
		if ownerErr != nil {
			return nil, false, ownerErr
		}
		bootstrapOwnerID = ownerID
		bootstrapOwnerKey = bootstrapOwner.AccountSigningKey[:]
	}
	command, err := tx.Exec(ctx,
		`INSERT INTO conversation_membership_epochs_v1 (
		   conversation_id, epoch_number, canonical_origin, conversation_kind,
		   predecessor_hash, roster_version, roster_commitment,
		   policy_threshold, policy_signer_count, crypto_profile, crypto_era,
		   mutation_nonce, epoch_hash, canonical_unsigned,
		   bootstrap_owner_id, bootstrap_owner_signing_key, submitted_by
		 ) VALUES (
		   $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
		   $12, $13, $14, $15::uuid, $16, $17::uuid
		 )`,
		conversationID, int64(epoch.Number), epoch.CanonicalOrigin, int16(epoch.ConversationKind),
		epoch.PredecessorHash[:], int64(epoch.RosterVersion), epoch.RosterCommitment[:],
		int32(epoch.SuccessorPolicy.Threshold), int32(len(epoch.SuccessorPolicy.Signers)),
		int16(epoch.CryptoProfile), int32(epoch.CryptoEra), epoch.MutationNonce[:], hash[:], canonical,
		bootstrapOwnerID, bootstrapOwnerKey, requesterID,
	)
	if err != nil {
		return nil, false, fmt.Errorf("insert membership epoch: %w", err)
	}
	if command.RowsAffected() != 1 {
		return nil, false, errors.New("membership epoch insert affected an unexpected row count")
	}
	for index, signer := range epoch.SuccessorPolicy.Signers {
		accountID, accountErr := membershipUUIDString("membership policy signer", signer.AccountID)
		if accountErr != nil {
			return nil, false, accountErr
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO conversation_membership_policy_signers_v1
			   (conversation_id, epoch_number, signer_index, account_id, account_signing_key)
			 VALUES ($1::uuid, $2, $3, $4::uuid, $5)`,
			conversationID, int64(epoch.Number), index, accountID, signer.AccountSigningKey[:],
		); err != nil {
			return nil, false, fmt.Errorf("insert membership policy signer: %w", err)
		}
	}
	for index, signature := range signatures {
		accountID, accountErr := membershipUUIDString("membership signature signer", signature.SignerAccountID)
		if accountErr != nil {
			return nil, false, accountErr
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO conversation_membership_signatures_v1
			   (conversation_id, epoch_number, signature_index, signer_account_id, signature)
			 VALUES ($1::uuid, $2, $3, $4::uuid, $5)`,
			conversationID, int64(epoch.Number), index, accountID, signature.Signature[:],
		); err != nil {
			return nil, false, fmt.Errorf("insert membership signature: %w", err)
		}
	}
	if predecessor == nil {
		command, err = tx.Exec(ctx,
			`INSERT INTO conversation_membership_epoch_heads_v1
			   (conversation_id, epoch_number, epoch_hash, roster_version, roster_commitment)
			 VALUES ($1::uuid, 1, $2, $3, $4)`,
			conversationID, hash[:], int64(epoch.RosterVersion), epoch.RosterCommitment[:],
		)
	} else {
		command, err = tx.Exec(ctx,
			`UPDATE conversation_membership_epoch_heads_v1
			 SET epoch_number = $2, epoch_hash = $3, roster_version = $4,
			     roster_commitment = $5, updated_at = now()
			 WHERE conversation_id = $1::uuid AND epoch_number = $6 AND epoch_hash = $7`,
			conversationID, int64(epoch.Number), hash[:], int64(epoch.RosterVersion),
			epoch.RosterCommitment[:], int64(predecessor.Epoch.Number), predecessor.Hash[:],
		)
	}
	if err != nil {
		return nil, false, fmt.Errorf("advance membership epoch head: %w", err)
	}
	if command.RowsAffected() != 1 {
		return nil, false, ErrMembershipEpochConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return &MembershipEpochRecordV1{
		Epoch: epoch, Hash: hash, Signatures: append([]veilmembership.Signature(nil), signatures...),
		BootstrapOwner: bootstrapOwner, CanonicalUnsigned: canonical, SubmittedBy: requesterID,
	}, true, nil
}

func validateMembershipPolicyAgainstRosterV1(
	policy *veilmembership.Policy,
	roster *ConversationDeviceRoster,
) error {
	if policy == nil || roster == nil {
		return errors.New("membership policy roster is unavailable")
	}
	members := make(map[[16]byte][32]byte, len(roster.Members))
	for _, member := range roster.Members {
		accountID, err := membershipUUIDBytes("membership roster account", member.UserID)
		if err != nil || len(member.SigningKey) != 32 || !cryptokey.ValidEd25519PublicKey(member.SigningKey) {
			return errors.New("membership roster account is invalid")
		}
		var signingKey [32]byte
		copy(signingKey[:], member.SigningKey)
		members[accountID] = signingKey
		for _, device := range member.Devices {
			if device.Binding != nil && device.Binding.Status == DeviceBindingActive &&
				device.Eligible &&
				device.Binding.Capabilities&DeviceCapabilityMembershipEpochV1 == 0 {
				return errors.New("membership roster contains an active device without v6 support")
			}
		}
	}
	for _, signer := range policy.Signers {
		if members[signer.AccountID] != signer.AccountSigningKey {
			return errors.New("membership successor policy contains a non-member or substituted key")
		}
	}
	return nil
}

func conversationMembershipOwnerV1(
	ctx context.Context,
	tx pgx.Tx,
	conversationID string,
	conversationKind int16,
) (veilmembership.PolicySigner, error) {
	var ownerID string
	var signingKey []byte
	var err error
	switch conversationKind {
	case int16(veilmembership.ConversationKindGroup):
		err = tx.QueryRow(ctx,
			`SELECT member.user_id::text, users.signing_key
			 FROM conversation_members AS member
			 JOIN users ON users.id = member.user_id
			 WHERE member.conversation_id = $1::uuid AND member.role = 2`,
			conversationID,
		).Scan(&ownerID, &signingKey)
	case int16(veilmembership.ConversationKindChannel):
		err = tx.QueryRow(ctx,
			`SELECT server.owner_id::text, users.signing_key
			 FROM channels AS channel
			 JOIN servers AS server ON server.id = channel.server_id
			 JOIN users ON users.id = server.owner_id
			 WHERE channel.conversation_id = $1::uuid AND server.deleted_at IS NULL`,
			conversationID,
		).Scan(&ownerID, &signingKey)
	default:
		return veilmembership.PolicySigner{}, errors.New("membership conversation has no bootstrap owner")
	}
	if err != nil {
		return veilmembership.PolicySigner{}, fmt.Errorf("resolve membership bootstrap owner: %w", err)
	}
	accountID, err := membershipUUIDBytes("membership bootstrap owner", ownerID)
	if err != nil || len(signingKey) != 32 || !cryptokey.ValidEd25519PublicKey(signingKey) {
		return veilmembership.PolicySigner{}, errors.New("membership bootstrap owner is invalid")
	}
	var key [32]byte
	copy(key[:], signingKey)
	return veilmembership.PolicySigner{AccountID: accountID, AccountSigningKey: key}, nil
}

func membershipRecordMatchesCandidateV1(
	record *MembershipEpochRecordV1,
	epoch *veilmembership.Epoch,
	signatures []veilmembership.Signature,
) bool {
	if record == nil || epoch == nil || len(record.Signatures) != len(signatures) {
		return false
	}
	hash, err := epoch.Hash()
	if err != nil || record.Hash != hash {
		return false
	}
	canonical, err := epoch.CanonicalUnsignedBytes()
	if err != nil || !bytes.Equal(record.CanonicalUnsigned, canonical) {
		return false
	}
	for index := range signatures {
		if record.Signatures[index] != signatures[index] {
			return false
		}
	}
	return true
}

func loadMembershipEpochTxV1(
	ctx context.Context,
	tx pgx.Tx,
	conversationID string,
	epochNumber uint64,
) (*MembershipEpochRecordV1, error) {
	if epochNumber == 0 || epochNumber > math.MaxInt64 {
		return nil, errors.New("membership epoch number is invalid")
	}
	var (
		origin, submittedBy                 string
		kind, profile                       int16
		number, rosterVersion               int64
		cryptoEra, threshold, signerCount   int32
		predecessor, rosterCommitment       []byte
		mutationNonce, epochHash, canonical []byte
		bootstrapOwnerID                    *string
		bootstrapOwnerKey                   []byte
	)
	err := tx.QueryRow(ctx,
		`SELECT canonical_origin, conversation_kind, epoch_number,
		        predecessor_hash, roster_version, roster_commitment,
		        policy_threshold, policy_signer_count, crypto_profile, crypto_era,
		        mutation_nonce, epoch_hash, canonical_unsigned,
		        bootstrap_owner_id::text, bootstrap_owner_signing_key,
		        submitted_by::text
		 FROM conversation_membership_epochs_v1
		 WHERE conversation_id = $1::uuid AND epoch_number = $2`,
		conversationID, int64(epochNumber),
	).Scan(
		&origin, &kind, &number, &predecessor, &rosterVersion, &rosterCommitment,
		&threshold, &signerCount, &profile, &cryptoEra, &mutationNonce, &epochHash,
		&canonical, &bootstrapOwnerID, &bootstrapOwnerKey, &submittedBy,
	)
	if err != nil {
		return nil, err
	}
	if _, err := membershipUUIDBytes("stored membership submitter", submittedBy); err != nil {
		return nil, err
	}
	conversationBytes, err := membershipUUIDBytes("stored membership conversation", conversationID)
	if err != nil || number != int64(epochNumber) || rosterVersion <= 0 ||
		threshold <= 0 || threshold > math.MaxUint16 || signerCount <= 0 || signerCount > 1024 ||
		profile < 0 || profile > math.MaxUint8 || cryptoEra <= 0 || cryptoEra > math.MaxUint16 {
		return nil, errors.New("stored membership epoch coordinates are invalid")
	}
	epoch := veilmembership.Epoch{
		CanonicalOrigin: origin, ConversationID: conversationBytes, ConversationKind: byte(kind),
		Number: uint64(number), RosterVersion: uint64(rosterVersion),
		SuccessorPolicy: veilmembership.Policy{Threshold: uint16(threshold)},
		CryptoProfile:   byte(profile), CryptoEra: uint16(cryptoEra),
	}
	copy(epoch.PredecessorHash[:], predecessor)
	copy(epoch.RosterCommitment[:], rosterCommitment)
	copy(epoch.MutationNonce[:], mutationNonce)
	if _, err := exactMembershipBytes("stored predecessor hash", predecessor, 32); err != nil {
		return nil, err
	}
	if _, err := exactMembershipBytes("stored roster commitment", rosterCommitment, 32); err != nil {
		return nil, err
	}
	if _, err := exactMembershipBytes("stored mutation nonce", mutationNonce, 32); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx,
		`SELECT signer_index, account_id::text, account_signing_key
		 FROM conversation_membership_policy_signers_v1
		 WHERE conversation_id = $1::uuid AND epoch_number = $2
		 ORDER BY signer_index`, conversationID, int64(epochNumber),
	)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var index int32
		var accountID string
		var signingKey []byte
		if err := rows.Scan(&index, &accountID, &signingKey); err != nil {
			rows.Close()
			return nil, err
		}
		if index != int32(len(epoch.SuccessorPolicy.Signers)) || len(signingKey) != 32 {
			rows.Close()
			return nil, errors.New("stored membership policy order is invalid")
		}
		parsedID, err := membershipUUIDBytes("stored membership policy account", accountID)
		if err != nil {
			rows.Close()
			return nil, err
		}
		var key [32]byte
		copy(key[:], signingKey)
		epoch.SuccessorPolicy.Signers = append(epoch.SuccessorPolicy.Signers,
			veilmembership.PolicySigner{AccountID: parsedID, AccountSigningKey: key})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(epoch.SuccessorPolicy.Signers) != int(signerCount) {
		return nil, errors.New("stored membership policy is incomplete")
	}
	signatureRows, err := tx.Query(ctx,
		`SELECT signature_index, signer_account_id::text, signature
		 FROM conversation_membership_signatures_v1
		 WHERE conversation_id = $1::uuid AND epoch_number = $2
		 ORDER BY signature_index`, conversationID, int64(epochNumber),
	)
	if err != nil {
		return nil, err
	}
	signatures := make([]veilmembership.Signature, 0)
	for signatureRows.Next() {
		var index int32
		var accountID string
		var encoded []byte
		if err := signatureRows.Scan(&index, &accountID, &encoded); err != nil {
			signatureRows.Close()
			return nil, err
		}
		if index != int32(len(signatures)) || len(encoded) != 64 {
			signatureRows.Close()
			return nil, errors.New("stored membership signature order is invalid")
		}
		parsedID, err := membershipUUIDBytes("stored membership signature account", accountID)
		if err != nil {
			signatureRows.Close()
			return nil, err
		}
		var signature [64]byte
		copy(signature[:], encoded)
		signatures = append(signatures, veilmembership.Signature{SignerAccountID: parsedID, Signature: signature})
	}
	if err := signatureRows.Err(); err != nil {
		signatureRows.Close()
		return nil, err
	}
	signatureRows.Close()
	if len(signatures) == 0 || epoch.Validate() != nil {
		return nil, errors.New("stored membership epoch is invalid")
	}
	computedCanonical, err := epoch.CanonicalUnsignedBytes()
	if err != nil || !bytes.Equal(computedCanonical, canonical) {
		return nil, errors.New("stored membership canonical bytes changed")
	}
	computedHash, err := epoch.Hash()
	if err != nil || len(epochHash) != 32 || !bytes.Equal(computedHash[:], epochHash) {
		return nil, errors.New("stored membership epoch hash changed")
	}
	var bootstrapOwner *veilmembership.PolicySigner
	if bootstrapOwnerID != nil {
		accountID, ownerErr := membershipUUIDBytes("stored bootstrap owner", *bootstrapOwnerID)
		if ownerErr != nil || len(bootstrapOwnerKey) != 32 {
			return nil, errors.New("stored membership bootstrap owner is invalid")
		}
		var key [32]byte
		copy(key[:], bootstrapOwnerKey)
		owner := veilmembership.PolicySigner{AccountID: accountID, AccountSigningKey: key}
		bootstrapOwner = &owner
	}
	return &MembershipEpochRecordV1{
		Epoch: epoch, Hash: computedHash, Signatures: signatures, BootstrapOwner: bootstrapOwner,
		CanonicalUnsigned: append([]byte(nil), canonical...), SubmittedBy: submittedBy,
	}, nil
}

// MembershipEpochForRosterForRequesterV1 returns the exact active epoch only
// when it authorizes the supplied roster snapshot. A racing ACL/device change
// therefore produces a refresh requirement, never a mismatched authorization.
func (db *DB) MembershipEpochForRosterForRequesterV1(
	ctx context.Context,
	conversationID string,
	requesterID string,
	rosterVersion uint64,
	rosterCommitment [32]byte,
) (*MembershipEpochRecordV1, error) {
	if db == nil || db.Pool == nil || rosterVersion == 0 || rosterVersion > math.MaxInt64 {
		return nil, ErrMembershipEpochRosterStale
	}
	if _, err := membershipUUIDBytes("membership conversation", conversationID); err != nil {
		return nil, err
	}
	if _, err := membershipUUIDBytes("membership requester", requesterID); err != nil {
		return nil, ErrMembershipEpochUnauthorized
	}
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	allowed, err := canAccessConversationWithQuery(
		ctx, tx, conversationID, requesterID, ChannelReadPermissions,
	)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrMembershipEpochUnauthorized
	}
	var epochNumber, storedRosterVersion int64
	var storedCommitment []byte
	if err := tx.QueryRow(ctx,
		`SELECT epoch_number, roster_version, roster_commitment
		 FROM conversation_membership_epoch_heads_v1
		 WHERE conversation_id = $1::uuid`, conversationID,
	).Scan(&epochNumber, &storedRosterVersion, &storedCommitment); err != nil {
		return nil, err
	}
	if epochNumber <= 0 || storedRosterVersion != int64(rosterVersion) ||
		!bytes.Equal(storedCommitment, rosterCommitment[:]) {
		return nil, ErrMembershipEpochRosterStale
	}
	record, err := loadMembershipEpochTxV1(ctx, tx, conversationID, uint64(epochNumber))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return record, nil
}

func (db *DB) ListMembershipEpochsForRequesterV1(
	ctx context.Context,
	conversationID string,
	requesterID string,
	afterEpoch uint64,
	limit int,
) (*MembershipEpochPageV1, error) {
	if db == nil || db.Pool == nil || afterEpoch > math.MaxInt64 || limit < 1 || limit > 100 {
		return nil, errors.New("membership epoch page coordinates are invalid")
	}
	if _, err := membershipUUIDBytes("membership conversation", conversationID); err != nil {
		return nil, err
	}
	if _, err := membershipUUIDBytes("membership requester", requesterID); err != nil {
		return nil, ErrMembershipEpochUnauthorized
	}
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	allowed, err := canAccessConversationWithQuery(
		ctx, tx, conversationID, requesterID, ChannelReadPermissions,
	)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrMembershipEpochUnauthorized
	}
	var headNumber int64
	var encodedHeadHash []byte
	if err := tx.QueryRow(ctx,
		`SELECT epoch_number, epoch_hash
		 FROM conversation_membership_epoch_heads_v1
		 WHERE conversation_id = $1::uuid`, conversationID,
	).Scan(&headNumber, &encodedHeadHash); err != nil {
		return nil, err
	}
	if headNumber <= 0 || len(encodedHeadHash) != 32 || afterEpoch > uint64(headNumber) {
		return nil, ErrMembershipEpochConflict
	}
	page := &MembershipEpochPageV1{HeadEpoch: uint64(headNumber)}
	copy(page.HeadHash[:], encodedHeadHash)
	remaining := uint64(headNumber) - afterEpoch
	count := min(remaining, uint64(limit))
	page.Epochs = make([]MembershipEpochRecordV1, 0, count)
	for offset := uint64(1); offset <= count; offset++ {
		record, err := loadMembershipEpochTxV1(ctx, tx, conversationID, afterEpoch+offset)
		if err != nil {
			return nil, err
		}
		page.Epochs = append(page.Epochs, *record)
	}
	page.HasMore = count < remaining
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return page, nil
}

// AuditMembershipEpochsV1 verifies every durable chain before the gateway
// serves traffic. This catches bypassed SQL writes, missing child rows,
// signature/policy corruption, head rollback, and configuration-origin drift.
func (db *DB) AuditMembershipEpochsV1(ctx context.Context, canonicalOrigin string) error {
	if db == nil || db.Pool == nil || canonicalOrigin == "" {
		return errors.New("membership epoch audit configuration is invalid")
	}
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var orphanEpochs int64
	if err := tx.QueryRow(ctx,
		`SELECT count(*)
		 FROM conversation_membership_epochs_v1 AS epoch
		 LEFT JOIN conversation_membership_epoch_heads_v1 AS head
		   ON head.conversation_id = epoch.conversation_id
		 WHERE head.conversation_id IS NULL`,
	).Scan(&orphanEpochs); err != nil {
		return err
	}
	if orphanEpochs != 0 {
		return errors.New("membership epoch history contains a conversation without a head")
	}
	type durableHead struct {
		conversationID   string
		epochNumber      int64
		epochHash        []byte
		rosterVersion    int64
		rosterCommitment []byte
	}
	rows, err := tx.Query(ctx,
		`SELECT conversation_id::text, epoch_number, epoch_hash,
		        roster_version, roster_commitment
		 FROM conversation_membership_epoch_heads_v1
		 ORDER BY conversation_id`,
	)
	if err != nil {
		return err
	}
	heads := make([]durableHead, 0)
	for rows.Next() {
		var head durableHead
		if err := rows.Scan(
			&head.conversationID, &head.epochNumber, &head.epochHash,
			&head.rosterVersion, &head.rosterCommitment,
		); err != nil {
			rows.Close()
			return err
		}
		heads = append(heads, head)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, head := range heads {
		if _, err := membershipUUIDBytes("audited membership conversation", head.conversationID); err != nil ||
			head.epochNumber <= 0 || head.rosterVersion <= 0 || len(head.epochHash) != 32 ||
			len(head.rosterCommitment) != 32 {
			return errors.New("membership epoch head is invalid")
		}
		var count, minimum, maximum int64
		if err := tx.QueryRow(ctx,
			`SELECT count(*), min(epoch_number), max(epoch_number)
			 FROM conversation_membership_epochs_v1
			 WHERE conversation_id = $1::uuid`, head.conversationID,
		).Scan(&count, &minimum, &maximum); err != nil {
			return err
		}
		if count != head.epochNumber || minimum != 1 || maximum != head.epochNumber {
			return errors.New("membership epoch history is not contiguous")
		}
		var predecessor *MembershipEpochRecordV1
		for number := int64(1); number <= head.epochNumber; number++ {
			record, err := loadMembershipEpochTxV1(ctx, tx, head.conversationID, uint64(number))
			if err != nil {
				return fmt.Errorf("audit membership epoch %d: %w", number, err)
			}
			if record.Epoch.CanonicalOrigin != canonicalOrigin {
				return errors.New("membership epoch canonical origin differs from gateway configuration")
			}
			if predecessor == nil {
				if record.BootstrapOwner == nil {
					return errors.New("membership epoch bootstrap owner is missing")
				}
				if err := veilmembership.VerifyBootstrap(
					record.Epoch, *record.BootstrapOwner, record.Signatures,
				); err != nil {
					return fmt.Errorf("audit membership epoch bootstrap: %w", err)
				}
			} else {
				if record.BootstrapOwner != nil {
					return errors.New("membership successor epoch invented a bootstrap owner")
				}
				if err := veilmembership.VerifyTransition(
					predecessor.Epoch, record.Epoch, record.Signatures,
				); err != nil {
					return fmt.Errorf("audit membership epoch transition: %w", err)
				}
			}
			predecessor = record
		}
		if predecessor == nil || !bytes.Equal(predecessor.Hash[:], head.epochHash) ||
			predecessor.Epoch.RosterVersion != uint64(head.rosterVersion) ||
			!bytes.Equal(predecessor.Epoch.RosterCommitment[:], head.rosterCommitment) {
			return errors.New("membership epoch head differs from the audited chain")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}
