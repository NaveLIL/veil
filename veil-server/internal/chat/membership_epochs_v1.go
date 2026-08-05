package chat

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	veilmembership "github.com/NaveLIL/veil/veil-server/internal/membership"
	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const maxMembershipEpochRequestBytesV1 = 64 * 1024

type membershipPolicySignerJSONV1 struct {
	AccountID         string `json:"account_id"`
	AccountSigningKey string `json:"account_signing_key"`
}

type membershipEpochSignatureJSONV1 struct {
	SignerAccountID string `json:"signer_account_id"`
	Signature       string `json:"signature"`
}

type membershipEpochRequestJSONV1 struct {
	Version          int                              `json:"version"`
	CanonicalOrigin  string                           `json:"canonical_origin"`
	ConversationID   string                           `json:"conversation_id"`
	ConversationKind uint8                            `json:"conversation_kind"`
	Epoch            string                           `json:"epoch"`
	PredecessorHash  string                           `json:"predecessor_hash"`
	RosterVersion    string                           `json:"roster_version"`
	RosterCommitment string                           `json:"roster_commitment"`
	PolicyThreshold  uint16                           `json:"policy_threshold"`
	PolicySigners    []membershipPolicySignerJSONV1   `json:"policy_signers"`
	CryptoProfile    string                           `json:"crypto_profile"`
	CryptoEra        string                           `json:"crypto_era"`
	MutationNonce    string                           `json:"mutation_nonce"`
	Signatures       []membershipEpochSignatureJSONV1 `json:"signatures"`
}

type membershipEpochResponseJSONV1 struct {
	Version          int                              `json:"version"`
	CanonicalOrigin  string                           `json:"canonical_origin"`
	ConversationID   string                           `json:"conversation_id"`
	ConversationKind uint8                            `json:"conversation_kind"`
	Epoch            string                           `json:"epoch"`
	PredecessorHash  string                           `json:"predecessor_hash"`
	RosterVersion    string                           `json:"roster_version"`
	RosterCommitment string                           `json:"roster_commitment"`
	PolicyThreshold  uint16                           `json:"policy_threshold"`
	PolicySigners    []membershipPolicySignerJSONV1   `json:"policy_signers"`
	CryptoProfile    string                           `json:"crypto_profile"`
	CryptoEra        string                           `json:"crypto_era"`
	MutationNonce    string                           `json:"mutation_nonce"`
	EpochHash        string                           `json:"epoch_hash"`
	Signatures       []membershipEpochSignatureJSONV1 `json:"signatures"`
	BootstrapOwner   *membershipPolicySignerJSONV1    `json:"bootstrap_owner,omitempty"`
}

type membershipEpochPageJSONV1 struct {
	Version   int                             `json:"version"`
	HeadEpoch string                          `json:"head_epoch"`
	HeadHash  string                          `json:"head_hash"`
	Epochs    []membershipEpochResponseJSONV1 `json:"epochs"`
	HasMore   bool                            `json:"has_more"`
}

func exactMembershipDecimalV1(label, encoded string, allowZero bool) (uint64, error) {
	if encoded == "" || len(encoded) > 19 || (len(encoded) > 1 && encoded[0] == '0') {
		return 0, errors.New(label + " is not canonical unsigned decimal")
	}
	for index := range len(encoded) {
		if encoded[index] < '0' || encoded[index] > '9' {
			return 0, errors.New(label + " is not canonical unsigned decimal")
		}
	}
	value, err := strconv.ParseUint(encoded, 10, 64)
	if err != nil || value > math.MaxInt64 || (!allowZero && value == 0) || strconv.FormatUint(value, 10) != encoded {
		return 0, errors.New(label + " is outside the supported range")
	}
	return value, nil
}

func exactMembershipHexV1(label, encoded string, size int) ([]byte, error) {
	if len(encoded) != size*2 {
		return nil, errors.New(label + " has invalid length")
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != size || hex.EncodeToString(decoded) != encoded {
		return nil, errors.New(label + " is not canonical lowercase hex")
	}
	return decoded, nil
}

func exactMembershipUUIDV1(label, encoded string) ([16]byte, error) {
	parsed, err := uuid.Parse(encoded)
	if err != nil || parsed == uuid.Nil || parsed.String() != encoded {
		return [16]byte{}, errors.New(label + " is not a canonical nonzero UUID")
	}
	return [16]byte(parsed), nil
}

func parseMembershipEpochRequestV1(
	req *membershipEpochRequestJSONV1,
	expectedOrigin string,
	expectedConversationID string,
) (veilmembership.Epoch, []veilmembership.Signature, error) {
	if req == nil || req.Version != 1 || req.CanonicalOrigin != expectedOrigin ||
		req.ConversationID != expectedConversationID || req.CryptoProfile != "sender_key_v6" {
		return veilmembership.Epoch{}, nil, errors.New("membership epoch scope is invalid")
	}
	conversationID, err := exactMembershipUUIDV1("membership conversation id", req.ConversationID)
	if err != nil {
		return veilmembership.Epoch{}, nil, err
	}
	epochNumber, err := exactMembershipDecimalV1("membership epoch", req.Epoch, false)
	if err != nil {
		return veilmembership.Epoch{}, nil, err
	}
	rosterVersion, err := exactMembershipDecimalV1("membership roster version", req.RosterVersion, false)
	if err != nil {
		return veilmembership.Epoch{}, nil, err
	}
	cryptoEra, err := exactMembershipDecimalV1("membership crypto era", req.CryptoEra, false)
	if err != nil || cryptoEra > math.MaxUint16 {
		return veilmembership.Epoch{}, nil, errors.New("membership crypto era is invalid")
	}
	epoch := veilmembership.Epoch{
		CanonicalOrigin: req.CanonicalOrigin, ConversationID: conversationID,
		ConversationKind: req.ConversationKind, Number: epochNumber,
		RosterVersion:   rosterVersion,
		SuccessorPolicy: veilmembership.Policy{Threshold: req.PolicyThreshold},
		CryptoProfile:   veilmembership.CryptoProfileSenderKeyV6,
		CryptoEra:       uint16(cryptoEra),
	}
	copy(epoch.PredecessorHash[:], mustMembershipHexV1("membership predecessor hash", req.PredecessorHash, 32, &err))
	if err != nil {
		return veilmembership.Epoch{}, nil, err
	}
	copy(epoch.RosterCommitment[:], mustMembershipHexV1("membership roster commitment", req.RosterCommitment, 32, &err))
	if err != nil {
		return veilmembership.Epoch{}, nil, err
	}
	copy(epoch.MutationNonce[:], mustMembershipHexV1("membership mutation nonce", req.MutationNonce, 32, &err))
	if err != nil {
		return veilmembership.Epoch{}, nil, err
	}
	epoch.SuccessorPolicy.Signers = make([]veilmembership.PolicySigner, len(req.PolicySigners))
	for index, encoded := range req.PolicySigners {
		accountID, parseErr := exactMembershipUUIDV1("membership policy account id", encoded.AccountID)
		if parseErr != nil {
			return veilmembership.Epoch{}, nil, parseErr
		}
		key, parseErr := exactMembershipHexV1("membership policy account signing key", encoded.AccountSigningKey, 32)
		if parseErr != nil {
			return veilmembership.Epoch{}, nil, parseErr
		}
		epoch.SuccessorPolicy.Signers[index].AccountID = accountID
		copy(epoch.SuccessorPolicy.Signers[index].AccountSigningKey[:], key)
	}
	signatures := make([]veilmembership.Signature, len(req.Signatures))
	for index, encoded := range req.Signatures {
		accountID, parseErr := exactMembershipUUIDV1("membership signature account id", encoded.SignerAccountID)
		if parseErr != nil {
			return veilmembership.Epoch{}, nil, parseErr
		}
		signature, parseErr := exactMembershipHexV1("membership epoch signature", encoded.Signature, 64)
		if parseErr != nil {
			return veilmembership.Epoch{}, nil, parseErr
		}
		signatures[index].SignerAccountID = accountID
		copy(signatures[index].Signature[:], signature)
	}
	if err := epoch.Validate(); err != nil {
		return veilmembership.Epoch{}, nil, err
	}
	return epoch, signatures, nil
}

func mustMembershipHexV1(label, encoded string, size int, target *error) []byte {
	if *target != nil {
		return nil
	}
	decoded, err := exactMembershipHexV1(label, encoded, size)
	if err != nil {
		*target = err
	}
	return decoded
}

func membershipSignerResponseV1(signer veilmembership.PolicySigner) membershipPolicySignerJSONV1 {
	return membershipPolicySignerJSONV1{
		AccountID:         uuid.UUID(signer.AccountID).String(),
		AccountSigningKey: hex.EncodeToString(signer.AccountSigningKey[:]),
	}
}

func membershipEpochResponseV1(record *db.MembershipEpochRecordV1) (membershipEpochResponseJSONV1, error) {
	if record == nil {
		return membershipEpochResponseJSONV1{}, errors.New("membership epoch record is missing")
	}
	if err := record.Epoch.Validate(); err != nil {
		return membershipEpochResponseJSONV1{}, err
	}
	response := membershipEpochResponseJSONV1{
		Version: 1, CanonicalOrigin: record.Epoch.CanonicalOrigin,
		ConversationID:   uuid.UUID(record.Epoch.ConversationID).String(),
		ConversationKind: record.Epoch.ConversationKind,
		Epoch:            strconv.FormatUint(record.Epoch.Number, 10),
		PredecessorHash:  hex.EncodeToString(record.Epoch.PredecessorHash[:]),
		RosterVersion:    strconv.FormatUint(record.Epoch.RosterVersion, 10),
		RosterCommitment: hex.EncodeToString(record.Epoch.RosterCommitment[:]),
		PolicyThreshold:  record.Epoch.SuccessorPolicy.Threshold,
		PolicySigners:    make([]membershipPolicySignerJSONV1, len(record.Epoch.SuccessorPolicy.Signers)),
		CryptoProfile:    "sender_key_v6", CryptoEra: strconv.FormatUint(uint64(record.Epoch.CryptoEra), 10),
		MutationNonce: hex.EncodeToString(record.Epoch.MutationNonce[:]),
		EpochHash:     hex.EncodeToString(record.Hash[:]),
		Signatures:    make([]membershipEpochSignatureJSONV1, len(record.Signatures)),
	}
	for index, signer := range record.Epoch.SuccessorPolicy.Signers {
		response.PolicySigners[index] = membershipSignerResponseV1(signer)
	}
	for index, signature := range record.Signatures {
		response.Signatures[index] = membershipEpochSignatureJSONV1{
			SignerAccountID: uuid.UUID(signature.SignerAccountID).String(),
			Signature:       hex.EncodeToString(signature.Signature[:]),
		}
	}
	if record.BootstrapOwner != nil {
		owner := membershipSignerResponseV1(*record.BootstrapOwner)
		response.BootstrapOwner = &owner
	}
	return response, nil
}

func exactMembershipConversationPathV1(r *http.Request) (string, error) {
	conversationID := r.PathValue("conversationID")
	if _, err := exactMembershipUUIDV1("membership conversation id", conversationID); err != nil ||
		r.URL.EscapedPath() != "/v1/conversations/"+conversationID+"/membership-epochs" {
		return "", errors.New("membership conversation path is invalid")
	}
	return conversationID, nil
}

func (h *Handler) StoreMembershipEpochV1(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.svc == nil || h.svc.db == nil || h.svc.cfg == nil || h.svc.cfg.PublicOrigin.IsZero() {
		writeJSON(w, http.StatusServiceUnavailable, errorResp("membership epochs unavailable"))
		return
	}
	requesterID := r.Header.Get("X-User-ID")
	if _, err := exactMembershipUUIDV1("membership requester id", requesterID); err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}
	conversationID, err := exactMembershipConversationPathV1(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid membership conversation"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxMembershipEpochRequestBytesV1)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request membershipEpochRequestJSONV1
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid membership epoch JSON"))
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid membership epoch JSON"))
		return
	}
	epoch, signatures, err := parseMembershipEpochRequestV1(
		&request, h.svc.cfg.PublicOrigin.String(), conversationID,
	)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid membership epoch"))
		return
	}
	record, stored, err := h.svc.db.StoreMembershipEpochV1(
		r.Context(), requesterID, epoch, signatures,
	)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrMembershipEpochUnauthorized):
			writeJSON(w, http.StatusForbidden, errorResp("not authorized for membership epoch"))
		case errors.Is(err, db.ErrMembershipEpochConflict), errors.Is(err, db.ErrMembershipEpochRosterStale):
			writeJSON(w, http.StatusConflict, errorResp("membership epoch or roster changed"))
		default:
			publicerr.Write(w, http.StatusBadRequest, err)
		}
		return
	}
	response, err := membershipEpochResponseV1(record)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to encode membership epoch"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stored": stored, "membership_epoch": response})
}

func exactMembershipPageQueryV1(raw string) (uint64, int, error) {
	if raw == "" {
		return 0, 50, nil
	}
	parts := strings.Split(raw, "&")
	if len(parts) < 1 || len(parts) > 2 || !strings.HasPrefix(parts[0], "after_epoch=") {
		return 0, 0, errors.New("membership page query is invalid")
	}
	after, err := exactMembershipDecimalV1("membership after epoch", strings.TrimPrefix(parts[0], "after_epoch="), true)
	if err != nil {
		return 0, 0, err
	}
	limit := uint64(50)
	if len(parts) == 2 {
		if !strings.HasPrefix(parts[1], "limit=") {
			return 0, 0, errors.New("membership page query is invalid")
		}
		limit, err = exactMembershipDecimalV1("membership page limit", strings.TrimPrefix(parts[1], "limit="), false)
		if err != nil || limit > 100 {
			return 0, 0, errors.New("membership page limit is invalid")
		}
	}
	return after, int(limit), nil
}

func (h *Handler) ListMembershipEpochsV1(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.svc == nil || h.svc.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResp("membership epochs unavailable"))
		return
	}
	requesterID := r.Header.Get("X-User-ID")
	if _, err := exactMembershipUUIDV1("membership requester id", requesterID); err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}
	conversationID, err := exactMembershipConversationPathV1(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid membership conversation"))
		return
	}
	after, limit, err := exactMembershipPageQueryV1(r.URL.RawQuery)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid membership epoch query"))
		return
	}
	page, err := h.svc.db.ListMembershipEpochsForRequesterV1(
		r.Context(), conversationID, requesterID, after, limit,
	)
	if err != nil {
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			writeJSON(w, http.StatusNotFound, errorResp("membership epochs are not activated"))
		case errors.Is(err, db.ErrMembershipEpochUnauthorized):
			writeJSON(w, http.StatusForbidden, errorResp("not authorized for membership epochs"))
		case errors.Is(err, db.ErrMembershipEpochConflict):
			writeJSON(w, http.StatusConflict, errorResp("membership epoch head changed"))
		default:
			writeJSON(w, http.StatusInternalServerError, errorResp("failed to load membership epochs"))
		}
		return
	}
	response := membershipEpochPageJSONV1{
		Version: 1, HeadEpoch: strconv.FormatUint(page.HeadEpoch, 10),
		HeadHash: hex.EncodeToString(page.HeadHash[:]),
		Epochs:   make([]membershipEpochResponseJSONV1, len(page.Epochs)), HasMore: page.HasMore,
	}
	for index := range page.Epochs {
		encoded, err := membershipEpochResponseV1(&page.Epochs[index])
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResp("failed to encode membership epochs"))
			return
		}
		response.Epochs[index] = encoded
	}
	writeJSON(w, http.StatusOK, response)
}
