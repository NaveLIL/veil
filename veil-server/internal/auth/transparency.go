package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/logsafe"
	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
	veiltransparency "github.com/NaveLIL/veil/veil-server/internal/transparency"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const identityTransparencyResponseVersion = 1

// IdentityTransparencySigner holds the Node-local signing identity for
// short-lived tree heads. Its fixed-size fields cannot be resized or replaced
// through a caller-owned slice after construction.
type IdentityTransparencySigner struct {
	canonicalOrigin nodeorigin.Canonical
	logID           veiltransparency.Hash
	publicKey       [ed25519.PublicKeySize]byte
	privateKey      [ed25519.PrivateKeySize]byte
	witnessCosigner identityTransparencyWitnessCosigner
	now             func() time.Time
}

type identityTransparencyWitnessCosigner interface {
	Cosign(
		context.Context,
		string,
		[ed25519.PublicKeySize]byte,
		veiltransparency.TreeHead,
		[ed25519.SignatureSize]byte,
	) ([]veiltransparency.WitnessSignature, error)
}

func NewIdentityTransparencySigner(
	canonicalOrigin nodeorigin.Canonical,
	signingSeed [ed25519.SeedSize]byte,
) (*IdentityTransparencySigner, error) {
	if canonicalOrigin.IsZero() {
		return nil, errors.New("identity transparency canonical origin is required")
	}
	privateKey := ed25519.NewKeyFromSeed(signingSeed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	logID, err := veiltransparency.LogID(canonicalOrigin.String(), publicKey)
	if err != nil {
		return nil, err
	}
	signer := &IdentityTransparencySigner{
		canonicalOrigin: canonicalOrigin,
		logID:           logID,
		now:             time.Now,
	}
	copy(signer.publicKey[:], publicKey)
	copy(signer.privateKey[:], privateKey)
	return signer, nil
}

func (s *IdentityTransparencySigner) LogID() veiltransparency.Hash {
	if s == nil {
		return veiltransparency.Hash{}
	}
	return s.logID
}

func (s *IdentityTransparencySigner) PublicKey() [ed25519.PublicKeySize]byte {
	if s == nil {
		return [ed25519.PublicKeySize]byte{}
	}
	return s.publicKey
}

func (s *IdentityTransparencySigner) SetWitnessCosigner(cosigner identityTransparencyWitnessCosigner) {
	if s != nil {
		s.witnessCosigner = cosigner
	}
}

// Destroy clears the in-memory private key after the HTTP server has stopped.
func (s *IdentityTransparencySigner) Destroy() {
	if s != nil {
		clear(s.privateKey[:])
	}
}

func (h *Handler) SetIdentityTransparencySigner(signer *IdentityTransparencySigner) {
	if h != nil {
		h.identityTransparencySigner = signer
	}
}

type identityTransparencyTreeHeadJSON struct {
	LogID          string                                     `json:"log_id"`
	NodeSigningKey string                                     `json:"node_signing_key"`
	TreeSize       string                                     `json:"tree_size"`
	RootHash       string                                     `json:"root_hash"`
	IssuedAtMS     string                                     `json:"issued_at_ms"`
	Signature      string                                     `json:"signature"`
	Witnesses      []identityTransparencyWitnessSignatureJSON `json:"witnesses"`
}

type identityTransparencyWitnessSignatureJSON struct {
	WitnessSigningKey string `json:"witness_signing_key"`
	Signature         string `json:"signature"`
}

type identityTransparencyAccountProofJSON struct {
	Version          int                              `json:"version"`
	CanonicalOrigin  string                           `json:"canonical_origin"`
	AccountUserID    string                           `json:"account_user_id"`
	CanonicalEvent   string                           `json:"canonical_event"`
	LeafIndex        string                           `json:"leaf_index"`
	TreeHead         identityTransparencyTreeHeadJSON `json:"tree_head"`
	InclusionProof   []string                         `json:"inclusion_proof"`
	ConsistencyFrom  string                           `json:"consistency_from"`
	ConsistencyProof []string                         `json:"consistency_proof"`
}

type identityTransparencyDeviceBindingProofJSON struct {
	Version              int                              `json:"version"`
	CanonicalOrigin      string                           `json:"canonical_origin"`
	DeviceKey            string                           `json:"device_key"`
	DeviceBindingVersion string                           `json:"device_binding_version"`
	CanonicalEvent       string                           `json:"canonical_event"`
	LeafIndex            string                           `json:"leaf_index"`
	TreeHead             identityTransparencyTreeHeadJSON `json:"tree_head"`
	InclusionProof       []string                         `json:"inclusion_proof"`
	ConsistencyFrom      string                           `json:"consistency_from"`
	ConsistencyProof     []string                         `json:"consistency_proof"`
}

func transparencyHashesHex(values []veiltransparency.Hash) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = hex.EncodeToString(values[index][:])
	}
	return result
}

func (s *IdentityTransparencySigner) signedTreeHead(
	ctx context.Context,
	proof *db.IdentityTransparencyProof,
) (identityTransparencyTreeHeadJSON, error) {
	if s == nil || proof == nil || proof.Head.LogID != s.logID ||
		proof.Head.NodeSigningKey != s.publicKey {
		return identityTransparencyTreeHeadJSON{}, errors.New("identity transparency proof signer mismatch")
	}
	issuedAt := s.now()
	if issuedAt.UnixMilli() <= 0 {
		return identityTransparencyTreeHeadJSON{}, errors.New("identity transparency clock is invalid")
	}
	head := veiltransparency.TreeHead{
		LogID:      proof.Head.LogID,
		TreeSize:   proof.Head.TreeSize,
		RootHash:   proof.Head.RootHash,
		IssuedAtMs: uint64(issuedAt.UnixMilli()),
	}
	message, err := head.SigningMessage(s.canonicalOrigin.String())
	if err != nil {
		return identityTransparencyTreeHeadJSON{}, err
	}
	signature := ed25519.Sign(s.privateKey[:], message)
	if !head.VerifyNodeSignature(s.canonicalOrigin.String(), s.publicKey[:], signature) {
		return identityTransparencyTreeHeadJSON{}, errors.New("identity transparency tree-head self-check failed")
	}
	var nodeSignature [ed25519.SignatureSize]byte
	copy(nodeSignature[:], signature)
	witnesses := make([]identityTransparencyWitnessSignatureJSON, 0)
	if s.witnessCosigner != nil {
		cosigned, err := s.witnessCosigner.Cosign(
			ctx, s.canonicalOrigin.String(), s.publicKey, head, nodeSignature,
		)
		if err != nil {
			return identityTransparencyTreeHeadJSON{}, err
		}
		if len(cosigned) == 0 || len(cosigned) > veiltransparency.MaxWitnesses {
			return identityTransparencyTreeHeadJSON{}, errors.New("identity transparency witness response is invalid")
		}
		checkpoint, err := veiltransparency.WitnessCheckpointMessage(
			s.canonicalOrigin.String(), s.publicKey[:], head, nodeSignature[:],
		)
		if err != nil {
			return identityTransparencyTreeHeadJSON{}, err
		}
		witnesses = make([]identityTransparencyWitnessSignatureJSON, len(cosigned))
		for index := range cosigned {
			if index > 0 && bytes.Compare(cosigned[index-1].SigningKey[:], cosigned[index].SigningKey[:]) >= 0 ||
				!ed25519.Verify(cosigned[index].SigningKey[:], checkpoint, cosigned[index].Signature[:]) {
				return identityTransparencyTreeHeadJSON{}, errors.New("identity transparency witness signature is invalid")
			}
			witnesses[index] = identityTransparencyWitnessSignatureJSON{
				WitnessSigningKey: hex.EncodeToString(cosigned[index].SigningKey[:]),
				Signature:         hex.EncodeToString(cosigned[index].Signature[:]),
			}
		}
	}
	return identityTransparencyTreeHeadJSON{
		LogID:          hex.EncodeToString(head.LogID[:]),
		NodeSigningKey: hex.EncodeToString(s.publicKey[:]),
		TreeSize:       strconv.FormatUint(head.TreeSize, 10),
		RootHash:       hex.EncodeToString(head.RootHash[:]),
		IssuedAtMS:     strconv.FormatUint(head.IssuedAtMs, 10),
		Signature:      hex.EncodeToString(signature),
		Witnesses:      witnesses,
	}, nil
}

func (s *IdentityTransparencySigner) response(
	ctx context.Context,
	accountUserID string,
	proof *db.IdentityTransparencyAccountProof,
) (*identityTransparencyAccountProofJSON, error) {
	head, err := s.signedTreeHead(ctx, proof)
	if err != nil {
		return nil, err
	}
	return s.accountResponseWithHead(accountUserID, proof, head), nil
}

func (s *IdentityTransparencySigner) accountResponseWithHead(
	accountUserID string,
	proof *db.IdentityTransparencyAccountProof,
	head identityTransparencyTreeHeadJSON,
) *identityTransparencyAccountProofJSON {
	return &identityTransparencyAccountProofJSON{
		Version:          identityTransparencyResponseVersion,
		CanonicalOrigin:  s.canonicalOrigin.String(),
		AccountUserID:    accountUserID,
		CanonicalEvent:   base64.RawURLEncoding.EncodeToString(proof.CanonicalEvent),
		LeafIndex:        strconv.FormatUint(proof.LeafIndex, 10),
		TreeHead:         head,
		InclusionProof:   transparencyHashesHex(proof.InclusionProof),
		ConsistencyFrom:  strconv.FormatUint(proof.ConsistencyFrom, 10),
		ConsistencyProof: transparencyHashesHex(proof.ConsistencyProof),
	}
}

func (s *IdentityTransparencySigner) deviceBindingResponse(
	ctx context.Context,
	deviceKey []byte,
	bindingVersion uint64,
	proof *db.IdentityTransparencyDeviceBindingProof,
) (*identityTransparencyDeviceBindingProofJSON, error) {
	head, err := s.signedTreeHead(ctx, proof)
	if err != nil {
		return nil, err
	}
	return s.deviceBindingResponseWithHead(deviceKey, bindingVersion, proof, head), nil
}

func (s *IdentityTransparencySigner) deviceBindingResponseWithHead(
	deviceKey []byte,
	bindingVersion uint64,
	proof *db.IdentityTransparencyDeviceBindingProof,
	head identityTransparencyTreeHeadJSON,
) *identityTransparencyDeviceBindingProofJSON {
	return &identityTransparencyDeviceBindingProofJSON{
		Version:              identityTransparencyResponseVersion,
		CanonicalOrigin:      s.canonicalOrigin.String(),
		DeviceKey:            hex.EncodeToString(deviceKey),
		DeviceBindingVersion: strconv.FormatUint(bindingVersion, 10),
		CanonicalEvent:       base64.RawURLEncoding.EncodeToString(proof.CanonicalEvent),
		LeafIndex:            strconv.FormatUint(proof.LeafIndex, 10),
		TreeHead:             head,
		InclusionProof:       transparencyHashesHex(proof.InclusionProof),
		ConsistencyFrom:      strconv.FormatUint(proof.ConsistencyFrom, 10),
		ConsistencyProof:     transparencyHashesHex(proof.ConsistencyProof),
	}
}

func identityTransparencyNoStore(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next(w, r)
	}
}

func exactTransparencyFromSize(r *http.Request) (uint64, error) {
	value, _, err := exactTransparencySizeQuery(r, "from_size")
	return value, err
}

func exactTransparencySizeQuery(r *http.Request, key string) (uint64, bool, error) {
	if r.URL.RawQuery == "" {
		return 0, false, nil
	}
	prefix := key + "="
	if len(r.URL.RawQuery) <= len(prefix) || r.URL.RawQuery[:len(prefix)] != prefix {
		return 0, false, errors.New("identity transparency size query is invalid")
	}
	encoded := r.URL.RawQuery[len(prefix):]
	value, err := strconv.ParseUint(encoded, 10, 64)
	if err != nil || strconv.FormatUint(value, 10) != encoded {
		return 0, false, errors.New("identity transparency size query is invalid")
	}
	return value, true, nil
}

type identityTransparencyPreKeyProofsJSON struct {
	Account       *identityTransparencyAccountProofJSON       `json:"account"`
	DeviceBinding *identityTransparencyDeviceBindingProofJSON `json:"device_binding"`
}

func (s *IdentityTransparencySigner) preKeyProofsResponse(
	ctx context.Context,
	accountUserID string,
	accountProof *db.IdentityTransparencyAccountProof,
	deviceKey []byte,
	bindingVersion uint64,
	deviceProof *db.IdentityTransparencyDeviceBindingProof,
) (*identityTransparencyPreKeyProofsJSON, bool, error) {
	if accountProof == nil || deviceProof == nil {
		return nil, false, errors.New("identity transparency prekey proof is missing")
	}
	if accountProof.Head != deviceProof.Head {
		return nil, false, nil
	}
	head, err := s.signedTreeHead(ctx, accountProof)
	if err != nil {
		return nil, false, err
	}
	return &identityTransparencyPreKeyProofsJSON{
		Account: s.accountResponseWithHead(accountUserID, accountProof, head),
		DeviceBinding: s.deviceBindingResponseWithHead(
			deviceKey, bindingVersion, deviceProof, head,
		),
	}, true, nil
}

func (h *Handler) identityTransparencyPreKeyProofs(
	ctx context.Context,
	identityKey []byte,
	deviceKey []byte,
	bindingVersion uint64,
	fromSize uint64,
) (*identityTransparencyPreKeyProofsJSON, error) {
	if h == nil || h.svc == nil || h.svc.db == nil || h.identityTransparencySigner == nil {
		return nil, ErrIdentityTransparencyUnavailable
	}
	user, err := h.svc.db.FindUserByIdentityKey(ctx, identityKey)
	if err != nil {
		return nil, err
	}
	for range 4 {
		accountProof, accountErr := h.svc.db.IdentityTransparencyProofForAccount(
			ctx, user.ID, fromSize,
		)
		if accountErr != nil {
			return nil, accountErr
		}
		deviceProof, deviceErr := h.svc.db.IdentityTransparencyProofForDeviceBinding(
			ctx, deviceKey, bindingVersion, fromSize,
		)
		if deviceErr != nil {
			return nil, deviceErr
		}
		response, sameHead, responseErr := h.identityTransparencySigner.preKeyProofsResponse(
			ctx, user.ID, accountProof, deviceKey, bindingVersion, deviceProof,
		)
		if responseErr != nil {
			return nil, responseErr
		}
		if !sameHead {
			continue
		}
		return response, nil
	}
	return nil, errors.New("identity transparency head changed during prekey proof snapshot")
}

var ErrIdentityTransparencyUnavailable = errors.New("identity transparency is unavailable")

// GetIdentityTransparencyAccountProof returns an authenticated, no-store,
// bounded proof. Decimal strings avoid lossy JavaScript integer coercion;
// binary values use either lowercase hex or canonical unpadded base64url.
func (h *Handler) GetIdentityTransparencyAccountProof(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.svc == nil || h.svc.db == nil || h.identityTransparencySigner == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResp("identity transparency unavailable"))
		return
	}
	if r.Header.Get("X-User-ID") == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}
	userID := r.PathValue("userID")
	parsedUserID, err := uuid.Parse(userID)
	if err != nil || parsedUserID == uuid.Nil || parsedUserID.String() != userID {
		writeJSON(w, http.StatusBadRequest, errorResp("user_id must be a canonical lowercase UUID"))
		return
	}
	if r.URL.EscapedPath() != "/v1/transparency/accounts/"+userID {
		writeJSON(w, http.StatusBadRequest, errorResp("non-canonical transparency path"))
		return
	}
	fromSize, err := exactTransparencyFromSize(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid transparency query"))
		return
	}
	proof, err := h.svc.db.IdentityTransparencyProofForAccount(r.Context(), userID, fromSize)
	if err != nil {
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			writeJSON(w, http.StatusNotFound, errorResp("account transparency proof not found"))
		case errors.Is(err, db.ErrIdentityTransparencyInactive):
			writeJSON(w, http.StatusServiceUnavailable, errorResp("identity transparency unavailable"))
		case errors.Is(err, db.ErrIdentityTransparencyHeadRegression):
			writeJSON(w, http.StatusConflict, errorResp("identity transparency head regression"))
		default:
			log.Printf("identity transparency proof error: class=%s", logsafe.ErrorClass(err))
			writeJSON(w, http.StatusInternalServerError, errorResp("failed to build identity transparency proof"))
		}
		return
	}
	response, err := h.identityTransparencySigner.response(r.Context(), userID, proof)
	if err != nil {
		log.Printf("identity transparency signing error: class=%s", logsafe.ErrorClass(err))
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to sign identity transparency proof"))
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) GetIdentityTransparencyDeviceBindingProof(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.svc == nil || h.svc.db == nil || h.identityTransparencySigner == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResp("identity transparency unavailable"))
		return
	}
	if r.Header.Get("X-User-ID") == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}
	deviceKeyHex := r.PathValue("deviceKey")
	deviceKey, err := hex.DecodeString(deviceKeyHex)
	if err != nil || len(deviceKey) != 16 || hex.EncodeToString(deviceKey) != deviceKeyHex {
		writeJSON(w, http.StatusBadRequest, errorResp("device_key must be canonical lowercase 16-byte hex"))
		return
	}
	bindingVersionText := r.PathValue("bindingVersion")
	bindingVersion, err := strconv.ParseUint(bindingVersionText, 10, 64)
	if err != nil || bindingVersion == 0 || bindingVersion > math.MaxInt64 ||
		strconv.FormatUint(bindingVersion, 10) != bindingVersionText {
		writeJSON(w, http.StatusBadRequest, errorResp("binding_version must be a canonical positive decimal integer"))
		return
	}
	expectedPath := "/v1/transparency/devices/" + deviceKeyHex + "/bindings/" + bindingVersionText
	if r.URL.EscapedPath() != expectedPath {
		writeJSON(w, http.StatusBadRequest, errorResp("non-canonical transparency path"))
		return
	}
	fromSize, err := exactTransparencyFromSize(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid transparency query"))
		return
	}
	proof, err := h.svc.db.IdentityTransparencyProofForDeviceBinding(
		r.Context(), deviceKey, bindingVersion, fromSize,
	)
	if err != nil {
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			writeJSON(w, http.StatusNotFound, errorResp("device-binding transparency proof not found"))
		case errors.Is(err, db.ErrIdentityTransparencyInactive):
			writeJSON(w, http.StatusServiceUnavailable, errorResp("identity transparency unavailable"))
		case errors.Is(err, db.ErrIdentityTransparencyHeadRegression):
			writeJSON(w, http.StatusConflict, errorResp("identity transparency head regression"))
		default:
			log.Printf("device-binding transparency proof error: class=%s", logsafe.ErrorClass(err))
			writeJSON(w, http.StatusInternalServerError, errorResp("failed to build device-binding transparency proof"))
		}
		return
	}
	response, err := h.identityTransparencySigner.deviceBindingResponse(
		r.Context(), deviceKey, bindingVersion, proof,
	)
	if err != nil {
		log.Printf("device-binding transparency signing error: class=%s", logsafe.ErrorClass(err))
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to sign device-binding transparency proof"))
		return
	}
	writeJSON(w, http.StatusOK, response)
}
