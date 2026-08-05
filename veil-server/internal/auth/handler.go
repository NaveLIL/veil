package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/NaveLIL/veil/veil-server/internal/authmw"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/logsafe"
	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
	"github.com/jackc/pgx/v5"
)

// Handler provides REST endpoints for the auth service.
// Prekey management, device registry, user lookup.
// (Challenge-response stays in the gateway — it's WS-bound.)
type Handler struct {
	svc                        *Service
	mw                         *authmw.Middleware
	restDispatcher             *authmw.RESTAuthVersionDispatcher
	rl                         *authmw.RateLimit
	identityTransparencySigner *IdentityTransparencySigner
}

// NewHandler builds the auth REST handler. A nil middleware is reserved for
// direct-handler unit tests; every server entry point installs REST v2.
func NewHandler(svc *Service, mw *authmw.Middleware, rl *authmw.RateLimit) *Handler {
	return &Handler{svc: svc, mw: mw, rl: rl}
}

// SetRESTAuthVersionDispatcher activates mandatory REST v2 authentication for
// every signed auth route. A nil dispatcher fails closed with 503.
func (h *Handler) SetRESTAuthVersionDispatcher(dispatcher *authmw.RESTAuthVersionDispatcher) {
	h.restDispatcher = dispatcher
}

// SigningKeyLookup returns an authmw.UserKeyLookup backed by the service's
// database, for use when constructing the shared signing middleware.
func (s *Service) SigningKeyLookup() authmw.UserKeyLookup {
	return authmw.LookupFunc(func(ctx context.Context, userID string) (ed25519.PublicKey, error) {
		if s == nil || s.db == nil || s.db.Pool == nil {
			return nil, errors.New("signing key lookup database is unavailable")
		}
		u, err := s.db.FindUserByID(ctx, userID)
		if err != nil {
			return nil, authmw.NormalizeSigningKeyLookupError(ctx, err, pgx.ErrNoRows)
		}
		if u == nil {
			return nil, errors.New("signing key lookup returned no account row")
		}
		return ed25519.PublicKey(u.SigningKey), nil
	})
}

// RegisterRoutes registers auth REST endpoints on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	signed := func(policy authmw.RESTAuthV2HTTPPolicy, f http.HandlerFunc) http.HandlerFunc {
		if h.rl != nil {
			f = h.rl.Wrap(f)
		}
		// A nil middleware is an existing direct-handler unit-test seam. Any
		// configured authentication stack without v2 dispatch fails closed.
		if h.restDispatcher != nil {
			f = h.restDispatcher.RequireSigned(policy, f)
		} else if h.mw != nil {
			var unavailable *authmw.RESTAuthVersionDispatcher
			f = unavailable.RequireSigned(policy, f)
		}
		return f
	}
	jsonPolicy, err := authmw.NewRESTAuthV2JSONHTTPPolicy(64 * 1024)
	if err != nil {
		panic("invalid auth REST v2 JSON policy")
	}
	bodylessPolicy := authmw.RESTAuthV2BodylessHTTPPolicy()

	// no-store remains outermost so authentication and rate-limit failures on
	// sensitive prekey routes cannot be cached either.
	mux.HandleFunc("POST /v1/prekeys", preKeyNoStore(signed(jsonPolicy, h.UploadPreKeys)))
	mux.HandleFunc("GET /v1/prekeys/{identityKey}", preKeyNoStore(signed(bodylessPolicy, h.GetPreKeyBundle)))
	mux.HandleFunc("GET /v1/prekeys/{identityKey}/count", preKeyNoStore(signed(bodylessPolicy, h.GetOPKCount)))
	mux.HandleFunc("GET /v1/devices/{userID}", signed(bodylessPolicy, h.ListDevices))
	mux.HandleFunc("GET /v1/device-bindings/{deviceKey}", signed(bodylessPolicy, h.GetDeviceBinding))
	mux.HandleFunc("PUT /v1/device-bindings/{deviceKey}", signed(jsonPolicy, h.PutDeviceBinding))
	mux.HandleFunc("GET /v1/users/search", signed(bodylessPolicy, h.SearchUser))
	mux.HandleFunc("GET /v1/users/{identityKey}", signed(bodylessPolicy, h.LookupUser))
	mux.HandleFunc("GET /v1/transparency/accounts/{userID}", identityTransparencyNoStore(signed(bodylessPolicy, h.GetIdentityTransparencyAccountProof)))
	mux.HandleFunc("GET /v1/transparency/devices/{deviceKey}/bindings/{bindingVersion}", identityTransparencyNoStore(signed(bodylessPolicy, h.GetIdentityTransparencyDeviceBindingProof)))
}

// --- Prekey Upload ---

// UploadPreKeysRequest is the JSON body for prekey upload.
type UploadPreKeysRequest struct {
	DeviceID     string       `json:"device_id"`        // hex-encoded device ID
	SignedPreKey *PreKeyJSON  `json:"signed_prekey"`    // Exactly one signed prekey
	OneTimeKeys  []PreKeyJSON `json:"one_time_prekeys"` // Batch of OPKs
}

type PreKeyJSON struct {
	KeyID     *uint32 `json:"key_id"`     // device-local protocol key id
	PublicKey string  `json:"public_key"` // base64
	Signature string  `json:"signature"`  // base64, only for signed prekeys
}

const (
	x3dhSignedPreKeyDomain   = "veil-x3dh-spk-v1\x00"
	maxPreKeyUploadBodyBytes = 64 << 10
	maxPreKeyJSONNesting     = 64
)

var (
	ErrPreKeyAccessDenied = errors.New("prekey access requires a shared conversation")
	errDuplicateJSONKey   = errors.New("duplicate JSON object key")
)

func (h *Handler) UploadPreKeys(w http.ResponseWriter, r *http.Request) {
	setPreKeyNoStore(w)
	requesterID := r.Header.Get("X-User-ID")
	if requesterID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPreKeyUploadBodyBytes))
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorResp("prekey upload body too large"))
			return
		}
		writeJSON(w, http.StatusBadRequest, errorResp("invalid JSON"))
		return
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid JSON"))
		return
	}

	var req UploadPreKeysRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid JSON"))
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid JSON"))
		return
	}

	if req.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("device_id required"))
		return
	}
	deviceKey, err := hex.DecodeString(req.DeviceID)
	if err != nil || len(deviceKey) != 16 || hex.EncodeToString(deviceKey) != req.DeviceID {
		writeJSON(w, http.StatusBadRequest, errorResp("device_id must be canonical lowercase 16-byte hex"))
		return
	}
	if req.SignedPreKey == nil {
		writeJSON(w, http.StatusBadRequest, errorResp("signed_prekey required"))
		return
	}
	if len(req.OneTimeKeys) > 1000 {
		writeJSON(w, http.StatusBadRequest, errorResp("too many one_time_prekeys (maximum 1000)"))
		return
	}

	signedPreKey, err := decodePreKey(req.SignedPreKey, 0)
	if err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_signed_prekey", "invalid signed_prekey", err,
		))
		return
	}
	prekeys := []preKeyInput{signedPreKey}
	seenOPKIDs := make(map[uint32]struct{}, len(req.OneTimeKeys))
	for _, otk := range req.OneTimeKeys {
		pk, err := decodePreKey(&otk, 1)
		if err != nil {
			publicerr.Write(w, http.StatusBadRequest, publicerr.New(
				http.StatusBadRequest, "invalid_one_time_prekey", "invalid one_time_prekey", err,
			))
			return
		}
		if _, duplicate := seenOPKIDs[pk.protocolKeyID]; duplicate {
			writeJSON(w, http.StatusBadRequest, errorResp("duplicate one_time_prekey key_id"))
			return
		}
		seenOPKIDs[pk.protocolKeyID] = struct{}{}
		prekeys = append(prekeys, pk)
	}

	// Verify the canonical device after all attacker-controlled body fields
	// have passed cheap validation.
	device, err := h.svc.db.FindDevice(r.Context(), deviceKey)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResp("device not found"))
		return
	}
	if !deviceBelongsToUser(device, requesterID) {
		writeJSON(w, http.StatusForbidden, errorResp("device does not belong to authenticated user"))
		return
	}

	owner, err := h.svc.db.FindUserByID(r.Context(), requesterID)
	if err != nil {
		log.Printf("prekey owner lookup error: class=%s", logsafe.ErrorClass(err))
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user not found"))
		return
	}
	if err := validateSignedPreKey(owner, &signedPreKey); err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_signed_prekey", "signed prekey validation failed", err,
		))
		return
	}

	// Convert to db.PreKey slice
	var dbKeys []dbPreKeyAdapter
	for _, pk := range prekeys {
		dbKeys = append(dbKeys, dbPreKeyAdapter{
			KeyType:       pk.keyType,
			ProtocolKeyID: pk.protocolKeyID,
			PublicKey:     pk.publicKey,
			Signature:     pk.signature,
		})
	}

	receipt, err := h.svc.StorePreKeys(r.Context(), device.ID, dbKeys, sha256.Sum256(body))
	if err != nil {
		log.Printf("store prekeys error: class=%s", logsafe.ErrorClass(err))
		if errors.Is(err, db.ErrPreKeyMaterialConflict) {
			writeJSON(w, http.StatusConflict, errorResp("prekey key_id already exists with different material"))
			return
		}
		if errors.Is(err, db.ErrPreKeyLiveStateFull) {
			writeJSON(w, http.StatusConflict, errorResp("prekey live-state capacity reached for this account"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to store prekeys"))
		return
	}

	remaining, err := h.svc.db.CountUnusedOPKs(r.Context(), device.ID)
	if err != nil {
		log.Printf("count uploaded prekeys error: class=%s", logsafe.ErrorClass(err))
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to count one-time prekeys"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"stored":        receipt.Stored,
		"opk_remaining": remaining,
	})
}

// --- Prekey Bundle Fetch ---

func (h *Handler) GetPreKeyBundle(w http.ResponseWriter, r *http.Request) {
	setPreKeyNoStore(w)
	identityKeyHex := r.PathValue("identityKey")
	identityKey, err := hex.DecodeString(identityKeyHex)
	if err != nil || len(identityKeyHex) != 64 || len(identityKey) != 32 ||
		hex.EncodeToString(identityKey) != identityKeyHex ||
		r.URL.EscapedPath() != "/v1/prekeys/"+identityKeyHex {
		writeJSON(w, http.StatusBadRequest, errorResp("identity_key must be canonical lowercase 32-byte hex"))
		return
	}

	requesterID := r.Header.Get("X-User-ID")
	if requesterID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}
	transparencyFrom, _, err := exactTransparencySizeQuery(
		r, "transparency_from_size",
	)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid prekey transparency query"))
		return
	}

	bundle, err := h.svc.GetPreKeyBundle(r.Context(), requesterID, identityKey)
	if err != nil {
		if errors.Is(err, ErrPreKeyAccessDenied) {
			publicerr.Write(w, http.StatusForbidden, publicerr.New(
				http.StatusForbidden, "prekey_access_denied", "prekey access requires a shared conversation", err,
			))
			return
		}
		publicerr.Write(w, http.StatusNotFound, err)
		return
	}
	if h.identityTransparencySigner != nil {
		deviceKeyHex, keyOK := bundle["device_id"].(string)
		bindingVersion, versionOK := bundle["device_binding_version"].(uint64)
		deviceKey, keyErr := hex.DecodeString(deviceKeyHex)
		if !keyOK || !versionOK || keyErr != nil || len(deviceKey) != 16 ||
			hex.EncodeToString(deviceKey) != deviceKeyHex || bindingVersion == 0 {
			writeJSON(w, http.StatusInternalServerError, errorResp("prekey transparency subject is invalid"))
			return
		}
		proofs, proofErr := h.identityTransparencyPreKeyProofs(
			r.Context(), identityKey, deviceKey, bindingVersion, transparencyFrom,
		)
		if proofErr != nil {
			if errors.Is(proofErr, db.ErrIdentityTransparencyHeadRegression) {
				writeJSON(w, http.StatusConflict, errorResp("identity transparency head regression"))
				return
			}
			log.Printf("prekey transparency proof error: class=%s", logsafe.ErrorClass(proofErr))
			writeJSON(w, http.StatusInternalServerError, errorResp("failed to build prekey transparency proofs"))
			return
		}
		bundle["identity_transparency"] = proofs
	}

	writeJSON(w, http.StatusOK, bundle)
}

// --- OPK Count ---

func (h *Handler) GetOPKCount(w http.ResponseWriter, r *http.Request) {
	setPreKeyNoStore(w)
	requesterID := r.Header.Get("X-User-ID")
	if requesterID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}

	identityKeyHex := r.PathValue("identityKey")
	identityKey, err := hex.DecodeString(identityKeyHex)
	if err != nil || len(identityKeyHex) != 64 || len(identityKey) != 32 ||
		hex.EncodeToString(identityKey) != identityKeyHex ||
		r.URL.EscapedPath() != "/v1/prekeys/"+identityKeyHex+"/count" {
		writeJSON(w, http.StatusBadRequest, errorResp("identity_key must be canonical lowercase 32-byte hex"))
		return
	}

	user, err := h.svc.db.FindUserByIdentityKey(r.Context(), identityKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, errorResp("user not found"))
			return
		}
		log.Printf("prekey count user lookup error: class=%s", logsafe.ErrorClass(err))
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to load prekey owner"))
		return
	}
	if user.ID != requesterID {
		writeJSON(w, http.StatusForbidden, errorResp("one-time prekey counts are private to their owner"))
		return
	}

	devices, err := h.svc.db.GetDevicesByUser(r.Context(), user.ID)
	if err != nil {
		log.Printf("prekey count device lookup error: class=%s", logsafe.ErrorClass(err))
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to load devices"))
		return
	}
	if len(devices) == 0 {
		writeJSON(w, http.StatusNotFound, errorResp("no devices"))
		return
	}

	counts, err := loadDevicePreKeyCounts(
		r.Context(),
		devices,
		h.svc.db.CountUnusedOPKs,
		h.svc.db.GetSignedPreKey,
	)
	if err != nil {
		log.Printf("prekey count lookup error: class=%s", logsafe.ErrorClass(err))
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to load prekey counts"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"devices": counts})
}

type devicePreKeyCount struct {
	DeviceID       string  `json:"device_id"`
	Remaining      int     `json:"remaining"`
	SignedPreKeyID *uint32 `json:"signed_prekey_id"`
}

func loadDevicePreKeyCounts(
	ctx context.Context,
	devices []db.Device,
	countUnused func(context.Context, string) (int, error),
	getSigned func(context.Context, string) (*db.PreKey, error),
) ([]devicePreKeyCount, error) {
	counts := make([]devicePreKeyCount, 0, len(devices))
	for _, device := range devices {
		remaining, err := countUnused(ctx, device.ID)
		if err != nil {
			return nil, fmt.Errorf("count unused one-time prekeys: %w", err)
		}
		signedPreKey, err := getSigned(ctx, device.ID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("load signed prekey: %w", err)
		}
		var signedPreKeyID *uint32
		if err == nil && signedPreKey != nil {
			id := signedPreKey.ProtocolKeyID
			signedPreKeyID = &id
		}
		counts = append(counts, devicePreKeyCount{
			DeviceID:       hex.EncodeToString(device.DeviceKey),
			Remaining:      remaining,
			SignedPreKeyID: signedPreKeyID,
		})
	}
	return counts, nil
}

// --- Device List ---

func (h *Handler) ListDevices(w http.ResponseWriter, r *http.Request) {
	requesterID := r.Header.Get("X-User-ID")
	if requesterID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}

	userID := r.PathValue("userID")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("user_id required"))
		return
	}
	if userID != requesterID {
		writeJSON(w, http.StatusForbidden, errorResp("device list is private to its owner"))
		return
	}

	devices, err := h.svc.db.GetDevicesByUser(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResp("user not found or no devices"))
		return
	}

	type deviceResp struct {
		ID         string  `json:"id"`
		DeviceKey  string  `json:"device_key"`
		DeviceName string  `json:"device_name"`
		LastSeen   *string `json:"last_seen,omitempty"`
	}
	var resp []deviceResp
	for _, d := range devices {
		dr := deviceResp{
			ID:         d.ID,
			DeviceKey:  hex.EncodeToString(d.DeviceKey),
			DeviceName: d.DeviceName,
		}
		if d.LastSeen != nil {
			t := d.LastSeen.Format("2006-01-02T15:04:05Z")
			dr.LastSeen = &t
		}
		resp = append(resp, dr)
	}

	writeJSON(w, http.StatusOK, map[string]any{"devices": resp})
}

// --- User Lookup ---

func (h *Handler) LookupUser(w http.ResponseWriter, r *http.Request) {
	identityKeyHex := r.PathValue("identityKey")
	identityKey, err := hex.DecodeString(identityKeyHex)
	if err != nil || len(identityKey) != 32 {
		writeJSON(w, http.StatusBadRequest, errorResp("identity_key must be 32 bytes hex"))
		return
	}

	user, err := h.svc.db.FindUserByIdentityKey(r.Context(), identityKey)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResp("user not found"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":      user.ID,
		"identity_key": hex.EncodeToString(user.IdentityKey),
		"signing_key":  hex.EncodeToString(user.SigningKey),
		"username":     user.Username,
	})
}

// --- Service methods for REST (leverage existing DB layer) ---

// StorePreKeys stores prekeys via the DB layer.
func (s *Service) StorePreKeys(
	ctx context.Context,
	deviceID string,
	keys []dbPreKeyAdapter,
	exactUploadDigest [sha256.Size]byte,
) (db.PreKeyUploadReceipt, error) {
	var dbKeys []db.PreKey
	for _, k := range keys {
		dbKeys = append(dbKeys, db.PreKey{
			KeyType:       k.KeyType,
			ProtocolKeyID: k.ProtocolKeyID,
			PublicKey:     k.PublicKey,
			Signature:     k.Signature,
		})
	}
	return s.db.StorePreKeysWithReceipt(ctx, deviceID, dbKeys, exactUploadDigest)
}

// GetPreKeyBundle fetches a prekey bundle for X3DH session establishment.
func (s *Service) GetPreKeyBundle(ctx context.Context, requesterID string, targetIdentityKey []byte) (map[string]any, error) {
	user, err := s.db.FindUserByIdentityKey(ctx, targetIdentityKey)
	if err != nil {
		return nil, errors.New("user not found")
	}
	if requesterID == "" {
		return nil, ErrPreKeyAccessDenied
	}
	if requesterID != user.ID {
		allowed, relationErr := s.db.UsersShareConversation(ctx, requesterID, user.ID)
		if relationErr != nil || !allowed {
			return nil, ErrPreKeyAccessDenied
		}
	}

	devices, err := s.db.GetDevicesByUser(ctx, user.ID)
	if err != nil || len(devices) == 0 {
		return nil, errors.New("no devices registered")
	}
	// Known limitation: a bundle currently represents only the most recently
	// seen device. Safely returning all devices requires a versioned client
	// protocol with per-device sessions and fan-out; do not silently combine
	// device keys into this single-device response.
	device := devices[0]
	binding, err := s.db.GetLatestDeviceBinding(ctx, device.ID)
	if err != nil || binding.Status != db.DeviceBindingActive ||
		len(binding.DeviceKey) != 16 || len(binding.DeviceIdentityKey) != 32 ||
		len(binding.DeviceSigningKey) != 32 || binding.Version == 0 ||
		len(binding.AccountSignature) != 64 {
		return nil, errors.New("no active device binding available")
	}

	spk, err := s.db.GetSignedPreKey(ctx, device.ID)
	if err != nil {
		return nil, errors.New("no signed prekey available")
	}

	bundle := map[string]any{
		"identity_key":             base64.StdEncoding.EncodeToString(user.IdentityKey),
		"signing_key":              base64.StdEncoding.EncodeToString(user.SigningKey),
		"signed_prekey":            base64.StdEncoding.EncodeToString(spk.PublicKey),
		"signed_prekey_signature":  base64.StdEncoding.EncodeToString(spk.Signature),
		"signed_prekey_id":         spk.ProtocolKeyID,
		"device_id":                hex.EncodeToString(binding.DeviceKey),
		"device_binding_version":   binding.Version,
		"device_identity_key":      base64.StdEncoding.EncodeToString(binding.DeviceIdentityKey),
		"device_signing_key":       base64.StdEncoding.EncodeToString(binding.DeviceSigningKey),
		"device_capabilities":      binding.Capabilities,
		"device_binding_status":    uint8(binding.Status),
		"device_account_signature": base64.StdEncoding.EncodeToString(binding.AccountSignature),
	}

	opk, err := s.db.ClaimOneTimePreKey(ctx, device.ID)
	if err == nil && opk != nil {
		bundle["one_time_prekey"] = base64.StdEncoding.EncodeToString(opk.PublicKey)
		bundle["one_time_prekey_id"] = opk.ProtocolKeyID
	}

	remaining, _ := s.db.CountUnusedOPKs(ctx, device.ID)
	if remaining < s.cfg.PreKeyLowWarning {
		bundle["opk_low_warning"] = true
		bundle["opk_remaining"] = remaining
	}

	return bundle, nil
}

// --- Internal helpers ---

type preKeyInput struct {
	keyType       int16
	protocolKeyID uint32
	publicKey     []byte
	signature     []byte
}

type dbPreKeyAdapter struct {
	KeyType       int16
	ProtocolKeyID uint32
	PublicKey     []byte
	Signature     []byte
}

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	return scanJSONValue(decoder, 0)
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	if depth >= maxPreKeyJSONNesting {
		return errors.New("JSON nesting is too deep")
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errDuplicateJSONKey
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("JSON object is not terminated")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("JSON array is not terminated")
		}
		return nil
	default:
		return errors.New("unexpected closing JSON delimiter")
	}
}

func decodePreKey(pk *PreKeyJSON, keyType int16) (preKeyInput, error) {
	if pk.KeyID == nil {
		return preKeyInput{}, errors.New("key_id required")
	}
	if *pk.KeyID == 0 {
		return preKeyInput{}, errors.New("key_id must be greater than zero")
	}
	pubKey, err := decodeCanonicalBase64(pk.PublicKey)
	if err != nil {
		return preKeyInput{}, errors.New("invalid base64 public_key")
	}
	if len(pubKey) != 32 {
		return preKeyInput{}, errors.New("public_key must be 32 bytes")
	}

	var sig []byte
	if keyType == 0 && pk.Signature == "" {
		return preKeyInput{}, errors.New("signature required for signed prekey")
	}
	if keyType == 1 && pk.Signature != "" {
		return preKeyInput{}, errors.New("signature is not allowed for one-time prekey")
	}
	if pk.Signature != "" {
		sig, err = decodeCanonicalBase64(pk.Signature)
		if err != nil {
			return preKeyInput{}, errors.New("invalid base64 signature")
		}
		if len(sig) != ed25519.SignatureSize {
			return preKeyInput{}, errors.New("signature must be 64 bytes")
		}
	}

	return preKeyInput{keyType: keyType, protocolKeyID: *pk.KeyID, publicKey: pubKey, signature: sig}, nil
}

func decodeCanonicalBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("base64 value is not canonical padded encoding")
	}
	return decoded, nil
}

func validateSignedPreKey(owner *db.User, prekey *preKeyInput) error {
	if owner == nil || len(owner.SigningKey) != ed25519.PublicKeySize {
		return errors.New("registered signing key is invalid")
	}
	if prekey == nil || prekey.keyType != 0 || len(prekey.signature) != ed25519.SignatureSize {
		return errors.New("signed prekey signature is invalid")
	}
	message, err := SignedPreKeySigningMessage(prekey.publicKey)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(owner.SigningKey), message, prekey.signature) {
		return errors.New("signed prekey signature verification failed")
	}
	return nil
}

// SignedPreKeySigningMessage returns the exact bytes an identity signs when
// publishing an X3DH signed prekey:
//
//	"veil-x3dh-spk-v1\0" || x25519_signed_prekey_public_32
func SignedPreKeySigningMessage(publicKey []byte) ([]byte, error) {
	if len(publicKey) != 32 {
		return nil, errors.New("signed prekey public key must be 32 bytes")
	}
	message := make([]byte, 0, len(x3dhSignedPreKeyDomain)+32)
	message = append(message, x3dhSignedPreKeyDomain...)
	message = append(message, publicKey...)
	return message, nil
}

func deviceBelongsToUser(device *db.Device, authenticatedUserID string) bool {
	return device != nil && authenticatedUserID != "" && device.UserID == authenticatedUserID
}

func setPreKeyNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

func preKeyNoStore(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setPreKeyNoStore(w)
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func errorResp(msg string) map[string]string {
	return map[string]string{"error": msg}
}

// SearchUser looks up a user by username query parameter.
func (h *Handler) SearchUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("username query parameter required"))
		return
	}

	user, err := h.svc.db.FindUserByUsername(r.Context(), username)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResp("user not found"))
		return
	}
	if len(user.IdentityKey) != 32 || len(user.SigningKey) != ed25519.PublicKeySize {
		log.Printf("search user_ref=%s has invalid public key material", logsafe.Ref("user", user.ID))
		writeJSON(w, http.StatusConflict, errorResp("user cryptographic identity is invalid"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":      user.ID,
		"username":     user.Username,
		"identity_key": hex.EncodeToString(user.IdentityKey),
		"signing_key":  hex.EncodeToString(user.SigningKey),
	})
}
