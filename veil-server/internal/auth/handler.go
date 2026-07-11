package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/AegisSec/veil-server/internal/authmw"
	"github.com/AegisSec/veil-server/internal/db"
)

// Handler provides REST endpoints for the auth service.
// Prekey management, device registry, user lookup.
// (Challenge-response stays in the gateway — it's WS-bound.)
type Handler struct {
	svc *Service
	mw  *authmw.Middleware
	rl  *authmw.RateLimit
}

// NewHandler builds the auth REST handler. mw and rl may be nil to disable
// signature checks / rate limiting (used in tests and the all-in-one binary).
func NewHandler(svc *Service, mw *authmw.Middleware, rl *authmw.RateLimit) *Handler {
	return &Handler{svc: svc, mw: mw, rl: rl}
}

// SigningKeyLookup returns an authmw.UserKeyLookup backed by the service's
// database, for use when constructing the shared signing middleware.
func (s *Service) SigningKeyLookup() authmw.UserKeyLookup {
	return authmw.LookupFunc(func(ctx context.Context, userID string) (ed25519.PublicKey, error) {
		u, err := s.db.FindUserByID(ctx, userID)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(u.SigningKey), nil
	})
}

// RegisterRoutes registers auth REST endpoints on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	signed := func(f http.HandlerFunc) http.HandlerFunc {
		if h.rl != nil {
			f = h.rl.Wrap(f)
		}
		if h.mw != nil {
			// Signature verification must be the outermost middleware so the
			// limiter sees only an authenticated principal context.
			f = h.mw.RequireSigned(f)
		}
		return f
	}

	mux.HandleFunc("POST /v1/prekeys", signed(h.UploadPreKeys))
	mux.HandleFunc("GET /v1/prekeys/{identityKey}", signed(h.GetPreKeyBundle))
	mux.HandleFunc("GET /v1/prekeys/{identityKey}/count", signed(h.GetOPKCount))
	mux.HandleFunc("GET /v1/devices/{userID}", signed(h.ListDevices))
	mux.HandleFunc("GET /v1/device-bindings/{deviceKey}", signed(h.GetDeviceBinding))
	mux.HandleFunc("PUT /v1/device-bindings/{deviceKey}", signed(h.PutDeviceBinding))
	mux.HandleFunc("GET /v1/users/search", signed(h.SearchUser))
	mux.HandleFunc("GET /v1/users/{identityKey}", signed(h.LookupUser))
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

const x3dhSignedPreKeyDomain = "veil-x3dh-spk-v1\x00"

var ErrPreKeyAccessDenied = errors.New("prekey access requires a shared conversation")

func (h *Handler) UploadPreKeys(w http.ResponseWriter, r *http.Request) {
	requesterID := r.Header.Get("X-User-ID")
	if requesterID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}

	var req UploadPreKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid JSON"))
		return
	}

	if req.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("device_id required"))
		return
	}
	if len(req.OneTimeKeys) > 1000 {
		writeJSON(w, http.StatusBadRequest, errorResp("too many one_time_prekeys (maximum 1000)"))
		return
	}

	// Verify device exists
	deviceKey, err := hex.DecodeString(req.DeviceID)
	if err != nil || len(deviceKey) != 16 {
		writeJSON(w, http.StatusBadRequest, errorResp("device_id must be 16 bytes hex"))
		return
	}

	device, err := h.svc.db.FindDevice(r.Context(), deviceKey)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResp("device not found"))
		return
	}
	if !deviceBelongsToUser(device, requesterID) {
		writeJSON(w, http.StatusForbidden, errorResp("device does not belong to authenticated user"))
		return
	}

	var prekeys []preKeyInput
	var signedPreKey *preKeyInput
	if req.SignedPreKey != nil {
		pk, err := decodePreKey(req.SignedPreKey, 0)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResp("invalid signed_prekey: "+err.Error()))
			return
		}
		prekeys = append(prekeys, pk)
		signedPreKey = &prekeys[len(prekeys)-1]
	}
	seenOPKIDs := make(map[uint32]struct{}, len(req.OneTimeKeys))
	for _, otk := range req.OneTimeKeys {
		pk, err := decodePreKey(&otk, 1)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResp("invalid one_time_prekey: "+err.Error()))
			return
		}
		if _, duplicate := seenOPKIDs[pk.protocolKeyID]; duplicate {
			writeJSON(w, http.StatusBadRequest, errorResp("duplicate one_time_prekey key_id"))
			return
		}
		seenOPKIDs[pk.protocolKeyID] = struct{}{}
		prekeys = append(prekeys, pk)
	}

	if len(prekeys) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResp("no prekeys provided"))
		return
	}

	if signedPreKey != nil {
		owner, err := h.svc.db.FindUserByID(r.Context(), requesterID)
		if err != nil {
			log.Printf("prekey owner lookup error: %v", err)
			writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user not found"))
			return
		}
		if err := validateSignedPreKey(owner, signedPreKey); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResp(err.Error()))
			return
		}
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

	if err := h.svc.StorePreKeys(r.Context(), device.ID, dbKeys); err != nil {
		log.Printf("store prekeys error: %v", err)
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to store prekeys"))
		return
	}

	remaining, _ := h.svc.db.CountUnusedOPKs(r.Context(), device.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"stored":        len(prekeys),
		"opk_remaining": remaining,
	})
}

// --- Prekey Bundle Fetch ---

func (h *Handler) GetPreKeyBundle(w http.ResponseWriter, r *http.Request) {
	identityKeyHex := r.PathValue("identityKey")
	identityKey, err := hex.DecodeString(identityKeyHex)
	if err != nil || len(identityKey) != 32 {
		writeJSON(w, http.StatusBadRequest, errorResp("identity_key must be 32 bytes hex"))
		return
	}

	requesterID := r.Header.Get("X-User-ID")
	if requesterID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}

	bundle, err := h.svc.GetPreKeyBundle(r.Context(), requesterID, identityKey)
	if err != nil {
		if errors.Is(err, ErrPreKeyAccessDenied) {
			writeJSON(w, http.StatusForbidden, errorResp(err.Error()))
			return
		}
		writeJSON(w, http.StatusNotFound, errorResp(err.Error()))
		return
	}

	writeJSON(w, http.StatusOK, bundle)
}

// --- OPK Count ---

func (h *Handler) GetOPKCount(w http.ResponseWriter, r *http.Request) {
	requesterID := r.Header.Get("X-User-ID")
	if requesterID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}

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
	if user.ID != requesterID {
		writeJSON(w, http.StatusForbidden, errorResp("one-time prekey counts are private to their owner"))
		return
	}

	devices, err := h.svc.db.GetDevicesByUser(r.Context(), user.ID)
	if err != nil || len(devices) == 0 {
		writeJSON(w, http.StatusNotFound, errorResp("no devices"))
		return
	}

	type deviceCount struct {
		DeviceID  string `json:"device_id"`
		Remaining int    `json:"remaining"`
	}
	var counts []deviceCount
	for _, d := range devices {
		n, _ := h.svc.db.CountUnusedOPKs(r.Context(), d.ID)
		counts = append(counts, deviceCount{
			DeviceID:  hex.EncodeToString(d.DeviceKey),
			Remaining: n,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"devices": counts})
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
func (s *Service) StorePreKeys(ctx context.Context, deviceID string, keys []dbPreKeyAdapter) error {
	var dbKeys []db.PreKey
	for _, k := range keys {
		dbKeys = append(dbKeys, db.PreKey{
			KeyType:       k.KeyType,
			ProtocolKeyID: k.ProtocolKeyID,
			PublicKey:     k.PublicKey,
			Signature:     k.Signature,
		})
	}
	return s.db.StorePreKeys(ctx, deviceID, dbKeys)
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

	spk, err := s.db.GetSignedPreKey(ctx, device.ID)
	if err != nil {
		return nil, errors.New("no signed prekey available")
	}

	bundle := map[string]any{
		"identity_key":            base64.StdEncoding.EncodeToString(user.IdentityKey),
		"signing_key":             base64.StdEncoding.EncodeToString(user.SigningKey),
		"signed_prekey":           base64.StdEncoding.EncodeToString(spk.PublicKey),
		"signed_prekey_signature": base64.StdEncoding.EncodeToString(spk.Signature),
		"signed_prekey_id":        spk.ProtocolKeyID,
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

func decodePreKey(pk *PreKeyJSON, keyType int16) (preKeyInput, error) {
	if pk.KeyID == nil {
		return preKeyInput{}, errors.New("key_id required")
	}
	pubKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pk.PublicKey))
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
		sig, err = base64.StdEncoding.DecodeString(strings.TrimSpace(pk.Signature))
		if err != nil {
			return preKeyInput{}, errors.New("invalid base64 signature")
		}
		if len(sig) != ed25519.SignatureSize {
			return preKeyInput{}, errors.New("signature must be 64 bytes")
		}
	}

	return preKeyInput{keyType: keyType, protocolKeyID: *pk.KeyID, publicKey: pubKey, signature: sig}, nil
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

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":      user.ID,
		"username":     user.Username,
		"identity_key": hex.EncodeToString(user.IdentityKey),
	})
}
