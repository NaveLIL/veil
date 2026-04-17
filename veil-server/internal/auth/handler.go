package auth

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/AegisSec/veil-server/internal/db"
)

// Handler provides REST endpoints for the auth service.
// Prekey management, device registry, user lookup.
// (Challenge-response stays in the gateway — it's WS-bound.)
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// RegisterRoutes registers auth REST endpoints on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/prekeys", h.UploadPreKeys)
	mux.HandleFunc("GET /v1/prekeys/{identityKey}", h.GetPreKeyBundle)
	mux.HandleFunc("GET /v1/prekeys/{identityKey}/count", h.GetOPKCount)
	mux.HandleFunc("GET /v1/devices/{userID}", h.ListDevices)
	mux.HandleFunc("GET /v1/users/search", h.SearchUser)
	mux.HandleFunc("GET /v1/users/{identityKey}", h.LookupUser)
}

// --- Prekey Upload ---

// UploadPreKeysRequest is the JSON body for prekey upload.
type UploadPreKeysRequest struct {
	DeviceID     string       `json:"device_id"`        // hex-encoded device ID
	SignedPreKey *PreKeyJSON  `json:"signed_prekey"`    // Exactly one signed prekey
	OneTimeKeys  []PreKeyJSON `json:"one_time_prekeys"` // Batch of OPKs
}

type PreKeyJSON struct {
	PublicKey string `json:"public_key"` // base64
	Signature string `json:"signature"`  // base64, only for signed prekeys
}

func (h *Handler) UploadPreKeys(w http.ResponseWriter, r *http.Request) {
	var req UploadPreKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid JSON"))
		return
	}

	if req.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("device_id required"))
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

	var prekeys []preKeyInput
	if req.SignedPreKey != nil {
		pk, err := decodePreKey(req.SignedPreKey, 0)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResp("invalid signed_prekey: "+err.Error()))
			return
		}
		prekeys = append(prekeys, pk)
	}
	for _, otk := range req.OneTimeKeys {
		pk, err := decodePreKey(&otk, 1)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResp("invalid one_time_prekey: "+err.Error()))
			return
		}
		prekeys = append(prekeys, pk)
	}

	if len(prekeys) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResp("no prekeys provided"))
		return
	}

	// Convert to db.PreKey slice
	var dbKeys []dbPreKeyAdapter
	for _, pk := range prekeys {
		dbKeys = append(dbKeys, dbPreKeyAdapter{
			KeyType:   pk.keyType,
			PublicKey: pk.publicKey,
			Signature: pk.signature,
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

	bundle, err := h.svc.GetPreKeyBundle(r.Context(), identityKey)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResp(err.Error()))
		return
	}

	writeJSON(w, http.StatusOK, bundle)
}

// --- OPK Count ---

func (h *Handler) GetOPKCount(w http.ResponseWriter, r *http.Request) {
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
	userID := r.PathValue("userID")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("user_id required"))
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
			KeyType:   k.KeyType,
			PublicKey: k.PublicKey,
			Signature: k.Signature,
		})
	}
	return s.db.StorePreKeys(ctx, deviceID, dbKeys)
}

// GetPreKeyBundle fetches a prekey bundle for X3DH session establishment.
func (s *Service) GetPreKeyBundle(ctx context.Context, targetIdentityKey []byte) (map[string]any, error) {
	user, err := s.db.FindUserByIdentityKey(ctx, targetIdentityKey)
	if err != nil {
		return nil, errors.New("user not found")
	}

	devices, err := s.db.GetDevicesByUser(ctx, user.ID)
	if err != nil || len(devices) == 0 {
		return nil, errors.New("no devices registered")
	}
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
		"signed_prekey_id":        spk.ID,
	}

	opk, err := s.db.ClaimOneTimePreKey(ctx, device.ID)
	if err == nil && opk != nil {
		bundle["one_time_prekey"] = base64.StdEncoding.EncodeToString(opk.PublicKey)
		bundle["one_time_prekey_id"] = opk.ID
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
	keyType   int16
	publicKey []byte
	signature []byte
}

type dbPreKeyAdapter struct {
	KeyType   int16
	PublicKey []byte
	Signature []byte
}

func decodePreKey(pk *PreKeyJSON, keyType int16) (preKeyInput, error) {
	pubKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pk.PublicKey))
	if err != nil {
		return preKeyInput{}, errors.New("invalid base64 public_key")
	}
	if len(pubKey) != 32 {
		return preKeyInput{}, errors.New("public_key must be 32 bytes")
	}

	var sig []byte
	if pk.Signature != "" {
		sig, err = base64.StdEncoding.DecodeString(strings.TrimSpace(pk.Signature))
		if err != nil {
			return preKeyInput{}, errors.New("invalid base64 signature")
		}
	}

	return preKeyInput{keyType: keyType, publicKey: pubKey, signature: sig}, nil
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
