package auth

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/AegisSec/veil-server/internal/db"
)

type deviceBindingRequest struct {
	DeviceIdentityKey string                 `json:"device_identity_key"`
	DeviceSigningKey  string                 `json:"device_signing_key"`
	Version           string                 `json:"version"`
	Capabilities      string                 `json:"capabilities"`
	Status            db.DeviceBindingStatus `json:"status"`
	AccountSignature  string                 `json:"account_signature"`
}

type deviceBindingResponse struct {
	DeviceID          string                 `json:"device_id"`
	DeviceIdentityKey string                 `json:"device_identity_key"`
	DeviceSigningKey  string                 `json:"device_signing_key"`
	Version           string                 `json:"version"`
	Capabilities      string                 `json:"capabilities"`
	Status            db.DeviceBindingStatus `json:"status"`
	AccountSignature  string                 `json:"account_signature"`
}

func decodeBindingPublicKey(value, field string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New(field + " must be base64-encoded 32 bytes")
	}
	return decoded, nil
}

func decodeBindingUint63(value, field string, allowZero bool) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 63)
	if err != nil || strconv.FormatUint(parsed, 10) != value || (!allowZero && parsed == 0) {
		return 0, errors.New(field + " must be a canonical decimal integer in the supported range")
	}
	return parsed, nil
}

func decodeDeviceBindingRequest(deviceKey []byte, request deviceBindingRequest) (*DeviceBindingInput, error) {
	identityKey, err := decodeBindingPublicKey(request.DeviceIdentityKey, "device_identity_key")
	if err != nil {
		return nil, err
	}
	signingKey, err := decodeBindingPublicKey(request.DeviceSigningKey, "device_signing_key")
	if err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(request.AccountSignature)
	if err != nil || len(signature) != 64 {
		return nil, errors.New("account_signature must be base64-encoded 64 bytes")
	}
	version, err := decodeBindingUint63(request.Version, "version", false)
	if err != nil {
		return nil, err
	}
	capabilities, err := decodeBindingUint63(request.Capabilities, "capabilities", true)
	if err != nil {
		return nil, err
	}
	binding := &DeviceBindingInput{
		DeviceKey:         append([]byte(nil), deviceKey...),
		DeviceIdentityKey: identityKey,
		DeviceSigningKey:  signingKey,
		Version:           version,
		Capabilities:      capabilities,
		Status:            request.Status,
		AccountSignature:  signature,
	}
	if err := validateDeviceBindingInput(binding, true); err != nil {
		return nil, err
	}
	return binding, nil
}

func bindingResponse(binding *db.DeviceBinding) deviceBindingResponse {
	return deviceBindingResponse{
		DeviceID:          hex.EncodeToString(binding.DeviceKey),
		DeviceIdentityKey: base64.StdEncoding.EncodeToString(binding.DeviceIdentityKey),
		DeviceSigningKey:  base64.StdEncoding.EncodeToString(binding.DeviceSigningKey),
		Version:           strconv.FormatUint(binding.Version, 10),
		Capabilities:      strconv.FormatUint(binding.Capabilities, 10),
		Status:            binding.Status,
		AccountSignature:  base64.StdEncoding.EncodeToString(binding.AccountSignature),
	}
}

func (h *Handler) GetDeviceBinding(w http.ResponseWriter, r *http.Request) {
	requesterID := r.Header.Get("X-User-ID")
	deviceKey, err := hex.DecodeString(r.PathValue("deviceKey"))
	if err != nil || len(deviceKey) != 16 {
		writeJSON(w, http.StatusBadRequest, errorResp("device key must be 16 bytes hex"))
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
	binding, err := h.svc.db.GetLatestDeviceBinding(r.Context(), device.ID)
	if errors.Is(err, db.ErrDeviceBindingUnavailable) {
		writeJSON(w, http.StatusOK, map[string]any{
			"device_id": hex.EncodeToString(device.DeviceKey),
			"status":    db.DeviceLegacyUnbound,
			"eligible":  false,
			"reason":    "legacy_unbound",
		})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to load device binding"))
		return
	}
	writeJSON(w, http.StatusOK, bindingResponse(binding))
}

func (h *Handler) PutDeviceBinding(w http.ResponseWriter, r *http.Request) {
	requesterID := r.Header.Get("X-User-ID")
	deviceKey, err := hex.DecodeString(r.PathValue("deviceKey"))
	if err != nil || len(deviceKey) != 16 {
		writeJSON(w, http.StatusBadRequest, errorResp("device key must be 16 bytes hex"))
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

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()
	var request deviceBindingRequest
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid device binding JSON"))
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, errorResp("device binding body must contain one JSON value"))
		return
	}
	bindingInput, err := decodeDeviceBindingRequest(deviceKey, request)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp(err.Error()))
		return
	}
	user, err := h.svc.db.FindUserByID(r.Context(), requesterID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user not found"))
		return
	}
	commitment, err := verifyAccountSignedDeviceBinding(user, bindingInput)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp(err.Error()))
		return
	}
	stored, err := h.svc.db.StoreDeviceBinding(r.Context(), &db.DeviceBinding{
		DeviceID:          device.ID,
		UserID:            requesterID,
		DeviceKey:         append([]byte(nil), deviceKey...),
		DeviceIdentityKey: append([]byte(nil), bindingInput.DeviceIdentityKey...),
		DeviceSigningKey:  append([]byte(nil), bindingInput.DeviceSigningKey...),
		Version:           bindingInput.Version,
		Capabilities:      bindingInput.Capabilities,
		Status:            bindingInput.Status,
		AccountSignature:  append([]byte(nil), bindingInput.AccountSignature...),
		Commitment:        commitment[:],
	})
	if err != nil {
		status := http.StatusConflict
		if !errors.Is(err, db.ErrDeviceBindingStale) &&
			!errors.Is(err, db.ErrDeviceBindingVersionGap) &&
			!errors.Is(err, db.ErrDeviceKeyReplacement) &&
			!errors.Is(err, db.ErrDeviceBindingConflict) &&
			!errors.Is(err, db.ErrDeviceBindingRevoked) {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, errorResp(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, bindingResponse(stored))
}
