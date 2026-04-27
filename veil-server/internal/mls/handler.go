package mls

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/AegisSec/veil-server/internal/authmw"
	"github.com/jackc/pgx/v5"
)

// Handler exposes the MLS REST surface. All endpoints require a signed
// request via the shared authmw middleware.
type Handler struct {
	store *Store
	mw    *authmw.Middleware
	rl    *authmw.RateLimit
	hub   Fanout // optional WS fan-out, may be nil
}

// Fanout abstracts the gateway hub's ability to push events to other
// online sessions. Implemented by the gateway; mls package keeps it as
// an interface to avoid an import cycle.
type Fanout interface {
	NotifyMLSWelcome(recipientUserID string, conversationID string, welcomeID string)
	NotifyMLSCommit(conversationID string, epoch uint64, senderUserID string)
}

// NewHandler wires the handler. mw and rl may be nil for tests.
func NewHandler(store *Store, mw *authmw.Middleware, rl *authmw.RateLimit, hub Fanout) *Handler {
	return &Handler{store: store, mw: mw, rl: rl, hub: hub}
}

// RegisterRoutes mounts the MLS routes on a mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	signed := func(f http.HandlerFunc) http.HandlerFunc {
		if h.mw != nil {
			f = h.mw.RequireSigned(f)
		}
		if h.rl != nil {
			f = h.rl.Wrap(f)
		}
		return f
	}
	mux.HandleFunc("POST /v1/mls/keypackages", signed(h.uploadKeyPackages))
	mux.HandleFunc("GET /v1/mls/keypackages/{userID}/{deviceID}/count", signed(h.countKeyPackages))
	mux.HandleFunc("GET /v1/mls/keypackages/{userID}/{deviceID}", signed(h.consumeKeyPackage))
	mux.HandleFunc("POST /v1/mls/welcomes", signed(h.uploadWelcome))
	mux.HandleFunc("GET /v1/mls/welcomes/{deviceID}", signed(h.listWelcomes))
	mux.HandleFunc("DELETE /v1/mls/welcomes/{id}", signed(h.deleteWelcome))
	mux.HandleFunc("POST /v1/mls/commits", signed(h.uploadCommit))
	mux.HandleFunc("GET /v1/mls/commits/{conversationID}", signed(h.listCommits))
}

// ─── KeyPackages ───────────────────────────────────────────────────

type uploadKPReq struct {
	DeviceID    string   `json:"device_id"`    // hex (16 bytes)
	KeyPackages []string `json:"key_packages"` // base64 TLS-encoded
}

func (h *Handler) uploadKeyPackages(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-Veil-User")
	if userID == "" {
		writeJSONErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	var req uploadKPReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	deviceID, err := hex.DecodeString(req.DeviceID)
	if err != nil || len(deviceID) != 16 {
		writeJSONErr(w, http.StatusBadRequest, "device_id must be 16 bytes hex")
		return
	}
	if len(req.KeyPackages) == 0 {
		writeJSONErr(w, http.StatusBadRequest, "key_packages required")
		return
	}
	if len(req.KeyPackages) > 100 {
		writeJSONErr(w, http.StatusBadRequest, "too many key_packages (max 100)")
		return
	}
	blobs := make([][]byte, 0, len(req.KeyPackages))
	for _, b64 := range req.KeyPackages {
		blob, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			writeJSONErr(w, http.StatusBadRequest, "invalid base64 in key_packages")
			return
		}
		if len(blob) == 0 || len(blob) > 16*1024 {
			writeJSONErr(w, http.StatusBadRequest, "key_package out of range")
			return
		}
		blobs = append(blobs, blob)
	}
	if err := h.store.InsertKeyPackages(r.Context(), userID, deviceID, blobs); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "insert failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"count": len(blobs)})
}

func (h *Handler) consumeKeyPackage(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")
	deviceHex := r.PathValue("deviceID")
	deviceID, err := hex.DecodeString(deviceHex)
	if err != nil || len(deviceID) != 16 {
		writeJSONErr(w, http.StatusBadRequest, "device_id must be 16 bytes hex")
		return
	}
	blob, err := h.store.ConsumeKeyPackage(r.Context(), userID, deviceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSONErr(w, http.StatusNotFound, "no key_packages available")
			return
		}
		writeJSONErr(w, http.StatusInternalServerError, "consume failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key_package": base64.StdEncoding.EncodeToString(blob),
	})
}

func (h *Handler) countKeyPackages(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")
	deviceHex := r.PathValue("deviceID")
	deviceID, err := hex.DecodeString(deviceHex)
	if err != nil || len(deviceID) != 16 {
		writeJSONErr(w, http.StatusBadRequest, "device_id must be 16 bytes hex")
		return
	}
	n, err := h.store.CountKeyPackages(r.Context(), userID, deviceID)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "count failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": n})
}

// ─── Welcomes ──────────────────────────────────────────────────────

type uploadWelcomeReq struct {
	RecipientUserID   string `json:"recipient_user_id"`
	RecipientDeviceID string `json:"recipient_device_id"` // hex
	ConversationID    string `json:"conversation_id"`
	Blob              string `json:"blob"` // base64
}

func (h *Handler) uploadWelcome(w http.ResponseWriter, r *http.Request) {
	senderUserID := r.Header.Get("X-Veil-User")
	if senderUserID == "" {
		writeJSONErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	var req uploadWelcomeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.RecipientUserID == "" || req.ConversationID == "" {
		writeJSONErr(w, http.StatusBadRequest, "recipient_user_id and conversation_id required")
		return
	}
	deviceID, err := hex.DecodeString(req.RecipientDeviceID)
	if err != nil || len(deviceID) != 16 {
		writeJSONErr(w, http.StatusBadRequest, "recipient_device_id must be 16 bytes hex")
		return
	}
	blob, err := base64.StdEncoding.DecodeString(req.Blob)
	if err != nil || len(blob) == 0 || len(blob) > 256*1024 {
		writeJSONErr(w, http.StatusBadRequest, "invalid blob")
		return
	}
	if err := h.store.InsertWelcome(r.Context(), req.RecipientUserID, deviceID, req.ConversationID, blob); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "insert failed")
		return
	}
	if h.hub != nil {
		h.hub.NotifyMLSWelcome(req.RecipientUserID, req.ConversationID, "")
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "queued"})
}

func (h *Handler) listWelcomes(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-Veil-User")
	if userID == "" {
		writeJSONErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	deviceHex := r.PathValue("deviceID")
	deviceID, err := hex.DecodeString(deviceHex)
	if err != nil || len(deviceID) != 16 {
		writeJSONErr(w, http.StatusBadRequest, "device_id must be 16 bytes hex")
		return
	}
	rows, err := h.store.ListWelcomes(r.Context(), userID, deviceID)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]map[string]string, 0, len(rows))
	for _, ww := range rows {
		out = append(out, map[string]string{
			"id":              ww.ID,
			"conversation_id": ww.ConversationID,
			"blob":            base64.StdEncoding.EncodeToString(ww.Blob),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"welcomes": out})
}

func (h *Handler) deleteWelcome(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-Veil-User")
	if userID == "" {
		writeJSONErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	id := r.PathValue("id")
	if err := h.store.DeleteWelcome(r.Context(), id, userID); err != nil {
		writeJSONErr(w, httpStatusForErr(err), "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Commits ───────────────────────────────────────────────────────

type uploadCommitReq struct {
	ConversationID string `json:"conversation_id"`
	Epoch          uint64 `json:"epoch"`
	Blob           string `json:"blob"`
}

func (h *Handler) uploadCommit(w http.ResponseWriter, r *http.Request) {
	senderUserID := r.Header.Get("X-Veil-User")
	if senderUserID == "" {
		writeJSONErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	var req uploadCommitReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.ConversationID == "" {
		writeJSONErr(w, http.StatusBadRequest, "conversation_id required")
		return
	}
	blob, err := base64.StdEncoding.DecodeString(req.Blob)
	if err != nil || len(blob) == 0 || len(blob) > 256*1024 {
		writeJSONErr(w, http.StatusBadRequest, "invalid blob")
		return
	}
	if err := h.store.InsertCommit(r.Context(), req.ConversationID, req.Epoch, senderUserID, blob); err != nil {
		writeJSONErr(w, httpStatusForErr(err), err.Error())
		return
	}
	if h.hub != nil {
		h.hub.NotifyMLSCommit(req.ConversationID, req.Epoch, senderUserID)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"epoch": req.Epoch})
}

func (h *Handler) listCommits(w http.ResponseWriter, r *http.Request) {
	conversationID := r.PathValue("conversationID")
	after, err := parseAfterEpoch(r)
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid after_epoch")
		return
	}
	rows, err := h.store.ListCommits(r.Context(), conversationID, after, 0)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		out = append(out, map[string]any{
			"epoch":          c.Epoch,
			"sender_user_id": c.SenderUserID,
			"blob":           base64.StdEncoding.EncodeToString(c.Blob),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"commits": out})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
