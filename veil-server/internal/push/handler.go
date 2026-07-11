package push

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/AegisSec/veil-server/internal/authmw"
	"github.com/AegisSec/veil-server/internal/db"
	"github.com/AegisSec/veil-server/internal/publicerr"
)

// Handler exposes the REST surface for managing push subscriptions.
// All routes require a signed request (the existing X-Veil triplet).
type Handler struct {
	db     *db.DB
	mw     *authmw.Middleware
	rl     *authmw.RateLimit
	policy *EndpointPolicy
}

// NewHandler builds the handler. mw and rl may be nil to disable
// signature checks / rate limiting (used in tests).
func NewHandler(database *db.DB, mw *authmw.Middleware, rl *authmw.RateLimit) *Handler {
	return NewHandlerWithEndpointPolicy(database, mw, rl, defaultEndpointPolicy())
}

func NewHandlerWithEndpointPolicy(database *db.DB, mw *authmw.Middleware, rl *authmw.RateLimit, policy *EndpointPolicy) *Handler {
	if policy == nil {
		policy = defaultEndpointPolicy()
	}
	return &Handler{db: database, mw: mw, rl: rl, policy: policy}
}

// RegisterRoutes mounts the handler onto a mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	signed := func(f http.HandlerFunc) http.HandlerFunc {
		if h.rl != nil {
			f = h.rl.Wrap(f)
		}
		if h.mw != nil {
			f = h.mw.RequireSigned(f)
		}
		return f
	}
	mux.HandleFunc("POST /v1/push/subscriptions", signed(h.create))
	mux.HandleFunc("GET /v1/push/subscriptions", signed(h.list))
	mux.HandleFunc("DELETE /v1/push/subscriptions/{id}", signed(h.delete))
}

type createReq struct {
	Endpoint    string `json:"endpoint"`
	DeviceLabel string `json:"device_label,omitempty"`
	Kind        string `json:"kind,omitempty"`
}

type subscriptionJSON struct {
	ID          int64  `json:"id"`
	Endpoint    string `json:"endpoint"`
	DeviceLabel string `json:"device_label,omitempty"`
	Kind        string `json:"kind"`
	CreatedAt   string `json:"created_at"`
	LastUsed    string `json:"last_used,omitempty"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-Veil-User")
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if err := validateSubscriptionRequest(&req); err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_push_subscription", "invalid push subscription", err,
		))
		return
	}
	endpoint, err := h.policy.ValidateEndpoint(r.Context(), req.Endpoint)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or unsafe endpoint"})
		return
	}
	req.Endpoint = endpoint.String()
	id, err := h.db.CreatePushSubscription(r.Context(), userID, req.Endpoint, req.DeviceLabel, req.Kind)
	if err != nil {
		if errors.Is(err, db.ErrPushSubscriptionLimit) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "push subscription limit reached"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create failed"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func validateSubscriptionRequest(req *createReq) error {
	if req == nil || req.Endpoint == "" {
		return errors.New("endpoint required")
	}
	if len(req.Endpoint) > 2048 {
		return errors.New("endpoint too long")
	}
	if !utf8.ValidString(req.DeviceLabel) || len(req.DeviceLabel) > 128 {
		return errors.New("device_label must be valid UTF-8 up to 128 bytes")
	}
	if req.Kind == "" {
		req.Kind = "unifiedpush"
	}
	if req.Kind != "unifiedpush" {
		return errors.New("unsupported push kind")
	}
	return nil
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-Veil-User")
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	rows, err := h.db.ListPushSubscriptions(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list failed"})
		return
	}
	out := make([]subscriptionJSON, 0, len(rows))
	for _, r := range rows {
		js := subscriptionJSON{
			ID:          r.ID,
			Endpoint:    r.EndpointURL,
			DeviceLabel: r.DeviceLabel,
			Kind:        r.PushKind,
			CreatedAt:   r.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		}
		if r.LastUsed != nil {
			js.LastUsed = r.LastUsed.UTC().Format("2006-01-02T15:04:05Z")
		}
		out = append(out, js)
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscriptions": out})
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-Veil-User")
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	ok, err := h.db.DeletePushSubscription(r.Context(), userID, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
