package push

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/NaveLIL/veil/veil-server/internal/authmw"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
	webpush "github.com/ergochat/webpush-go/v2"
)

// Handler exposes the REST surface for managing push subscriptions.
// All routes require a signed request (the existing X-Veil triplet).
type Handler struct {
	db                 *db.DB
	mw                 *authmw.Middleware
	restAuthDispatcher *authmw.RESTAuthVersionDispatcher
	rl                 *authmw.RateLimit
	policy             *EndpointPolicy
	dispatcher         *Dispatcher
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

// SetRESTAuthVersionDispatcher activates explicit REST authentication version
// selection for every signed push route.
func (h *Handler) SetRESTAuthVersionDispatcher(dispatcher *authmw.RESTAuthVersionDispatcher) {
	h.restAuthDispatcher = dispatcher
}

// RegisterRoutes mounts the handler onto a mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	signed := func(policy authmw.RESTAuthV2HTTPPolicy, f http.HandlerFunc) http.HandlerFunc {
		if h.rl != nil {
			f = h.rl.Wrap(f)
		}
		if h.restAuthDispatcher != nil {
			f = h.restAuthDispatcher.RequireSigned(policy, f)
		} else if h.mw != nil {
			f = h.mw.RequireSigned(f)
		}
		return f
	}
	jsonPolicy, err := authmw.NewRESTAuthV2JSONHTTPPolicy(8 << 10)
	if err != nil {
		panic("invalid push REST v2 JSON policy")
	}
	bodylessPolicy := authmw.RESTAuthV2BodylessHTTPPolicy()
	mux.HandleFunc("POST /v1/push/subscriptions", signed(jsonPolicy, h.create))
	mux.HandleFunc("GET /v1/push/subscriptions", signed(bodylessPolicy, h.list))
	mux.HandleFunc("GET /v1/push/vapid-key", signed(bodylessPolicy, h.vapidKey))
	mux.HandleFunc("POST /v1/push/subscriptions/{id}/confirm", signed(jsonPolicy, h.confirm))
	mux.HandleFunc("DELETE /v1/push/subscriptions/{id}", signed(bodylessPolicy, h.delete))
	mux.HandleFunc("PATCH /v1/push/subscriptions/{id}/policy", signed(jsonPolicy, h.updatePolicy))
}

type createReq struct {
	Endpoint    string `json:"endpoint"`
	DeviceLabel string `json:"device_label,omitempty"`
	Kind        string `json:"kind,omitempty"`
	PublicKey   string `json:"p256dh"`
	AuthSecret  string `json:"auth"`
}

type subscriptionJSON struct {
	ID             int64  `json:"id"`
	EndpointOrigin string `json:"endpoint_origin"`
	DeviceLabel    string `json:"device_label,omitempty"`
	Kind           string `json:"kind"`
	CreatedAt      string `json:"created_at"`
	LastUsed       string `json:"last_used,omitempty"`
	Enabled        bool   `json:"enabled"`
	MutedUntil     string `json:"muted_until,omitempty"`
	Validated      bool   `json:"validated"`
}

func (h *Handler) SetDispatcher(dispatcher *Dispatcher) { h.dispatcher = dispatcher }

func (h *Handler) vapidKey(w http.ResponseWriter, _ *http.Request) {
	if h.dispatcher == nil || !h.dispatcher.Enabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "push delivery is not configured"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"public_key": h.dispatcher.VAPIDPublicKey()})
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	userID, ok := authmw.VerifiedUserID(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	var req createReq
	if err := decodePushJSON(w, r, &req); err != nil {
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
	if h.dispatcher == nil || !h.dispatcher.Enabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "push delivery is not configured"})
		return
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create failed"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256(tokenBytes)
	id, err := h.db.CreatePushSubscription(r.Context(), userID, db.NewPushSubscription{
		EndpointURL: req.Endpoint, PublicKey: req.PublicKey, AuthSecret: req.AuthSecret,
		DeviceLabel: req.DeviceLabel, PushKind: req.Kind,
		ValidationTokenHash: tokenHash[:], ValidationExpiresAt: time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		if errors.Is(err, db.ErrPushSubscriptionLimit) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "push subscription limit reached"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create failed"})
		return
	}
	challengeSub := Subscription{ID: id, UserID: userID, EndpointURL: req.Endpoint,
		PublicKey: req.PublicKey, AuthSecret: req.AuthSecret, PushKind: req.Kind}
	if err := h.dispatcher.SendValidationChallenge(r.Context(), challengeSub, token); err != nil {
		_, _ = h.db.DeletePushSubscription(r.Context(), userID, id)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "push channel validation failed"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"id": id, "validation_required": true})
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
	if len(req.AuthSecret) != 22 || len(req.PublicKey) != 87 {
		return errors.New("invalid Web Push key shape")
	}
	if _, err := webpush.DecodeSubscriptionKeys(req.AuthSecret, req.PublicKey); err != nil {
		return errors.New("invalid Web Push subscription keys")
	}
	return nil
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	userID, ok := authmw.VerifiedUserID(r.Context())
	if !ok {
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
		endpoint, err := url.Parse(r.EndpointURL)
		if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list failed"})
			return
		}
		js := subscriptionJSON{
			ID:             r.ID,
			EndpointOrigin: endpoint.Scheme + "://" + endpoint.Host,
			DeviceLabel:    r.DeviceLabel,
			Kind:           r.PushKind,
			CreatedAt:      r.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			Enabled:        r.Enabled,
			Validated:      r.ValidatedAt != nil,
		}
		if r.LastUsed != nil {
			js.LastUsed = r.LastUsed.UTC().Format("2006-01-02T15:04:05Z")
		}
		if r.MutedUntil != nil {
			js.MutedUntil = r.MutedUntil.UTC().Format("2006-01-02T15:04:05Z")
		}
		out = append(out, js)
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscriptions": out})
}

type confirmReq struct {
	Token string `json:"token"`
}

func (h *Handler) confirm(w http.ResponseWriter, r *http.Request) {
	userID, authenticated := authmw.VerifiedUserID(r.Context())
	if !authenticated {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req confirmReq
	if err := decodePushJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(req.Token)
	if err != nil || len(raw) != 32 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid validation token"})
		return
	}
	hash := sha256.Sum256(raw)
	ok, err := h.db.ConfirmPushSubscription(r.Context(), userID, id, hash[:])
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "confirmation failed"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "validation token rejected or expired"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type policyReq struct {
	Enabled     *bool  `json:"enabled,omitempty"`
	MuteSeconds *int64 `json:"mute_seconds,omitempty"`
}

const maxPushMuteSeconds int64 = 7 * 24 * 60 * 60

func validatePolicyRequest(req *policyReq) error {
	if req == nil || (req.Enabled == nil && req.MuteSeconds == nil) {
		return errors.New("at least one policy field is required")
	}
	if req.MuteSeconds != nil && (*req.MuteSeconds < 0 || *req.MuteSeconds > maxPushMuteSeconds) {
		return errors.New("mute_seconds is outside the supported range")
	}
	return nil
}

func (h *Handler) updatePolicy(w http.ResponseWriter, r *http.Request) {
	userID, authenticated := authmw.VerifiedUserID(r.Context())
	if !authenticated {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req policyReq
	if err := decodePushJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if err := validatePolicyRequest(&req); err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_push_policy", "invalid push policy", err,
		))
		return
	}
	ok, err := h.db.UpdatePushSubscriptionPolicy(r.Context(), userID, id, req.Enabled, req.MuteSeconds)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	userID, authenticated := authmw.VerifiedUserID(r.Context())
	if !authenticated {
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

func decodePushJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON value")
	}
	return nil
}
