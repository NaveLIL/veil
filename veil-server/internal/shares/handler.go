package shares

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/authmw"
	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
)

var selectorRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

type Handler struct {
	store          Store
	mw             *authmw.Middleware
	restDispatcher *authmw.RESTAuthVersionDispatcher
	rl             *authmw.RateLimit
	publicRL       *authmw.RateLimit
	claimRL        *authmw.RateLimit
}

func NewHandler(
	store Store,
	mw *authmw.Middleware,
	rl *authmw.RateLimit,
	publicRL *authmw.RateLimit,
	claimRL *authmw.RateLimit,
) *Handler {
	return &Handler{
		store:    store,
		mw:       mw,
		rl:       rl,
		publicRL: publicRL,
		claimRL:  claimRL,
	}
}

func (h *Handler) SetRESTAuthVersionDispatcher(dispatcher *authmw.RESTAuthVersionDispatcher) {
	h.restDispatcher = dispatcher
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	signed := func(policy authmw.RESTAuthV2HTTPPolicy, f http.HandlerFunc) http.HandlerFunc {
		if h.rl != nil {
			f = h.rl.Wrap(f)
		}
		if h.restDispatcher != nil {
			f = h.restDispatcher.RequireSigned(policy, f)
		} else if h.mw != nil {
			var unavailable *authmw.RESTAuthVersionDispatcher
			f = unavailable.RequireSigned(policy, f)
		}
		return f
	}

	bodylessPolicy := authmw.RESTAuthV2BodylessHTTPPolicy()
	jsonPolicy, err := authmw.NewRESTAuthV2JSONHTTPPolicy(authmw.RESTAuthV2MaxBodyBytes)
	if err != nil {
		panic("invalid shares REST v2 JSON policy: " + err.Error())
	}

	// Creator Authenticated Routes (REST v2)
	mux.HandleFunc("POST /v1/shares", signed(jsonPolicy, h.createShare))
	mux.HandleFunc("GET /v1/shares", signed(bodylessPolicy, h.listShares))
	mux.HandleFunc("POST /v1/shares/{selector}/revoke", signed(bodylessPolicy, h.revokeShare))

	// Public Guest Routes
	wrapPublic := func(rl *authmw.RateLimit, f http.HandlerFunc) http.HandlerFunc {
		if rl != nil {
			f = rl.Wrap(f)
		}
		return f
	}

	mux.HandleFunc("GET /v1/shares/public/{selector}", wrapPublic(h.publicRL, h.getPublicMetadata))
	mux.HandleFunc("POST /v1/shares/public/{selector}/claim", wrapPublic(h.claimRL, h.claimShare))
	mux.HandleFunc("GET /v1/shares/public/{selector}/content", wrapPublic(h.publicRL, h.getContent))
}

type CreateShareRequest struct {
	PublicSelector             string `json:"public_selector"`
	RedemptionHashBase64       string `json:"redemption_hash_base64"`
	ReportCapabilityHashBase64 string `json:"report_capability_hash_base64"`
	CiphertextBase64           string `json:"ciphertext_base64"`
	SizeBytes                  int64  `json:"size_bytes"`
	ContentType                string `json:"content_type"`
	MaxClaims                  int    `json:"max_claims"`
	TTLSeconds                 int64  `json:"ttl_seconds"`
}

func (h *Handler) createShare(w http.ResponseWriter, r *http.Request) {
	callerID := r.Header.Get("X-User-ID")
	if callerID == "" {
		publicerr.Write(w, http.StatusUnauthorized, publicerr.New(http.StatusUnauthorized, "unauthorized", "authentication required", nil))
		return
	}

	var req CreateShareRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(http.StatusBadRequest, "invalid_request", "failed to read body", nil))
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(http.StatusBadRequest, "invalid_json", "malformed json request", nil))
		return
	}

	if !selectorRegex.MatchString(req.PublicSelector) {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(http.StatusBadRequest, "invalid_selector", "public selector must be 16-64 base64url characters", nil))
		return
	}

	redemptionHash, err := base64.RawURLEncoding.DecodeString(req.RedemptionHashBase64)
	if err != nil || len(redemptionHash) != 32 {
		redemptionHash, err = base64.StdEncoding.DecodeString(req.RedemptionHashBase64)
		if err != nil || len(redemptionHash) != 32 {
			publicerr.Write(w, http.StatusBadRequest, publicerr.New(http.StatusBadRequest, "invalid_redemption_hash", "redemption hash must be 32 bytes base64", nil))
			return
		}
	}

	reportCapHash, err := base64.RawURLEncoding.DecodeString(req.ReportCapabilityHashBase64)
	if err != nil || len(reportCapHash) != 32 {
		reportCapHash, err = base64.StdEncoding.DecodeString(req.ReportCapabilityHashBase64)
		if err != nil || len(reportCapHash) != 32 {
			publicerr.Write(w, http.StatusBadRequest, publicerr.New(http.StatusBadRequest, "invalid_report_hash", "report capability hash must be 32 bytes base64", nil))
			return
		}
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(req.CiphertextBase64)
	if err != nil {
		ciphertext, err = base64.StdEncoding.DecodeString(req.CiphertextBase64)
		if err != nil {
			publicerr.Write(w, http.StatusBadRequest, publicerr.New(http.StatusBadRequest, "invalid_ciphertext", "ciphertext must be valid base64", nil))
			return
		}
	}
	if len(ciphertext) == 0 || len(ciphertext) > MaxCiphertextSize {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(http.StatusBadRequest, "ciphertext_size_invalid", "ciphertext exceeds maximum allowed size", nil))
		return
	}

	if req.ContentType != "text" && req.ContentType != "file" {
		req.ContentType = "text"
	}
	if req.MaxClaims <= 0 || req.MaxClaims > 100 {
		req.MaxClaims = 1
	}
	if req.TTLSeconds < 300 || req.TTLSeconds > 30*86400 {
		req.TTLSeconds = 86400 // default 24h
	}

	expiresAt := time.Now().Add(time.Duration(req.TTLSeconds) * time.Second)

	share := &SecureShare{
		PublicSelector:       req.PublicSelector,
		RedemptionHash:       redemptionHash,
		ReportCapabilityHash: reportCapHash,
		CreatorUserID:        callerID,
		Ciphertext:           ciphertext,
		SizeBytes:            req.SizeBytes,
		ContentType:          req.ContentType,
		MaxClaims:            req.MaxClaims,
		ExpiresAt:            expiresAt,
	}

	created, err := h.store.CreateShare(r.Context(), share)
	if err != nil {
		if errors.Is(err, ErrMaxSharesExceeded) {
			publicerr.Write(w, http.StatusTooManyRequests, publicerr.New(http.StatusTooManyRequests, "share_quota_exceeded", "maximum active shares reached", nil))
			return
		}
		publicerr.Write(w, http.StatusInternalServerError, publicerr.New(http.StatusInternalServerError, "database_error", "failed to create secure share", nil))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func (h *Handler) listShares(w http.ResponseWriter, r *http.Request) {
	callerID := r.Header.Get("X-User-ID")
	if callerID == "" {
		publicerr.Write(w, http.StatusUnauthorized, publicerr.New(http.StatusUnauthorized, "unauthorized", "authentication required", nil))
		return
	}

	items, err := h.store.ListCreatorShares(r.Context(), callerID, 50)
	if err != nil {
		publicerr.Write(w, http.StatusInternalServerError, publicerr.New(http.StatusInternalServerError, "database_error", "failed to list shares", nil))
		return
	}
	if items == nil {
		items = []*SecureShare{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(items)
}

func (h *Handler) revokeShare(w http.ResponseWriter, r *http.Request) {
	callerID := r.Header.Get("X-User-ID")
	if callerID == "" {
		publicerr.Write(w, http.StatusUnauthorized, publicerr.New(http.StatusUnauthorized, "unauthorized", "authentication required", nil))
		return
	}

	selector := r.PathValue("selector")
	if !selectorRegex.MatchString(selector) {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(http.StatusBadRequest, "invalid_selector", "invalid selector format", nil))
		return
	}

	err := h.store.RevokeShare(r.Context(), callerID, selector)
	if err != nil {
		if errors.Is(err, ErrShareNotFound) {
			publicerr.Write(w, http.StatusNotFound, publicerr.New(http.StatusNotFound, "share_not_found", "share not found or already deleted", nil))
			return
		}
		publicerr.Write(w, http.StatusInternalServerError, publicerr.New(http.StatusInternalServerError, "database_error", "failed to revoke share", nil))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}

func (h *Handler) getPublicMetadata(w http.ResponseWriter, r *http.Request) {
	selector := r.PathValue("selector")
	if !selectorRegex.MatchString(selector) {
		h.writeUniformPublicError(w)
		return
	}

	meta, err := h.store.GetPublicMetadata(r.Context(), selector)
	if err != nil {
		h.writeUniformPublicError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(meta)
}

type ClaimRequest struct {
	RedemptionKeyBase64 string `json:"redemption_key_base64"`
}

type ClaimResponse struct {
	LeaseTokenBase64 string    `json:"lease_token_base64"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (h *Handler) claimShare(w http.ResponseWriter, r *http.Request) {
	selector := r.PathValue("selector")
	if !selectorRegex.MatchString(selector) {
		h.writeUniformPublicError(w)
		return
	}

	var req ClaimRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeUniformPublicError(w)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeUniformPublicError(w)
		return
	}

	redemptionKey, err := base64.RawURLEncoding.DecodeString(req.RedemptionKeyBase64)
	if err != nil || len(redemptionKey) != 32 {
		redemptionKey, err = base64.StdEncoding.DecodeString(req.RedemptionKeyBase64)
		if err != nil || len(redemptionKey) != 32 {
			h.writeUniformPublicError(w)
			return
		}
	}

	// Generate a fresh random 32-byte lease token
	var leaseToken [32]byte
	if _, err := rand.Read(leaseToken[:]); err != nil {
		publicerr.Write(w, http.StatusInternalServerError, publicerr.New(http.StatusInternalServerError, "crypto_error", "failed to generate lease token", nil))
		return
	}

	leaseTokenHash := sha256.Sum256(leaseToken[:])

	lease, err := h.store.ClaimShare(r.Context(), selector, redemptionKey, leaseTokenHash[:], DefaultLeaseDuration)
	if err != nil {
		h.writeUniformPublicError(w)
		return
	}

	resp := ClaimResponse{
		LeaseTokenBase64: base64.RawURLEncoding.EncodeToString(leaseToken[:]),
		ExpiresAt:        lease.ExpiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) getContent(w http.ResponseWriter, r *http.Request) {
	selector := r.PathValue("selector")
	if !selectorRegex.MatchString(selector) {
		h.writeUniformPublicError(w)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		publicerr.Write(w, http.StatusUnauthorized, publicerr.New(http.StatusUnauthorized, "lease_required", "bearer lease token required", nil))
		return
	}

	rawToken := strings.TrimPrefix(authHeader, "Bearer ")
	leaseToken, err := base64.RawURLEncoding.DecodeString(rawToken)
	if err != nil || len(leaseToken) != 32 {
		leaseToken, err = base64.StdEncoding.DecodeString(rawToken)
		if err != nil || len(leaseToken) != 32 {
			publicerr.Write(w, http.StatusUnauthorized, publicerr.New(http.StatusUnauthorized, "invalid_lease_token", "invalid lease token format", nil))
			return
		}
	}

	leaseTokenHash := sha256.Sum256(leaseToken)

	ciphertext, contentType, sizeBytes, err := h.store.GetCiphertextByLease(r.Context(), selector, leaseTokenHash[:])
	if err != nil {
		if errors.Is(err, ErrLeaseInvalid) || errors.Is(err, ErrShareRevoked) {
			publicerr.Write(w, http.StatusUnauthorized, publicerr.New(http.StatusUnauthorized, "lease_invalid", "lease is invalid, revoked, or expired", nil))
			return
		}
		publicerr.Write(w, http.StatusInternalServerError, publicerr.New(http.StatusInternalServerError, "database_error", "failed to read ciphertext", nil))
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Veil-Share-Content-Type", contentType)
	if sizeBytes > 0 {
		w.Header().Set("X-Veil-Share-Size", string(rune(sizeBytes)))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(ciphertext)
}

func (h *Handler) writeUniformPublicError(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	publicerr.Write(w, http.StatusNotFound, publicerr.New(
		http.StatusNotFound,
		"share_unavailable",
		"This secure share is unavailable, expired, or burned.",
		nil,
	))
}
