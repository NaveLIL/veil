package profiles

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"strconv"

	"github.com/AegisSec/veil-server/internal/authmw"
	"github.com/AegisSec/veil-server/internal/logsafe"
	"github.com/AegisSec/veil-server/internal/publicerr"
	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Handler struct {
	store           Store
	mw              *authmw.Middleware
	rl              *authmw.RateLimit
	mutationRL      *authmw.RateLimit
	avatarAdmission chan struct{}
	bcast           Broadcaster
}

type Broadcaster interface {
	BroadcastToUsers(userIDs []string, env *pb.Envelope)
}

func NewHandler(store Store, mw *authmw.Middleware, rl, mutationRL *authmw.RateLimit, bcast Broadcaster) *Handler {
	return &Handler{
		store:           store,
		mw:              mw,
		rl:              rl,
		mutationRL:      mutationRL,
		avatarAdmission: make(chan struct{}, 4),
		bcast:           bcast,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	signed := func(f http.HandlerFunc, mutation bool) http.HandlerFunc {
		if mutation && h.mutationRL != nil {
			f = h.mutationRL.Wrap(f)
		}
		if h.rl != nil {
			f = h.rl.Wrap(f)
		}
		if h.mw != nil {
			f = h.mw.RequireSigned(f)
		}
		return f
	}
	mux.HandleFunc("GET /v1/users/{userID}/profile", signed(h.getProfile, false))
	mux.HandleFunc("PUT /v1/users/me/profile", signed(h.updateProfile, true))
	mux.HandleFunc("PUT /v1/users/me/profile/avatar", signed(h.admitAvatarUpload(h.updateAvatar), true))
	mux.HandleFunc("DELETE /v1/users/me/profile/avatar", signed(h.removeAvatar, true))
	mux.HandleFunc("GET /v1/profile-avatars/{assetID}", signed(h.getAvatar, false))
}

func (h *Handler) admitAvatarUpload(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case h.avatarAdmission <- struct{}{}:
			defer func() { <-h.avatarAdmission }()
			next(w, r)
		default:
			w.Header().Set("Retry-After", "1")
			publicerr.Write(w, http.StatusTooManyRequests, publicerr.New(
				http.StatusTooManyRequests,
				"avatar_upload_busy",
				"avatar upload capacity is busy",
				nil,
			))
		}
	}
}

func expectedAvatarVersion(r *http.Request) (int64, error) {
	raw := r.URL.Query().Get("expected_version")
	version, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || version < 0 || strconv.FormatInt(version, 10) != raw {
		return 0, errors.New("invalid avatar profile version")
	}
	return version, nil
}

func (h *Handler) updateAvatar(w http.ResponseWriter, r *http.Request) {
	userID, ok := authmw.VerifiedUserID(r.Context())
	if !ok {
		publicerr.Write(w, http.StatusUnauthorized, nil)
		return
	}
	expectedVersion, err := expectedAvatarVersion(r)
	if err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(http.StatusBadRequest, "invalid_profile_version", "invalid profile version", err))
		return
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		publicerr.Write(w, http.StatusUnsupportedMediaType, publicerr.New(http.StatusUnsupportedMediaType, "invalid_avatar_type", "avatar must be PNG or JPEG", err))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAvatarInputBytes))
	if err != nil {
		publicerr.Write(w, http.StatusRequestEntityTooLarge, publicerr.New(http.StatusRequestEntityTooLarge, "avatar_too_large", "avatar is too large", err))
		return
	}
	asset, err := normalizeAvatar(r.Context(), body, contentType)
	if err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(http.StatusBadRequest, "invalid_avatar", "avatar image is not allowed", err))
		return
	}
	profile, err := h.store.UpdateAvatar(r.Context(), userID, expectedVersion, asset)
	if !h.writeAvatarMutation(w, r, userID, profile, err) {
		return
	}
}

func (h *Handler) removeAvatar(w http.ResponseWriter, r *http.Request) {
	userID, ok := authmw.VerifiedUserID(r.Context())
	if !ok {
		publicerr.Write(w, http.StatusUnauthorized, nil)
		return
	}
	expectedVersion, err := expectedAvatarVersion(r)
	if err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(http.StatusBadRequest, "invalid_profile_version", "invalid profile version", err))
		return
	}
	profile, err := h.store.UpdateAvatar(r.Context(), userID, expectedVersion, nil)
	if !h.writeAvatarMutation(w, r, userID, profile, err) {
		return
	}
}

func (h *Handler) writeAvatarMutation(w http.ResponseWriter, r *http.Request, userID string, profile *Profile, err error) bool {
	if errors.Is(err, ErrVersionConflict) {
		publicerr.Write(w, http.StatusConflict, publicerr.New(http.StatusConflict, "profile_version_conflict", "profile was updated elsewhere", err))
		return false
	}
	if errors.Is(err, ErrAvatarUploadQuota) {
		w.Header().Set("Retry-After", "3600")
		publicerr.Write(w, http.StatusTooManyRequests, publicerr.New(
			http.StatusTooManyRequests,
			"avatar_upload_quota",
			"avatar upload quota exceeded",
			err,
		))
		return false
	}
	if err != nil {
		log.Printf("update avatar error: class=%s", logsafe.ErrorClass(err))
		publicerr.Write(w, http.StatusInternalServerError, nil)
		return false
	}
	writeJSON(w, http.StatusOK, profile)
	h.broadcastProfileUpdate(r, userID, profile)
	return true
}

func (h *Handler) getAvatar(w http.ResponseWriter, r *http.Request) {
	if _, ok := authmw.VerifiedUserID(r.Context()); !ok {
		publicerr.Write(w, http.StatusUnauthorized, nil)
		return
	}
	assetID := r.PathValue("assetID")
	if !canonicalUUID(assetID) {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(http.StatusBadRequest, "invalid_avatar_id", "invalid avatar id", nil))
		return
	}
	asset, err := h.store.GetAvatar(r.Context(), assetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			publicerr.Write(w, http.StatusNotFound, nil)
			return
		}
		log.Printf("get avatar error: class=%s", logsafe.ErrorClass(err))
		publicerr.Write(w, http.StatusInternalServerError, nil)
		return
	}
	w.Header().Set("Content-Type", asset.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(asset.Data)))
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Veil-Avatar-SHA256", fmt.Sprintf("%x", asset.SHA256))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(asset.Data)
}

func (h *Handler) getProfile(w http.ResponseWriter, r *http.Request) {
	if _, ok := authmw.VerifiedUserID(r.Context()); !ok {
		publicerr.Write(w, http.StatusUnauthorized, nil)
		return
	}
	userID := r.PathValue("userID")
	if !canonicalUUID(userID) {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_user_id", "invalid user id", nil,
		))
		return
	}
	profile, err := h.store.GetProfile(r.Context(), userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			publicerr.Write(w, http.StatusNotFound, nil)
			return
		}
		log.Printf("get profile error: class=%s", logsafe.ErrorClass(err))
		publicerr.Write(w, http.StatusInternalServerError, nil)
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

type updateProfileRequest struct {
	ExpectedVersion *int64  `json:"expected_version"`
	DisplayName     *string `json:"display_name"`
	About           string  `json:"about"`
}

func (h *Handler) updateProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := authmw.VerifiedUserID(r.Context())
	if !ok {
		publicerr.Write(w, http.StatusUnauthorized, nil)
		return
	}
	var request updateProfileRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.ExpectedVersion == nil || *request.ExpectedVersion < 0 {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_profile", "invalid profile", err,
		))
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_profile", "invalid profile", err,
		))
		return
	}
	displayName, about, err := NormalizeProfileText(request.DisplayName, request.About)
	if err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_profile_text", "profile text is not allowed", err,
		))
		return
	}
	profile, err := h.store.UpdateProfile(r.Context(), userID, *request.ExpectedVersion, displayName, about)
	if errors.Is(err, ErrVersionConflict) {
		publicerr.Write(w, http.StatusConflict, publicerr.New(
			http.StatusConflict, "profile_version_conflict", "profile was updated elsewhere", err,
		))
		return
	}
	if err != nil {
		log.Printf("update profile error: class=%s", logsafe.ErrorClass(err))
		publicerr.Write(w, http.StatusInternalServerError, nil)
		return
	}
	// The REST response stays authoritative. Fanout is a best-effort, bounded
	// invalidation hint and is deliberately sent only after the response body
	// has been written so the initiating client normally observes its own PUT
	// result first.
	writeJSON(w, http.StatusOK, profile)
	h.broadcastProfileUpdate(r, userID, profile)
}

func (h *Handler) broadcastProfileUpdate(r *http.Request, userID string, profile *Profile) {
	if h.bcast == nil || profile == nil || profile.ProfileVersion <= 0 {
		return
	}
	recipients, audienceErr := h.store.ProfileUpdateRecipients(r.Context(), userID)
	if audienceErr != nil {
		log.Printf("profile update audience error: class=%s", logsafe.ErrorClass(audienceErr))
		return
	}
	h.bcast.BroadcastToUsers(recipients, &pb.Envelope{
		Payload: &pb.Envelope_ProfileUpdated{
			ProfileUpdated: &pb.ProfileUpdated{
				UserId:         profile.UserID,
				ProfileVersion: uint64(profile.ProfileVersion),
			},
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
