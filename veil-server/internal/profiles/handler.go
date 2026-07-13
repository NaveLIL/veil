package profiles

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/AegisSec/veil-server/internal/authmw"
	"github.com/AegisSec/veil-server/internal/logsafe"
	"github.com/AegisSec/veil-server/internal/publicerr"
	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Handler struct {
	store Store
	mw    *authmw.Middleware
	rl    *authmw.RateLimit
	bcast Broadcaster
}

type Broadcaster interface {
	BroadcastToUsers(userIDs []string, env *pb.Envelope)
}

func NewHandler(store Store, mw *authmw.Middleware, rl *authmw.RateLimit, bcast Broadcaster) *Handler {
	return &Handler{store: store, mw: mw, rl: rl, bcast: bcast}
}

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
	mux.HandleFunc("GET /v1/users/{userID}/profile", signed(h.getProfile))
	mux.HandleFunc("PUT /v1/users/me/profile", signed(h.updateProfile))
}

func (h *Handler) getProfile(w http.ResponseWriter, r *http.Request) {
	if _, ok := authmw.VerifiedUserID(r.Context()); !ok {
		publicerr.Write(w, http.StatusUnauthorized, nil)
		return
	}
	userID := r.PathValue("userID")
	if _, err := uuid.Parse(userID); err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_user_id", "invalid user id", err,
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
	if h.bcast == nil || profile.ProfileVersion <= 0 {
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
