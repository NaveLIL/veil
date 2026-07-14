package servers

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/AegisSec/veil-server/internal/authmw"
	"github.com/AegisSec/veil-server/internal/db"
	"github.com/AegisSec/veil-server/internal/publicerr"
	"github.com/google/uuid"
)

// Handler exposes REST endpoints for Spaces/Rooms/roles/Veil Links.
type Handler struct {
	svc           *Service
	mw            *authmw.Middleware
	rl            *authmw.RateLimit
	veilPreviewRL *authmw.RateLimit
	veilJoinRL    *authmw.RateLimit
}

// NewHandler builds a handler. The middleware and rate limiter may be nil; in
// that case routes are registered without authentication or throttling — used
// by tests and the all-in-one binary's local mode.
func NewHandler(svc *Service, mw *authmw.Middleware, rl *authmw.RateLimit) *Handler {
	return &Handler{svc: svc, mw: mw, rl: rl}
}

// SetVeilLinkRateLimits installs quotas that are intentionally independent of
// ordinary REST traffic. Ownership remains with the caller, which must close
// the limiters during shutdown.
func (h *Handler) SetVeilLinkRateLimits(preview, join *authmw.RateLimit) {
	h.veilPreviewRL = preview
	h.veilJoinRL = join
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	signed := func(f http.HandlerFunc) http.HandlerFunc {
		if h.rl != nil {
			f = h.rl.Wrap(f)
		}
		if h.mw != nil {
			// Verify first; the limiter keys from verified principal context.
			f = h.mw.RequireSigned(f)
		}
		return f
	}
	signedWith := func(f http.HandlerFunc, limiter *authmw.RateLimit) http.HandlerFunc {
		if limiter != nil {
			f = limiter.Wrap(f)
		}
		if h.mw != nil {
			f = h.mw.RequireSigned(f)
		}
		return f
	}
	publicWith := func(f http.HandlerFunc, limiter *authmw.RateLimit) http.HandlerFunc {
		if limiter != nil {
			return limiter.Wrap(f)
		}
		return f
	}

	// Servers
	mux.HandleFunc("POST /v1/servers", signed(h.CreateServer))
	mux.HandleFunc("GET /v1/servers", signed(h.ListServers))
	mux.HandleFunc("GET /v1/servers/{serverID}", signed(h.GetServer))
	mux.HandleFunc("PATCH /v1/servers/{serverID}", signed(h.UpdateServer))
	mux.HandleFunc("DELETE /v1/servers/{serverID}", signed(h.DeleteServer))
	mux.HandleFunc("POST /v1/servers/{serverID}/leave", signed(h.LeaveServer))

	// Members
	mux.HandleFunc("GET /v1/servers/{serverID}/members", signed(h.ListMembers))
	mux.HandleFunc("DELETE /v1/servers/{serverID}/members/{userID}", signed(h.KickMember))
	mux.HandleFunc("GET /v1/servers/{serverID}/bans", signed(h.ListBans))
	mux.HandleFunc("PUT /v1/servers/{serverID}/bans/{userID}", signed(h.BanMember))
	mux.HandleFunc("DELETE /v1/servers/{serverID}/bans/{userID}", signed(h.UnbanMember))

	// Channels
	mux.HandleFunc("GET /v1/servers/{serverID}/channels", signed(h.ListChannels))
	mux.HandleFunc("POST /v1/servers/{serverID}/channels", signed(h.CreateChannel))
	mux.HandleFunc("POST /v1/servers/{serverID}/channels/reorder", signed(h.ReorderChannels))
	mux.HandleFunc("PATCH /v1/channels/{channelID}", signed(h.UpdateChannel))
	mux.HandleFunc("DELETE /v1/channels/{channelID}", signed(h.DeleteChannel))
	mux.HandleFunc("GET /v1/channels/{channelID}/overwrites", signed(h.ListChannelOverwrites))
	mux.HandleFunc("PUT /v1/channels/{channelID}/overwrites", signed(h.UpsertChannelOverwrite))
	mux.HandleFunc("DELETE /v1/channels/{channelID}/overwrites/{targetType}/{targetID}", signed(h.DeleteChannelOverwrite))

	// Roles
	mux.HandleFunc("GET /v1/servers/{serverID}/roles", signed(h.ListRoles))
	mux.HandleFunc("POST /v1/servers/{serverID}/roles", signed(h.CreateRole))
	mux.HandleFunc("PATCH /v1/servers/{serverID}/roles/{roleID}", signed(h.UpdateRole))
	mux.HandleFunc("DELETE /v1/servers/{serverID}/roles/{roleID}", signed(h.DeleteRole))
	mux.HandleFunc("PUT /v1/servers/{serverID}/members/{userID}/roles/{roleID}", signed(h.AssignRole))
	mux.HandleFunc("DELETE /v1/servers/{serverID}/members/{userID}/roles/{roleID}", signed(h.UnassignRole))

	// Veil Link v1. Public preview sees selector-only metadata; secret-bearing
	// preview/join and all management operations are request-signed.
	mux.HandleFunc("GET /assets/veil-link-bg-v1-38824a5f41228389.jpg", h.VeilLinkBackground)
	mux.HandleFunc("POST /v1/servers/{serverID}/veil-links", signed(h.CreateInvite))
	mux.HandleFunc("GET /v1/servers/{serverID}/veil-links", signed(h.ListInvites))
	mux.HandleFunc("DELETE /v1/servers/{serverID}/veil-links/{inviteID}", signed(h.RevokeInvite))
	mux.HandleFunc("DELETE /v1/servers/{serverID}/veil-links", signed(h.RevokeAllInvites))
	mux.HandleFunc("GET /v1/veil-links/{selector}", publicWith(h.PreviewInvite, h.veilPreviewRL))
	mux.HandleFunc("GET /join/v1/{selector}", publicWith(h.VeilLinkPortal, h.veilPreviewRL))
	mux.HandleFunc("POST /v1/veil-links/{selector}/preview", signedWith(h.AuthenticatedPreviewInvite, h.veilPreviewRL))
	mux.HandleFunc("POST /v1/veil-links/{selector}/join", signedWith(h.UseInvite, h.veilJoinRL))
}

// ─── Helpers ─────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errResp(msg string) map[string]string { return map[string]string{"error": msg} }

func requireUser(w http.ResponseWriter, r *http.Request) string {
	uid := r.Header.Get("X-User-ID")
	if uid == "" {
		writeJSON(w, http.StatusUnauthorized, errResp("X-User-ID header required"))
	}
	return uid
}

// ─── Servers ─────────────────────────────────────────

type createServerReq struct {
	Name    string  `json:"name"`
	IconURL *string `json:"icon_url,omitempty"`
}

type serverJSON struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	OwnerID     string  `json:"owner_id"`
	CreatedAt   string  `json:"created_at"`
}

func (h *Handler) CreateServer(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req createServerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid JSON"))
		return
	}
	if req.IconURL != nil {
		writeJSON(w, http.StatusBadRequest, errResp("remote Space icons are not supported"))
		return
	}
	srv, err := h.svc.CreateServer(r.Context(), req.Name, uid)
	if err != nil {
		publicerr.Write(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, serverDTO(srv))
}

func (h *Handler) ListServers(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	srvs, err := h.svc.ListUserServers(r.Context(), uid)
	if err != nil {
		publicerr.Write(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]serverJSON, len(srvs))
	for i := range srvs {
		out[i] = serverDTO(&srvs[i])
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": out})
}

func (h *Handler) GetServer(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	srv, err := h.svc.GetServer(r.Context(), r.PathValue("serverID"), uid)
	if err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, serverDTO(srv))
}

type updateServerReq struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	IconURL     *string `json:"icon_url,omitempty"`
}

func (h *Handler) UpdateServer(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req updateServerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid JSON"))
		return
	}
	if req.IconURL != nil {
		writeJSON(w, http.StatusBadRequest, errResp("remote Space icons are not supported"))
		return
	}
	if err := h.svc.UpdateServer(r.Context(), r.PathValue("serverID"), uid, req.Name, req.Description, req.IconURL); err != nil {
		status := http.StatusForbidden
		publicerr.Write(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) DeleteServer(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	if err := h.svc.DeleteServer(r.Context(), r.PathValue("serverID"), uid); err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Handler) LeaveServer(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	if err := h.svc.LeaveServer(r.Context(), r.PathValue("serverID"), uid); err != nil {
		publicerr.Write(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "left"})
}

// ─── Members ─────────────────────────────────────────

type memberJSON struct {
	UserID      string   `json:"user_id"`
	IdentityKey string   `json:"identity_key"`
	SigningKey  string   `json:"signing_key"`
	Username    string   `json:"username"`
	Nickname    *string  `json:"nickname,omitempty"`
	JoinedAt    string   `json:"joined_at"`
	RoleIDs     []string `json:"role_ids"`
}

func (h *Handler) ListMembers(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	members, err := h.svc.ListMembers(r.Context(), r.PathValue("serverID"), uid)
	if err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	out := make([]memberJSON, len(members))
	for i, m := range members {
		out[i] = memberJSON{
			UserID:      m.UserID,
			IdentityKey: hex.EncodeToString(m.IdentityKey),
			SigningKey:  hex.EncodeToString(m.SigningKey),
			Username:    m.Username,
			Nickname:    m.Nickname,
			JoinedAt:    m.JoinedAt.Format(time.RFC3339),
			RoleIDs:     m.RoleIDs,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": out})
}

type kickReq struct {
	Reason *string `json:"reason,omitempty"`
}

func (h *Handler) KickMember(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req kickReq
	if err := decodeRequestJSON(r, &req, true); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid JSON"))
		return
	}
	reason, err := normalizeKickReason(req.Reason)
	if err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_kick_reason", "invalid kick reason", err,
		))
		return
	}
	if err := h.svc.KickMember(r.Context(), r.PathValue("serverID"), uid, r.PathValue("userID"), reason); err != nil {
		if errors.Is(err, ErrInvalidKickReason) {
			publicerr.Write(w, http.StatusBadRequest, publicerr.New(
				http.StatusBadRequest, "invalid_kick_reason", "invalid kick reason", err,
			))
			return
		}
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "kicked"})
}

func (h *Handler) BanMember(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req kickReq
	if err := decodeRequestJSON(r, &req, true); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid JSON"))
		return
	}
	if err := h.svc.BanMember(r.Context(), r.PathValue("serverID"), uid, r.PathValue("userID"), req.Reason); err != nil {
		if errors.Is(err, ErrInvalidKickReason) {
			publicerr.Write(w, http.StatusBadRequest, publicerr.New(
				http.StatusBadRequest, "invalid_ban_reason", "invalid ban reason", err,
			))
			return
		}
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "banned"})
}

func (h *Handler) ListBans(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	bans, err := h.svc.ListBans(r.Context(), r.PathValue("serverID"), uid)
	if err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	type banJSON struct {
		UserID    string  `json:"user_id"`
		Username  string  `json:"username"`
		BannedBy  string  `json:"banned_by"`
		Reason    *string `json:"reason,omitempty"`
		CreatedAt string  `json:"created_at"`
	}
	out := make([]banJSON, len(bans))
	for i, ban := range bans {
		out[i] = banJSON{
			UserID: ban.UserID, Username: ban.Username, BannedBy: ban.BannedBy,
			Reason: ban.Reason, CreatedAt: ban.CreatedAt.Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"bans": out})
}

func (h *Handler) UnbanMember(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	if err := h.svc.UnbanMember(r.Context(), r.PathValue("serverID"), uid, r.PathValue("userID")); err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unbanned"})
}

// ─── Channels ────────────────────────────────────────

type channelJSON struct {
	ID             string  `json:"id"`
	ServerID       string  `json:"server_id"`
	ConversationID *string `json:"conversation_id,omitempty"`
	Name           string  `json:"name"`
	ChannelType    int16   `json:"channel_type"`
	CategoryID     *string `json:"category_id,omitempty"`
	Position       int16   `json:"position"`
	Topic          *string `json:"topic,omitempty"`
	NSFW           bool    `json:"nsfw"`
	SlowmodeSecs   int32   `json:"slowmode_secs"`
	CreatedAt      string  `json:"created_at"`
}

func (h *Handler) ListChannels(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	chans, err := h.svc.ListChannels(r.Context(), r.PathValue("serverID"), uid)
	if err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	out := make([]channelJSON, len(chans))
	for i, c := range chans {
		out[i] = channelJSON{
			ID: c.ID, ServerID: c.ServerID, ConversationID: c.ConversationID,
			Name: c.Name, ChannelType: c.ChannelType, CategoryID: c.CategoryID,
			Position: c.Position, Topic: c.Topic, NSFW: c.NSFW,
			SlowmodeSecs: c.SlowmodeSecs, CreatedAt: c.CreatedAt.Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"channels": out})
}

type createChannelReq struct {
	Name        string  `json:"name"`
	ChannelType int16   `json:"channel_type"`
	CategoryID  *string `json:"category_id,omitempty"`
	Topic       *string `json:"topic,omitempty"`
}

func (h *Handler) CreateChannel(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req createChannelReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid JSON"))
		return
	}
	ch, err := h.svc.CreateChannel(r.Context(), r.PathValue("serverID"), uid, req.Name, req.ChannelType, req.CategoryID, req.Topic)
	if err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusCreated, channelJSON{
		ID: ch.ID, ServerID: ch.ServerID, ConversationID: ch.ConversationID,
		Name: ch.Name, ChannelType: ch.ChannelType, CategoryID: ch.CategoryID,
		Position: ch.Position, Topic: ch.Topic, NSFW: ch.NSFW,
		SlowmodeSecs: ch.SlowmodeSecs, CreatedAt: ch.CreatedAt.Format(time.RFC3339),
	})
}

type updateChannelReq struct {
	Name         *string `json:"name,omitempty"`
	Topic        *string `json:"topic,omitempty"`
	NSFW         *bool   `json:"nsfw,omitempty"`
	SlowmodeSecs *int32  `json:"slowmode_secs,omitempty"`
}

func (h *Handler) UpdateChannel(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req updateChannelReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid JSON"))
		return
	}
	if err := h.svc.UpdateChannel(r.Context(), r.PathValue("channelID"), uid, req.Name, req.Topic, req.NSFW, req.SlowmodeSecs); err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) DeleteChannel(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	if err := h.svc.DeleteChannel(r.Context(), r.PathValue("channelID"), uid); err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

type channelOverwriteJSON struct {
	TargetID   string `json:"target_id"`
	TargetType int16  `json:"target_type"`
	Allow      uint64 `json:"allow"`
	Deny       uint64 `json:"deny"`
}

func (h *Handler) ListChannelOverwrites(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	overwrites, err := h.svc.ListChannelOverwrites(r.Context(), r.PathValue("channelID"), uid)
	if err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	result := make([]channelOverwriteJSON, 0, len(overwrites))
	for _, overwrite := range overwrites {
		result = append(result, channelOverwriteJSON{
			TargetID: overwrite.TargetID, TargetType: overwrite.TargetType,
			Allow: overwrite.Allow, Deny: overwrite.Deny,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"overwrites": result})
}

func (h *Handler) UpsertChannelOverwrite(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req channelOverwriteJSON
	if err := decodeRequestJSON(r, &req, false); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid JSON"))
		return
	}
	targetID, err := uuid.Parse(req.TargetID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid overwrite target"))
		return
	}
	err = h.svc.UpsertChannelOverwrite(r.Context(), uid, db.ChannelOverwrite{
		ChannelID: r.PathValue("channelID"), TargetID: targetID.String(),
		TargetType: req.TargetType, Allow: req.Allow, Deny: req.Deny,
	})
	if err != nil {
		status := http.StatusForbidden
		mapped := err
		if errors.Is(err, db.ErrInvalidChannelOverwrite) {
			status = http.StatusBadRequest
			mapped = publicerr.New(
				status, "invalid_channel_overwrite", "invalid channel permission overwrite", err,
			)
		}
		publicerr.Write(w, status, mapped)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) DeleteChannelOverwrite(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	targetID, err := uuid.Parse(r.PathValue("targetID"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid overwrite target"))
		return
	}
	targetType, err := strconv.ParseInt(r.PathValue("targetType"), 10, 16)
	if err != nil || targetType < int64(db.ChannelOverwriteRole) || targetType > int64(db.ChannelOverwriteUser) {
		writeJSON(w, http.StatusBadRequest, errResp("invalid overwrite target type"))
		return
	}
	if err := h.svc.DeleteChannelOverwrite(
		r.Context(), r.PathValue("channelID"), uid, targetID.String(), int16(targetType),
	); err != nil {
		status := http.StatusForbidden
		mapped := err
		if errors.Is(err, db.ErrInvalidChannelOverwrite) {
			status = http.StatusBadRequest
			mapped = publicerr.New(
				status, "invalid_channel_overwrite", "invalid channel permission overwrite", err,
			)
		}
		publicerr.Write(w, status, mapped)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ReorderChannels accepts a list of channel placements and updates them in bulk.
type reorderItemReq struct {
	ChannelID     string  `json:"channel_id"`
	Position      int16   `json:"position"`
	CategoryID    *string `json:"category_id,omitempty"`
	ClearCategory bool    `json:"clear_category,omitempty"`
}

type reorderReq struct {
	Items []reorderItemReq `json:"items"`
}

func (h *Handler) ReorderChannels(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req reorderReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid JSON"))
		return
	}
	items := make([]ReorderItem, 0, len(req.Items))
	for _, it := range req.Items {
		items = append(items, ReorderItem(it))
	}
	if err := h.svc.ReorderChannels(r.Context(), r.PathValue("serverID"), uid, items); err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reordered"})
}

// ─── Roles ───────────────────────────────────────────

type roleJSON struct {
	ID          string `json:"id"`
	ServerID    string `json:"server_id"`
	Name        string `json:"name"`
	Permissions uint64 `json:"permissions"`
	Position    int16  `json:"position"`
	Color       *int32 `json:"color,omitempty"`
	IsDefault   bool   `json:"is_default"`
	Hoist       bool   `json:"hoist"`
	Mentionable bool   `json:"mentionable"`
}

func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	roles, err := h.svc.ListRoles(r.Context(), r.PathValue("serverID"), uid)
	if err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	out := make([]roleJSON, len(roles))
	for i, r0 := range roles {
		out[i] = roleJSON{
			ID: r0.ID, ServerID: r0.ServerID, Name: r0.Name,
			Permissions: r0.Permissions, Position: r0.Position, Color: r0.Color,
			IsDefault: r0.IsDefault, Hoist: r0.Hoist, Mentionable: r0.Mentionable,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": out})
}

type createRoleReq struct {
	Name        string `json:"name"`
	Permissions uint64 `json:"permissions"`
	Color       *int32 `json:"color,omitempty"`
}

func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req createRoleReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid JSON"))
		return
	}
	role, err := h.svc.CreateRole(r.Context(), r.PathValue("serverID"), uid, req.Name, req.Permissions, req.Color)
	if err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusCreated, roleJSON{
		ID: role.ID, ServerID: role.ServerID, Name: role.Name,
		Permissions: role.Permissions, Position: role.Position, Color: role.Color,
		IsDefault: role.IsDefault, Hoist: role.Hoist, Mentionable: role.Mentionable,
	})
}

type updateRoleReq struct {
	Name        *string `json:"name,omitempty"`
	Permissions *uint64 `json:"permissions,omitempty"`
	Color       *int32  `json:"color,omitempty"`
}

func (h *Handler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req updateRoleReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid JSON"))
		return
	}
	if err := h.svc.UpdateRole(r.Context(), r.PathValue("serverID"), r.PathValue("roleID"), uid, req.Name, req.Permissions, req.Color); err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	if err := h.svc.DeleteRole(r.Context(), r.PathValue("serverID"), r.PathValue("roleID"), uid); err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Handler) AssignRole(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	if err := h.svc.AssignRole(r.Context(), r.PathValue("serverID"), uid, r.PathValue("userID"), r.PathValue("roleID")); err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "assigned"})
}

func (h *Handler) UnassignRole(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	if err := h.svc.UnassignRole(r.Context(), r.PathValue("serverID"), uid, r.PathValue("userID"), r.PathValue("roleID")); err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unassigned"})
}

// ─── Invites ─────────────────────────────────────────

type createInviteReq struct {
	MaxUses       int32 `json:"max_uses"`
	ExpiresInSecs int64 `json:"expires_in_secs"`
}

type inviteJSON struct {
	ID             string  `json:"id"`
	PublicSelector string  `json:"public_selector"`
	Version        int16   `json:"version"`
	LinkType       string  `json:"type"`
	ServerID       string  `json:"space_id"`
	MaxUses        int32   `json:"max_uses"`
	Uses           int32   `json:"uses"`
	ExpiresAt      string  `json:"expires_at"`
	RevokedAt      *string `json:"revoked_at,omitempty"`
	CreatedAt      string  `json:"created_at"`
	Secret         string  `json:"secret,omitempty"`
	ShareURL       string  `json:"share_url,omitempty"`
}

func inviteDTO(inv db.Invite) inviteJSON {
	out := inviteJSON{
		ID: inv.ID, PublicSelector: inv.PublicSelector, Version: inv.Version,
		LinkType: inv.LinkType, ServerID: inv.ServerID, MaxUses: inv.MaxUses,
		Uses: inv.Uses, ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
		CreatedAt: inv.CreatedAt.Format(time.RFC3339),
	}
	if inv.RevokedAt != nil {
		revokedAt := inv.RevokedAt.Format(time.RFC3339)
		out.RevokedAt = &revokedAt
	}
	return out
}

func veilLinkShareURL(r *http.Request, selector, secret string) string {
	u := url.URL{Scheme: requestScheme(r), Host: r.Host, Path: "/join/v1/" + selector}
	return u.String() + "#s=" + secret
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func requestOrigin(r *http.Request) string {
	return (&url.URL{Scheme: requestScheme(r), Host: r.Host}).String()
}

func (h *Handler) CreateInvite(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req createInviteReq
	if err := decodeRequestJSON(r, &req, false); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid JSON"))
		return
	}
	if err := validateInviteInput(req.MaxUses, req.ExpiresInSecs); err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_invite_limits", "invalid invite limits", err,
		))
		return
	}
	inv, err := h.svc.CreateInvite(r.Context(), r.PathValue("serverID"), uid, req.MaxUses, req.ExpiresInSecs)
	if err != nil {
		if errors.Is(err, ErrInvalidInviteInput) {
			publicerr.Write(w, http.StatusBadRequest, publicerr.New(
				http.StatusBadRequest, "invalid_invite_limits", "invalid invite limits", err,
			))
			return
		}
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	out := inviteDTO(inv.Invite)
	out.Secret = inv.Secret
	out.ShareURL = veilLinkShareURL(r, inv.PublicSelector, inv.Secret)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	writeJSON(w, http.StatusCreated, out)
}

func decodeRequestJSON(r *http.Request, destination any, allowEmpty bool) error {
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(destination); err != nil {
		if allowEmpty && errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func (h *Handler) ListInvites(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	invs, err := h.svc.ListInvites(r.Context(), r.PathValue("serverID"), uid)
	if err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	out := make([]inviteJSON, len(invs))
	for i, inv := range invs {
		out[i] = inviteDTO(inv)
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

func (h *Handler) RevokeInvite(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	if err := h.svc.RevokeInvite(r.Context(), r.PathValue("serverID"), r.PathValue("inviteID"), uid); err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (h *Handler) RevokeAllInvites(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	if err := h.svc.RevokeAllInvites(r.Context(), r.PathValue("serverID"), uid); err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func setVeilLinkPrivacyHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

const veilLinkBackgroundPath = "/assets/veil-link-bg-v1-38824a5f41228389.jpg"

//go:embed assets/veil-link-bg-v1-38824a5f41228389.jpg
var veilLinkBackground []byte

// VeilLinkBackground serves one audited, content-hashed visual asset. It is
// deliberately outside the invitation preview limiter: a browser subresource
// must never consume the selector's privacy quota. No runtime path or remote
// image URL can reach this handler.
func (h *Handler) VeilLinkBackground(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("ETag", `"38824a5f41228389"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(veilLinkBackground)
}

func validVeilLinkToken(token string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == token
}

func publicSpaceMarkSeed(canonicalOrigin, spaceID string) string {
	material := []byte("veil-space-mark-v1\x00" + canonicalOrigin + "\x00" + spaceID)
	hash := sha256.Sum256(material)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func publicVeilLinkPreview(canonicalOrigin string, srv *db.Server, inv *db.Invite) map[string]any {
	description := ""
	if srv.Description != nil {
		description = *srv.Description
	}
	return map[string]any{
		"version": 1,
		"type":    "space",
		"space": map[string]any{
			"name":        srv.Name,
			"description": description,
			"mark_seed":   publicSpaceMarkSeed(canonicalOrigin, srv.ID),
		},
		"expires_at":  inv.ExpiresAt.Format(time.RFC3339),
		"join_policy": "immediate_after_native_confirmation",
	}
}

func (h *Handler) PreviewInvite(w http.ResponseWriter, r *http.Request) {
	setVeilLinkPrivacyHeaders(w)
	selector := r.PathValue("selector")
	if !validVeilLinkToken(selector) {
		publicerr.Write(w, http.StatusNotFound, errors.New("veil link unavailable"))
		return
	}
	srv, inv, err := h.svc.PreviewInvite(r.Context(), selector)
	if err != nil {
		publicerr.Write(w, http.StatusNotFound, errors.New("veil link unavailable"))
		return
	}
	writeJSON(w, http.StatusOK, publicVeilLinkPreview(requestOrigin(r), srv, inv))
}

//go:embed assets/veil-link-portal.html
var veilLinkPortalHTML string

var veilLinkPortalTemplate = template.Must(
	template.New("veil-link-portal").Parse(veilLinkPortalHTML),
)

func (h *Handler) VeilLinkPortal(w http.ResponseWriter, r *http.Request) {
	setVeilLinkPrivacyHeaders(w)
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	selector := r.PathValue("selector")
	if !validVeilLinkToken(selector) {
		h.writeUnavailableVeilLinkPortal(w, http.StatusNotFound)
		return
	}
	srv, inv, err := h.svc.PreviewInvite(r.Context(), selector)
	if err != nil {
		h.writeUnavailableVeilLinkPortal(w, http.StatusNotFound)
		return
	}
	nonceBytes := make([]byte, 18)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		h.writeUnavailableVeilLinkPortal(w, http.StatusInternalServerError)
		return
	}
	nonce := base64.RawStdEncoding.EncodeToString(nonceBytes)
	description := "A private Space on Veil"
	if srv.Description != nil && *srv.Description != "" {
		description = *srv.Description
	}
	markSeed := publicSpaceMarkSeed(requestOrigin(r), srv.ID)
	var output bytes.Buffer
	if err := veilLinkPortalTemplate.Execute(&output, map[string]string{
		"MarkSeed": markSeed, "MarkRef": markSeed[:12], "Name": srv.Name,
		"Origin": requestOrigin(r), "Description": description,
		"Expires": inv.ExpiresAt.UTC().Format("02 Jan 2006 · 15:04 UTC"), "Nonce": nonce,
	}); err != nil {
		h.writeUnavailableVeilLinkPortal(w, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-"+nonce+"'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; connect-src 'none'; img-src 'self'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(output.Bytes())
}

func (h *Handler) writeUnavailableVeilLinkPortal(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>Veil Link unavailable</title><style>body{color-scheme:dark;background:#090d18;color:#d7e2f5;font:16px system-ui;min-height:100vh;display:grid;place-items:center;margin:0}main{text-align:center}</style><main><h1>Veil Link unavailable</h1><p>Ask the sender for a new invitation.</p></main>`)
}

type veilLinkSecretReq struct {
	Secret string `json:"secret"`
}

func (h *Handler) AuthenticatedPreviewInvite(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req veilLinkSecretReq
	selector := r.PathValue("selector")
	if err := decodeRequestJSON(r, &req, false); err != nil ||
		!validVeilLinkToken(selector) || !validVeilLinkToken(req.Secret) {
		publicerr.Write(w, http.StatusBadRequest, errors.New("veil link unavailable"))
		return
	}
	setVeilLinkPrivacyHeaders(w)
	srv, inv, alreadyMember, err := h.svc.AuthenticatedPreviewInvite(r.Context(), selector, req.Secret, uid)
	if err != nil {
		publicerr.Write(w, http.StatusNotFound, errors.New("veil link unavailable"))
		return
	}
	preview := publicVeilLinkPreview(requestOrigin(r), srv, inv)
	preview["already_member"] = alreadyMember
	preview["space_id"] = srv.ID
	writeJSON(w, http.StatusOK, preview)
}

func (h *Handler) UseInvite(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req veilLinkSecretReq
	selector := r.PathValue("selector")
	if err := decodeRequestJSON(r, &req, false); err != nil ||
		!validVeilLinkToken(selector) || !validVeilLinkToken(req.Secret) {
		publicerr.Write(w, http.StatusBadRequest, errors.New("veil link unavailable"))
		return
	}
	setVeilLinkPrivacyHeaders(w)
	srv, err := h.svc.UseInvite(r.Context(), selector, req.Secret, uid)
	if err != nil {
		publicerr.Write(w, http.StatusBadRequest, errors.New("veil link unavailable"))
		return
	}
	writeJSON(w, http.StatusOK, serverDTO(srv))
}

// serverDTO builds the wire JSON for a *db.Server.
func serverDTO(s *db.Server) serverJSON {
	if s == nil {
		return serverJSON{}
	}
	return serverJSON{
		ID: s.ID, Name: s.Name, OwnerID: s.OwnerID,
		Description: s.Description,
		CreatedAt:   s.CreatedAt.Format(time.RFC3339),
	}
}
