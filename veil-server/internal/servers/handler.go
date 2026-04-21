package servers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/AegisSec/veil-server/internal/db"
)

// Handler exposes REST endpoints for servers/channels/roles/invites.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Servers
	mux.HandleFunc("POST /v1/servers", h.CreateServer)
	mux.HandleFunc("GET /v1/servers", h.ListServers)
	mux.HandleFunc("GET /v1/servers/{serverID}", h.GetServer)
	mux.HandleFunc("PATCH /v1/servers/{serverID}", h.UpdateServer)
	mux.HandleFunc("DELETE /v1/servers/{serverID}", h.DeleteServer)
	mux.HandleFunc("POST /v1/servers/{serverID}/leave", h.LeaveServer)

	// Members
	mux.HandleFunc("GET /v1/servers/{serverID}/members", h.ListMembers)
	mux.HandleFunc("DELETE /v1/servers/{serverID}/members/{userID}", h.KickMember)

	// Channels
	mux.HandleFunc("GET /v1/servers/{serverID}/channels", h.ListChannels)
	mux.HandleFunc("POST /v1/servers/{serverID}/channels", h.CreateChannel)
	mux.HandleFunc("PATCH /v1/channels/{channelID}", h.UpdateChannel)
	mux.HandleFunc("DELETE /v1/channels/{channelID}", h.DeleteChannel)

	// Roles
	mux.HandleFunc("GET /v1/servers/{serverID}/roles", h.ListRoles)
	mux.HandleFunc("POST /v1/servers/{serverID}/roles", h.CreateRole)
	mux.HandleFunc("PATCH /v1/servers/{serverID}/roles/{roleID}", h.UpdateRole)
	mux.HandleFunc("DELETE /v1/servers/{serverID}/roles/{roleID}", h.DeleteRole)
	mux.HandleFunc("PUT /v1/servers/{serverID}/members/{userID}/roles/{roleID}", h.AssignRole)
	mux.HandleFunc("DELETE /v1/servers/{serverID}/members/{userID}/roles/{roleID}", h.UnassignRole)

	// Invites
	mux.HandleFunc("POST /v1/servers/{serverID}/invites", h.CreateInvite)
	mux.HandleFunc("GET /v1/servers/{serverID}/invites", h.ListInvites)
	mux.HandleFunc("DELETE /v1/invites/{code}", h.RevokeInvite)
	mux.HandleFunc("GET /v1/invites/{code}", h.PreviewInvite)
	mux.HandleFunc("POST /v1/invites/{code}/use", h.UseInvite)
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
	Name string `json:"name"`
}

type serverJSON struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	IconURL     *string `json:"icon_url,omitempty"`
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
	srv, err := h.svc.CreateServer(r.Context(), req.Name, uid)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp(err.Error()))
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
		writeJSON(w, http.StatusInternalServerError, errResp(err.Error()))
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
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
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
	if err := h.svc.UpdateServer(r.Context(), r.PathValue("serverID"), uid, req.Name, req.Description, req.IconURL); err != nil {
		status := http.StatusForbidden
		writeJSON(w, status, errResp(err.Error()))
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
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
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
		writeJSON(w, http.StatusBadRequest, errResp(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "left"})
}

// ─── Members ─────────────────────────────────────────

type memberJSON struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Nickname *string  `json:"nickname,omitempty"`
	JoinedAt string   `json:"joined_at"`
	RoleIDs  []string `json:"role_ids"`
}

func (h *Handler) ListMembers(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	members, err := h.svc.ListMembers(r.Context(), r.PathValue("serverID"), uid)
	if err != nil {
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
		return
	}
	out := make([]memberJSON, len(members))
	for i, m := range members {
		out[i] = memberJSON{
			UserID:   m.UserID,
			Username: m.Username,
			Nickname: m.Nickname,
			JoinedAt: m.JoinedAt.Format(time.RFC3339),
			RoleIDs:  m.RoleIDs,
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
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := h.svc.KickMember(r.Context(), r.PathValue("serverID"), uid, r.PathValue("userID"), req.Reason); err != nil {
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "kicked"})
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
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
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
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
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
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
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
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
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
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
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
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
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
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
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
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
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
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
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
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
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
	Code      string  `json:"code"`
	ServerID  string  `json:"server_id"`
	CreatedBy string  `json:"created_by"`
	MaxUses   int32   `json:"max_uses"`
	Uses      int32   `json:"uses"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	CreatedAt string  `json:"created_at"`
}

func (h *Handler) CreateInvite(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	var req createInviteReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	inv, err := h.svc.CreateInvite(r.Context(), r.PathValue("serverID"), uid, req.MaxUses, req.ExpiresInSecs)
	if err != nil {
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
		return
	}
	out := inviteJSON{
		Code: inv.Code, ServerID: inv.ServerID, CreatedBy: inv.CreatedBy,
		MaxUses: inv.MaxUses, Uses: inv.Uses, CreatedAt: inv.CreatedAt.Format(time.RFC3339),
	}
	if inv.ExpiresAt != nil {
		s := inv.ExpiresAt.Format(time.RFC3339)
		out.ExpiresAt = &s
	}
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handler) ListInvites(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	invs, err := h.svc.ListInvites(r.Context(), r.PathValue("serverID"), uid)
	if err != nil {
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
		return
	}
	out := make([]inviteJSON, len(invs))
	for i, inv := range invs {
		ij := inviteJSON{
			Code: inv.Code, ServerID: inv.ServerID, CreatedBy: inv.CreatedBy,
			MaxUses: inv.MaxUses, Uses: inv.Uses, CreatedAt: inv.CreatedAt.Format(time.RFC3339),
		}
		if inv.ExpiresAt != nil {
			s := inv.ExpiresAt.Format(time.RFC3339)
			ij.ExpiresAt = &s
		}
		out[i] = ij
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

func (h *Handler) RevokeInvite(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	if err := h.svc.RevokeInvite(r.Context(), r.PathValue("code"), uid); err != nil {
		writeJSON(w, http.StatusForbidden, errResp(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (h *Handler) PreviewInvite(w http.ResponseWriter, r *http.Request) {
	srv, inv, err := h.svc.PreviewInvite(r.Context(), r.PathValue("code"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, errResp(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"server": serverDTO(srv),
		"invite": map[string]any{
			"code":     inv.Code,
			"uses":     inv.Uses,
			"max_uses": inv.MaxUses,
		},
	})
}

func (h *Handler) UseInvite(w http.ResponseWriter, r *http.Request) {
	uid := requireUser(w, r)
	if uid == "" {
		return
	}
	srv, err := h.svc.UseInvite(r.Context(), r.PathValue("code"), uid)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp(err.Error()))
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
		Description: s.Description, IconURL: s.IconURL,
		CreatedAt: s.CreatedAt.Format(time.RFC3339),
	}
}
