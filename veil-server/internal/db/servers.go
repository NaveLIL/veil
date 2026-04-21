package db

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ─── Permission bitmask ──────────────────────────────

const (
	PermViewChannel        uint64 = 1 << 0  // can see channel exists in list
	PermSendMessages       uint64 = 1 << 1
	PermManageMessages     uint64 = 1 << 2
	PermMentionEveryone    uint64 = 1 << 3
	PermManageChannels     uint64 = 1 << 4
	PermManageRoles        uint64 = 1 << 5
	PermKickMembers        uint64 = 1 << 6
	PermBanMembers         uint64 = 1 << 7
	PermCreateInvite       uint64 = 1 << 8
	PermManageServer       uint64 = 1 << 9
	PermReadMessageHistory uint64 = 1 << 10 // gets epoch key envelopes; can decrypt
	PermAdministrator      uint64 = 1 << 32

	// Default @everyone gets visibility + read + send + invite. No history by default.
	DefaultEveryonePerms = PermViewChannel | PermReadMessageHistory | PermSendMessages | PermCreateInvite
)

// ─── Models ──────────────────────────────────────────

type Server struct {
	ID          string
	Name        string
	Description *string
	IconURL     *string
	OwnerID     string
	CreatedAt   time.Time
}

type ServerMember struct {
	ServerID string
	UserID   string
	Username string
	Nickname *string
	JoinedAt time.Time
	RoleIDs  []string
}

type Role struct {
	ID          string
	ServerID    string
	Name        string
	Permissions uint64
	Position    int16
	Color       *int32
	IsDefault   bool
	Hoist       bool
	Mentionable bool
}

type Channel struct {
	ID             string
	ServerID       string
	ConversationID *string
	Name           string
	ChannelType    int16 // 0=text, 1=voice, 2=category
	CategoryID     *string
	Position       int16
	Topic          *string
	NSFW           bool
	SlowmodeSecs   int32
	CreatedAt      time.Time
}

type Invite struct {
	Code      string
	ServerID  string
	CreatedBy string
	MaxUses   int32
	Uses      int32
	ExpiresAt *time.Time
	CreatedAt time.Time
}

// ─── Servers ─────────────────────────────────────────

// CreateServer creates a new server with default @everyone role and a "general" text channel.
// Returns the new server ID.
func (db *DB) CreateServer(ctx context.Context, name string, ownerUserID string) (*Server, error) {
	if name == "" {
		return nil, errors.New("server name required")
	}
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var s Server
	err = tx.QueryRow(ctx,
		`INSERT INTO servers (name, owner_id) VALUES ($1, $2::uuid)
		 RETURNING id, name, description, icon_url, owner_id, created_at`,
		name, ownerUserID,
	).Scan(&s.ID, &s.Name, &s.Description, &s.IconURL, &s.OwnerID, &s.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create server: %w", err)
	}

	// Add owner as member
	if _, err := tx.Exec(ctx,
		`INSERT INTO server_members (server_id, user_id) VALUES ($1, $2::uuid)`,
		s.ID, ownerUserID); err != nil {
		return nil, fmt.Errorf("add owner: %w", err)
	}

	// Create default @everyone role
	if _, err := tx.Exec(ctx,
		`INSERT INTO roles (server_id, name, permissions, position, is_default)
		 VALUES ($1, '@everyone', $2, 0, TRUE)`,
		s.ID, int64(DefaultEveryonePerms)); err != nil {
		return nil, fmt.Errorf("create default role: %w", err)
	}

	// Create default "general" text channel with backing conversation
	var convID string
	if err := tx.QueryRow(ctx,
		`INSERT INTO conversations (conv_type, server_id, name) VALUES (2, $1, 'general') RETURNING id`,
		s.ID,
	).Scan(&convID); err != nil {
		return nil, fmt.Errorf("create general conversation: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO channels (server_id, conversation_id, name, channel_type, position)
		 VALUES ($1, $2, 'general', 0, 0)`,
		s.ID, convID); err != nil {
		return nil, fmt.Errorf("create general channel: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO conversation_members (conversation_id, user_id, role) VALUES ($1, $2::uuid, 2)`,
		convID, ownerUserID); err != nil {
		return nil, fmt.Errorf("add owner to general: %w", err)
	}

	return &s, tx.Commit(ctx)
}

// GetServer returns a server by ID.
func (db *DB) GetServer(ctx context.Context, serverID string) (*Server, error) {
	var s Server
	err := db.Pool.QueryRow(ctx,
		`SELECT id, name, description, icon_url, owner_id, created_at
		 FROM servers WHERE id = $1 AND deleted_at IS NULL`, serverID,
	).Scan(&s.ID, &s.Name, &s.Description, &s.IconURL, &s.OwnerID, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// GetUserServers returns all servers a user is a member of.
func (db *DB) GetUserServers(ctx context.Context, userID string) ([]Server, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT s.id, s.name, s.description, s.icon_url, s.owner_id, s.created_at
		 FROM servers s
		 JOIN server_members sm ON sm.server_id = s.id
		 WHERE sm.user_id = $1::uuid AND s.deleted_at IS NULL
		 ORDER BY s.created_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Server
	for rows.Next() {
		var s Server
		if err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.IconURL, &s.OwnerID, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpdateServer updates name/description/icon. Empty strings → no change.
func (db *DB) UpdateServer(ctx context.Context, serverID string, name, description, iconURL *string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE servers
		 SET name = COALESCE($2, name),
		     description = COALESCE($3, description),
		     icon_url = COALESCE($4, icon_url)
		 WHERE id = $1`,
		serverID, name, description, iconURL)
	return err
}

// DeleteServer soft-deletes a server (only owner allowed — caller must check).
func (db *DB) DeleteServer(ctx context.Context, serverID string) error {
	_, err := db.Pool.Exec(ctx, `UPDATE servers SET deleted_at = now() WHERE id = $1`, serverID)
	return err
}

// IsServerOwner checks if user owns the server.
func (db *DB) IsServerOwner(ctx context.Context, serverID, userID string) (bool, error) {
	var ownerID string
	err := db.Pool.QueryRow(ctx, `SELECT owner_id FROM servers WHERE id = $1`, serverID).Scan(&ownerID)
	if err != nil {
		return false, err
	}
	return ownerID == userID, nil
}

// IsServerMember checks if user is a member of server.
func (db *DB) IsServerMember(ctx context.Context, serverID, userID string) (bool, error) {
	var exists bool
	err := db.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2::uuid)`,
		serverID, userID).Scan(&exists)
	return exists, err
}

// ─── Members ─────────────────────────────────────────

// AddServerMember adds a user to a server (assigns @everyone implicitly).
func (db *DB) AddServerMember(ctx context.Context, serverID, userID string) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO server_members (server_id, user_id) VALUES ($1, $2::uuid) ON CONFLICT DO NOTHING`,
		serverID, userID)
	return err
}

// RemoveServerMember removes a user from a server (does not delete the user).
func (db *DB) RemoveServerMember(ctx context.Context, serverID, userID string) error {
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM server_members WHERE server_id = $1 AND user_id = $2::uuid`,
		serverID, userID)
	return err
}

// GetServerMembers returns all members of a server with their assigned role IDs.
func (db *DB) GetServerMembers(ctx context.Context, serverID string) ([]ServerMember, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT sm.server_id, sm.user_id, u.username, sm.nickname, sm.joined_at,
		        COALESCE(array_agg(mr.role_id) FILTER (WHERE mr.role_id IS NOT NULL), '{}')::uuid[]
		 FROM server_members sm
		 JOIN users u ON u.id = sm.user_id
		 LEFT JOIN member_roles mr ON mr.server_id = sm.server_id AND mr.user_id = sm.user_id
		 WHERE sm.server_id = $1
		 GROUP BY sm.server_id, sm.user_id, u.username, sm.nickname, sm.joined_at
		 ORDER BY sm.joined_at ASC`,
		serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServerMember
	for rows.Next() {
		var m ServerMember
		var roleIDs []string
		if err := rows.Scan(&m.ServerID, &m.UserID, &m.Username, &m.Nickname, &m.JoinedAt, &roleIDs); err != nil {
			return nil, err
		}
		m.RoleIDs = roleIDs
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetUserPermissions computes effective permissions for a user in a server.
// Owner gets ADMINISTRATOR. Otherwise OR of @everyone perms + assigned role perms.
func (db *DB) GetUserPermissions(ctx context.Context, serverID, userID string) (uint64, error) {
	owner, err := db.IsServerOwner(ctx, serverID, userID)
	if err != nil {
		return 0, err
	}
	if owner {
		return PermAdministrator, nil
	}

	var perms int64
	err = db.Pool.QueryRow(ctx,
		`SELECT COALESCE(BIT_OR(r.permissions), 0)
		 FROM roles r
		 WHERE r.server_id = $1 AND (
		     r.is_default = TRUE
		     OR r.id IN (
		         SELECT role_id FROM member_roles
		         WHERE server_id = $1 AND user_id = $2::uuid
		     )
		 )`,
		serverID, userID,
	).Scan(&perms)
	if err != nil {
		return 0, err
	}
	return uint64(perms), nil
}

// HasPermission checks one specific permission for a user.
func (db *DB) HasPermission(ctx context.Context, serverID, userID string, perm uint64) (bool, error) {
	p, err := db.GetUserPermissions(ctx, serverID, userID)
	if err != nil {
		return false, err
	}
	if p&PermAdministrator != 0 {
		return true, nil
	}
	return p&perm != 0, nil
}

// ─── Roles ───────────────────────────────────────────

// GetServerRoles returns all roles for a server, ordered by position desc (highest first).
func (db *DB) GetServerRoles(ctx context.Context, serverID string) ([]Role, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, server_id, name, permissions, position, color, is_default, hoist, mentionable
		 FROM roles WHERE server_id = $1 ORDER BY position DESC`,
		serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		var r Role
		var perms int64
		if err := rows.Scan(&r.ID, &r.ServerID, &r.Name, &perms, &r.Position, &r.Color, &r.IsDefault, &r.Hoist, &r.Mentionable); err != nil {
			return nil, err
		}
		r.Permissions = uint64(perms)
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateRole creates a new role. Returns the new role.
func (db *DB) CreateRole(ctx context.Context, serverID, name string, perms uint64, color *int32) (*Role, error) {
	var r Role
	var p int64
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO roles (server_id, name, permissions, position, color)
		 VALUES ($1, $2, $3, COALESCE((SELECT MAX(position) + 1 FROM roles WHERE server_id = $1), 1), $4)
		 RETURNING id, server_id, name, permissions, position, color, is_default, hoist, mentionable`,
		serverID, name, int64(perms), color,
	).Scan(&r.ID, &r.ServerID, &r.Name, &p, &r.Position, &r.Color, &r.IsDefault, &r.Hoist, &r.Mentionable)
	if err != nil {
		return nil, err
	}
	r.Permissions = uint64(p)
	return &r, nil
}

// UpdateRole updates name/permissions/color of a role.
func (db *DB) UpdateRole(ctx context.Context, roleID string, name *string, perms *uint64, color *int32) error {
	var permsArg interface{}
	if perms != nil {
		permsArg = int64(*perms)
	}
	_, err := db.Pool.Exec(ctx,
		`UPDATE roles
		 SET name = COALESCE($2, name),
		     permissions = COALESCE($3, permissions),
		     color = COALESCE($4, color)
		 WHERE id = $1`,
		roleID, name, permsArg, color)
	return err
}

// DeleteRole removes a role (default @everyone cannot be deleted).
func (db *DB) DeleteRole(ctx context.Context, roleID string) error {
	res, err := db.Pool.Exec(ctx,
		`DELETE FROM roles WHERE id = $1 AND is_default = FALSE`, roleID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return errors.New("role not found or is default")
	}
	return nil
}

// AssignRole assigns a role to a member.
func (db *DB) AssignRole(ctx context.Context, serverID, userID, roleID string) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO member_roles (server_id, user_id, role_id) VALUES ($1, $2::uuid, $3)
		 ON CONFLICT DO NOTHING`,
		serverID, userID, roleID)
	return err
}

// UnassignRole removes a role from a member.
func (db *DB) UnassignRole(ctx context.Context, serverID, userID, roleID string) error {
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM member_roles WHERE server_id = $1 AND user_id = $2::uuid AND role_id = $3`,
		serverID, userID, roleID)
	return err
}

// ─── Channels ────────────────────────────────────────

// GetServerChannels returns all channels for a server, ordered by category and position.
func (db *DB) GetServerChannels(ctx context.Context, serverID string) ([]Channel, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, server_id, conversation_id, name, channel_type, category_id, position, topic,
		        COALESCE(nsfw, FALSE), COALESCE(slowmode_secs, 0), COALESCE(created_at, now())
		 FROM channels WHERE server_id = $1
		 ORDER BY position ASC, name ASC`,
		serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		var c Channel
		if err := rows.Scan(&c.ID, &c.ServerID, &c.ConversationID, &c.Name, &c.ChannelType,
			&c.CategoryID, &c.Position, &c.Topic, &c.NSFW, &c.SlowmodeSecs, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CreateChannel creates a new text/voice/category channel. For text, also creates a backing conversation.
func (db *DB) CreateChannel(ctx context.Context, serverID, name string, channelType int16, categoryID *string, topic *string) (*Channel, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var convIDPtr *string
	if channelType == 0 { // text
		var convID string
		if err := tx.QueryRow(ctx,
			`INSERT INTO conversations (conv_type, server_id, name) VALUES (2, $1, $2) RETURNING id`,
			serverID, name).Scan(&convID); err != nil {
			return nil, fmt.Errorf("create conv: %w", err)
		}
		// Add all server members to the conversation
		if _, err := tx.Exec(ctx,
			`INSERT INTO conversation_members (conversation_id, user_id, role)
			 SELECT $1, user_id, 0 FROM server_members WHERE server_id = $2`,
			convID, serverID); err != nil {
			return nil, fmt.Errorf("add members to channel: %w", err)
		}
		convIDPtr = &convID
	}

	var c Channel
	err = tx.QueryRow(ctx,
		`INSERT INTO channels (server_id, conversation_id, name, channel_type, category_id, topic, position)
		 VALUES ($1, $2, $3, $4, $5, $6, COALESCE((SELECT MAX(position) + 1 FROM channels WHERE server_id = $1), 0))
		 RETURNING id, server_id, conversation_id, name, channel_type, category_id, position, topic,
		           COALESCE(nsfw, FALSE), COALESCE(slowmode_secs, 0), COALESCE(created_at, now())`,
		serverID, convIDPtr, name, channelType, categoryID, topic,
	).Scan(&c.ID, &c.ServerID, &c.ConversationID, &c.Name, &c.ChannelType,
		&c.CategoryID, &c.Position, &c.Topic, &c.NSFW, &c.SlowmodeSecs, &c.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create channel: %w", err)
	}
	return &c, tx.Commit(ctx)
}

// UpdateChannel updates name/topic/nsfw/slowmode.
func (db *DB) UpdateChannel(ctx context.Context, channelID string, name, topic *string, nsfw *bool, slowmode *int32) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE channels
		 SET name = COALESCE($2, name),
		     topic = COALESCE($3, topic),
		     nsfw = COALESCE($4, nsfw),
		     slowmode_secs = COALESCE($5, slowmode_secs)
		 WHERE id = $1`,
		channelID, name, topic, nsfw, slowmode)
	return err
}

// DeleteChannel removes a channel and its backing conversation.
func (db *DB) DeleteChannel(ctx context.Context, channelID string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var convID *string
	err = tx.QueryRow(ctx, `SELECT conversation_id FROM channels WHERE id = $1`, channelID).Scan(&convID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM channels WHERE id = $1`, channelID); err != nil {
		return err
	}
	if convID != nil {
		if _, err := tx.Exec(ctx, `DELETE FROM conversations WHERE id = $1`, *convID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// GetChannel returns a channel by ID.
func (db *DB) GetChannel(ctx context.Context, channelID string) (*Channel, error) {
	var c Channel
	err := db.Pool.QueryRow(ctx,
		`SELECT id, server_id, conversation_id, name, channel_type, category_id, position, topic,
		        COALESCE(nsfw, FALSE), COALESCE(slowmode_secs, 0), COALESCE(created_at, now())
		 FROM channels WHERE id = $1`, channelID,
	).Scan(&c.ID, &c.ServerID, &c.ConversationID, &c.Name, &c.ChannelType,
		&c.CategoryID, &c.Position, &c.Topic, &c.NSFW, &c.SlowmodeSecs, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ─── Invites ─────────────────────────────────────────

// generateInviteCode produces an 8-char URL-safe code.
func generateInviteCode() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// CreateInvite creates a new invite for a server.
func (db *DB) CreateInvite(ctx context.Context, serverID, createdBy string, maxUses int32, expiresAt *time.Time) (*Invite, error) {
	// Try a few times in case of unlikely collision
	for i := 0; i < 5; i++ {
		code := generateInviteCode()
		var inv Invite
		err := db.Pool.QueryRow(ctx,
			`INSERT INTO server_invites (code, server_id, created_by, max_uses, expires_at)
			 VALUES ($1, $2, $3::uuid, $4, $5)
			 RETURNING code, server_id, created_by, max_uses, uses, expires_at, created_at`,
			code, serverID, createdBy, maxUses, expiresAt,
		).Scan(&inv.Code, &inv.ServerID, &inv.CreatedBy, &inv.MaxUses, &inv.Uses, &inv.ExpiresAt, &inv.CreatedAt)
		if err == nil {
			return &inv, nil
		}
	}
	return nil, errors.New("failed to generate unique invite code")
}

// GetInvite looks up an invite by code, returns server info if valid.
func (db *DB) GetInvite(ctx context.Context, code string) (*Invite, error) {
	var inv Invite
	err := db.Pool.QueryRow(ctx,
		`SELECT code, server_id, created_by, max_uses, uses, expires_at, created_at
		 FROM server_invites WHERE code = $1`, code,
	).Scan(&inv.Code, &inv.ServerID, &inv.CreatedBy, &inv.MaxUses, &inv.Uses, &inv.ExpiresAt, &inv.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &inv, nil
}

// UseInvite atomically validates and consumes an invite, joining the user to the server.
// Returns the joined server.
func (db *DB) UseInvite(ctx context.Context, code, userID string) (*Server, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var inv Invite
	err = tx.QueryRow(ctx,
		`SELECT code, server_id, created_by, max_uses, uses, expires_at, created_at
		 FROM server_invites WHERE code = $1 FOR UPDATE`, code,
	).Scan(&inv.Code, &inv.ServerID, &inv.CreatedBy, &inv.MaxUses, &inv.Uses, &inv.ExpiresAt, &inv.CreatedAt)
	if err != nil {
		return nil, errors.New("invite not found")
	}
	if inv.ExpiresAt != nil && time.Now().After(*inv.ExpiresAt) {
		return nil, errors.New("invite expired")
	}
	if inv.MaxUses > 0 && inv.Uses >= inv.MaxUses {
		return nil, errors.New("invite usage limit reached")
	}

	// Check if user already in server
	var alreadyMember bool
	err = tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2::uuid)`,
		inv.ServerID, userID).Scan(&alreadyMember)
	if err != nil {
		return nil, err
	}

	if !alreadyMember {
		if _, err := tx.Exec(ctx,
			`INSERT INTO server_members (server_id, user_id) VALUES ($1, $2::uuid)`,
			inv.ServerID, userID); err != nil {
			return nil, fmt.Errorf("join server: %w", err)
		}
		// Add to all text channels in this server
		if _, err := tx.Exec(ctx,
			`INSERT INTO conversation_members (conversation_id, user_id, role)
			 SELECT conversation_id, $2::uuid, 0 FROM channels
			 WHERE server_id = $1 AND channel_type = 0 AND conversation_id IS NOT NULL
			 ON CONFLICT DO NOTHING`,
			inv.ServerID, userID); err != nil {
			return nil, fmt.Errorf("add to channels: %w", err)
		}
	}

	// Increment uses
	if _, err := tx.Exec(ctx,
		`UPDATE server_invites SET uses = uses + 1 WHERE code = $1`, code); err != nil {
		return nil, err
	}

	var s Server
	err = tx.QueryRow(ctx,
		`SELECT id, name, description, icon_url, owner_id, created_at FROM servers WHERE id = $1`,
		inv.ServerID,
	).Scan(&s.ID, &s.Name, &s.Description, &s.IconURL, &s.OwnerID, &s.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &s, tx.Commit(ctx)
}

// GetServerInvites lists all invites for a server.
func (db *DB) GetServerInvites(ctx context.Context, serverID string) ([]Invite, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT code, server_id, created_by, max_uses, uses, expires_at, created_at
		 FROM server_invites WHERE server_id = $1 ORDER BY created_at DESC`,
		serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		var inv Invite
		if err := rows.Scan(&inv.Code, &inv.ServerID, &inv.CreatedBy, &inv.MaxUses, &inv.Uses, &inv.ExpiresAt, &inv.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// RevokeInvite deletes an invite code.
func (db *DB) RevokeInvite(ctx context.Context, code string) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM server_invites WHERE code = $1`, code)
	return err
}

// ─── Audit log ───────────────────────────────────────

// LogAudit records a server-side audit event (best-effort, errors swallowed).
func (db *DB) LogAudit(ctx context.Context, serverID, actorID, action string, targetID *string, metadata []byte) {
	_, _ = db.Pool.Exec(ctx,
		`INSERT INTO server_audit (server_id, actor_id, action, target_id, metadata)
		 VALUES ($1, $2::uuid, $3, $4, $5)`,
		serverID, actorID, action, targetID, metadata)
}
