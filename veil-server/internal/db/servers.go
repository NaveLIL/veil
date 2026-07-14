package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ─── Permission bitmask ──────────────────────────────

const (
	PermViewChannel        uint64 = 1 << 0 // can see channel exists in list
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
	AllRolePermissions            = PermViewChannel | PermSendMessages | PermManageMessages |
		PermMentionEveryone | PermManageChannels | PermManageRoles | PermKickMembers |
		PermBanMembers | PermCreateInvite | PermManageServer | PermReadMessageHistory |
		PermAdministrator
	AllChannelPermissions = PermViewChannel | PermSendMessages | PermManageMessages |
		PermMentionEveryone | PermManageChannels | PermReadMessageHistory

	// Default @everyone gets visibility + history + send. Admission capability
	// creation is owner/explicit-role only.
	DefaultEveryonePerms = PermViewChannel | PermReadMessageHistory | PermSendMessages
)

// ─── Models ──────────────────────────────────────────

type Server struct {
	ID          string
	Name        string
	Description *string
	OwnerID     string
	CreatedAt   time.Time
}

type ServerMember struct {
	ServerID    string
	UserID      string
	IdentityKey []byte
	SigningKey  []byte
	Username    string
	Nickname    *string
	JoinedAt    time.Time
	RoleIDs     []string
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

const (
	ChannelOverwriteRole int16 = iota
	ChannelOverwriteUser
)

type ChannelOverwrite struct {
	ChannelID  string
	TargetID   string
	TargetType int16
	Allow      uint64
	Deny       uint64
}

type Invite struct {
	ID             string
	PublicSelector string
	SecretHash     []byte
	Version        int16
	LinkType       string
	ServerID       string
	CreatedBy      string
	MaxUses        int32
	Uses           int32
	ExpiresAt      time.Time
	RevokedAt      *time.Time
	CreatedAt      time.Time
}

type CreatedInvite struct {
	Invite
	Secret string
}

type ServerBan struct {
	ServerID  string
	UserID    string
	Username  string
	BannedBy  string
	Reason    *string
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
		 RETURNING id, name, description, owner_id, created_at`,
		name, ownerUserID,
	).Scan(&s.ID, &s.Name, &s.Description, &s.OwnerID, &s.CreatedAt)
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
		`SELECT id, name, description, owner_id, created_at
		 FROM servers WHERE id = $1 AND deleted_at IS NULL`, serverID,
	).Scan(&s.ID, &s.Name, &s.Description, &s.OwnerID, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// GetUserServers returns all servers a user is a member of.
func (db *DB) GetUserServers(ctx context.Context, userID string) ([]Server, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT s.id, s.name, s.description, s.owner_id, s.created_at
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
		if err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.OwnerID, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpdateServer updates Space name/description. Artwork stays local and deterministic.
func (db *DB) UpdateServer(ctx context.Context, serverID string, name, description *string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE servers
		 SET name = COALESCE($2, name),
		     description = COALESCE($3, description)
		 WHERE id = $1`,
		serverID, name, description)
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

// RemoveServerMember removes a user from a server.
// Also cleans up conversation memberships in this server's channels and any
// role assignments. Does not delete the user account itself.
func (db *DB) RemoveServerMember(ctx context.Context, serverID, userID string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Remove from all conversation_members for this server's channels.
	// (The conversation_members FK does not cascade with server_members.)
	if _, err := tx.Exec(ctx,
		`DELETE FROM conversation_members
		 WHERE user_id = $2::uuid
		   AND conversation_id IN (
		       SELECT conversation_id FROM channels
		       WHERE server_id = $1 AND conversation_id IS NOT NULL
		   )`,
		serverID, userID); err != nil {
		return fmt.Errorf("clean conv members: %w", err)
	}

	// member_roles cascades on (server_id, user_id) FK to server_members,
	// so removing the row below will also drop role assignments.
	if _, err := tx.Exec(ctx,
		`DELETE FROM server_members WHERE server_id = $1 AND user_id = $2::uuid`,
		serverID, userID); err != nil {
		return fmt.Errorf("delete member: %w", err)
	}

	return tx.Commit(ctx)
}

// BanServerMember records the authoritative admission denial and removes the
// current Space/Room rosters in the same transaction. A failed operation never
// leaves a kicked-but-unbanned account that can immediately rejoin.
func (db *DB) BanServerMember(ctx context.Context, serverID, userID, bannedBy string, reason *string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`INSERT INTO server_bans (server_id, user_id, banned_by, reason)
		 VALUES ($1, $2::uuid, $3::uuid, $4)
		 ON CONFLICT (server_id, user_id) DO UPDATE
		 SET banned_by=EXCLUDED.banned_by, reason=EXCLUDED.reason, created_at=now()`,
		serverID, userID, bannedBy, reason,
	); err != nil {
		return fmt.Errorf("record Space ban: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM conversation_members
		 WHERE user_id=$2::uuid AND conversation_id IN (
			SELECT conversation_id FROM channels
			WHERE server_id=$1 AND conversation_id IS NOT NULL
		)`, serverID, userID,
	); err != nil {
		return fmt.Errorf("remove banned Room rosters: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM server_members WHERE server_id=$1 AND user_id=$2::uuid`,
		serverID, userID,
	); err != nil {
		return fmt.Errorf("remove banned Space member: %w", err)
	}
	return tx.Commit(ctx)
}

func (db *DB) UnbanServerMember(ctx context.Context, serverID, userID string) error {
	command, err := db.Pool.Exec(ctx,
		`DELETE FROM server_bans WHERE server_id=$1 AND user_id=$2::uuid`, serverID, userID)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return errors.New("ban not found")
	}
	return nil
}

func (db *DB) GetServerBans(ctx context.Context, serverID string) ([]ServerBan, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT ban.server_id, ban.user_id, user_account.username,
		        ban.banned_by, ban.reason, ban.created_at
		 FROM server_bans ban
		 JOIN users user_account ON user_account.id=ban.user_id
		 WHERE ban.server_id=$1 ORDER BY ban.created_at DESC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bans := make([]ServerBan, 0)
	for rows.Next() {
		var ban ServerBan
		if err := rows.Scan(&ban.ServerID, &ban.UserID, &ban.Username, &ban.BannedBy, &ban.Reason, &ban.CreatedAt); err != nil {
			return nil, err
		}
		bans = append(bans, ban)
	}
	return bans, rows.Err()
}

// GetServerMembers returns all members of a server with their assigned role IDs.
func (db *DB) GetServerMembers(ctx context.Context, serverID string) ([]ServerMember, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT sm.server_id, sm.user_id, u.identity_key, u.signing_key, u.username, sm.nickname, sm.joined_at,
		        COALESCE(array_agg(mr.role_id) FILTER (WHERE mr.role_id IS NOT NULL), '{}')::uuid[]
		 FROM server_members sm
		 JOIN users u ON u.id = sm.user_id
		 LEFT JOIN member_roles mr ON mr.server_id = sm.server_id AND mr.user_id = sm.user_id
		 WHERE sm.server_id = $1
		 GROUP BY sm.server_id, sm.user_id, u.identity_key, u.signing_key, u.username, sm.nickname, sm.joined_at
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
		if err := rows.Scan(&m.ServerID, &m.UserID, &m.IdentityKey, &m.SigningKey, &m.Username, &m.Nickname, &m.JoinedAt, &roleIDs); err != nil {
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
		 FROM server_members sm
		 JOIN roles r ON r.server_id = sm.server_id
		 WHERE sm.server_id = $1 AND sm.user_id = $2::uuid AND (
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

// GetRole returns a role only when both its server and role IDs match.
func (db *DB) GetRole(ctx context.Context, serverID, roleID string) (*Role, error) {
	var role Role
	var permissions int64
	err := db.Pool.QueryRow(ctx,
		`SELECT id, server_id, name, permissions, position, color, is_default, hoist, mentionable
		 FROM roles WHERE server_id = $1::uuid AND id = $2::uuid`,
		serverID, roleID,
	).Scan(&role.ID, &role.ServerID, &role.Name, &permissions, &role.Position,
		&role.Color, &role.IsDefault, &role.Hoist, &role.Mentionable)
	if err != nil {
		return nil, err
	}
	role.Permissions = uint64(permissions)
	return &role, nil
}

// GetHighestRolePosition returns the highest assigned/default role for a
// member. Callers must separately handle the server owner, whose hierarchy is
// above every database role.
func (db *DB) GetHighestRolePosition(ctx context.Context, serverID, userID string) (int16, error) {
	var position int16
	err := db.Pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(r.position), 0)
		 FROM server_members sm
		 JOIN roles r ON r.server_id = sm.server_id
		 WHERE sm.server_id = $1::uuid AND sm.user_id = $2::uuid
		   AND (r.is_default = TRUE OR EXISTS (
		     SELECT 1 FROM member_roles mr
		     WHERE mr.server_id = sm.server_id AND mr.user_id = sm.user_id AND mr.role_id = r.id
		   ))`,
		serverID, userID,
	).Scan(&position)
	return position, err
}

// CreateRole creates a new role. Returns the new role.
func (db *DB) CreateRole(ctx context.Context, serverID, name string, perms uint64, color *int32, positionCeiling *int16) (*Role, error) {
	var r Role
	var p int64
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO roles (server_id, name, permissions, position, color)
		 VALUES ($1, $2, $3,
		   CASE WHEN $5::smallint IS NULL
		     THEN LEAST(COALESCE((SELECT MAX(position)::integer + 1 FROM roles WHERE server_id = $1), 1), 32767)
		     ELSE LEAST(COALESCE((SELECT MAX(position)::integer + 1 FROM roles WHERE server_id = $1), 1), $5::smallint)
		   END,
		   $4)
		 RETURNING id, server_id, name, permissions, position, color, is_default, hoist, mentionable`,
		serverID, name, int64(perms), color, positionCeiling,
	).Scan(&r.ID, &r.ServerID, &r.Name, &p, &r.Position, &r.Color, &r.IsDefault, &r.Hoist, &r.Mentionable)
	if err != nil {
		return nil, err
	}
	r.Permissions = uint64(p)
	return &r, nil
}

// UpdateRole updates name/permissions/color of a role.
func (db *DB) UpdateRole(ctx context.Context, serverID, roleID string, name *string, perms *uint64, color *int32) error {
	var permsArg interface{}
	if perms != nil {
		permsArg = int64(*perms)
	}
	result, err := db.Pool.Exec(ctx,
		`UPDATE roles
		 SET name = COALESCE($3, name),
		     permissions = COALESCE($4, permissions),
		     color = COALESCE($5, color)
		 WHERE server_id = $1::uuid AND id = $2::uuid`,
		serverID, roleID, name, permsArg, color)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return errors.New("role not found in server")
	}
	return nil
}

// DeleteRole removes a role (default @everyone cannot be deleted).
func (db *DB) DeleteRole(ctx context.Context, serverID, roleID string) error {
	res, err := db.Pool.Exec(ctx,
		`DELETE FROM roles WHERE server_id = $1::uuid AND id = $2::uuid AND is_default = FALSE`,
		serverID, roleID)
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
	result, err := db.Pool.Exec(ctx,
		`INSERT INTO member_roles (server_id, user_id, role_id)
		 SELECT role.server_id, member.user_id, role.id
		 FROM roles role
		 JOIN server_members member ON member.server_id = role.server_id AND member.user_id = $2::uuid
		 WHERE role.server_id = $1::uuid AND role.id = $3::uuid AND role.is_default = FALSE
		 ON CONFLICT (server_id, user_id, role_id)
		 DO UPDATE SET role_id = EXCLUDED.role_id`,
		serverID, userID, roleID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return errors.New("role or target member not found in server")
	}
	return nil
}

// UnassignRole removes a role from a member.
func (db *DB) UnassignRole(ctx context.Context, serverID, userID, roleID string) error {
	result, err := db.Pool.Exec(ctx,
		`DELETE FROM member_roles assignment
		 USING roles role
		 WHERE assignment.server_id = $1::uuid AND assignment.user_id = $2::uuid
		   AND assignment.role_id = $3::uuid
		   AND role.server_id = assignment.server_id AND role.id = assignment.role_id`,
		serverID, userID, roleID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return errors.New("role assignment not found in server")
	}
	return nil
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

// GetVisibleServerChannels returns only channels whose effective overwrite
// result grants VIEW_CHANNEL to the requester. Authorization errors are
// propagated so callers fail closed instead of leaking a partial channel tree.
func (db *DB) GetVisibleServerChannels(ctx context.Context, serverID, userID string) ([]Channel, error) {
	channels, err := db.GetServerChannels(ctx, serverID)
	if err != nil {
		return nil, err
	}
	visible := make([]Channel, 0, len(channels))
	for _, channel := range channels {
		allowed, err := db.HasAllChannelPermissions(ctx, channel.ID, userID, PermViewChannel)
		if err != nil {
			return nil, err
		}
		if allowed {
			visible = append(visible, channel)
		}
	}
	return visible, nil
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

// UpdateChannel updates name/topic/nsfw/slowmode/position/category.
// If clearCategory is true, category_id is set to NULL (move out of any category).
// Otherwise, when categoryID != nil it's set to that value.
func (db *DB) UpdateChannel(ctx context.Context, channelID string, name, topic *string, nsfw *bool, slowmode *int32, position *int16, categoryID *string, clearCategory bool) error {
	if clearCategory {
		_, err := db.Pool.Exec(ctx,
			`UPDATE channels
			 SET name = COALESCE($2, name),
			     topic = COALESCE($3, topic),
			     nsfw = COALESCE($4, nsfw),
			     slowmode_secs = COALESCE($5, slowmode_secs),
			     position = COALESCE($6, position),
			     category_id = NULL
			 WHERE id = $1`,
			channelID, name, topic, nsfw, slowmode, position)
		return err
	}
	_, err := db.Pool.Exec(ctx,
		`UPDATE channels
		 SET name = COALESCE($2, name),
		     topic = COALESCE($3, topic),
		     nsfw = COALESCE($4, nsfw),
		     slowmode_secs = COALESCE($5, slowmode_secs),
		     position = COALESCE($6, position),
		     category_id = COALESCE($7, category_id)
		 WHERE id = $1`,
		channelID, name, topic, nsfw, slowmode, position, categoryID)
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

const veilLinkTokenBytes = 32

var veilLinkHashDomain = []byte("veil-link-v1\x00")

func generateVeilLinkToken() (string, error) {
	return generateVeilLinkTokenFrom(rand.Reader)
}

func generateVeilLinkTokenFrom(reader io.Reader) (string, error) {
	b := make([]byte, veilLinkTokenBytes)
	if _, err := io.ReadFull(reader, b); err != nil {
		return "", fmt.Errorf("generate Veil Link token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashVeilLinkSecret(secret string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(raw) != veilLinkTokenBytes || base64.RawURLEncoding.EncodeToString(raw) != secret {
		return nil, errors.New("invalid Veil Link secret")
	}
	hashInput := make([]byte, 0, len(veilLinkHashDomain)+len(raw))
	hashInput = append(hashInput, veilLinkHashDomain...)
	hashInput = append(hashInput, raw...)
	hash := sha256.Sum256(hashInput)
	return hash[:], nil
}

// CreateInvite creates a bounded Veil Link and returns its raw secret exactly
// once. Only the domain-separated hash is stored.
func (db *DB) CreateInvite(ctx context.Context, serverID, createdBy string, maxUses int32, lifetime time.Duration) (*CreatedInvite, error) {
	createdAt := time.Now()
	expiresAt := createdAt.Add(lifetime)
	secret, err := generateVeilLinkToken()
	if err != nil {
		return nil, err
	}
	secretHash, err := hashVeilLinkSecret(secret)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 5; i++ {
		selector, tokenErr := generateVeilLinkToken()
		if tokenErr != nil {
			return nil, tokenErr
		}
		tx, txErr := db.Pool.Begin(ctx)
		if txErr != nil {
			return nil, txErr
		}
		var inv Invite
		err = tx.QueryRow(ctx,
			`INSERT INTO server_invites
			 (public_selector, secret_hash, server_id, created_by, max_uses, expires_at, created_at)
			 VALUES ($1, $2, $3::uuid, $4::uuid, $5, $6, $7)
			 RETURNING id, public_selector, version, link_type, server_id, created_by,
			           max_uses, uses, expires_at, revoked_at, created_at`,
			selector, secretHash, serverID, createdBy, maxUses, expiresAt, createdAt,
		).Scan(
			&inv.ID, &inv.PublicSelector, &inv.Version, &inv.LinkType,
			&inv.ServerID, &inv.CreatedBy, &inv.MaxUses, &inv.Uses,
			&inv.ExpiresAt, &inv.RevokedAt, &inv.CreatedAt,
		)
		if err == nil {
			if err = insertVeilLinkEvent(ctx, tx, inv.ServerID, &inv.ID, createdBy, "created"); err != nil {
				_ = tx.Rollback(ctx)
				return nil, err
			}
			if err = tx.Commit(ctx); err != nil {
				return nil, err
			}
			return &CreatedInvite{Invite: inv, Secret: secret}, nil
		}
		_ = tx.Rollback(ctx)
		if !errors.Is(err, pgx.ErrNoRows) {
			// A selector collision is the only expected retryable failure. Other
			// constraint/connection errors must fail closed.
			var pgErr interface{ SQLState() string }
			if !errors.As(err, &pgErr) || pgErr.SQLState() != "23505" {
				return nil, err
			}
		}
	}
	return nil, errors.New("failed to generate unique Veil Link selector")
}

type veilLinkEventExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func insertVeilLinkEvent(
	ctx context.Context,
	executor veilLinkEventExecutor,
	serverID string,
	linkID *string,
	actorID string,
	eventType string,
) error {
	_, err := executor.Exec(ctx,
		`INSERT INTO veil_link_events (server_id, link_id, actor_id, event_type)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, $4)`,
		serverID, linkID, actorID, eventType,
	)
	return err
}

type inviteRowScanner interface {
	Scan(dest ...any) error
}

func scanInvite(row inviteRowScanner, includeSecretHash bool) (*Invite, error) {
	var inv Invite
	var err error
	if includeSecretHash {
		err = row.Scan(
			&inv.ID, &inv.PublicSelector, &inv.SecretHash, &inv.Version, &inv.LinkType,
			&inv.ServerID, &inv.CreatedBy, &inv.MaxUses, &inv.Uses,
			&inv.ExpiresAt, &inv.RevokedAt, &inv.CreatedAt,
		)
	} else {
		err = row.Scan(
			&inv.ID, &inv.PublicSelector, &inv.Version, &inv.LinkType,
			&inv.ServerID, &inv.CreatedBy, &inv.MaxUses, &inv.Uses,
			&inv.ExpiresAt, &inv.RevokedAt, &inv.CreatedAt,
		)
	}
	if err != nil {
		return nil, err
	}
	return &inv, nil
}

// GetInvite resolves only the public selector. Callers must independently
// enforce active/bounded state; this method never authenticates admission.
func (db *DB) GetInvite(ctx context.Context, selector string) (*Invite, error) {
	return scanInvite(db.Pool.QueryRow(ctx,
		`SELECT id, public_selector, version, link_type, server_id, created_by,
		        max_uses, uses, expires_at, revoked_at, created_at
		 FROM server_invites WHERE public_selector = $1`, selector,
	), false)
}

func (db *DB) AuthenticateInvite(ctx context.Context, selector, secret string) (*Invite, error) {
	providedHash, err := hashVeilLinkSecret(secret)
	if err != nil {
		return nil, errors.New("Veil Link unavailable")
	}
	inv, err := scanInvite(db.Pool.QueryRow(ctx,
		`SELECT id, public_selector, secret_hash, version, link_type, server_id,
		        created_by, max_uses, uses, expires_at, revoked_at, created_at
		 FROM server_invites WHERE public_selector=$1`, selector,
	), true)
	if err != nil || inv.Version != 1 || inv.LinkType != "space" || inv.RevokedAt != nil ||
		time.Now().After(inv.ExpiresAt) || inv.Uses >= inv.MaxUses ||
		subtle.ConstantTimeCompare(providedHash, inv.SecretHash) != 1 {
		return nil, errors.New("Veil Link unavailable")
	}
	inv.SecretHash = nil
	return inv, nil
}

// UseInvite validates and consumes a Veil Link in one transaction. Ban, use
// counter and roster changes are linearized by the locked capability row.
func (db *DB) UseInvite(ctx context.Context, selector, secret, userID string) (*Server, bool, error) {
	providedHash, err := hashVeilLinkSecret(secret)
	if err != nil {
		return nil, false, errors.New("Veil Link unavailable")
	}
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)

	inv, err := scanInvite(tx.QueryRow(ctx,
		`SELECT invite.id, invite.public_selector, invite.secret_hash, invite.version,
		        invite.link_type, invite.server_id, invite.created_by, invite.max_uses,
		        invite.uses, invite.expires_at, invite.revoked_at, invite.created_at
		 FROM server_invites invite
		 JOIN servers server ON server.id = invite.server_id AND server.deleted_at IS NULL
		 WHERE invite.public_selector = $1
		 FOR UPDATE OF invite`, selector,
	), true)
	if err != nil || inv.Version != 1 || inv.LinkType != "space" || inv.RevokedAt != nil ||
		time.Now().After(inv.ExpiresAt) ||
		subtle.ConstantTimeCompare(providedHash, inv.SecretHash) != 1 {
		return nil, false, errors.New("Veil Link unavailable")
	}

	var banned bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM server_bans WHERE server_id=$1 AND user_id=$2::uuid)`,
		inv.ServerID, userID,
	).Scan(&banned); err != nil {
		return nil, false, err
	}
	if banned {
		return nil, false, errors.New("Veil Link unavailable")
	}

	var alreadyMember bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM server_members WHERE server_id=$1 AND user_id=$2::uuid)`,
		inv.ServerID, userID,
	).Scan(&alreadyMember); err != nil {
		return nil, false, err
	}
	if !alreadyMember && inv.Uses >= inv.MaxUses {
		return nil, false, errors.New("Veil Link unavailable")
	}

	if !alreadyMember {
		if _, err := tx.Exec(ctx,
			`INSERT INTO server_members (server_id, user_id) VALUES ($1, $2::uuid)`,
			inv.ServerID, userID,
		); err != nil {
			return nil, false, fmt.Errorf("join Space: %w", err)
		}

		rows, err := tx.Query(ctx,
			`SELECT id::text, conversation_id::text FROM channels
			 WHERE server_id=$1 AND channel_type=0 AND conversation_id IS NOT NULL`,
			inv.ServerID,
		)
		if err != nil {
			return nil, false, err
		}
		type roomConversation struct{ roomID, conversationID string }
		rooms := make([]roomConversation, 0)
		for rows.Next() {
			var room roomConversation
			if err := rows.Scan(&room.roomID, &room.conversationID); err != nil {
				rows.Close()
				return nil, false, err
			}
			rooms = append(rooms, room)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, false, err
		}
		rows.Close()
		for _, room := range rooms {
			permissions, err := getChannelPermissions(ctx, tx, room.roomID, userID)
			if err != nil {
				return nil, false, err
			}
			if permissions&PermViewChannel == 0 {
				continue
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO conversation_members (conversation_id, user_id, role)
				 VALUES ($1::uuid, $2::uuid, 0) ON CONFLICT DO NOTHING`,
				room.conversationID, userID,
			); err != nil {
				return nil, false, fmt.Errorf("join Room roster: %w", err)
			}
		}

		if _, err := tx.Exec(ctx,
			`UPDATE server_invites SET uses=uses+1 WHERE id=$1::uuid`, inv.ID,
		); err != nil {
			return nil, false, err
		}
		if err := insertVeilLinkEvent(ctx, tx, inv.ServerID, &inv.ID, userID, "joined"); err != nil {
			return nil, false, err
		}
	}

	var server Server
	if err := tx.QueryRow(ctx,
		`SELECT id, name, description, owner_id, created_at
		 FROM servers WHERE id=$1 AND deleted_at IS NULL`, inv.ServerID,
	).Scan(&server.ID, &server.Name, &server.Description, &server.OwnerID, &server.CreatedAt); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return &server, !alreadyMember, nil
}

func (db *DB) GetServerInvites(ctx context.Context, serverID string) ([]Invite, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, public_selector, version, link_type, server_id, created_by,
		        max_uses, uses, expires_at, revoked_at, created_at
		 FROM server_invites WHERE server_id=$1 ORDER BY created_at DESC`, serverID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Invite, 0)
	for rows.Next() {
		inv, err := scanInvite(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, *inv)
	}
	return out, rows.Err()
}

func (db *DB) RevokeInvite(ctx context.Context, serverID, inviteID, actorID string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var revokedID string
	err = tx.QueryRow(ctx,
		`UPDATE server_invites SET revoked_at=now()
		 WHERE id=$1::uuid AND server_id=$2::uuid AND revoked_at IS NULL
		 RETURNING id::text`, inviteID, serverID,
	).Scan(&revokedID)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if checkErr := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM server_invites WHERE id=$1::uuid AND server_id=$2::uuid)`,
			inviteID, serverID,
		).Scan(&exists); checkErr != nil {
			return checkErr
		}
		if !exists {
			return errors.New("Veil Link not found")
		}
		return tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	if err := insertVeilLinkEvent(ctx, tx, serverID, &revokedID, actorID, "revoked"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (db *DB) RevokeAllInvites(ctx context.Context, serverID, actorID string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	command, err := tx.Exec(ctx,
		`UPDATE server_invites SET revoked_at=COALESCE(revoked_at, now())
		 WHERE server_id=$1::uuid AND revoked_at IS NULL`, serverID,
	)
	if err != nil {
		return err
	}
	if command.RowsAffected() > 0 {
		if err := insertVeilLinkEvent(ctx, tx, serverID, nil, actorID, "revoked_all"); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ─── Audit log ───────────────────────────────────────

// LogAudit records a server-side audit event (best-effort, errors swallowed).
func (db *DB) LogAudit(ctx context.Context, serverID, actorID, action string, targetID *string, metadata []byte) {
	_, _ = db.Pool.Exec(ctx,
		`INSERT INTO server_audit (server_id, actor_id, action, target_id, metadata)
		 VALUES ($1, $2::uuid, $3, $4, $5)`,
		serverID, actorID, action, targetID, metadata)
}
