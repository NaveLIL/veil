package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

const ChannelReadPermissions = PermViewChannel | PermReadMessageHistory

// HasAllPermissions requires every requested bit (or Administrator), unlike
// HasPermission which intentionally answers a single-bit capability query.
func (db *DB) HasAllPermissions(ctx context.Context, serverID, userID string, required uint64) (bool, error) {
	if required&^AllRolePermissions != 0 {
		return false, nil
	}
	server, err := db.GetServer(ctx, serverID)
	if err != nil {
		return false, err
	}
	member, err := db.IsServerMember(ctx, serverID, userID)
	if err != nil || !member {
		return false, err
	}
	if server.OwnerID == userID {
		return true, nil
	}
	permissions, err := db.GetUserPermissions(ctx, serverID, userID)
	if err != nil {
		return false, err
	}
	return permissions&PermAdministrator != 0 || permissions&required == required, nil
}

// CanAccessConversation preserves the membership-only semantics of DMs and
// standalone groups. Server-backed channel conversations additionally require
// the requested server role bits.
func (db *DB) CanAccessConversation(ctx context.Context, conversationID, userID string, required uint64) (bool, error) {
	var conversationType int16
	var serverID *string
	err := db.Pool.QueryRow(ctx,
		`SELECT conv_type, server_id FROM conversations WHERE id = $1::uuid`,
		conversationID,
	).Scan(&conversationType, &serverID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	member, err := db.IsConversationMember(ctx, conversationID, userID)
	if err != nil || !member {
		return false, err
	}
	if conversationType != 2 {
		return true, nil
	}
	if serverID == nil {
		return false, nil
	}
	return db.HasAllPermissions(ctx, *serverID, userID, required)
}

// GetAuthorizedConversationMembers returns all current recipients for a
// conversation. DMs/groups return their ordinary member set; channels filter
// dynamically by role permissions so role changes take effect immediately.
func (db *DB) GetAuthorizedConversationMembers(ctx context.Context, conversationID string, required uint64) ([]string, error) {
	var conversationType int16
	err := db.Pool.QueryRow(ctx,
		`SELECT conv_type FROM conversations WHERE id = $1::uuid`,
		conversationID,
	).Scan(&conversationType)
	if err != nil {
		return nil, err
	}
	if conversationType != 2 {
		return db.GetConversationMembers(ctx, conversationID)
	}

	rows, err := db.Pool.Query(ctx,
		`SELECT member.user_id::text
		 FROM conversation_members member
		 JOIN conversations conversation ON conversation.id = member.conversation_id
		 JOIN servers server ON server.id = conversation.server_id AND server.deleted_at IS NULL
		 JOIN server_members server_member
		   ON server_member.server_id = server.id AND server_member.user_id = member.user_id
		 LEFT JOIN roles role
		   ON role.server_id = server.id
		  AND (role.is_default = TRUE OR EXISTS (
		    SELECT 1 FROM member_roles assignment
		    WHERE assignment.server_id = server.id
		      AND assignment.user_id = member.user_id
		      AND assignment.role_id = role.id
		  ))
		 WHERE conversation.id = $1::uuid AND conversation.conv_type = 2
		 GROUP BY member.user_id, server.owner_id
		 HAVING server.owner_id = member.user_id
		    OR (COALESCE(BIT_OR(role.permissions), 0) & $2::bigint) <> 0
		    OR (COALESCE(BIT_OR(role.permissions), 0) & $3::bigint) = $3::bigint
		 ORDER BY member.user_id`,
		conversationID, int64(PermAdministrator), int64(required),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	members := make([]string, 0)
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}
		members = append(members, userID)
	}
	return members, rows.Err()
}

// GetAuthorizedConversationMemberBindings returns the public cryptographic
// directory for exactly the users currently authorized to receive traffic in
// a conversation. It deliberately derives the ID set through the same ACL
// helper used by message and sender-key fan-out.
func (db *DB) GetAuthorizedConversationMemberBindings(ctx context.Context, conversationID string, required uint64) ([]ConversationMemberBinding, error) {
	memberIDs, err := db.GetAuthorizedConversationMembers(ctx, conversationID, required)
	if err != nil {
		return nil, err
	}
	if len(memberIDs) == 0 {
		return []ConversationMemberBinding{}, nil
	}
	rows, err := db.Pool.Query(ctx,
		`SELECT member.user_id::text, users.username, users.identity_key,
		        users.signing_key, member.role, member.joined_at
		 FROM conversation_members member
		 JOIN users ON users.id = member.user_id
		 WHERE member.conversation_id = $1::uuid
		   AND member.user_id = ANY($2::uuid[])
		 ORDER BY member.role DESC, member.joined_at ASC, member.user_id ASC`,
		conversationID, memberIDs,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	members := make([]ConversationMemberBinding, 0, len(memberIDs))
	for rows.Next() {
		var member ConversationMemberBinding
		if err := rows.Scan(
			&member.UserID, &member.Username, &member.IdentityKey,
			&member.SigningKey, &member.Role, &member.JoinedAt,
		); err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, rows.Err()
}
