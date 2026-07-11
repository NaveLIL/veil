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
	var channelID *string
	err := db.Pool.QueryRow(ctx,
		`SELECT conversation.conv_type, channel.id
		 FROM conversations conversation
		 LEFT JOIN channels channel ON channel.conversation_id = conversation.id
		 WHERE conversation.id = $1::uuid`,
		conversationID,
	).Scan(&conversationType, &channelID)
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
	if channelID == nil {
		return false, nil
	}
	return db.HasAllChannelPermissions(ctx, *channelID, userID, required)
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
		`SELECT user_id::text
		 FROM conversation_members
		 WHERE conversation_id = $1::uuid
		 ORDER BY user_id`,
		conversationID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := make([]string, 0)
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}
		candidates = append(candidates, userID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	members := make([]string, 0, len(candidates))
	for _, userID := range candidates {
		allowed, err := db.CanAccessConversation(ctx, conversationID, userID, required)
		if err != nil {
			return nil, err
		}
		if allowed {
			members = append(members, userID)
		}
	}
	return members, nil
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
