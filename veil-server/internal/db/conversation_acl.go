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
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	allowed, err := canAccessConversationWithQuery(
		ctx, tx, conversationID, userID, required,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return allowed, nil
}

// GetAuthorizedConversationMembers returns all current recipients for a
// conversation. DMs/groups return their ordinary member set; channels filter
// dynamically by role permissions so role changes take effect immediately.
func (db *DB) GetAuthorizedConversationMembers(ctx context.Context, conversationID string, required uint64) ([]string, error) {
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	members, err := authorizedConversationMemberIDs(
		ctx, tx, conversationID, required,
	)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return members, nil
}

// GetConversationMemberBindingsForRequester authorizes the requester and
// reads the returned public directory from one repeatable-read snapshot. This
// prevents a committed role/history revocation from landing between a handler
// precheck and the member-key query.
func (db *DB) GetConversationMemberBindingsForRequester(ctx context.Context, conversationID, requesterID string, required uint64) ([]ConversationMemberBinding, error) {
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	allowed, err := canAccessConversationWithQuery(
		ctx, tx, conversationID, requesterID, required,
	)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrConversationAccessDenied
	}
	members, err := getAuthorizedConversationMemberBindingsWithQuery(
		ctx, tx, conversationID, required,
	)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return members, nil
}

func getAuthorizedConversationMemberBindingsWithQuery(ctx context.Context, query rosterQuerier, conversationID string, required uint64) ([]ConversationMemberBinding, error) {
	memberIDs, err := authorizedConversationMemberIDs(ctx, query, conversationID, required)
	if err != nil {
		return nil, err
	}
	if len(memberIDs) == 0 {
		return []ConversationMemberBinding{}, nil
	}
	rows, err := query.Query(ctx,
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
