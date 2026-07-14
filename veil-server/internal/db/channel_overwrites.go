package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

var ErrInvalidChannelOverwrite = errors.New("invalid channel permission overwrite")

// GetChannelPermissions resolves the effective permissions for one channel in
// deterministic tiers: server roles, @everyone overwrite, aggregate assigned
// role overwrites, then the member overwrite. Within the aggregate role tier,
// allows are applied after denies, matching the established server role model.
// Server owners and members with the server-wide Administrator bit bypass
// channel overwrites.
func (db *DB) GetChannelPermissions(ctx context.Context, channelID, userID string) (uint64, error) {
	return getChannelPermissions(ctx, db.Pool, channelID, userID)
}

// getChannelPermissions keeps permission resolution available to security-
// sensitive callers that must evaluate ACL state inside their own transaction.
// Both pgx.Pool and pgx.Tx satisfy bindingQuerier.
func getChannelPermissions(ctx context.Context, query bindingQuerier, channelID, userID string) (uint64, error) {
	var (
		owner                       bool
		basePermissions             int64
		defaultRoleCount            int64
		everyoneAllow, everyoneDeny int64
		roleAllow, roleDeny         int64
		memberAllow, memberDeny     int64
	)
	err := query.QueryRow(ctx,
		`WITH channel_scope AS (
		   SELECT channel.id AS channel_id, channel.server_id, server.owner_id
		   FROM channels channel
		   JOIN servers server ON server.id = channel.server_id AND server.deleted_at IS NULL
		   WHERE channel.id = $1::uuid
		 ), member_scope AS (
		   SELECT channel_scope.*, member.user_id
		   FROM channel_scope
		   JOIN server_members member
		     ON member.server_id = channel_scope.server_id
		    AND member.user_id = $2::uuid
		 ), applicable_roles AS (
		   SELECT role.id, role.permissions, role.is_default
		   FROM member_scope
		   JOIN roles role ON role.server_id = member_scope.server_id
		   WHERE role.is_default = TRUE OR EXISTS (
		     SELECT 1 FROM member_roles assignment
		     WHERE assignment.server_id = member_scope.server_id
		       AND assignment.user_id = member_scope.user_id
		       AND assignment.role_id = role.id
		   )
		 ), base AS (
		   SELECT member_scope.channel_id, member_scope.owner_id, member_scope.user_id,
		          COALESCE(BIT_OR(applicable_roles.permissions), 0) AS permissions,
		          COUNT(*) FILTER (WHERE applicable_roles.is_default = TRUE) AS default_role_count
		   FROM member_scope
		   LEFT JOIN applicable_roles ON TRUE
		   GROUP BY member_scope.channel_id, member_scope.owner_id, member_scope.user_id
		 ), everyone_overwrite AS (
		   SELECT COALESCE(BIT_OR(overwrite.allow), 0) AS allow,
		          COALESCE(BIT_OR(overwrite.deny), 0) AS deny
		   FROM base
		   JOIN applicable_roles role ON role.is_default = TRUE
		   JOIN channel_overwrites overwrite
		     ON overwrite.channel_id = base.channel_id
		    AND overwrite.target_type = 0
		    AND overwrite.target_id = role.id
		 ), role_overwrites AS (
		   SELECT COALESCE(BIT_OR(overwrite.allow), 0) AS allow,
		          COALESCE(BIT_OR(overwrite.deny), 0) AS deny
		   FROM base
		   JOIN applicable_roles role ON role.is_default = FALSE
		   JOIN channel_overwrites overwrite
		     ON overwrite.channel_id = base.channel_id
		    AND overwrite.target_type = 0
		    AND overwrite.target_id = role.id
		 ), member_overwrite AS (
		   SELECT COALESCE(BIT_OR(overwrite.allow), 0) AS allow,
		          COALESCE(BIT_OR(overwrite.deny), 0) AS deny
		   FROM base
		   JOIN channel_overwrites overwrite
		     ON overwrite.channel_id = base.channel_id
		    AND overwrite.target_type = 1
		    AND overwrite.target_id = base.user_id
		 )
		 SELECT base.owner_id = base.user_id, base.permissions, base.default_role_count,
		        COALESCE(everyone_overwrite.allow, 0), COALESCE(everyone_overwrite.deny, 0),
		        COALESCE(role_overwrites.allow, 0), COALESCE(role_overwrites.deny, 0),
		        COALESCE(member_overwrite.allow, 0), COALESCE(member_overwrite.deny, 0)
		 FROM base
		 LEFT JOIN everyone_overwrite ON TRUE
		 LEFT JOIN role_overwrites ON TRUE
		 LEFT JOIN member_overwrite ON TRUE`,
		channelID, userID,
	).Scan(
		&owner, &basePermissions, &defaultRoleCount,
		&everyoneAllow, &everyoneDeny,
		&roleAllow, &roleDeny,
		&memberAllow, &memberDeny,
	)
	if err != nil {
		return 0, err
	}

	if !isKnownSignedPermissionMask(basePermissions, AllRolePermissions) ||
		!isKnownSignedPermissionMask(everyoneAllow, AllChannelPermissions) ||
		!isKnownSignedPermissionMask(everyoneDeny, AllChannelPermissions) ||
		!isKnownSignedPermissionMask(roleAllow, AllChannelPermissions) ||
		!isKnownSignedPermissionMask(roleDeny, AllChannelPermissions) ||
		!isKnownSignedPermissionMask(memberAllow, AllChannelPermissions) ||
		!isKnownSignedPermissionMask(memberDeny, AllChannelPermissions) {
		return 0, fmt.Errorf("%w: database contains an invalid permission mask", ErrInvalidChannelOverwrite)
	}

	return resolveChannelPermissions(
		owner, uint64(basePermissions), defaultRoleCount,
		uint64(everyoneAllow), uint64(everyoneDeny),
		uint64(roleAllow), uint64(roleDeny),
		uint64(memberAllow), uint64(memberDeny),
	)
}

func isKnownSignedPermissionMask(value int64, known uint64) bool {
	return value >= 0 && uint64(value)&^known == 0
}

func resolveChannelPermissions(
	owner bool,
	basePermissions uint64,
	defaultRoleCount int64,
	everyoneAllow, everyoneDeny uint64,
	roleAllow, roleDeny uint64,
	memberAllow, memberDeny uint64,
) (uint64, error) {
	if owner || basePermissions&PermAdministrator != 0 {
		return basePermissions | PermAdministrator, nil
	}
	if defaultRoleCount != 1 {
		return 0, fmt.Errorf("%w: server must have exactly one default role", ErrInvalidChannelOverwrite)
	}
	permissions := applyChannelOverwrite(basePermissions, everyoneAllow, everyoneDeny)
	permissions = applyChannelOverwrite(permissions, roleAllow, roleDeny)
	permissions = applyChannelOverwrite(permissions, memberAllow, memberDeny)
	return permissions, nil
}

func applyChannelOverwrite(permissions, allow, deny uint64) uint64 {
	return (permissions &^ deny) | allow
}

// HasAllChannelPermissions requires every requested channel-scoped bit. An
// unknown/non-channel bit is rejected rather than silently ignored.
func (db *DB) HasAllChannelPermissions(ctx context.Context, channelID, userID string, required uint64) (bool, error) {
	if required&^AllChannelPermissions != 0 {
		return false, nil
	}
	permissions, err := db.GetChannelPermissions(ctx, channelID, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return permissions&PermAdministrator != 0 || permissions&required == required, nil
}

func (db *DB) GetChannelOverwrites(ctx context.Context, channelID string) ([]ChannelOverwrite, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT channel_id::text, target_id::text, target_type, allow, deny
		 FROM channel_overwrites
		 WHERE channel_id = $1::uuid
		 ORDER BY target_type, target_id`,
		channelID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	overwrites := make([]ChannelOverwrite, 0)
	for rows.Next() {
		var overwrite ChannelOverwrite
		var allow, deny int64
		if err := rows.Scan(
			&overwrite.ChannelID, &overwrite.TargetID, &overwrite.TargetType,
			&allow, &deny,
		); err != nil {
			return nil, err
		}
		overwrite.Allow = uint64(allow)
		overwrite.Deny = uint64(deny)
		overwrites = append(overwrites, overwrite)
	}
	return overwrites, rows.Err()
}

func (db *DB) UpsertChannelOverwrite(ctx context.Context, overwrite ChannelOverwrite) error {
	if err := validateChannelOverwrite(overwrite); err != nil {
		return err
	}
	result, err := db.Pool.Exec(ctx,
		`INSERT INTO channel_overwrites (channel_id, target_id, target_type, allow, deny)
		 SELECT channel.id, $2::uuid, $3::smallint, $4::bigint, $5::bigint
		 FROM channels channel
		 WHERE channel.id = $1::uuid AND (
		   ($3::smallint = 0 AND EXISTS (
		     SELECT 1 FROM roles role
		     WHERE role.id = $2::uuid AND role.server_id = channel.server_id
		   )) OR
		   ($3::smallint = 1 AND EXISTS (
		     SELECT 1 FROM server_members member
		     WHERE member.user_id = $2::uuid AND member.server_id = channel.server_id
		   ))
		 )
		 ON CONFLICT (channel_id, target_id, target_type)
		 DO UPDATE SET allow = EXCLUDED.allow, deny = EXCLUDED.deny`,
		overwrite.ChannelID, overwrite.TargetID, overwrite.TargetType,
		int64(overwrite.Allow), int64(overwrite.Deny),
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidChannelOverwrite, err)
	}
	if result.RowsAffected() != 1 {
		return ErrInvalidChannelOverwrite
	}
	return nil
}

func validateChannelOverwrite(overwrite ChannelOverwrite) error {
	if overwrite.TargetType != ChannelOverwriteRole && overwrite.TargetType != ChannelOverwriteUser ||
		overwrite.Allow&^AllChannelPermissions != 0 ||
		overwrite.Deny&^AllChannelPermissions != 0 ||
		overwrite.Allow&overwrite.Deny != 0 {
		return ErrInvalidChannelOverwrite
	}
	return nil
}

func (db *DB) DeleteChannelOverwrite(ctx context.Context, channelID, targetID string, targetType int16) error {
	if targetType != ChannelOverwriteRole && targetType != ChannelOverwriteUser {
		return ErrInvalidChannelOverwrite
	}
	result, err := db.Pool.Exec(ctx,
		`DELETE FROM channel_overwrites
		 WHERE channel_id = $1::uuid AND target_id = $2::uuid AND target_type = $3`,
		channelID, targetID, targetType,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}
