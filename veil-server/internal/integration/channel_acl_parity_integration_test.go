//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/NaveLIL/veil/veil-server/internal/db"
)

// TestChannelReadSQLParity locks the deferred target-pruning predicate to the
// same ACL semantics used by the Go runtime. Any Go/SQL drift could either
// leak an old SKDM after authorization loss or destroy history for a target
// that remained continuously authorized.
func TestChannelReadSQLParity(t *testing.T) {
	h := New(t)
	ctx := context.Background()
	owner := h.CreateUser("acl-parity-owner")
	target := h.CreateUser("acl-parity-target")
	serverID := mkServer(t, h, owner, "acl-parity-server")
	joinViaInvite(t, h, target, mkInviteCode(t, h, owner, serverID))

	var channelID, defaultRoleID string
	if err := h.DB.Pool.QueryRow(ctx,
		`SELECT id::text FROM channels
		 WHERE server_id = $1::uuid AND channel_type = 0
		 ORDER BY position, id LIMIT 1`,
		serverID,
	).Scan(&channelID); err != nil {
		t.Fatal(err)
	}
	if err := h.DB.Pool.QueryRow(ctx,
		`SELECT id::text FROM roles
		 WHERE server_id = $1::uuid AND is_default = TRUE`,
		serverID,
	).Scan(&defaultRoleID); err != nil {
		t.Fatal(err)
	}

	requireChannelReadParity(t, h, channelID, target.ID, true, "default allow")
	requireChannelReadParity(t, h, channelID, owner.ID, true, "owner bypass")

	zero := uint64(0)
	if err := h.DB.UpdateRole(ctx, serverID, defaultRoleID, nil, &zero, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.DB.UpsertChannelOverwrite(ctx, db.ChannelOverwrite{
		ChannelID: channelID, TargetID: defaultRoleID,
		TargetType: db.ChannelOverwriteRole, Deny: db.ChannelReadPermissions,
	}); err != nil {
		t.Fatal(err)
	}

	adminRole, err := h.DB.CreateRole(ctx, serverID, "acl-parity-admin", db.PermAdministrator, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DB.AssignRole(ctx, serverID, target.ID, adminRole.ID); err != nil {
		t.Fatal(err)
	}
	requireChannelReadParity(t, h, channelID, target.ID, true, "administrator bypass")
	if err := h.DB.UnassignRole(ctx, serverID, target.ID, adminRole.ID); err != nil {
		t.Fatal(err)
	}
	requireChannelReadParity(t, h, channelID, target.ID, false, "default overwrite deny")

	denyRole, err := h.DB.CreateRole(ctx, serverID, "acl-parity-deny", db.ChannelReadPermissions, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	allowRole, err := h.DB.CreateRole(ctx, serverID, "acl-parity-allow", db.ChannelReadPermissions, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, roleID := range []string{denyRole.ID, allowRole.ID} {
		if err := h.DB.AssignRole(ctx, serverID, target.ID, roleID); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.DB.UpsertChannelOverwrite(ctx, db.ChannelOverwrite{
		ChannelID: channelID, TargetID: denyRole.ID,
		TargetType: db.ChannelOverwriteRole, Deny: db.ChannelReadPermissions,
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.DB.UpsertChannelOverwrite(ctx, db.ChannelOverwrite{
		ChannelID: channelID, TargetID: allowRole.ID,
		TargetType: db.ChannelOverwriteRole, Allow: db.ChannelReadPermissions,
	}); err != nil {
		t.Fatal(err)
	}
	requireChannelReadParity(t, h, channelID, target.ID, true, "aggregate role allow after deny")

	if err := h.DB.UpsertChannelOverwrite(ctx, db.ChannelOverwrite{
		ChannelID: channelID, TargetID: target.ID,
		TargetType: db.ChannelOverwriteUser, Deny: db.PermReadMessageHistory,
	}); err != nil {
		t.Fatal(err)
	}
	requireChannelReadParity(t, h, channelID, target.ID, false, "member deny after role allow")
	if err := h.DB.UpsertChannelOverwrite(ctx, db.ChannelOverwrite{
		ChannelID: channelID, TargetID: target.ID,
		TargetType: db.ChannelOverwriteUser, Allow: db.ChannelReadPermissions,
	}); err != nil {
		t.Fatal(err)
	}
	requireChannelReadParity(t, h, channelID, target.ID, true, "member allow after role deny")

	// Corrupt the disposable fixture only after valid-state parity is covered.
	// Both implementations must fail closed when the exact-one-default database
	// invariant is missing.
	if _, err := h.DB.Pool.Exec(ctx,
		`DROP TRIGGER roles_enforce_default_invariant ON roles`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.Pool.Exec(ctx,
		`UPDATE roles SET is_default = FALSE WHERE id = $1::uuid`, defaultRoleID,
	); err != nil {
		t.Fatal(err)
	}
	requireChannelReadParity(t, h, channelID, target.ID, false, "missing default role")

	if _, err := h.DB.Pool.Exec(ctx,
		`UPDATE roles SET is_default = TRUE WHERE id = $1::uuid`, defaultRoleID,
	); err != nil {
		t.Fatal(err)
	}
	requireChannelReadParity(t, h, channelID, target.ID, true, "restored default invariant")
	if _, err := h.DB.Pool.Exec(ctx,
		`UPDATE servers SET deleted_at = now() WHERE id = $1::uuid`, serverID,
	); err != nil {
		t.Fatal(err)
	}
	requireChannelReadParity(t, h, channelID, target.ID, false, "soft-deleted server")
}

func requireChannelReadParity(t *testing.T, h *Harness, channelID, userID string, want bool, scenario string) {
	t.Helper()
	var sqlAllowed bool
	if err := h.DB.Pool.QueryRow(context.Background(),
		`SELECT veil_channel_user_can_read($1::uuid, $2::uuid)`,
		channelID, userID,
	).Scan(&sqlAllowed); err != nil {
		t.Fatalf("%s SQL ACL: %v", scenario, err)
	}
	goAllowed, goErr := h.DB.HasAllChannelPermissions(
		context.Background(), channelID, userID, db.ChannelReadPermissions,
	)
	if goErr != nil {
		goAllowed = false
	}
	if sqlAllowed != goAllowed || sqlAllowed != want {
		t.Fatalf(
			"%s parity SQL=%v Go=%v GoErr=%v, want %v",
			scenario, sqlAllowed, goAllowed, goErr, want,
		)
	}
}
