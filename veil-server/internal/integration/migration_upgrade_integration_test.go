//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestMigrationUpgradePreflights exercises the upgrade boundaries that a
// fresh-schema integration run cannot reach. Each subtest gets an independent
// database in one PostgreSQL container so an intentionally failed migration
// cannot contaminate the next fixture.
func TestMigrationUpgradePreflights(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	baseDSN, admin := startMigrationPostgres(t)

	t.Run("015 blocks legacy and partial sender-key rows until explicit cleanup", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_015")
		applyMigrationsBefore(t, pool, migrations, 15)
		seedLegacySenderKeyCutover(t, pool)

		err := execMigration(t, pool, migrations, 15)
		requireMigrationError(t, err, "23514", "sender-key device-routing cutover blocked")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var pendingRows, headRows int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM sender_keys`).Scan(&pendingRows); err != nil {
			t.Fatalf("count blocked sender-key rows: %v", err)
		}
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM sender_key_heads`).Scan(&headRows); err != nil {
			t.Fatalf("count sender-key heads before cleanup: %v", err)
		}
		if pendingRows != 2 || headRows != 2 {
			t.Fatalf("failed preflight changed state: pending=%d heads=%d, want 2/2", pendingRows, headRows)
		}

		// This is the destructive step migration 015 deliberately refuses to
		// infer. The operator must first back up/audit these rows and explicitly
		// accept loss of legacy offline delivery. Stream heads are not deleted.
		if _, err := pool.Exec(ctx,
			`DELETE FROM sender_keys
			 WHERE roster_version IS NULL
			    OR roster_commitment IS NULL
			    OR owner_binding_version IS NULL
			    OR target_binding_version IS NULL`,
		); err != nil {
			t.Fatalf("explicit legacy sender-key cleanup: %v", err)
		}
		if err := execMigration(t, pool, migrations, 15); err != nil {
			t.Fatalf("migration 015 after explicit cleanup: %v", err)
		}

		var generations []int64
		rows, err := pool.Query(ctx,
			`SELECT max_generation FROM sender_key_heads ORDER BY max_generation`,
		)
		if err != nil {
			t.Fatalf("query preserved sender-key heads: %v", err)
		}
		for rows.Next() {
			var generation int64
			if err := rows.Scan(&generation); err != nil {
				rows.Close()
				t.Fatalf("scan preserved sender-key head: %v", err)
			}
			generations = append(generations, generation)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatalf("iterate preserved sender-key heads: %v", err)
		}
		rows.Close()
		if len(generations) != 2 || generations[0] != 7 || generations[1] != 8 {
			t.Fatalf("preserved head generations=%v, want [7 8]", generations)
		}
		var retentionValidated bool
		if err := pool.QueryRow(ctx,
			`SELECT convalidated
			 FROM pg_constraint
			 WHERE conrelid = 'sender_keys'::regclass
			   AND conname = 'sender_keys_retention_window'`,
		).Scan(&retentionValidated); err != nil || !retentionValidated {
			t.Fatalf("retention constraint validated=%v err=%v", retentionValidated, err)
		}
		var nullableRouteColumns int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*)
			 FROM information_schema.columns
			 WHERE table_schema = current_schema()
			   AND table_name = 'sender_keys'
			   AND column_name IN (
			     'roster_version', 'roster_commitment',
			     'owner_binding_version', 'target_binding_version'
			   )
			   AND is_nullable = 'YES'`,
		).Scan(&nullableRouteColumns); err != nil || nullableRouteColumns != 0 {
			t.Fatalf("nullable post-cutover route columns=%d err=%v, want 0", nullableRouteColumns, err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO sender_keys (
			   conversation_id, owner_device_id, target_device_id,
			   encrypted_key, generation, envelope_commitment
			 )
			 SELECT conversation_id, owner_device_id, target_device_id,
			        '\x01', max_generation + 100, digest('\x01'::bytea, 'sha256')
			 FROM sender_key_heads
			 ORDER BY conversation_id, owner_device_id, target_device_id
			 LIMIT 1`,
		); err == nil {
			t.Fatal("post-cutover database accepted an account-routed sender-key row")
		}
	})

	t.Run("016 blocks an active server with no default role", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_016_zero")
		applyMigrationsBefore(t, pool, migrations, 16)
		seedMigrationServer(t, pool, "zero-default")

		err := execMigration(t, pool, migrations, 16)
		requireMigrationError(t, err, "23514", "active server must have exactly one default role")
	})

	t.Run("016 blocks ambiguous everyone-role backfill", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_016_ambiguous")
		applyMigrationsBefore(t, pool, migrations, 16)
		serverID := seedMigrationServer(t, pool, "ambiguous-default")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for position := 0; position < 2; position++ {
			if _, err := pool.Exec(ctx,
				`INSERT INTO roles (server_id, name, permissions, position, is_default)
				 VALUES ($1::uuid, '@everyone', 0, $2, FALSE)`,
				serverID, position,
			); err != nil {
				t.Fatalf("insert ambiguous @everyone role %d: %v", position, err)
			}
		}

		err := execMigration(t, pool, migrations, 16)
		requireMigrationError(t, err, "23514", "active server must have exactly one default role")
	})

	t.Run("016 blocks negative and unknown role masks", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_016_masks")
		applyMigrationsBefore(t, pool, migrations, 16)
		serverID := seedMigrationServer(t, pool, "invalid-masks")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx,
			`INSERT INTO roles (server_id, name, permissions, position, is_default)
			 VALUES
			   ($1::uuid, '@everyone', 0, 0, TRUE),
			   ($1::uuid, 'negative', -1, 1, FALSE),
			   ($1::uuid, 'unknown-bit', $2, 2, FALSE)`,
			serverID, int64(1<<20),
		); err != nil {
			t.Fatalf("insert invalid permission fixtures: %v", err)
		}

		err := execMigration(t, pool, migrations, 16)
		requireMigrationError(t, err, "23514", "negative or unknown permission bits")
	})

	t.Run("016 backfills one unambiguous everyone role", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_016_backfill")
		applyMigrationsBefore(t, pool, migrations, 16)
		serverID := seedMigrationServer(t, pool, "unambiguous-default")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var everyoneID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO roles (server_id, name, permissions, position, is_default)
			 VALUES ($1::uuid, '@everyone', NULL, 0, NULL)
			 RETURNING id::text`,
			serverID,
		).Scan(&everyoneID); err != nil {
			t.Fatalf("insert unambiguous @everyone role: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO roles (server_id, name, permissions, position, is_default)
			 VALUES ($1::uuid, 'member', NULL, 1, NULL)`,
			serverID,
		); err != nil {
			t.Fatalf("insert nullable legacy role: %v", err)
		}

		if err := execMigration(t, pool, migrations, 16); err != nil {
			t.Fatalf("migration 016 unambiguous backfill: %v", err)
		}
		var isDefault bool
		var permissions int64
		if err := pool.QueryRow(ctx,
			`SELECT is_default, permissions FROM roles WHERE id = $1::uuid`,
			everyoneID,
		).Scan(&isDefault, &permissions); err != nil {
			t.Fatalf("query backfilled @everyone role: %v", err)
		}
		if !isDefault || permissions != 0 {
			t.Fatalf("backfilled @everyone default=%v permissions=%d, want true/0", isDefault, permissions)
		}
		var defaultCount, nullableRoleColumns int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM roles
			 WHERE server_id = $1::uuid AND is_default = TRUE`,
			serverID,
		).Scan(&defaultCount); err != nil || defaultCount != 1 {
			t.Fatalf("default role count=%d err=%v, want 1", defaultCount, err)
		}
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*)
			 FROM information_schema.columns
			 WHERE table_schema = current_schema()
			   AND table_name = 'roles'
			   AND column_name IN ('permissions', 'is_default')
			   AND is_nullable = 'YES'`,
		).Scan(&nullableRoleColumns); err != nil || nullableRoleColumns != 0 {
			t.Fatalf("nullable protected role columns=%d err=%v, want 0", nullableRoleColumns, err)
		}

		// Both the known-mask constraint and deferred exact-one-default trigger
		// must protect direct database writers after the migration.
		if _, err := pool.Exec(ctx,
			`INSERT INTO roles (server_id, name, permissions, position, is_default)
			 VALUES ($1::uuid, 'invalid-after-upgrade', $2, 2, FALSE)`,
			serverID, int64(1<<20),
		); err == nil {
			t.Fatal("post-upgrade database accepted an unknown role permission bit")
		}
		if _, err := pool.Exec(ctx,
			`DELETE FROM roles WHERE id = $1::uuid`, everyoneID,
		); err == nil {
			t.Fatal("post-upgrade database allowed deletion of the only default role")
		}
	})

	t.Run("017 backfills revision state and dirties an existing roster head", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_017_backfill")
		applyMigrationsBefore(t, pool, migrations, 17)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var conversationID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO conversations (conv_type, name)
			 VALUES (1, 'pre-linearization-roster') RETURNING id::text`,
		).Scan(&conversationID); err != nil {
			t.Fatalf("insert pre-017 conversation: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO conversation_device_rosters
			   (conversation_id, roster_version, roster_commitment)
			 VALUES ($1::uuid, 7, $2)`,
			conversationID, bytes.Repeat([]byte{0x71}, 32),
		); err != nil {
			t.Fatalf("insert pre-017 roster head: %v", err)
		}

		if err := execMigration(t, pool, migrations, 17); err != nil {
			t.Fatalf("migration 017 existing-head backfill: %v", err)
		}
		var dirty bool
		var version, mutationRevision, resolvedRevision int64
		if err := pool.QueryRow(ctx,
			`SELECT head.dirty, head.roster_version,
			        revision.mutation_revision, head.resolved_mutation_revision
			 FROM conversation_device_rosters head
			 JOIN conversation_roster_revisions revision USING (conversation_id)
			 WHERE head.conversation_id = $1::uuid`,
			conversationID,
		).Scan(&dirty, &version, &mutationRevision, &resolvedRevision); err != nil {
			t.Fatalf("query migration 017 backfill: %v", err)
		}
		if !dirty || version != 7 || mutationRevision != 0 || resolvedRevision != 0 {
			t.Fatalf(
				"017 backfill dirty=%v version=%d mutation=%d resolved=%d, want true/7/0/0",
				dirty, version, mutationRevision, resolvedRevision,
			)
		}

		if _, err := pool.Exec(ctx,
			`UPDATE conversations SET conv_type = 2 WHERE id = $1::uuid`, conversationID,
		); err != nil {
			t.Fatalf("post-017 security-type mutation: %v", err)
		}
		if err := pool.QueryRow(ctx,
			`SELECT mutation_revision
			 FROM conversation_roster_revisions WHERE conversation_id = $1::uuid`,
			conversationID,
		).Scan(&mutationRevision); err != nil || mutationRevision != 1 {
			t.Fatalf("post-017 mutation revision=%d err=%v, want 1", mutationRevision, err)
		}
	})

	t.Run("018 preserves legacy rows and requires context for new secure rows", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_018_context")
		applyMigrationsBefore(t, pool, migrations, 18)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var userID, groupID, dmID, legacyMessageID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (identity_key, signing_key, username)
			 VALUES ($1, $2, 'message-context-owner') RETURNING id::text`,
			bytes.Repeat([]byte{0x81}, 32), bytes.Repeat([]byte{0x82}, 32),
		).Scan(&userID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx,
			`INSERT INTO conversations (conv_type, name)
			 VALUES (1, 'legacy-secure-row') RETURNING id::text`,
		).Scan(&groupID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx,
			`INSERT INTO conversations (conv_type, name)
			 VALUES (0, 'dm-context-scope') RETURNING id::text`,
		).Scan(&dmID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx,
			`INSERT INTO messages (conversation_id, sender_id, ciphertext)
			 VALUES ($1::uuid, $2::uuid, '\x01') RETURNING id::text`,
			groupID, userID,
		).Scan(&legacyMessageID); err != nil {
			t.Fatal(err)
		}

		if err := execMigration(t, pool, migrations, 18); err != nil {
			t.Fatalf("migration 018: %v", err)
		}
		var legacyNulls int
		if err := pool.QueryRow(ctx,
			`SELECT num_nulls(
			   crypto_profile, crypto_era, roster_version, roster_commitment,
			   sender_device_id, sender_binding_version
			 ) FROM messages WHERE id = $1::uuid`,
			legacyMessageID,
		).Scan(&legacyNulls); err != nil || legacyNulls != 6 {
			t.Fatalf("legacy context nulls=%d err=%v, want 6", legacyNulls, err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO messages (conversation_id, sender_id, ciphertext)
			 VALUES ($1::uuid, $2::uuid, '\x02')`,
			groupID, userID,
		); err == nil {
			t.Fatal("new group row without security context was accepted")
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO messages (
			   conversation_id, sender_id, ciphertext, crypto_profile
			 ) VALUES ($1::uuid, $2::uuid, '\x02', 'sender_key_v5')`,
			groupID, userID,
		); err == nil {
			t.Fatal("new group row with partial security context was accepted")
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO messages (
			   conversation_id, sender_id, ciphertext, crypto_era
			 ) VALUES ($1::uuid, $2::uuid, '\x02', 1)`,
			dmID, userID,
		); err == nil {
			t.Fatal("DM row with partial Sender-Key context was accepted")
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO messages (
			   conversation_id, sender_id, ciphertext, crypto_profile, crypto_era,
			   roster_version, roster_commitment, sender_device_id, sender_binding_version
			 ) VALUES (
			   $1::uuid, $2::uuid, '\x03', 'sender_key_v5', 1,
			   7, $3, $4, 2
			 )`,
			groupID, userID, bytes.Repeat([]byte{0x83}, 32), bytes.Repeat([]byte{0x84}, 16),
		); err != nil {
			t.Fatalf("valid secure row rejected: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO messages (
			   conversation_id, sender_id, ciphertext, crypto_profile, crypto_era,
			   roster_version, roster_commitment, sender_device_id, sender_binding_version
			 ) VALUES (
			   $1::uuid, $2::uuid, '\x04', 'sender_key_v5', 1,
			   7, $3, $4, 2
			 )`,
			dmID, userID, bytes.Repeat([]byte{0x85}, 32), bytes.Repeat([]byte{0x86}, 16),
		); err == nil {
			t.Fatal("DM row with Sender-Key context was accepted")
		}
		if _, err := pool.Exec(ctx,
			`UPDATE messages SET ciphertext = '\x05'
			 WHERE id = $1::uuid`,
			legacyMessageID,
		); err == nil {
			t.Fatal("legacy group ciphertext was editable after migration 018")
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO messages (conversation_id, sender_id, ciphertext)
			 VALUES ($1::uuid, $2::uuid, '\x06')`,
			dmID, userID,
		); err != nil {
			t.Fatalf("ordinary DM row rejected after migration 018: %v", err)
		}
	})

	t.Run("019 blocks retained rows whose exact binding proof is missing", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_019_preflight")
		applyMigrationsBefore(t, pool, migrations, 19)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ownerUserID, targetUserID, ownerDeviceID, targetDeviceID, conversationID :=
			seedMigrationSenderKeyHistory(t, pool, false)
		_ = ownerUserID
		_ = targetUserID
		_ = ownerDeviceID
		_ = targetDeviceID
		_ = conversationID

		err := execMigration(t, pool, migrations, 19)
		requireMigrationError(t, err, "23514", "retained rows reference missing binding versions")
		var retained int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM sender_keys`).Scan(&retained); err != nil || retained != 1 {
			t.Fatalf("019 failed preflight retained rows=%d err=%v, want 1", retained, err)
		}
	})

	t.Run("019 makes identity history immutable and preserves atomic hard-delete cascades", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_019_identity")
		applyMigrationsBefore(t, pool, migrations, 19)
		ownerUserID, targetUserID, ownerDeviceID, targetDeviceID, _ :=
			seedMigrationSenderKeyHistory(t, pool, true)
		if err := execMigration(t, pool, migrations, 19); err != nil {
			t.Fatalf("migration 019: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// No-op writes remain legal, including ordinary profile metadata in the
		// same statement; only cryptographic identity changes are rejected.
		if _, err := pool.Exec(ctx,
			`UPDATE users SET identity_key = identity_key, signing_key = signing_key,
			 username = 'renamed-owner' WHERE id = $1::uuid`, ownerUserID,
		); err != nil {
			t.Fatalf("account identity no-op rejected: %v", err)
		}
		for _, mutation := range []struct {
			name, sql string
			args      []any
			message   string
		}{
			{
				name: "account identity key", sql: `UPDATE users SET identity_key = $2 WHERE id = $1::uuid`,
				args: []any{ownerUserID, bytes.Repeat([]byte{0x91}, 32)}, message: "account cryptographic identity is immutable",
			},
			{
				name: "account signing key", sql: `UPDATE users SET signing_key = $2 WHERE id = $1::uuid`,
				args: []any{ownerUserID, bytes.Repeat([]byte{0x92}, 32)}, message: "account cryptographic identity is immutable",
			},
			{
				name: "device owner", sql: `UPDATE devices SET user_id = $2::uuid WHERE id = $1::uuid`,
				args: []any{ownerDeviceID, targetUserID}, message: "device ownership and protocol identifier are immutable",
			},
			{
				name: "device protocol id", sql: `UPDATE devices SET device_key = $2 WHERE id = $1::uuid`,
				args: []any{ownerDeviceID, bytes.Repeat([]byte{0x93}, 16)}, message: "device ownership and protocol identifier are immutable",
			},
			{
				name: "device identity key", sql: `UPDATE device_crypto_keys SET device_identity_key = $2 WHERE device_id = $1::uuid`,
				args: []any{ownerDeviceID, bytes.Repeat([]byte{0x94}, 32)}, message: "device cryptographic keys are immutable",
			},
			{
				name: "binding history", sql: `UPDATE device_binding_versions SET capabilities = capabilities + 1 WHERE device_id = $1::uuid AND binding_version = 1`,
				args: []any{ownerDeviceID}, message: "device binding history is append-only",
			},
		} {
			_, err := pool.Exec(ctx, mutation.sql, mutation.args...)
			if err == nil {
				t.Fatalf("019 accepted %s mutation", mutation.name)
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" || !strings.Contains(pgErr.Message, mutation.message) {
				t.Fatalf("%s mutation error=%v, want 23514 containing %q", mutation.name, err, mutation.message)
			}
		}
		if _, err := pool.Exec(ctx,
			`UPDATE device_binding_versions SET capabilities = capabilities
			 WHERE device_id = $1::uuid AND binding_version = 1`, ownerDeviceID,
		); err != nil {
			t.Fatalf("binding history no-op rejected: %v", err)
		}

		var validated, deferrable, initiallyDeferred bool
		for _, constraint := range []string{
			"sender_keys_owner_binding_version_fk",
			"sender_keys_target_binding_version_fk",
		} {
			if err := pool.QueryRow(ctx,
				`SELECT convalidated, condeferrable, condeferred
				 FROM pg_constraint WHERE conname = $1`, constraint,
			).Scan(&validated, &deferrable, &initiallyDeferred); err != nil ||
				!validated || !deferrable || !initiallyDeferred {
				t.Fatalf("constraint %s validated/deferrable/deferred=%v/%v/%v err=%v",
					constraint, validated, deferrable, initiallyDeferred, err)
			}
		}
		if _, err := pool.Exec(ctx,
			`DELETE FROM device_binding_versions
			 WHERE device_id = $1::uuid AND binding_version = 1`, ownerDeviceID,
		); err == nil {
			t.Fatal("019 allowed deletion of binding history referenced by retained sender key")
		} else {
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
				t.Fatalf("referenced binding deletion error=%v, want SQLSTATE 23503", err)
			}
		}
		var retainedOwnerBinding int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM device_binding_versions
			 WHERE device_id = $1::uuid AND binding_version = 1`, ownerDeviceID,
		).Scan(&retainedOwnerBinding); err != nil || retainedOwnerBinding != 1 {
			t.Fatalf("referenced owner binding count=%d err=%v, want 1", retainedOwnerBinding, err)
		}

		// Hard account deletion is an explicit atomic cleanup path: device FKs
		// cascade sender-key rows/heads before the deferred history FKs check.
		if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, ownerUserID); err != nil {
			t.Fatalf("019 owner hard-delete cascade: %v", err)
		}
		var pending, heads, devices, bindings int
		if err := pool.QueryRow(ctx,
			`SELECT
			 (SELECT COUNT(*) FROM sender_keys),
			 (SELECT COUNT(*) FROM sender_key_heads),
			 (SELECT COUNT(*) FROM devices WHERE id = $1::uuid),
			 (SELECT COUNT(*) FROM device_binding_versions WHERE device_id = $1::uuid)`,
			ownerDeviceID,
		).Scan(&pending, &heads, &devices, &bindings); err != nil {
			t.Fatal(err)
		}
		if pending != 0 || heads != 0 || devices != 0 || bindings != 0 {
			t.Fatalf("hard-delete cleanup pending/heads/devices/bindings=%d/%d/%d/%d, want 0/0/0/0",
				pending, heads, devices, bindings)
		}
		var targetDevices int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM devices WHERE id = $1::uuid AND user_id = $2::uuid`,
			targetDeviceID, targetUserID,
		).Scan(&targetDevices); err != nil || targetDevices != 1 {
			t.Fatalf("unrelated target device count=%d err=%v, want 1", targetDevices, err)
		}
	})

	t.Run("019 preserves atomic target hard-delete cascades", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_019_target_cascade")
		applyMigrationsBefore(t, pool, migrations, 19)
		ownerUserID, targetUserID, ownerDeviceID, targetDeviceID, _ :=
			seedMigrationSenderKeyHistory(t, pool, true)
		_ = ownerUserID
		if err := execMigration(t, pool, migrations, 19); err != nil {
			t.Fatalf("migration 019: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx,
			`DELETE FROM device_binding_versions
			 WHERE device_id = $1::uuid AND binding_version = 1`, targetDeviceID,
		); err == nil {
			t.Fatal("019 allowed deletion of target binding history referenced by retained sender key")
		} else {
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
				t.Fatalf("referenced target binding deletion error=%v, want SQLSTATE 23503", err)
			}
		}

		// The target side of the exact composite binding FK must permit the
		// same atomic account-removal path as the owner side: device cascades
		// remove retained envelopes and stream heads before deferred checks.
		if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, targetUserID); err != nil {
			t.Fatalf("019 target hard-delete cascade: %v", err)
		}
		var pending, heads, devices, bindings int
		if err := pool.QueryRow(ctx,
			`SELECT
			 (SELECT COUNT(*) FROM sender_keys),
			 (SELECT COUNT(*) FROM sender_key_heads),
			 (SELECT COUNT(*) FROM devices WHERE id = $1::uuid),
			 (SELECT COUNT(*) FROM device_binding_versions WHERE device_id = $1::uuid)`,
			targetDeviceID,
		).Scan(&pending, &heads, &devices, &bindings); err != nil {
			t.Fatal(err)
		}
		if pending != 0 || heads != 0 || devices != 0 || bindings != 0 {
			t.Fatalf("target hard-delete cleanup pending/heads/devices/bindings=%d/%d/%d/%d, want 0/0/0/0",
				pending, heads, devices, bindings)
		}
		var ownerDevices int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM devices WHERE id = $1::uuid`, ownerDeviceID,
		).Scan(&ownerDevices); err != nil || ownerDevices != 1 {
			t.Fatalf("unrelated owner device count=%d err=%v, want 1", ownerDevices, err)
		}
	})

	t.Run("fresh migration chain includes and applies 001 through 019", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_fresh")
		seen := make(map[int]bool)
		for _, item := range migrations {
			seen[migrationNumber(t, item.name)] = true
		}
		for number := 1; number <= 19; number++ {
			if !seen[number] {
				t.Fatalf("migration chain is missing %03d", number)
			}
		}
		applyMigrationsBefore(t, pool, migrations, 20)
	})
}

func seedMigrationSenderKeyHistory(t *testing.T, pool *pgxpool.Pool, completeBindings bool) (string, string, string, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var ownerUserID, targetUserID, ownerDeviceID, targetDeviceID, conversationID string
	for _, fixture := range []struct {
		username string
		marker   byte
		result   *string
	}{
		{username: "history-owner", marker: 0xa1, result: &ownerUserID},
		{username: "history-target", marker: 0xb1, result: &targetUserID},
	} {
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (identity_key, signing_key, username)
			 VALUES ($1, $2, $3) RETURNING id::text`,
			bytes.Repeat([]byte{fixture.marker}, 32),
			bytes.Repeat([]byte{fixture.marker + 1}, 32), fixture.username,
		).Scan(fixture.result); err != nil {
			t.Fatalf("insert 019 user %s: %v", fixture.username, err)
		}
	}
	for _, fixture := range []struct {
		userID string
		marker byte
		name   string
		result *string
		owner  bool
	}{
		{userID: ownerUserID, marker: 0xc1, name: "history-owner-device", result: &ownerDeviceID, owner: true},
		{userID: targetUserID, marker: 0xd1, name: "history-target-device", result: &targetDeviceID},
	} {
		if err := pool.QueryRow(ctx,
			`INSERT INTO devices (user_id, device_key, device_name)
			 VALUES ($1::uuid, $2, $3) RETURNING id::text`,
			fixture.userID, bytes.Repeat([]byte{fixture.marker}, 16), fixture.name,
		).Scan(fixture.result); err != nil {
			t.Fatalf("insert 019 device %s: %v", fixture.name, err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO device_crypto_keys
			   (device_id, device_identity_key, device_signing_key)
			 VALUES ($1::uuid, $2, $3)`,
			*fixture.result, bytes.Repeat([]byte{fixture.marker}, 32),
			bytes.Repeat([]byte{fixture.marker + 1}, 32),
		); err != nil {
			t.Fatalf("insert 019 device keys %s: %v", fixture.name, err)
		}
		if completeBindings || fixture.owner {
			if _, err := pool.Exec(ctx,
				`INSERT INTO device_binding_versions
				   (device_id, binding_version, capabilities, binding_status,
				    account_signature, binding_commitment)
				 VALUES ($1::uuid, 1, 3, 1, $2, $3)`,
				*fixture.result, bytes.Repeat([]byte{fixture.marker + 2}, 64),
				bytes.Repeat([]byte{fixture.marker + 3}, 32),
			); err != nil {
				t.Fatalf("insert 019 binding %s: %v", fixture.name, err)
			}
			if _, err := pool.Exec(ctx,
				`INSERT INTO device_binding_heads (device_id, binding_version)
				 VALUES ($1::uuid, 1)`, *fixture.result,
			); err != nil {
				t.Fatalf("insert 019 binding head %s: %v", fixture.name, err)
			}
		}
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO conversations (conv_type, name)
		 VALUES (1, '019-history') RETURNING id::text`,
	).Scan(&conversationID); err != nil {
		t.Fatalf("insert 019 conversation: %v", err)
	}
	wire := []byte("019-retained-sender-key")
	if _, err := pool.Exec(ctx,
		`INSERT INTO sender_keys (
		   conversation_id, owner_device_id, target_device_id,
		   encrypted_key, generation, envelope_commitment,
		   roster_version, roster_commitment,
		   owner_binding_version, target_binding_version
		 ) VALUES (
		   $1::uuid, $2::uuid, $3::uuid, $4::bytea, 1, digest($4::bytea, 'sha256'),
		   1, $5, 1, 1
		 )`,
		conversationID, ownerDeviceID, targetDeviceID, wire,
		bytes.Repeat([]byte{0xe1}, 32),
	); err != nil {
		t.Fatalf("insert 019 retained sender key: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO sender_key_heads (
		   conversation_id, owner_device_id, target_device_id,
		   max_generation, max_commitment
		 ) VALUES ($1::uuid, $2::uuid, $3::uuid, 1, digest($4::bytea, 'sha256'))`,
		conversationID, ownerDeviceID, targetDeviceID, wire,
	); err != nil {
		t.Fatalf("insert 019 sender-key head: %v", err)
	}
	return ownerUserID, targetUserID, ownerDeviceID, targetDeviceID, conversationID
}

func startMigrationPostgres(t *testing.T) (string, *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("veil"),
		tcpostgres.WithUsername("veil"),
		tcpostgres.WithPassword("veil"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start migration postgres container: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	baseDSN, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("migration postgres dsn: %v", err)
	}
	admin, err := pgxpool.New(ctx, baseDSN)
	if err != nil {
		t.Fatalf("connect migration postgres admin: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatalf("ping migration postgres admin: %v", err)
	}
	t.Cleanup(admin.Close)
	return baseDSN, admin
}

func newMigrationDatabase(t *testing.T, admin *pgxpool.Pool, baseDSN, name string) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create migration database %s: %v", name, err)
	}
	parsed, err := url.Parse(baseDSN)
	if err != nil {
		t.Fatalf("parse migration postgres dsn: %v", err)
	}
	parsed.Path = "/" + name
	pool, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatalf("connect migration database %s: %v", name, err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping migration database %s: %v", name, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func migrationNumber(t *testing.T, name string) int {
	t.Helper()
	if len(name) < 4 || name[3] != '_' {
		t.Fatalf("migration %q does not start with NNN_", name)
	}
	number, err := strconv.Atoi(name[:3])
	if err != nil {
		t.Fatalf("parse migration number from %q: %v", name, err)
	}
	return number
}

func applyMigrationsBefore(t *testing.T, pool *pgxpool.Pool, migrations []migration, stop int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	for _, item := range migrations {
		if migrationNumber(t, item.name) >= stop {
			continue
		}
		if _, err := pool.Exec(ctx, item.sql); err != nil {
			t.Fatalf("apply migration %s: %v", item.name, err)
		}
	}
}

func execMigration(t *testing.T, pool *pgxpool.Pool, migrations []migration, number int) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, item := range migrations {
		if migrationNumber(t, item.name) == number {
			_, err := pool.Exec(ctx, item.sql)
			return err
		}
	}
	t.Fatalf("migration %03d not found", number)
	return nil
}

func requireMigrationError(t *testing.T, err error, code, message string) {
	t.Helper()
	if err == nil {
		t.Fatalf("migration unexpectedly succeeded; wanted SQLSTATE %s containing %q", code, message)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("migration error type=%T, want pg error: %v", err, err)
	}
	if pgErr.Code != code || !strings.Contains(pgErr.Message, message) {
		t.Fatalf("migration error SQLSTATE=%s message=%q, want %s containing %q", pgErr.Code, pgErr.Message, code, message)
	}
}

func seedMigrationServer(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var userID, serverID string
	marker := byte(len(name) + 1)
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (identity_key, signing_key, username)
		 VALUES ($1, $2, $3) RETURNING id::text`,
		bytes.Repeat([]byte{marker}, 32), bytes.Repeat([]byte{marker + 1}, 32), name+"-owner",
	).Scan(&userID); err != nil {
		t.Fatalf("insert migration owner: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO servers (name, owner_id)
		 VALUES ($1, $2::uuid) RETURNING id::text`,
		name, userID,
	).Scan(&serverID); err != nil {
		t.Fatalf("insert migration server: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO server_members (server_id, user_id) VALUES ($1::uuid, $2::uuid)`,
		serverID, userID,
	); err != nil {
		t.Fatalf("insert migration server owner membership: %v", err)
	}
	return serverID
}

func seedLegacySenderKeyCutover(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var ownerUserID, targetUserID, ownerDeviceID, targetOneID, targetTwoID, conversationID string
	for _, fixture := range []struct {
		username string
		identity byte
		target   *string
	}{
		{username: "migration-owner", identity: 0x11, target: &ownerUserID},
		{username: "migration-target", identity: 0x21, target: &targetUserID},
	} {
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (identity_key, signing_key, username)
			 VALUES ($1, $2, $3) RETURNING id::text`,
			bytes.Repeat([]byte{fixture.identity}, 32),
			bytes.Repeat([]byte{fixture.identity + 1}, 32),
			fixture.username,
		).Scan(fixture.target); err != nil {
			t.Fatalf("insert sender-key migration user %s: %v", fixture.username, err)
		}
	}
	for _, fixture := range []struct {
		userID string
		key    byte
		name   string
		target *string
	}{
		{userID: ownerUserID, key: 0x31, name: "owner-device", target: &ownerDeviceID},
		{userID: targetUserID, key: 0x41, name: "target-one", target: &targetOneID},
		{userID: targetUserID, key: 0x42, name: "target-two", target: &targetTwoID},
	} {
		if err := pool.QueryRow(ctx,
			`INSERT INTO devices (user_id, device_key, device_name)
			 VALUES ($1::uuid, $2, $3) RETURNING id::text`,
			fixture.userID, bytes.Repeat([]byte{fixture.key}, 16), fixture.name,
		).Scan(fixture.target); err != nil {
			t.Fatalf("insert sender-key migration device %s: %v", fixture.name, err)
		}
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO conversations (conv_type, name)
		 VALUES (1, 'migration-cutover') RETURNING id::text`,
	).Scan(&conversationID); err != nil {
		t.Fatalf("insert sender-key migration conversation: %v", err)
	}

	// Migration 014 enforces all-null or all-present for new writes. Dropping
	// that constraint only in this disposable fixture simulates a deployed
	// database whose invariant was manually disabled before a partial write.
	if _, err := pool.Exec(ctx,
		`ALTER TABLE sender_keys DROP CONSTRAINT sender_keys_device_route_complete`,
	); err != nil {
		t.Fatalf("prepare partial sender-key corruption fixture: %v", err)
	}
	for _, fixture := range []struct {
		targetDeviceID string
		generation     int64
		wire           []byte
		partial        bool
	}{
		{targetDeviceID: targetOneID, generation: 7, wire: []byte("legacy-account-routed"), partial: false},
		{targetDeviceID: targetTwoID, generation: 8, wire: []byte("partial-device-route"), partial: true},
	} {
		var rosterVersion any
		if fixture.partial {
			rosterVersion = int64(3)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO sender_keys (
			   conversation_id, owner_device_id, target_device_id,
			   encrypted_key, generation, envelope_commitment,
			   roster_version, roster_commitment, owner_binding_version, target_binding_version
			 ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::bytea, $5, digest($4::bytea, 'sha256'), $6, NULL, NULL, NULL)`,
			conversationID, ownerDeviceID, fixture.targetDeviceID,
			fixture.wire, fixture.generation, rosterVersion,
		); err != nil {
			t.Fatalf("insert sender-key cutover fixture generation %d: %v", fixture.generation, err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO sender_key_heads (
			   conversation_id, owner_device_id, target_device_id,
			   max_generation, max_commitment
			 ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, digest($5, 'sha256'))`,
			conversationID, ownerDeviceID, fixture.targetDeviceID,
			fixture.generation, fixture.wire,
		); err != nil {
			t.Fatalf("insert sender-key head generation %d: %v", fixture.generation, err)
		}
	}
}
