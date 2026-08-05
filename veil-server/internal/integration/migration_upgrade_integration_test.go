//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	veildb "github.com/NaveLIL/veil/veil-server/internal/db"
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

	t.Run("020 adds bounded monotonic text profiles without changing identity keys", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_020")
		applyMigrationsBefore(t, pool, migrations, 20)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var userID string
		identityKey := bytes.Repeat([]byte{0xe1}, 32)
		signingKey := bytes.Repeat([]byte{0xe2}, 32)
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (identity_key, signing_key, username)
			 VALUES ($1, $2, 'profile-owner') RETURNING id::text`,
			identityKey, signingKey,
		).Scan(&userID); err != nil {
			t.Fatalf("insert pre-020 user: %v", err)
		}
		if err := execMigration(t, pool, migrations, 20); err != nil {
			t.Fatalf("migration 020: %v", err)
		}

		var displayName *string
		var about string
		var version int64
		var storedIdentity, storedSigning []byte
		if err := pool.QueryRow(ctx,
			`SELECT display_name, about, profile_version, identity_key, signing_key
			 FROM users WHERE id = $1::uuid`, userID,
		).Scan(&displayName, &about, &version, &storedIdentity, &storedSigning); err != nil {
			t.Fatal(err)
		}
		if displayName != nil || about != "" || version != 0 ||
			!bytes.Equal(storedIdentity, identityKey) || !bytes.Equal(storedSigning, signingKey) {
			t.Fatalf("unexpected 020 defaults or identity mutation: name=%v about=%q version=%d", displayName, about, version)
		}

		command, err := pool.Exec(ctx,
			`UPDATE users SET display_name = 'Alice', about = 'hello',
			 profile_version = profile_version + 1, profile_updated_at = now()
			 WHERE id = $1::uuid AND profile_version = 0`, userID)
		if err != nil || command.RowsAffected() != 1 {
			t.Fatalf("first optimistic update rows=%d err=%v", command.RowsAffected(), err)
		}
		command, err = pool.Exec(ctx,
			`UPDATE users SET display_name = 'rollback', profile_version = profile_version + 1
			 WHERE id = $1::uuid AND profile_version = 0`, userID)
		if err != nil || command.RowsAffected() != 0 {
			t.Fatalf("stale optimistic update rows=%d err=%v", command.RowsAffected(), err)
		}

		_, err = pool.Exec(ctx, `UPDATE users SET display_name = $1 WHERE id = $2::uuid`, strings.Repeat("x", 513), userID)
		requireMigrationError(t, err, "23514", "users_display_name_byte_limit")
	})

	t.Run("022 adds owner-bound bounded avatar storage without changing account keys", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_022")
		applyMigrationsBefore(t, pool, migrations, 22)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var ownerID, otherID string
		for _, fixture := range []struct {
			username string
			marker   byte
			result   *string
		}{
			{username: "avatar-owner", marker: 0xf1, result: &ownerID},
			{username: "avatar-other", marker: 0xf3, result: &otherID},
		} {
			if err := pool.QueryRow(ctx,
				`INSERT INTO users(identity_key, signing_key, username)
				 VALUES ($1,$2,$3) RETURNING id::text`,
				bytes.Repeat([]byte{fixture.marker}, 32),
				bytes.Repeat([]byte{fixture.marker + 1}, 32), fixture.username,
			).Scan(fixture.result); err != nil {
				t.Fatalf("insert avatar fixture: %v", err)
			}
		}
		if err := execMigration(t, pool, migrations, 22); err != nil {
			t.Fatalf("migration 022: %v", err)
		}
		var assetID string
		if err := pool.QueryRow(ctx, `INSERT INTO profile_avatar_assets
			(owner_id, id, content_type, sha256, width, height, data)
			VALUES ($1::uuid, gen_random_uuid(), 'image/jpeg', $2, 512, 512, '\xffd8ffd9')
			RETURNING id::text`, ownerID, bytes.Repeat([]byte{0xa5}, 32)).Scan(&assetID); err != nil {
			t.Fatalf("insert avatar asset: %v", err)
		}
		if _, err := pool.Exec(ctx, `UPDATE users SET avatar_asset_id=$1::uuid WHERE id=$2::uuid`, assetID, ownerID); err != nil {
			t.Fatalf("bind owned avatar: %v", err)
		}
		_, err := pool.Exec(ctx, `UPDATE users SET avatar_asset_id=$1::uuid WHERE id=$2::uuid`, assetID, otherID)
		requireMigrationError(t, err, "23514", "profile avatar owner mismatch")
		_, err = pool.Exec(ctx, `UPDATE profile_avatar_assets SET owner_id=$1::uuid WHERE id=$2::uuid`, otherID, assetID)
		requireMigrationError(t, err, "23514", "profile avatar owner is immutable")
		var indexes int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM pg_indexes
			WHERE schemaname=current_schema() AND indexname IN
			('profile_avatar_assets_orphaned_idx','profile_avatar_assets_owner_idx','users_avatar_asset_idx')`).Scan(&indexes); err != nil || indexes != 3 {
			t.Fatalf("avatar retention/FK indexes=%d err=%v, want 3", indexes, err)
		}
		_, err = pool.Exec(ctx, `UPDATE users SET avatar_upload_window_started_at=now(), avatar_upload_count=13 WHERE id=$1::uuid`, ownerID)
		requireMigrationError(t, err, "23514", "users_avatar_upload_quota_state")
	})

	t.Run("023 hard-cuts plaintext invites and adds bounded Veil Links and bans", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_023")
		applyMigrationsBefore(t, pool, migrations, 23)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var ownerID, targetID, spaceID string
		for _, fixture := range []struct {
			name string
			mark byte
			out  *string
		}{{"link-owner", 0x31, &ownerID}, {"link-target", 0x41, &targetID}} {
			if err := pool.QueryRow(ctx, `INSERT INTO users(identity_key, signing_key, username)
				VALUES ($1,$2,$3) RETURNING id::text`, bytes.Repeat([]byte{fixture.mark}, 32),
				bytes.Repeat([]byte{fixture.mark + 1}, 32), fixture.name).Scan(fixture.out); err != nil {
				t.Fatal(err)
			}
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := tx.QueryRow(ctx, `INSERT INTO servers(name, icon_url, owner_id)
			VALUES ('Link Space','https://legacy.invalid/space.png',$1::uuid) RETURNING id::text`, ownerID).Scan(&spaceID); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO roles(server_id,name,permissions,position,is_default)
			VALUES ($1::uuid,'@everyone',1799,0,TRUE)`, spaceID); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO server_invites(code,server_id,created_by,max_uses)
			VALUES ('plaintext',$1::uuid,$2::uuid,0)`, spaceID, ownerID); err != nil {
			t.Fatal(err)
		}
		if err := execMigration(t, pool, migrations, 23); err != nil {
			t.Fatalf("migration 023: %v", err)
		}
		var legacyRows, defaultPermissions int64
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM server_invites`).Scan(&legacyRows); err != nil || legacyRows != 0 {
			t.Fatalf("legacy invite rows=%d err=%v", legacyRows, err)
		}
		if err := pool.QueryRow(ctx, `SELECT permissions FROM roles WHERE server_id=$1::uuid AND is_default`, spaceID).Scan(&defaultPermissions); err != nil || defaultPermissions&256 != 0 {
			t.Fatalf("default invite permission=%d err=%v", defaultPermissions, err)
		}
		var iconColumns int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='servers' AND column_name='icon_url'`).Scan(&iconColumns); err != nil || iconColumns != 0 {
			t.Fatalf("legacy remote Space icon column count=%d err=%v", iconColumns, err)
		}
		_, err = pool.Exec(ctx, `UPDATE servers SET icon_url='https://remote.invalid/space.png' WHERE id=$1::uuid`, spaceID)
		requireMigrationError(t, err, "42703", "icon_url")
		selector := strings.Repeat("A", 43)
		if _, err := pool.Exec(ctx, `INSERT INTO server_invites
			(public_selector,secret_hash,server_id,created_by,max_uses,expires_at)
			VALUES ($1,$2,$3::uuid,$4::uuid,1,now()+interval '1 day')`, selector,
			bytes.Repeat([]byte{0x55}, 32), spaceID, ownerID); err != nil {
			t.Fatalf("insert bounded Veil Link: %v", err)
		}
		_, err = pool.Exec(ctx, `INSERT INTO server_invites
			(public_selector,secret_hash,server_id,created_by,max_uses,expires_at)
			VALUES ($1,$2,$3::uuid,$4::uuid,0,now()+interval '1 day')`, strings.Repeat("B", 43),
			bytes.Repeat([]byte{0x66}, 32), spaceID, ownerID)
		requireMigrationError(t, err, "23514", "server_invites_bounded_uses")
		if _, err := pool.Exec(ctx, `INSERT INTO server_bans(server_id,user_id,banned_by,reason)
			VALUES ($1::uuid,$2::uuid,$3::uuid,'raid')`, spaceID, targetID, ownerID); err != nil {
			t.Fatalf("insert authoritative ban: %v", err)
		}
	})

	t.Run("024 adds fail-closed push delivery policy defaults and index", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_024")
		applyMigrationsBefore(t, pool, migrations, 24)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var userID string
		if err := pool.QueryRow(ctx, `INSERT INTO users(identity_key, signing_key, username)
			VALUES ($1,$2,'push-policy-upgrade') RETURNING id::text`,
			bytes.Repeat([]byte{0x71}, 32), bytes.Repeat([]byte{0x72}, 32)).Scan(&userID); err != nil {
			t.Fatal(err)
		}
		var subscriptionID int64
		if err := pool.QueryRow(ctx, `INSERT INTO push_subscriptions(user_id, endpoint_url)
			VALUES ($1::uuid,'https://push.example/legacy') RETURNING id`, userID).Scan(&subscriptionID); err != nil {
			t.Fatal(err)
		}
		if err := execMigration(t, pool, migrations, 24); err != nil {
			t.Fatalf("migration 024: %v", err)
		}
		var enabled bool
		var mutedUntil *time.Time
		if err := pool.QueryRow(ctx, `SELECT enabled, muted_until FROM push_subscriptions WHERE id=$1`, subscriptionID).Scan(&enabled, &mutedUntil); err != nil || !enabled || mutedUntil != nil {
			t.Fatalf("legacy push policy defaults enabled=%v muted=%v err=%v", enabled, mutedUntil, err)
		}
		var indexes int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM pg_indexes
			WHERE schemaname=current_schema() AND indexname='idx_push_subscriptions_delivery'`).Scan(&indexes); err != nil || indexes != 1 {
			t.Fatalf("push delivery policy index=%d err=%v", indexes, err)
		}
	})

	t.Run("025 removes endpoint-only subscriptions and requires Web Push validation state", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_025")
		applyMigrationsBefore(t, pool, migrations, 25)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var userID string
		if err := pool.QueryRow(ctx, `INSERT INTO users(identity_key, signing_key, username)
			VALUES ($1,$2,'webpush-cutover') RETURNING id::text`,
			bytes.Repeat([]byte{0x73}, 32), bytes.Repeat([]byte{0x74}, 32)).Scan(&userID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO push_subscriptions(user_id, endpoint_url)
			VALUES ($1::uuid,'https://push.example/obsolete')`, userID); err != nil {
			t.Fatal(err)
		}
		if err := execMigration(t, pool, migrations, 25); err != nil {
			t.Fatalf("migration 025: %v", err)
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM push_subscriptions`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("obsolete subscriptions retained count=%d err=%v", count, err)
		}
		_, err := pool.Exec(ctx, `INSERT INTO push_subscriptions
			(user_id,endpoint_url,webpush_public_key,webpush_auth_secret)
			VALUES ($1::uuid,'https://push.example/incomplete',$2,$3)`, userID,
			base64.RawURLEncoding.EncodeToString(append([]byte{4}, make([]byte, 64)...)),
			base64.RawURLEncoding.EncodeToString(make([]byte, 16)))
		requireMigrationError(t, err, "23514", "push_validation_state_consistent")
	})

	t.Run("027 backfills monotonic prekey state and requires verifiable legacy receipt", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_027")
		applyMigrationsBefore(t, pool, migrations, 27)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var userID, deviceID, missingDeviceID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO users(identity_key, signing_key, username)
			 VALUES ($1,$2,'prekey-state-upgrade') RETURNING id::text`,
			bytes.Repeat([]byte{0x81}, 32), bytes.Repeat([]byte{0x82}, 32),
		).Scan(&userID); err != nil {
			t.Fatal(err)
		}
		for _, fixture := range []struct {
			marker byte
			name   string
			result *string
		}{
			{marker: 0x83, name: "legacy-complete", result: &deviceID},
			{marker: 0x84, name: "legacy-missing", result: &missingDeviceID},
		} {
			if err := pool.QueryRow(ctx,
				`INSERT INTO devices(user_id,device_key,device_name)
				 VALUES ($1::uuid,$2,$3) RETURNING id::text`,
				userID, bytes.Repeat([]byte{fixture.marker}, 16), fixture.name,
			).Scan(fixture.result); err != nil {
				t.Fatal(err)
			}
		}

		oldSPK := bytes.Repeat([]byte{0x91}, 32)
		oldSignature := bytes.Repeat([]byte{0x92}, 64)
		currentSPK := bytes.Repeat([]byte{0x93}, 32)
		currentSignature := bytes.Repeat([]byte{0x94}, 64)
		if _, err := pool.Exec(ctx,
			`INSERT INTO prekeys(device_id,key_type,protocol_key_id,public_key,signature,used)
			 VALUES ($1::uuid,0,9,$2,$3,false),
			        ($1::uuid,1,1,$4,NULL,true)`,
			deviceID, oldSPK, oldSignature, bytes.Repeat([]byte{0x95}, 32),
		); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO prekeys(device_id,key_type,protocol_key_id,public_key,signature,used)
			 SELECT $1::uuid,1,n,digest(n::text,'sha256'),NULL,false
			 FROM generate_series(2,106) n`,
			deviceID,
		); err != nil {
			t.Fatal(err)
		}
		opk111 := bytes.Repeat([]byte{0x96}, 32)
		opk112 := bytes.Repeat([]byte{0x97}, 32)
		if _, err := pool.Exec(ctx,
			`INSERT INTO prekeys(device_id,key_type,protocol_key_id,public_key,signature,used)
			 VALUES ($1::uuid,0,2,$2,$3,false),
			        ($1::uuid,1,111,$4,NULL,true),
			        ($1::uuid,1,112,$5,NULL,false)`,
			deviceID, currentSPK, currentSignature, opk111, opk112,
		); err != nil {
			t.Fatal(err)
		}
		missingSPK := bytes.Repeat([]byte{0xa1}, 32)
		missingSignature := bytes.Repeat([]byte{0xa2}, 64)
		missingOPK := bytes.Repeat([]byte{0xa3}, 32)
		if _, err := pool.Exec(ctx,
			`INSERT INTO prekeys(device_id,key_type,protocol_key_id,public_key,signature,used)
			 VALUES ($1::uuid,0,5,$2,$3,false),
			        ($1::uuid,1,50,$4,NULL,true)`,
			missingDeviceID, missingSPK, missingSignature, missingOPK,
		); err != nil {
			t.Fatal(err)
		}

		if err := execMigration(t, pool, migrations, 27); err != nil {
			t.Fatalf("migration 027: %v", err)
		}
		var signedHigh, oneTimeHigh, signedRows, unusedRows, usedRows int
		var latestDigest []byte
		if err := pool.QueryRow(ctx,
			`SELECT s.signed_prekey_high_watermark,
			        s.one_time_prekey_high_watermark,
			        s.latest_upload_digest,
			        COUNT(*) FILTER (WHERE p.key_type=0),
			        COUNT(*) FILTER (WHERE p.key_type=1 AND p.used=false),
			        COUNT(*) FILTER (WHERE p.key_type=1 AND p.used=true)
			 FROM prekey_publication_state s
			 LEFT JOIN prekeys p ON p.device_id=s.device_id
			 WHERE s.device_id=$1::uuid
			 GROUP BY s.signed_prekey_high_watermark,
			          s.one_time_prekey_high_watermark,
			          s.latest_upload_digest`,
			deviceID,
		).Scan(&signedHigh, &oneTimeHigh, &latestDigest, &signedRows, &unusedRows, &usedRows); err != nil {
			t.Fatal(err)
		}
		// The historical protocol allowed non-monotonic SPK ids. The newest
		// database row is current even though the durable watermark must retain
		// the larger retired id 9 to prevent resurrection.
		if signedHigh != 9 || oneTimeHigh != 112 || latestDigest != nil ||
			signedRows != 1 || unusedRows > 100 || usedRows != 2 {
			t.Fatalf("027 backfill high=%d/%d digest=%x rows=%d/%d/%d",
				signedHigh, oneTimeHigh, latestDigest, signedRows, unusedRows, usedRows)
		}

		database := &veildb.DB{Pool: pool}
		claimed, err := database.ClaimOneTimePreKey(ctx, deviceID)
		if err != nil || claimed == nil {
			t.Fatalf("legacy claim=%#v err=%v", claimed, err)
		}
		var claimedRetained bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM prekeys WHERE id=$1 AND used=true)`,
			claimed.ID,
		).Scan(&claimedRetained); err != nil || !claimedRetained {
			t.Fatalf("legacy claim retained=%v err=%v", claimedRetained, err)
		}

		if _, err := pool.Exec(ctx,
			`DELETE FROM prekeys
			 WHERE device_id=$1::uuid AND key_type=1 AND protocol_key_id=50`,
			missingDeviceID,
		); err != nil {
			t.Fatal(err)
		}
		missingBatch := []veildb.PreKey{
			{KeyType: 0, ProtocolKeyID: 5, PublicKey: missingSPK, Signature: missingSignature},
			{KeyType: 1, ProtocolKeyID: 50, PublicKey: missingOPK},
		}
		if _, err := database.StorePreKeysWithReceipt(
			ctx, missingDeviceID, missingBatch, sha256.Sum256([]byte("missing-legacy-body")),
		); !errors.Is(err, veildb.ErrPreKeyMaterialConflict) {
			t.Fatalf("missing legacy material error=%v", err)
		}

		legacyBatch := []veildb.PreKey{
			{KeyType: 0, ProtocolKeyID: 2, PublicKey: currentSPK, Signature: currentSignature},
			{KeyType: 1, ProtocolKeyID: 111, PublicKey: opk111},
			{KeyType: 1, ProtocolKeyID: 112, PublicKey: opk112},
		}
		legacyDigest := sha256.Sum256([]byte("exact-legacy-body"))
		receipt, err := database.StorePreKeysWithReceipt(ctx, deviceID, legacyBatch, legacyDigest)
		if err != nil || receipt.Stored != len(legacyBatch) {
			t.Fatalf("verified legacy adoption receipt=%#v err=%v", receipt, err)
		}
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM prekeys
			 WHERE device_id=$1::uuid AND key_type=1 AND used=true`,
			deviceID,
		).Scan(&usedRows); err != nil || usedRows != 0 {
			t.Fatalf("post-adoption legacy used rows=%d err=%v", usedRows, err)
		}
		receipt, err = database.StorePreKeysWithReceipt(ctx, deviceID, legacyBatch, legacyDigest)
		if err != nil || !receipt.Replay || receipt.Stored != len(legacyBatch) {
			t.Fatalf("legacy exact replay receipt=%#v err=%v", receipt, err)
		}

		retiredSigned := []veildb.PreKey{{
			KeyType: 0, ProtocolKeyID: 9, PublicKey: oldSPK, Signature: oldSignature,
		}}
		if _, err := database.StorePreKeysWithReceipt(
			ctx, deviceID, retiredSigned, sha256.Sum256([]byte("retired-signed-body")),
		); !errors.Is(err, veildb.ErrPreKeyMaterialConflict) {
			t.Fatalf("retired signed prekey error=%v, want material conflict", err)
		}

		nextSPK := []veildb.PreKey{{
			KeyType:       0,
			ProtocolKeyID: 10,
			PublicKey:     bytes.Repeat([]byte{0x98}, 32),
			Signature:     bytes.Repeat([]byte{0x99}, 64),
		}}
		if _, err := database.StorePreKeysWithReceipt(
			ctx, deviceID, nextSPK, sha256.Sum256([]byte("next-monotonic-body")),
		); err != nil {
			t.Fatalf("next monotonic signed prekey: %v", err)
		}
		current, err := database.GetSignedPreKey(ctx, deviceID)
		if err != nil || current.ProtocolKeyID != 10 {
			t.Fatalf("current signed prekey=%#v err=%v, want protocol id 10", current, err)
		}
	})

	t.Run("028 cleans legacy scope, prunes deterministically, and guards raw writers", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_028")
		applyMigrationsBefore(t, pool, migrations, 28)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var userID, messageID, conversationID, otherConversationID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO users(identity_key, signing_key, username)
			 VALUES ($1,$2,'reaction-bound-upgrade') RETURNING id::text`,
			bytes.Repeat([]byte{0xb1}, 32), bytes.Repeat([]byte{0xb2}, 32),
		).Scan(&userID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx,
			`INSERT INTO conversations(conv_type,name)
			 VALUES (0,'reaction-bound-primary') RETURNING id::text`,
		).Scan(&conversationID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx,
			`INSERT INTO conversations(conv_type,name)
			 VALUES (0,'reaction-bound-other') RETURNING id::text`,
		).Scan(&otherConversationID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx,
			`INSERT INTO messages(conversation_id,sender_id,ciphertext)
			 VALUES ($1::uuid,$2::uuid,'\x01') RETURNING id::text`,
			conversationID, userID,
		).Scan(&messageID); err != nil {
			t.Fatal(err)
		}

		// Simulate rows that predate migration 009's NOT VALID foreign keys.
		if _, err := pool.Exec(ctx,
			`ALTER TABLE reactions DROP CONSTRAINT reactions_message_conversation_fk;
			 ALTER TABLE reactions DROP CONSTRAINT reactions_user_fk`,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO reactions(message_id,conversation_id,user_id,emoji,created_at)
			 SELECT $1::uuid,$2::uuid,$3::uuid,
			        'legacy-' || lpad(value::text,3,'0'),
			        TIMESTAMPTZ '2026-01-01 00:00:00+00' + value * INTERVAL '1 second'
			 FROM generate_series(1,260) AS value`,
			messageID, conversationID, userID,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO reactions(message_id,conversation_id,user_id,emoji,created_at)
			 VALUES
			   ($1::uuid,$2::uuid,$3::uuid,'legacy-invalid-scope',TIMESTAMPTZ '2025-01-01'),
			   ($1::uuid,$4::uuid,gen_random_uuid(),'legacy-invalid-user',TIMESTAMPTZ '2025-01-02')`,
			messageID, otherConversationID, userID, conversationID,
		); err != nil {
			t.Fatal(err)
		}

		if err := execMigration(t, pool, migrations, 28); err != nil {
			t.Fatalf("migration 028: %v", err)
		}
		var retained []string
		if err := pool.QueryRow(ctx,
			`SELECT array_agg(emoji ORDER BY created_at,user_id,emoji COLLATE "C")
			 FROM reactions WHERE message_id=$1::uuid`,
			messageID,
		).Scan(&retained); err != nil {
			t.Fatal(err)
		}
		if len(retained) != veildb.MaxReactionsPerMessage {
			t.Fatalf("retained reaction count=%d, want %d", len(retained), veildb.MaxReactionsPerMessage)
		}
		for index, emoji := range retained {
			want := "legacy-" + fmt.Sprintf("%03d", index+1)
			if emoji != want {
				t.Fatalf("retained reaction[%d]=%q, want %q", index, emoji, want)
			}
		}
		var minSlot, maxSlot, distinctSlots int
		if err := pool.QueryRow(ctx,
			`SELECT min(history_slot),max(history_slot),count(DISTINCT history_slot)
			 FROM reactions WHERE message_id=$1::uuid`,
			messageID,
		).Scan(&minSlot, &maxSlot, &distinctSlots); err != nil ||
			minSlot != 0 || maxSlot != veildb.MaxReactionsPerMessage-1 ||
			distinctSlots != veildb.MaxReactionsPerMessage {
			t.Fatalf(
				"reaction slots min=%d max=%d distinct=%d err=%v",
				minSlot, maxSlot, distinctSlots, err,
			)
		}
		var validatedCount int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM pg_constraint
			 WHERE conrelid='reactions'::regclass
			   AND conname IN ('reactions_message_conversation_fk','reactions_user_fk')
			   AND convalidated`,
		).Scan(&validatedCount); err != nil || validatedCount != 2 {
			t.Fatalf("validated reaction FK count=%d err=%v, want 2", validatedCount, err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO reactions(message_id,conversation_id,user_id,emoji)
			 VALUES ($1::uuid,$2::uuid,$3::uuid,'legacy-001')
			 ON CONFLICT (message_id,user_id,emoji) DO NOTHING`,
			messageID, conversationID, userID,
		); err != nil {
			t.Fatalf("raw exact retry at cap: %v", err)
		}
		_, err := pool.Exec(ctx,
			`INSERT INTO reactions(message_id,conversation_id,user_id,emoji)
			 VALUES ($1::uuid,$2::uuid,$3::uuid,'raw-overflow')`,
			messageID, conversationID, userID,
		)
		requireMigrationError(t, err, "23514", "message reaction limit reached")
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.ConstraintName != "reactions_per_message_limit" {
			t.Fatalf("raw overflow constraint=%v, want reactions_per_message_limit", pgErr)
		}

		var sourceMessageID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO messages(conversation_id,sender_id,ciphertext)
			 VALUES ($1::uuid,$2::uuid,'\x02') RETURNING id::text`,
			otherConversationID, userID,
		).Scan(&sourceMessageID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO reactions(message_id,conversation_id,user_id,emoji)
			 VALUES ($1::uuid,$2::uuid,$3::uuid,'move-source')`,
			sourceMessageID, otherConversationID, userID,
		); err != nil {
			t.Fatal(err)
		}
		_, err = pool.Exec(ctx,
			`UPDATE reactions
			 SET message_id=$1::uuid, conversation_id=$2::uuid, emoji='raw-update-overflow'
			 WHERE message_id=$3::uuid AND user_id=$4::uuid AND emoji='move-source'`,
			messageID, conversationID, sourceMessageID, userID,
		)
		requireMigrationError(t, err, "23514", "reaction identity is immutable")
		pgErr = nil
		if !errors.As(err, &pgErr) || pgErr.ConstraintName != "reactions_identity_immutable" {
			t.Fatalf("raw update constraint=%v, want reactions_identity_immutable", pgErr)
		}
		var targetCount int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM reactions WHERE message_id=$1::uuid`, messageID,
		).Scan(&targetCount); err != nil || targetCount != veildb.MaxReactionsPerMessage {
			t.Fatalf("raw update target count=%d err=%v, want %d", targetCount, err, veildb.MaxReactionsPerMessage)
		}
	})

	t.Run("029 adds durable account-scoped message send idempotency", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_029")
		applyMigrationsBefore(t, pool, migrations, 29)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var senderID, otherSenderID string
		for index, destination := range []*string{&senderID, &otherSenderID} {
			if err := pool.QueryRow(ctx,
				`INSERT INTO users(identity_key,signing_key,username)
				 VALUES ($1,$2,$3) RETURNING id::text`,
				bytes.Repeat([]byte{byte(0xc1 + index*2)}, 32),
				bytes.Repeat([]byte{byte(0xc2 + index*2)}, 32),
				fmt.Sprintf("send-ledger-%d", index),
			).Scan(destination); err != nil {
				t.Fatal(err)
			}
		}
		if err := execMigration(t, pool, migrations, 29); err != nil {
			t.Fatalf("migration 029: %v", err)
		}

		var messageForeignKeys, senderForeignKeys int
		if err := pool.QueryRow(ctx,
			`SELECT
			   count(*) FILTER (WHERE pg_get_constraintdef(oid) LIKE 'FOREIGN KEY (message_id)%'),
			   count(*) FILTER (WHERE pg_get_constraintdef(oid) LIKE 'FOREIGN KEY (sender_id)%')
			 FROM pg_constraint
			 WHERE conrelid='message_send_idempotency'::regclass AND contype='f'`,
		).Scan(&messageForeignKeys, &senderForeignKeys); err != nil {
			t.Fatal(err)
		}
		if messageForeignKeys != 0 || senderForeignKeys != 1 {
			t.Fatalf("ledger foreign keys message=%d sender=%d, want 0,1", messageForeignKeys, senderForeignKeys)
		}

		clientMessageID := "11111111-1111-4111-8111-111111111111"
		messageID := "22222222-2222-4222-8222-222222222222"
		if _, err := pool.Exec(ctx,
			`INSERT INTO message_send_idempotency
			   (sender_id,client_message_id,request_digest,message_id,server_timestamp)
			 VALUES ($1::uuid,$2::uuid,$3,$4::uuid,now())`,
			senderID, clientMessageID, bytes.Repeat([]byte{0xd1}, sha256.Size), messageID,
		); err != nil {
			t.Fatalf("insert tombstone-safe ledger row: %v", err)
		}

		_, err := pool.Exec(ctx,
			`INSERT INTO message_send_idempotency
			   (sender_id,client_message_id,request_digest,message_id,server_timestamp)
			 VALUES ($1::uuid,gen_random_uuid(),$2,gen_random_uuid(),now())`,
			senderID, bytes.Repeat([]byte{0xd2}, sha256.Size-1),
		)
		requireMigrationError(t, err, "23514", "message_send_idempotency_digest_length")

		_, err = pool.Exec(ctx,
			`INSERT INTO message_send_idempotency
			   (sender_id,client_message_id,request_digest,message_id,server_timestamp,ack_roster_version)
			 VALUES ($1::uuid,gen_random_uuid(),$2,gen_random_uuid(),now(),0)`,
			senderID, bytes.Repeat([]byte{0xd3}, sha256.Size),
		)
		requireMigrationError(t, err, "23514", "message_send_idempotency_roster_version")

		_, err = pool.Exec(ctx,
			`INSERT INTO message_send_idempotency
			   (sender_id,client_message_id,request_digest,message_id,server_timestamp)
			 VALUES ($1::uuid,$2::uuid,$3,gen_random_uuid(),now())`,
			senderID, clientMessageID, bytes.Repeat([]byte{0xd4}, sha256.Size),
		)
		requireMigrationError(t, err, "23505", "message_send_idempotency_pkey")

		// The same client ID belongs to a different account scope, while a
		// server message ID can never identify two send intents.
		if _, err := pool.Exec(ctx,
			`INSERT INTO message_send_idempotency
			   (sender_id,client_message_id,request_digest,message_id,server_timestamp,ack_roster_version)
			 VALUES ($1::uuid,$2::uuid,$3,gen_random_uuid(),now(),7)`,
			otherSenderID, clientMessageID, bytes.Repeat([]byte{0xd5}, sha256.Size),
		); err != nil {
			t.Fatalf("account-scoped client ID insert: %v", err)
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO message_send_idempotency
			   (sender_id,client_message_id,request_digest,message_id,server_timestamp)
			 VALUES ($1::uuid,gen_random_uuid(),$2,$3::uuid,now())`,
			otherSenderID, bytes.Repeat([]byte{0xd6}, sha256.Size), messageID,
		)
		requireMigrationError(t, err, "23505", "message_send_idempotency_message_id_unique")

		if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, senderID); err != nil {
			t.Fatal(err)
		}
		var retained int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM message_send_idempotency WHERE sender_id=$1::uuid`, senderID,
		).Scan(&retained); err != nil || retained != 0 {
			t.Fatalf("sender cascade retained=%d err=%v, want 0", retained, err)
		}
	})

	t.Run("030 adds bounded cross-process REST auth v2 replay markers", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_030")
		applyMigrationsBefore(t, pool, migrations, 30)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var userA, userB string
		for index, destination := range []*string{&userA, &userB} {
			if err := pool.QueryRow(ctx,
				`INSERT INTO users(identity_key, signing_key, username)
				 VALUES ($1, $2, $3) RETURNING id::text`,
				bytes.Repeat([]byte{byte(0xe1 + index*2)}, 32),
				bytes.Repeat([]byte{byte(0xe2 + index*2)}, 32),
				fmt.Sprintf("rest-replay-%d", index),
			).Scan(destination); err != nil {
				t.Fatal(err)
			}
		}
		if err := execMigration(t, pool, migrations, 30); err != nil {
			t.Fatalf("migration 030: %v", err)
		}

		nonce := bytes.Repeat([]byte{0xf1}, 32)
		if _, err := pool.Exec(ctx,
			`INSERT INTO rest_auth_v2_replay_nonces (user_id, nonce, expires_at)
			 VALUES ($1::uuid, $2, clock_timestamp() + interval '5 minutes')`,
			userA, nonce,
		); err != nil {
			t.Fatalf("insert valid REST replay marker: %v", err)
		}
		_, err := pool.Exec(ctx,
			`INSERT INTO rest_auth_v2_replay_nonces (user_id, nonce, expires_at)
			 VALUES ($1::uuid, $2, clock_timestamp() + interval '5 minutes')`,
			userA, nonce,
		)
		requireMigrationError(t, err, "23505", "rest_auth_v2_replay_nonces_pkey")
		if _, err := pool.Exec(ctx,
			`INSERT INTO rest_auth_v2_replay_nonces (user_id, nonce, expires_at)
			 VALUES ($1::uuid, $2, clock_timestamp() + interval '5 minutes')`,
			userB, nonce,
		); err != nil {
			t.Fatalf("account-scoped nonce insert: %v", err)
		}

		for name, input := range map[string]struct {
			nonce      []byte
			expiry     string
			constraint string
		}{
			"short nonce": {
				nonce: bytes.Repeat([]byte{0xf2}, 31), expiry: "5 minutes",
				constraint: "rest_auth_v2_replay_nonce_length",
			},
			"zero nonce": {
				nonce: make([]byte, 32), expiry: "5 minutes",
				constraint: "rest_auth_v2_replay_nonce_nonzero",
			},
			"old expiry": {
				nonce: bytes.Repeat([]byte{0xf3}, 32), expiry: "-1 minute",
				constraint: "rest_auth_v2_replay_expiry_order",
			},
			"long expiry": {
				nonce: bytes.Repeat([]byte{0xf4}, 32), expiry: "11 minutes",
				constraint: "rest_auth_v2_replay_retention_bound",
			},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := pool.Exec(ctx,
					`INSERT INTO rest_auth_v2_replay_nonces (user_id, nonce, expires_at)
					 VALUES ($1::uuid, $2, clock_timestamp() + $3::interval)`,
					userA, input.nonce, input.expiry,
				)
				requireMigrationError(t, err, "23514", input.constraint)
			})
		}

		var expiryIndexes int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_indexes
			 WHERE schemaname = current_schema()
			   AND tablename = 'rest_auth_v2_replay_nonces'
			   AND indexname = 'idx_rest_auth_v2_replay_expiry'`,
		).Scan(&expiryIndexes); err != nil || expiryIndexes != 1 {
			t.Fatalf("expiry indexes=%d err=%v, want 1", expiryIndexes, err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, userB); err != nil {
			t.Fatal(err)
		}
		var retained int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM rest_auth_v2_replay_nonces WHERE user_id=$1::uuid`, userB,
		).Scan(&retained); err != nil || retained != 0 {
			t.Fatalf("user cascade retained=%d err=%v, want 0", retained, err)
		}
	})

	t.Run("031 preserves legacy rows and enforces exact Direct v2 context", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_031")
		applyMigrationsBefore(t, pool, migrations, 31)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var senderID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO users(identity_key, signing_key, username)
				 VALUES ($1, $2, 'direct-v2-migration-sender') RETURNING id::text`,
			bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x12}, 32),
		).Scan(&senderID); err != nil {
			t.Fatal(err)
		}
		var directConversationID, groupConversationID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO conversations(conv_type, name)
				 VALUES (0, '031-direct') RETURNING id::text`,
		).Scan(&directConversationID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx,
			`INSERT INTO conversations(conv_type, name)
				 VALUES (1, '031-group') RETURNING id::text`,
		).Scan(&groupConversationID); err != nil {
			t.Fatal(err)
		}

		var legacyMessageID, senderKeyMessageID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO messages(conversation_id, sender_id, ciphertext, header)
				 VALUES ($1::uuid, $2::uuid, $3, $4) RETURNING id::text`,
			directConversationID, senderID, []byte("legacy-direct"), []byte{0x01},
		).Scan(&legacyMessageID); err != nil {
			t.Fatalf("insert pre-031 legacy Direct row: %v", err)
		}
		if err := pool.QueryRow(ctx,
			`INSERT INTO messages(
				   conversation_id, sender_id, ciphertext, header,
				   crypto_profile, crypto_era, roster_version, roster_commitment,
				   sender_device_id, sender_binding_version
				 ) VALUES ($1::uuid, $2::uuid, $3, $4, 'sender_key_v5', 1, 9, $5, $6, 7)
				 RETURNING id::text`,
			groupConversationID, senderID, []byte("sender-key"), []byte{0x05},
			bytes.Repeat([]byte{0x21}, 32), bytes.Repeat([]byte{0x22}, 16),
		).Scan(&senderKeyMessageID); err != nil {
			t.Fatalf("insert pre-031 Sender-Key row: %v", err)
		}

		if err := execMigration(t, pool, migrations, 31); err != nil {
			t.Fatalf("migration 031: %v", err)
		}

		var legacyRows, senderKeyRows int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM messages
				 WHERE id=$1::uuid
				   AND crypto_profile IS NULL AND target_device_id IS NULL
				   AND direct_session_id IS NULL AND sender_account_signature IS NULL`,
			legacyMessageID,
		).Scan(&legacyRows); err != nil || legacyRows != 1 {
			t.Fatalf("legacy Direct rows=%d err=%v, want preserved all-NULL context", legacyRows, err)
		}
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM messages
				 WHERE id=$1::uuid AND crypto_profile='sender_key_v5'
				   AND target_device_id IS NULL AND direct_session_id IS NULL
				   AND sender_device_identity_key IS NULL AND sender_account_signature IS NULL`,
			senderKeyMessageID,
		).Scan(&senderKeyRows); err != nil || senderKeyRows != 1 {
			t.Fatalf("Sender-Key rows=%d err=%v, want preserved profile-specific context", senderKeyRows, err)
		}

		senderDeviceID := bytes.Repeat([]byte{0x31}, 16)
		targetDeviceID := bytes.Repeat([]byte{0x32}, 16)
		directSessionID := bytes.Repeat([]byte{0x33}, 32)
		identityKey := bytes.Repeat([]byte{0x34}, 32)
		signingKey := bytes.Repeat([]byte{0x35}, 32)
		accountSignature := bytes.Repeat([]byte{0x36}, 64)
		var directV2MessageID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO messages(
				   conversation_id, sender_id, ciphertext, header,
				   crypto_profile, crypto_era, sender_device_id, sender_binding_version,
				   target_device_id, target_binding_version, direct_session_id,
				   sender_device_identity_key, sender_device_signing_key,
				   sender_device_capabilities, sender_device_binding_status,
				   sender_account_signature
				 ) VALUES (
				   $1::uuid, $2::uuid, $3, $4, 'direct_v2', 1, $5, 7,
				   $6, 8, $7, $8, $9, 3, 1, $10
				 ) RETURNING id::text`,
			directConversationID, senderID, []byte("direct-v2"), []byte{0x11},
			senderDeviceID, targetDeviceID, directSessionID,
			identityKey, signingKey, accountSignature,
		).Scan(&directV2MessageID); err != nil {
			t.Fatalf("insert valid Direct v2 row: %v", err)
		}

		for name, mutation := range map[string]struct {
			sessionID   []byte
			targetID    []byte
			identityKey []byte
			signingKey  []byte
			signature   []byte
		}{
			"zero session": {
				sessionID: make([]byte, 32), targetID: targetDeviceID,
				identityKey: identityKey, signingKey: signingKey, signature: accountSignature,
			},
			"sender target collision": {
				sessionID: directSessionID, targetID: senderDeviceID,
				identityKey: identityKey, signingKey: signingKey, signature: accountSignature,
			},
			"zero identity key": {
				sessionID: directSessionID, targetID: targetDeviceID,
				identityKey: make([]byte, 32), signingKey: signingKey, signature: accountSignature,
			},
			"key collision": {
				sessionID: directSessionID, targetID: targetDeviceID,
				identityKey: identityKey, signingKey: identityKey, signature: accountSignature,
			},
			"zero signature": {
				sessionID: directSessionID, targetID: targetDeviceID,
				identityKey: identityKey, signingKey: signingKey, signature: make([]byte, 64),
			},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := pool.Exec(ctx,
					`INSERT INTO messages(
						   conversation_id, sender_id, ciphertext, crypto_profile, crypto_era,
						   sender_device_id, sender_binding_version,
						   target_device_id, target_binding_version, direct_session_id,
						   sender_device_identity_key, sender_device_signing_key,
						   sender_device_capabilities, sender_device_binding_status,
						   sender_account_signature
						 ) VALUES ($1::uuid, $2::uuid, $3, 'direct_v2', 1, $4, 7, $5, 8, $6, $7, $8, 3, 1, $9)`,
					directConversationID, senderID, []byte("invalid-direct-v2"),
					senderDeviceID, mutation.targetID, mutation.sessionID,
					mutation.identityKey, mutation.signingKey, mutation.signature,
				)
				requireMigrationError(t, err, "23514", "messages_security_context_all_or_none")
			})
		}

		_, err := pool.Exec(ctx,
			`INSERT INTO messages(
				   conversation_id, sender_id, ciphertext,
				   crypto_profile, crypto_era, roster_version, roster_commitment,
				   sender_device_id, sender_binding_version
				 ) VALUES ($1::uuid, $2::uuid, $3, 'sender_key_v5', 1, 1, $4, $5, 1)`,
			directConversationID, senderID, []byte("profile-smuggling"),
			bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x42}, 16),
		)
		requireMigrationError(t, err, "23514", "direct-message row has an invalid crypto profile")

		_, err = pool.Exec(ctx,
			`INSERT INTO messages(
				   conversation_id, sender_id, ciphertext, crypto_profile, crypto_era,
				   sender_device_id, sender_binding_version,
				   target_device_id, target_binding_version, direct_session_id,
				   sender_device_identity_key, sender_device_signing_key,
				   sender_device_capabilities, sender_device_binding_status,
				   sender_account_signature
				 ) VALUES ($1::uuid, $2::uuid, $3, 'direct_v2', 1, $4, 7, $5, 8, $6, $7, $8, 3, 1, $9)`,
			groupConversationID, senderID, []byte("cross-profile"),
			senderDeviceID, targetDeviceID, directSessionID,
			identityKey, signingKey, accountSignature,
		)
		requireMigrationError(t, err, "23514", "new group/channel message requires persisted Sender-Key security context")

		_, err = pool.Exec(ctx,
			`UPDATE messages SET ciphertext=$1 WHERE id=$2::uuid`,
			[]byte("mutated-direct-v2"), directV2MessageID,
		)
		requireMigrationError(t, err, "23514", "versioned secure ciphertext edits require a new exact routing protocol")

		var targetIndexes int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_indexes
				 WHERE schemaname=current_schema() AND tablename='messages'
				   AND indexname='idx_messages_direct_v2_target'`,
		).Scan(&targetIndexes); err != nil || targetIndexes != 1 {
			t.Fatalf("Direct v2 target indexes=%d err=%v, want 1", targetIndexes, err)
		}
	})

	t.Run("032 makes transparency history append-only and head advances exact", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_032")
		applyMigrationsBefore(t, pool, migrations, 32)
		ownerID, _ := seedMigrationMembershipScope(t, pool, "transparency")
		if err := execMigration(t, pool, migrations, 32); err != nil {
			t.Fatalf("migration 032: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx,
			`INSERT INTO identity_transparency_log_state
			   (singleton, log_id, node_signing_key, tree_size, root_hash)
			 VALUES (TRUE, $1, $2, 0, $3)`,
			bytes.Repeat([]byte{0x31}, 32), bytes.Repeat([]byte{0x32}, 32),
			bytes.Repeat([]byte{0x33}, 32),
		); err != nil {
			t.Fatalf("insert transparency head: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO identity_transparency_log_leaves
			   (leaf_index, event_kind, subject_user_id, canonical_event, leaf_hash)
			 VALUES (0, 1, $1::uuid, $2, $3)`,
			ownerID, []byte("account-registration"), bytes.Repeat([]byte{0x34}, 32),
		); err != nil {
			t.Fatalf("insert transparency leaf: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO identity_transparency_log_nodes(node_level, node_index, node_hash)
			 VALUES (0, 0, $1)`, bytes.Repeat([]byte{0x34}, 32),
		); err != nil {
			t.Fatalf("insert transparency node: %v", err)
		}
		_, err := pool.Exec(ctx,
			`UPDATE identity_transparency_log_leaves
			 SET canonical_event=$1 WHERE leaf_index=0`, []byte("rewritten"),
		)
		requireMigrationError(t, err, "23514", "identity transparency history is append-only")
		_, err = pool.Exec(ctx,
			`DELETE FROM identity_transparency_log_nodes WHERE node_level=0 AND node_index=0`,
		)
		requireMigrationError(t, err, "23514", "identity transparency history is append-only")
		_, err = pool.Exec(ctx,
			`UPDATE identity_transparency_log_state
			 SET tree_size=2, root_hash=$1 WHERE singleton=TRUE`,
			bytes.Repeat([]byte{0x35}, 32),
		)
		requireMigrationError(t, err, "23514", "identity transparency head transition is invalid")
	})

	t.Run("033 requires complete immutable membership epochs", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_033")
		applyMigrationsBefore(t, pool, migrations, 33)
		ownerID, conversationID := seedMigrationMembershipScope(t, pool, "membership")
		if err := execMigration(t, pool, migrations, 33); err != nil {
			t.Fatalf("migration 033: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		epochOneHash := bytes.Repeat([]byte{0x41}, 32)
		rosterCommitment := bytes.Repeat([]byte{0x42}, 32)
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		insertMigrationMembershipEpoch(t, ctx, tx, conversationID, ownerID, 1,
			make([]byte, 32), 1, rosterCommitment, epochOneHash)
		if _, err := tx.Exec(ctx,
			`INSERT INTO conversation_membership_epoch_heads_v1
			   (conversation_id, epoch_number, epoch_hash, roster_version, roster_commitment)
			 VALUES ($1::uuid, 1, $2, 1, $3)`,
			conversationID, epochOneHash, rosterCommitment,
		); err != nil {
			t.Fatalf("insert membership head: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit complete membership epoch: %v", err)
		}
		_, err = pool.Exec(ctx,
			`UPDATE conversation_membership_epochs_v1
			 SET canonical_unsigned=$1 WHERE conversation_id=$2::uuid AND epoch_number=1`,
			[]byte("rewritten"), conversationID,
		)
		requireMigrationError(t, err, "55000", "membership epoch history is immutable")

		tx, err = pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO conversation_membership_epochs_v1 (
			   conversation_id, epoch_number, canonical_origin, conversation_kind,
			   predecessor_hash, roster_version, roster_commitment,
			   policy_threshold, policy_signer_count, crypto_profile, crypto_era,
			   mutation_nonce, epoch_hash, canonical_unsigned, submitted_by
			 ) VALUES ($1::uuid, 2, 'https://veil.example:443', 1, $2, 2, $3,
			           1, 1, 1, 1, $4, $5, $6, $7::uuid)`,
			conversationID, epochOneHash, bytes.Repeat([]byte{0x43}, 32),
			bytes.Repeat([]byte{0x44}, 32), bytes.Repeat([]byte{0x45}, 32),
			[]byte("incomplete-epoch"), ownerID,
		); err != nil {
			t.Fatalf("insert incomplete membership epoch: %v", err)
		}
		err = tx.Commit(ctx)
		requireMigrationError(t, err, "23514", "membership epoch child rows are incomplete")
	})

	t.Run("034 preserves legacy Sender-Key rows and rejects partial epoch coordinates", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_034")
		applyMigrationsBefore(t, pool, migrations, 34)
		_, _, ownerDeviceID, targetDeviceID, conversationID :=
			seedMigrationSenderKeyHistory(t, pool, true)
		if err := execMigration(t, pool, migrations, 34); err != nil {
			t.Fatalf("migration 034: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var legacyRows int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM sender_keys
			 WHERE conversation_id=$1::uuid AND membership_epoch IS NULL
			   AND membership_epoch_hash IS NULL`, conversationID,
		).Scan(&legacyRows); err != nil || legacyRows != 1 {
			t.Fatalf("legacy Sender-Key rows=%d err=%v, want 1", legacyRows, err)
		}
		wire := []byte("partial-membership-coordinate")
		_, err := pool.Exec(ctx,
			`INSERT INTO sender_keys (
			   conversation_id, owner_device_id, target_device_id,
			   encrypted_key, generation, envelope_commitment,
			   roster_version, roster_commitment,
			   owner_binding_version, target_binding_version,
			   membership_epoch
			 ) SELECT $1::uuid, $2::uuid, $3::uuid, $4, 2, digest($4, 'sha256'),
			          roster_version, roster_commitment,
			          owner_binding_version, target_binding_version, 1
			     FROM sender_keys
			    WHERE conversation_id=$1::uuid
			    LIMIT 1`,
			conversationID, ownerDeviceID, targetDeviceID, wire,
		)
		requireMigrationError(t, err, "23514", "sender_keys_membership_context_shape")
	})

	t.Run("035 makes membership topology and Sender-Key activation fail closed in SQL", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_035")
		applyMigrationsBefore(t, pool, migrations, 35)
		ownerID, _, ownerDeviceID, targetDeviceID, conversationID :=
			seedMigrationSenderKeyHistory(t, pool, true)
		if err := execMigration(t, pool, migrations, 35); err != nil {
			t.Fatalf("migration 035: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		epochOneHash := bytes.Repeat([]byte{0x51}, 32)
		rosterOne := bytes.Repeat([]byte{0x52}, 32)
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		insertMigrationMembershipEpoch(t, ctx, tx, conversationID, ownerID, 1,
			make([]byte, 32), 1, rosterOne, epochOneHash)
		if _, err := tx.Exec(ctx,
			`INSERT INTO conversation_membership_epoch_heads_v1
			   (conversation_id, epoch_number, epoch_hash, roster_version, roster_commitment)
			 VALUES ($1::uuid, 1, $2, 1, $3)`,
			conversationID, epochOneHash, rosterOne,
		); err != nil {
			t.Fatalf("insert exact membership head: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit epoch one: %v", err)
		}

		legacyWire := []byte("post-activation-legacy")
		_, err = pool.Exec(ctx,
			`INSERT INTO sender_keys (
			   conversation_id, owner_device_id, target_device_id,
			   encrypted_key, generation, envelope_commitment,
			   roster_version, roster_commitment,
			   owner_binding_version, target_binding_version
			 ) SELECT $1::uuid, $2::uuid, $3::uuid, $4, 2, digest($4, 'sha256'),
			          roster_version, roster_commitment,
			          owner_binding_version, target_binding_version
			     FROM sender_keys WHERE conversation_id=$1::uuid LIMIT 1`,
			conversationID, ownerDeviceID, targetDeviceID, legacyWire,
		)
		requireMigrationError(t, err, "23514", "requires the exact active membership epoch")

		boundWire := []byte("post-activation-v6")
		if _, err := pool.Exec(ctx,
			`INSERT INTO sender_keys (
			   conversation_id, owner_device_id, target_device_id,
			   encrypted_key, generation, envelope_commitment,
			   roster_version, roster_commitment,
			   owner_binding_version, target_binding_version,
			   membership_epoch, membership_epoch_hash
			 ) SELECT $1::uuid, $2::uuid, $3::uuid, $4, 2, digest($4, 'sha256'),
			          roster_version, roster_commitment,
			          owner_binding_version, target_binding_version, 1, $5
			     FROM sender_keys WHERE conversation_id=$1::uuid LIMIT 1`,
			conversationID, ownerDeviceID, targetDeviceID, boundWire, epochOneHash,
		); err != nil {
			t.Fatalf("insert exact membership-bound Sender-Key: %v", err)
		}

		epochTwoHash := bytes.Repeat([]byte{0x53}, 32)
		rosterTwo := bytes.Repeat([]byte{0x54}, 32)
		tx, err = pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		insertMigrationMembershipEpoch(t, ctx, tx, conversationID, ownerID, 2,
			epochOneHash, 2, rosterTwo, epochTwoHash)
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit epoch two history: %v", err)
		}
		_, err = pool.Exec(ctx,
			`UPDATE conversation_membership_epoch_heads_v1
			 SET epoch_number=2, epoch_hash=$1, roster_version=999, roster_commitment=$2
			 WHERE conversation_id=$3::uuid`,
			epochTwoHash, rosterTwo, conversationID,
		)
		requireMigrationError(t, err, "23503", "membership_epoch_head_exact_coordinates_v1")
		if _, err := pool.Exec(ctx,
			`UPDATE conversation_membership_epoch_heads_v1
			 SET epoch_number=2, epoch_hash=$1, roster_version=2, roster_commitment=$2
			 WHERE conversation_id=$3::uuid`,
			epochTwoHash, rosterTwo, conversationID,
		); err != nil {
			t.Fatalf("advance exact membership head: %v", err)
		}

		_, err = pool.Exec(ctx,
			`INSERT INTO conversation_membership_epochs_v1 (
			   conversation_id, epoch_number, canonical_origin, conversation_kind,
			   predecessor_hash, roster_version, roster_commitment,
			   policy_threshold, policy_signer_count, crypto_profile, crypto_era,
			   mutation_nonce, epoch_hash, canonical_unsigned, submitted_by
			 ) VALUES ($1::uuid, 4, 'https://veil.example:443', 1, $2, 3, $3,
			           1, 1, 1, 1, $4, $5, $6, $7::uuid)`,
			conversationID, epochTwoHash, bytes.Repeat([]byte{0x55}, 32),
			bytes.Repeat([]byte{0x56}, 32), bytes.Repeat([]byte{0x57}, 32),
			[]byte("forked-epoch"), ownerID,
		)
		requireMigrationError(t, err, "23514", "does not extend the current head")
	})

	t.Run("fresh migration chain includes and applies 001 through 035", func(t *testing.T) {
		pool := newMigrationDatabase(t, admin, baseDSN, "veil_migration_fresh")
		seen := make(map[int]bool)
		for _, item := range migrations {
			seen[migrationNumber(t, item.name)] = true
		}
		for number := 1; number <= 35; number++ {
			if !seen[number] {
				t.Fatalf("migration chain is missing %03d", number)
			}
		}
		applyMigrationsBefore(t, pool, migrations, 36)
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

func seedMigrationMembershipScope(t *testing.T, pool *pgxpool.Pool, suffix string) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	marker := byte(len(suffix) + 0x61)
	var ownerID, conversationID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO users(identity_key, signing_key, username)
		 VALUES ($1, $2, $3) RETURNING id::text`,
		bytes.Repeat([]byte{marker}, 32), bytes.Repeat([]byte{marker + 1}, 32),
		"membership-"+suffix,
	).Scan(&ownerID); err != nil {
		t.Fatalf("insert membership migration owner: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO conversations(conv_type, name)
		 VALUES (1, $1) RETURNING id::text`,
		"membership-"+suffix,
	).Scan(&conversationID); err != nil {
		t.Fatalf("insert membership migration conversation: %v", err)
	}
	return ownerID, conversationID
}

func insertMigrationMembershipEpoch(
	t *testing.T,
	ctx context.Context,
	tx pgx.Tx,
	conversationID string,
	ownerID string,
	number int64,
	predecessorHash []byte,
	rosterVersion int64,
	rosterCommitment []byte,
	epochHash []byte,
) {
	t.Helper()
	var bootstrapOwner, bootstrapSigningKey any
	if number == 1 {
		bootstrapOwner = ownerID
		bootstrapSigningKey = bytes.Repeat([]byte{0x62}, 32)
	}
	marker := byte(0x70 + number)
	if _, err := tx.Exec(ctx,
		`INSERT INTO conversation_membership_epochs_v1 (
		   conversation_id, epoch_number, canonical_origin, conversation_kind,
		   predecessor_hash, roster_version, roster_commitment,
		   policy_threshold, policy_signer_count, crypto_profile, crypto_era,
		   mutation_nonce, epoch_hash, canonical_unsigned,
		   bootstrap_owner_id, bootstrap_owner_signing_key, submitted_by
		 ) VALUES (
		   $1::uuid, $2, 'https://veil.example:443', 1, $3, $4, $5,
		   1, 1, 1, 1, $6, $7, $8, $9::uuid, $10, $11::uuid
		 )`,
		conversationID, number, predecessorHash, rosterVersion, rosterCommitment,
		bytes.Repeat([]byte{marker}, 32), epochHash, []byte{marker},
		bootstrapOwner, bootstrapSigningKey, ownerID,
	); err != nil {
		t.Fatalf("insert membership epoch %d: %v", number, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO conversation_membership_policy_signers_v1
		   (conversation_id, epoch_number, signer_index, account_id, account_signing_key)
		 VALUES ($1::uuid, $2, 0, $3::uuid, $4)`,
		conversationID, number, ownerID, bytes.Repeat([]byte{0x62}, 32),
	); err != nil {
		t.Fatalf("insert membership epoch %d signer: %v", number, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO conversation_membership_signatures_v1
		   (conversation_id, epoch_number, signature_index, signer_account_id, signature)
		 VALUES ($1::uuid, $2, 0, $3::uuid, $4)`,
		conversationID, number, ownerID, bytes.Repeat([]byte{marker + 1}, 64),
	); err != nil {
		t.Fatalf("insert membership epoch %d signature: %v", number, err)
	}
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
