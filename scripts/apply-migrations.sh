#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required}"

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE IF NOT EXISTS veil_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Upgrade path from the former compose file, which mounted only 001 directly
-- into docker-entrypoint-initdb.d and therefore had no migration ledger.
INSERT INTO veil_schema_migrations(name)
SELECT '001_initial.sql'
WHERE to_regclass('public.users') IS NOT NULL
ON CONFLICT (name) DO NOTHING;

INSERT INTO veil_schema_migrations(name)
SELECT '002_edit_delete.sql'
WHERE EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_schema = 'public' AND table_name = 'messages' AND column_name = 'edited_at')
ON CONFLICT (name) DO NOTHING;
INSERT INTO veil_schema_migrations(name) SELECT '003_reactions.sql'
WHERE to_regclass('public.reactions') IS NOT NULL ON CONFLICT (name) DO NOTHING;
INSERT INTO veil_schema_migrations(name) SELECT '004_friends.sql'
WHERE to_regclass('public.friend_requests') IS NOT NULL ON CONFLICT (name) DO NOTHING;
INSERT INTO veil_schema_migrations(name) SELECT '005_servers.sql'
WHERE to_regclass('public.member_roles') IS NOT NULL ON CONFLICT (name) DO NOTHING;
INSERT INTO veil_schema_migrations(name) SELECT '006_push.sql'
WHERE to_regclass('public.push_subscriptions') IS NOT NULL ON CONFLICT (name) DO NOTHING;
INSERT INTO veil_schema_migrations(name) SELECT '007_uploads.sql'
WHERE to_regclass('public.tus_uploads') IS NOT NULL ON CONFLICT (name) DO NOTHING;
INSERT INTO veil_schema_migrations(name) SELECT '008_mls.sql'
WHERE to_regclass('public.mls_key_packages') IS NOT NULL ON CONFLICT (name) DO NOTHING;
INSERT INTO veil_schema_migrations(name)
SELECT '009_security_constraints.sql'
WHERE EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_schema = 'public' AND table_name = 'prekeys' AND column_name = 'protocol_key_id')
ON CONFLICT (name) DO NOTHING;
SQL

for migration in /migrations/*.sql; do
    name="$(basename "$migration")"
    case "$name" in
        *[!0-9A-Za-z_.-]*)
            echo "unsafe migration filename: $name" >&2
            exit 1
            ;;
    esac

    applied="$(psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -tAc \
        "SELECT 1 FROM veil_schema_migrations WHERE name = '$name'")"
    if [ "$applied" = "1" ]; then
        echo "migration already applied: $name"
        continue
    fi

    echo "applying migration: $name"
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 --single-transaction \
        -f "$migration" \
        -c "INSERT INTO veil_schema_migrations(name) VALUES ('$name')"
done
