-- Complete the database invariants required by runtime channel ACL resolution.
--
-- AllRolePermissions is bits 0..10 plus Administrator at bit 32:
-- 2047 + 4294967296 = 4294969343.

-- NULL had the same intended meaning as the column defaults but cannot be
-- scanned safely by the runtime. Normalize only that unambiguous legacy state.
UPDATE roles SET permissions = 0 WHERE permissions IS NULL;
UPDATE roles SET is_default = FALSE WHERE is_default IS NULL;

ALTER TABLE roles ALTER COLUMN permissions SET DEFAULT 0;
ALTER TABLE roles ALTER COLUMN permissions SET NOT NULL;
ALTER TABLE roles ALTER COLUMN is_default SET DEFAULT FALSE;
ALTER TABLE roles ALTER COLUMN is_default SET NOT NULL;

-- Migration 005 introduced is_default after roles already existed. Recover an
-- old server automatically only when it has exactly one role named @everyone;
-- choosing between multiple candidates could silently grant the wrong ACL.
WITH unambiguous_default AS (
    SELECT server.id AS server_id, MIN(role.id::text)::uuid AS role_id
    FROM servers server
    JOIN roles role
      ON role.server_id = server.id
     AND role.name = '@everyone'
    WHERE server.deleted_at IS NULL
      AND NOT EXISTS (
          SELECT 1
          FROM roles current_default
          WHERE current_default.server_id = server.id
            AND current_default.is_default = TRUE
      )
    GROUP BY server.id
    HAVING COUNT(*) = 1
)
UPDATE roles role
SET is_default = TRUE
FROM unambiguous_default candidate
WHERE role.id = candidate.role_id;

-- Unknown or negative role masks are authorization corruption. Do not guess at
-- a repair by masking them: stop the migration so an operator can audit them.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM roles
        WHERE permissions < 0
           OR (permissions & ~4294969343::bigint) <> 0
    ) THEN
        RAISE EXCEPTION
            'roles contains negative or unknown permission bits; audit before retrying migration 016'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM servers server
        WHERE server.deleted_at IS NULL
          AND (
              SELECT COUNT(*)
              FROM roles role
              WHERE role.server_id = server.id
                AND role.is_default = TRUE
          ) <> 1
    ) THEN
        RAISE EXCEPTION
            'an active server must have exactly one default role; audit ambiguous legacy roles before retrying migration 016'
            USING ERRCODE = '23514';
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'roles_permissions_known_mask_check'
          AND conrelid = 'roles'::regclass
    ) THEN
        ALTER TABLE roles
            ADD CONSTRAINT roles_permissions_known_mask_check
            CHECK (
                permissions >= 0
                AND (permissions & ~4294969343::bigint) = 0
            ) NOT VALID;
    END IF;
END
$$;

ALTER TABLE roles VALIDATE CONSTRAINT roles_permissions_known_mask_check;

-- The partial unique index from migration 005 guarantees "at most one".
-- Deferred constraint triggers add "at least one" without breaking the normal
-- CreateServer transaction, which inserts the server before its default role.
CREATE OR REPLACE FUNCTION public.assert_active_server_has_one_default_role(candidate_server_id UUID)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    default_count BIGINT;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM public.servers
        WHERE id = candidate_server_id
          AND deleted_at IS NULL
    ) THEN
        RETURN;
    END IF;

    SELECT COUNT(*) INTO default_count
    FROM public.roles
    WHERE server_id = candidate_server_id
      AND is_default = TRUE;

    IF default_count <> 1 THEN
        RAISE EXCEPTION 'active server % must have exactly one default role', candidate_server_id
            USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.enforce_role_default_invariant()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM public.assert_active_server_has_one_default_role(NEW.server_id);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM public.assert_active_server_has_one_default_role(OLD.server_id);
        RETURN OLD;
    END IF;

    PERFORM public.assert_active_server_has_one_default_role(OLD.server_id);
    IF NEW.server_id IS DISTINCT FROM OLD.server_id THEN
        PERFORM public.assert_active_server_has_one_default_role(NEW.server_id);
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS roles_enforce_default_invariant ON public.roles;
CREATE CONSTRAINT TRIGGER roles_enforce_default_invariant
AFTER INSERT OR UPDATE OR DELETE ON public.roles
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.enforce_role_default_invariant();

CREATE OR REPLACE FUNCTION public.enforce_server_default_invariant()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    PERFORM public.assert_active_server_has_one_default_role(NEW.id);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS servers_enforce_default_invariant ON public.servers;
CREATE CONSTRAINT TRIGGER servers_enforce_default_invariant
AFTER INSERT OR UPDATE ON public.servers
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.enforce_server_default_invariant();
