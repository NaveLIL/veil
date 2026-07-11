-- Linearize roster resolution, Sender-Key durable admission, and every
-- database mutation that can change a cryptographic conversation roster.
--
-- conversation_roster_revisions is the common lock row. Mutation triggers
-- update it first, then mark an existing materialized roster head dirty.
-- Resolve and SKDM Store lock revision -> head in the same order. The triggers
-- never attempt to calculate a commitment; only the canonical Go resolver may
-- replace a dirty head with a recomputed commitment.

CREATE TABLE conversation_roster_revisions (
    conversation_id   UUID PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    mutation_revision BIGINT NOT NULL DEFAULT 0,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT conversation_roster_mutation_revision_range
        CHECK (mutation_revision BETWEEN 0 AND 9223372036854775807)
);

INSERT INTO conversation_roster_revisions (conversation_id)
SELECT id FROM conversations
ON CONFLICT (conversation_id) DO NOTHING;

ALTER TABLE conversation_device_rosters
    ADD COLUMN dirty BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN resolved_mutation_revision BIGINT NOT NULL DEFAULT 0;

-- A pre-migration head may have become stale between its last lazy resolve and
-- this deployment. Force one canonical recomputation instead of trusting that
-- unknown interval.
UPDATE conversation_device_rosters SET dirty = TRUE;

ALTER TABLE conversation_device_rosters
    ADD CONSTRAINT conversation_roster_resolved_revision_range
    CHECK (resolved_mutation_revision BETWEEN 0 AND 9223372036854775807);

CREATE OR REPLACE FUNCTION veil_create_conversation_roster_revision()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    INSERT INTO public.conversation_roster_revisions (conversation_id)
    VALUES (NEW.id)
    ON CONFLICT (conversation_id) DO NOTHING;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS conversations_create_roster_revision ON conversations;
CREATE TRIGGER conversations_create_roster_revision
AFTER INSERT ON conversations
FOR EACH ROW EXECUTE FUNCTION veil_create_conversation_roster_revision();

CREATE OR REPLACE FUNCTION veil_dirty_roster_for_conversation_security_type()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM public.veil_mark_conversation_rosters_dirty(ARRAY[NEW.id]);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS conversations_roster_dirty_security_type ON conversations;
CREATE TRIGGER conversations_roster_dirty_security_type
AFTER UPDATE OF conv_type ON conversations
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_conversation_security_type();

CREATE OR REPLACE FUNCTION veil_mark_conversation_rosters_dirty(conversation_ids UUID[])
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    candidate_id UUID;
BEGIN
    -- UUID ordering gives every multi-conversation mutation the same lock
    -- order, avoiding role/server/device operations deadlocking each other.
    FOR candidate_id IN
        SELECT DISTINCT candidate
        FROM unnest(conversation_ids) AS candidate
        WHERE candidate IS NOT NULL
          AND EXISTS (
              SELECT 1 FROM public.conversations
              WHERE conversations.id = candidate
          )
        ORDER BY candidate
    LOOP
        INSERT INTO public.conversation_roster_revisions (conversation_id)
        VALUES (candidate_id)
        ON CONFLICT (conversation_id) DO NOTHING;

        UPDATE public.conversation_roster_revisions
        SET mutation_revision = mutation_revision + 1,
            updated_at = now()
        WHERE conversation_roster_revisions.conversation_id = candidate_id
          AND mutation_revision < 9223372036854775807;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'conversation roster mutation revision exhausted for %', candidate_id
                USING ERRCODE = '22003';
        END IF;

        UPDATE public.conversation_device_rosters
        SET dirty = TRUE,
            updated_at = now()
        WHERE conversation_device_rosters.conversation_id = candidate_id;
    END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION veil_dirty_roster_for_conversation_member()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM public.veil_mark_conversation_rosters_dirty(ARRAY[NEW.conversation_id]);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM public.veil_mark_conversation_rosters_dirty(ARRAY[OLD.conversation_id]);
        RETURN OLD;
    END IF;
    PERFORM public.veil_mark_conversation_rosters_dirty(
        ARRAY[OLD.conversation_id, NEW.conversation_id]
    );
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS conversation_members_roster_dirty_insert_delete ON conversation_members;
CREATE TRIGGER conversation_members_roster_dirty_insert_delete
AFTER INSERT OR DELETE ON conversation_members
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_conversation_member();
DROP TRIGGER IF EXISTS conversation_members_roster_dirty_update ON conversation_members;
CREATE TRIGGER conversation_members_roster_dirty_update
AFTER UPDATE OF conversation_id, user_id ON conversation_members
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_conversation_member();

CREATE OR REPLACE FUNCTION veil_dirty_rosters_for_users(user_ids UUID[])
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    conversation_ids UUID[];
BEGIN
    SELECT COALESCE(array_agg(DISTINCT member.conversation_id ORDER BY member.conversation_id), ARRAY[]::UUID[])
    INTO conversation_ids
    FROM public.conversation_members AS member
    WHERE member.user_id = ANY(user_ids);
    PERFORM public.veil_mark_conversation_rosters_dirty(conversation_ids);
END;
$$;

CREATE OR REPLACE FUNCTION veil_dirty_roster_for_device()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM public.veil_dirty_rosters_for_users(ARRAY[NEW.user_id]);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM public.veil_dirty_rosters_for_users(ARRAY[OLD.user_id]);
        RETURN OLD;
    END IF;
    PERFORM public.veil_dirty_rosters_for_users(ARRAY[OLD.user_id, NEW.user_id]);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS devices_roster_dirty_insert_delete ON devices;
CREATE TRIGGER devices_roster_dirty_insert_delete
AFTER INSERT OR DELETE ON devices
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_device();
DROP TRIGGER IF EXISTS devices_roster_dirty_update ON devices;
CREATE TRIGGER devices_roster_dirty_update
AFTER UPDATE OF user_id, device_key ON devices
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_device();

CREATE OR REPLACE FUNCTION veil_dirty_roster_for_device_binding_head()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    owner_ids UUID[];
BEGIN
    SELECT COALESCE(array_agg(DISTINCT device.user_id ORDER BY device.user_id), ARRAY[]::UUID[])
    INTO owner_ids
    FROM public.devices AS device
    WHERE device.id = ANY(ARRAY[
        CASE WHEN TG_OP <> 'INSERT' THEN OLD.device_id ELSE NULL END,
        CASE WHEN TG_OP <> 'DELETE' THEN NEW.device_id ELSE NULL END
    ]);
    PERFORM public.veil_dirty_rosters_for_users(owner_ids);
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS device_binding_heads_roster_dirty ON device_binding_heads;
CREATE TRIGGER device_binding_heads_roster_dirty
AFTER INSERT OR UPDATE OR DELETE ON device_binding_heads
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_device_binding_head();

CREATE OR REPLACE FUNCTION veil_dirty_roster_for_device_crypto_state()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    owner_ids UUID[];
BEGIN
    SELECT COALESCE(array_agg(DISTINCT device.user_id ORDER BY device.user_id), ARRAY[]::UUID[])
    INTO owner_ids
    FROM public.devices AS device
    WHERE device.id = ANY(ARRAY[
        CASE WHEN TG_OP <> 'INSERT' THEN OLD.device_id ELSE NULL END,
        CASE WHEN TG_OP <> 'DELETE' THEN NEW.device_id ELSE NULL END
    ]);
    PERFORM public.veil_dirty_rosters_for_users(owner_ids);
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS device_crypto_keys_roster_dirty ON device_crypto_keys;
CREATE TRIGGER device_crypto_keys_roster_dirty
AFTER INSERT OR UPDATE OR DELETE ON device_crypto_keys
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_device_crypto_state();

DROP TRIGGER IF EXISTS device_binding_versions_roster_dirty ON device_binding_versions;
CREATE TRIGGER device_binding_versions_roster_dirty
AFTER INSERT OR UPDATE OR DELETE ON device_binding_versions
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_device_crypto_state();

CREATE OR REPLACE FUNCTION veil_dirty_roster_for_user_identity()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM public.veil_dirty_rosters_for_users(ARRAY[OLD.id, NEW.id]);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS users_roster_dirty_identity_update ON users;
CREATE TRIGGER users_roster_dirty_identity_update
AFTER UPDATE OF identity_key, signing_key ON users
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_user_identity();

CREATE OR REPLACE FUNCTION veil_dirty_rosters_for_servers(server_ids UUID[])
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    conversation_ids UUID[];
BEGIN
    SELECT COALESCE(array_agg(DISTINCT channel.conversation_id ORDER BY channel.conversation_id), ARRAY[]::UUID[])
    INTO conversation_ids
    FROM public.channels AS channel
    WHERE channel.server_id = ANY(server_ids)
      AND channel.conversation_id IS NOT NULL;
    PERFORM public.veil_mark_conversation_rosters_dirty(conversation_ids);
END;
$$;

CREATE OR REPLACE FUNCTION veil_dirty_roster_for_server_member()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM public.veil_dirty_rosters_for_servers(ARRAY[NEW.server_id]);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM public.veil_dirty_rosters_for_servers(ARRAY[OLD.server_id]);
        RETURN OLD;
    END IF;
    PERFORM public.veil_dirty_rosters_for_servers(ARRAY[OLD.server_id, NEW.server_id]);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS server_members_roster_dirty_insert_delete ON server_members;
CREATE TRIGGER server_members_roster_dirty_insert_delete
AFTER INSERT OR DELETE ON server_members
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_server_member();
DROP TRIGGER IF EXISTS server_members_roster_dirty_update ON server_members;
CREATE TRIGGER server_members_roster_dirty_update
AFTER UPDATE OF server_id, user_id ON server_members
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_server_member();

DROP TRIGGER IF EXISTS member_roles_roster_dirty ON member_roles;
CREATE TRIGGER member_roles_roster_dirty
AFTER INSERT OR UPDATE OR DELETE ON member_roles
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_server_member();

CREATE OR REPLACE FUNCTION veil_dirty_roster_for_role()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM public.veil_dirty_rosters_for_servers(ARRAY[NEW.server_id]);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM public.veil_dirty_rosters_for_servers(ARRAY[OLD.server_id]);
        RETURN OLD;
    END IF;
    PERFORM public.veil_dirty_rosters_for_servers(ARRAY[OLD.server_id, NEW.server_id]);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS roles_roster_dirty_insert_delete ON roles;
CREATE TRIGGER roles_roster_dirty_insert_delete
AFTER INSERT OR DELETE ON roles
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_role();
DROP TRIGGER IF EXISTS roles_roster_dirty_update ON roles;
CREATE TRIGGER roles_roster_dirty_update
AFTER UPDATE OF server_id, permissions, is_default ON roles
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_role();

CREATE OR REPLACE FUNCTION veil_dirty_roster_for_channel_overwrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    conversation_ids UUID[];
BEGIN
    SELECT COALESCE(array_agg(DISTINCT channel.conversation_id ORDER BY channel.conversation_id), ARRAY[]::UUID[])
    INTO conversation_ids
    FROM public.channels AS channel
    WHERE channel.id = ANY(ARRAY[
        CASE WHEN TG_OP <> 'INSERT' THEN OLD.channel_id ELSE NULL END,
        CASE WHEN TG_OP <> 'DELETE' THEN NEW.channel_id ELSE NULL END
    ])
      AND channel.conversation_id IS NOT NULL;
    PERFORM public.veil_mark_conversation_rosters_dirty(conversation_ids);
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS channel_overwrites_roster_dirty ON channel_overwrites;
CREATE TRIGGER channel_overwrites_roster_dirty
AFTER INSERT OR UPDATE OR DELETE ON channel_overwrites
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_channel_overwrite();

CREATE OR REPLACE FUNCTION veil_dirty_roster_for_server()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM public.veil_dirty_rosters_for_servers(ARRAY[OLD.id, NEW.id]);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS servers_roster_dirty_security_update ON servers;
CREATE TRIGGER servers_roster_dirty_security_update
AFTER UPDATE OF owner_id, deleted_at ON servers
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_server();

CREATE OR REPLACE FUNCTION veil_dirty_roster_for_channel_scope()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM public.veil_mark_conversation_rosters_dirty(ARRAY[NEW.conversation_id]);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM public.veil_mark_conversation_rosters_dirty(ARRAY[OLD.conversation_id]);
        RETURN OLD;
    END IF;
    PERFORM public.veil_mark_conversation_rosters_dirty(
        ARRAY[OLD.conversation_id, NEW.conversation_id]
    );
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS channels_roster_dirty_insert_delete ON channels;
CREATE TRIGGER channels_roster_dirty_insert_delete
AFTER INSERT OR DELETE ON channels
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_channel_scope();
DROP TRIGGER IF EXISTS channels_roster_dirty_update ON channels;
CREATE TRIGGER channels_roster_dirty_update
AFTER UPDATE OF server_id, conversation_id ON channels
FOR EACH ROW EXECUTE FUNCTION veil_dirty_roster_for_channel_scope();

-- Future-only target authorization
-- --------------------------------
-- Dirty roster heads alone are insufficient: a target could lose read access
-- and regain it before any resolver ran, making an old retained SKDM visible
-- again. Deferred triggers evaluate the FINAL ACL state of each committed
-- mutation and collect pending rows only for target accounts that actually
-- lost channel-read authorization. Owner/sender removal is intentionally not
-- part of the predicate, and sender_key_heads remain untouched.

CREATE OR REPLACE FUNCTION public.veil_channel_user_can_read(
    candidate_channel_id UUID,
    candidate_user_id UUID
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $$
WITH channel_scope AS (
    SELECT channel.id AS channel_id, channel.server_id, server.owner_id
    FROM public.channels AS channel
    JOIN public.servers AS server
      ON server.id = channel.server_id
     AND server.deleted_at IS NULL
    WHERE channel.id = candidate_channel_id
), member_scope AS (
    SELECT channel_scope.*, member.user_id
    FROM channel_scope
    JOIN public.server_members AS member
      ON member.server_id = channel_scope.server_id
     AND member.user_id = candidate_user_id
), applicable_roles AS (
    SELECT role.id, role.permissions, role.is_default
    FROM member_scope
    JOIN public.roles AS role ON role.server_id = member_scope.server_id
    WHERE role.is_default = TRUE
       OR EXISTS (
           SELECT 1
           FROM public.member_roles AS assignment
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
    SELECT COALESCE(BIT_OR(overwrite.allow), 0) AS allow_mask,
           COALESCE(BIT_OR(overwrite.deny), 0) AS deny_mask
    FROM base
    JOIN applicable_roles AS role ON role.is_default = TRUE
    JOIN public.channel_overwrites AS overwrite
      ON overwrite.channel_id = base.channel_id
     AND overwrite.target_type = 0
     AND overwrite.target_id = role.id
), role_overwrites AS (
    SELECT COALESCE(BIT_OR(overwrite.allow), 0) AS allow_mask,
           COALESCE(BIT_OR(overwrite.deny), 0) AS deny_mask
    FROM base
    JOIN applicable_roles AS role ON role.is_default = FALSE
    JOIN public.channel_overwrites AS overwrite
      ON overwrite.channel_id = base.channel_id
     AND overwrite.target_type = 0
     AND overwrite.target_id = role.id
), member_overwrite AS (
    SELECT COALESCE(BIT_OR(overwrite.allow), 0) AS allow_mask,
           COALESCE(BIT_OR(overwrite.deny), 0) AS deny_mask
    FROM base
    JOIN public.channel_overwrites AS overwrite
      ON overwrite.channel_id = base.channel_id
     AND overwrite.target_type = 1
     AND overwrite.target_id = base.user_id
), masks AS (
    SELECT base.owner_id = base.user_id AS owner,
           base.permissions AS base_permissions,
           base.default_role_count,
           COALESCE(everyone_overwrite.allow_mask, 0) AS everyone_allow,
           COALESCE(everyone_overwrite.deny_mask, 0) AS everyone_deny,
           COALESCE(role_overwrites.allow_mask, 0) AS role_allow,
           COALESCE(role_overwrites.deny_mask, 0) AS role_deny,
           COALESCE(member_overwrite.allow_mask, 0) AS member_allow,
           COALESCE(member_overwrite.deny_mask, 0) AS member_deny
    FROM base
    LEFT JOIN everyone_overwrite ON TRUE
    LEFT JOIN role_overwrites ON TRUE
    LEFT JOIN member_overwrite ON TRUE
), resolved AS (
    SELECT masks.*,
           (
             (
               (
                 ((base_permissions & ~everyone_deny) | everyone_allow)
                 & ~role_deny
               ) | role_allow
             ) & ~member_deny
           ) | member_allow AS effective_permissions
    FROM masks
)
SELECT COALESCE((
    SELECT
        base_permissions >= 0
        AND (base_permissions & ~4294969343::BIGINT) = 0
        AND everyone_allow >= 0 AND everyone_deny >= 0
        AND role_allow >= 0 AND role_deny >= 0
        AND member_allow >= 0 AND member_deny >= 0
        AND (everyone_allow & ~1055::BIGINT) = 0
        AND (everyone_deny & ~1055::BIGINT) = 0
        AND (role_allow & ~1055::BIGINT) = 0
        AND (role_deny & ~1055::BIGINT) = 0
        AND (member_allow & ~1055::BIGINT) = 0
        AND (member_deny & ~1055::BIGINT) = 0
        AND (everyone_allow & everyone_deny) = 0
        AND (member_allow & member_deny) = 0
        AND (
            owner
            OR (base_permissions & 4294967296::BIGINT) <> 0
            OR (
                default_role_count = 1
                AND (effective_permissions & 1025::BIGINT) = 1025::BIGINT
            )
        )
    FROM resolved
), FALSE);
$$;

CREATE OR REPLACE FUNCTION public.veil_conversation_user_can_read(
    candidate_conversation_id UUID,
    candidate_user_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
    conversation_type SMALLINT;
    channel_id UUID;
BEGIN
    SELECT conversation.conv_type, channel.id
    INTO conversation_type, channel_id
    FROM public.conversations AS conversation
    LEFT JOIN public.channels AS channel
      ON channel.conversation_id = conversation.id
    WHERE conversation.id = candidate_conversation_id;

    IF NOT FOUND OR NOT EXISTS (
        SELECT 1
        FROM public.conversation_members AS member
        WHERE member.conversation_id = candidate_conversation_id
          AND member.user_id = candidate_user_id
    ) THEN
        RETURN FALSE;
    END IF;

    IF conversation_type = 1 THEN
        RETURN TRUE;
    END IF;
    IF conversation_type = 2 AND channel_id IS NOT NULL THEN
        RETURN public.veil_channel_user_can_read(channel_id, candidate_user_id);
    END IF;
    RETURN FALSE;
END;
$$;

CREATE OR REPLACE FUNCTION public.veil_prune_sender_keys_for_conversations(
    candidate_conversation_ids UUID[]
)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF COALESCE(array_length(candidate_conversation_ids, 1), 0) = 0 THEN
        RETURN;
    END IF;

    DELETE FROM public.sender_keys AS sender_key
    USING public.devices AS target_device
    WHERE sender_key.conversation_id = ANY(candidate_conversation_ids)
      AND target_device.id = sender_key.target_device_id
      AND NOT public.veil_conversation_user_can_read(
          sender_key.conversation_id,
          target_device.user_id
      );
END;
$$;

CREATE OR REPLACE FUNCTION public.veil_prune_sender_keys_for_servers(
    candidate_server_ids UUID[]
)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    conversation_ids UUID[];
BEGIN
    SELECT COALESCE(
        array_agg(DISTINCT channel.conversation_id ORDER BY channel.conversation_id),
        ARRAY[]::UUID[]
    )
    INTO conversation_ids
    FROM public.channels AS channel
    WHERE channel.server_id = ANY(candidate_server_ids)
      AND channel.conversation_id IS NOT NULL;

    PERFORM public.veil_prune_sender_keys_for_conversations(conversation_ids);
END;
$$;

CREATE OR REPLACE FUNCTION public.veil_prune_sender_keys_for_conversation_member()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM public.veil_prune_sender_keys_for_conversations(ARRAY[NEW.conversation_id]);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM public.veil_prune_sender_keys_for_conversations(ARRAY[OLD.conversation_id]);
        RETURN OLD;
    END IF;
    PERFORM public.veil_prune_sender_keys_for_conversations(
        ARRAY[OLD.conversation_id, NEW.conversation_id]
    );
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.veil_prune_sender_keys_for_server_scope()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM public.veil_prune_sender_keys_for_servers(ARRAY[NEW.server_id]);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM public.veil_prune_sender_keys_for_servers(ARRAY[OLD.server_id]);
        RETURN OLD;
    END IF;
    PERFORM public.veil_prune_sender_keys_for_servers(ARRAY[OLD.server_id, NEW.server_id]);
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.veil_prune_sender_keys_for_channel_overwrite()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    conversation_ids UUID[];
BEGIN
    SELECT COALESCE(
        array_agg(DISTINCT channel.conversation_id ORDER BY channel.conversation_id),
        ARRAY[]::UUID[]
    )
    INTO conversation_ids
    FROM public.channels AS channel
    WHERE channel.id = ANY(ARRAY[
        CASE WHEN TG_OP <> 'INSERT' THEN OLD.channel_id ELSE NULL END,
        CASE WHEN TG_OP <> 'DELETE' THEN NEW.channel_id ELSE NULL END
    ])
      AND channel.conversation_id IS NOT NULL;
    PERFORM public.veil_prune_sender_keys_for_conversations(conversation_ids);
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.veil_prune_sender_keys_for_server_row()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM public.veil_prune_sender_keys_for_servers(ARRAY[OLD.id]);
        RETURN OLD;
    ELSIF TG_OP = 'INSERT' THEN
        PERFORM public.veil_prune_sender_keys_for_servers(ARRAY[NEW.id]);
        RETURN NEW;
    END IF;
    PERFORM public.veil_prune_sender_keys_for_servers(ARRAY[OLD.id, NEW.id]);
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.veil_prune_sender_keys_for_channel_row()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM public.veil_prune_sender_keys_for_conversations(ARRAY[NEW.conversation_id]);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM public.veil_prune_sender_keys_for_conversations(ARRAY[OLD.conversation_id]);
        RETURN OLD;
    END IF;
    PERFORM public.veil_prune_sender_keys_for_conversations(
        ARRAY[OLD.conversation_id, NEW.conversation_id]
    );
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.veil_prune_sender_keys_for_conversation_row()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    PERFORM public.veil_prune_sender_keys_for_conversations(ARRAY[NEW.id]);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS conversation_members_sender_key_target_prune ON public.conversation_members;
CREATE CONSTRAINT TRIGGER conversation_members_sender_key_target_prune
AFTER INSERT OR UPDATE OR DELETE ON public.conversation_members
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.veil_prune_sender_keys_for_conversation_member();

DROP TRIGGER IF EXISTS server_members_sender_key_target_prune ON public.server_members;
CREATE CONSTRAINT TRIGGER server_members_sender_key_target_prune
AFTER INSERT OR UPDATE OR DELETE ON public.server_members
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.veil_prune_sender_keys_for_server_scope();

DROP TRIGGER IF EXISTS member_roles_sender_key_target_prune ON public.member_roles;
CREATE CONSTRAINT TRIGGER member_roles_sender_key_target_prune
AFTER INSERT OR UPDATE OR DELETE ON public.member_roles
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.veil_prune_sender_keys_for_server_scope();

DROP TRIGGER IF EXISTS roles_sender_key_target_prune ON public.roles;
CREATE CONSTRAINT TRIGGER roles_sender_key_target_prune
AFTER INSERT OR UPDATE OR DELETE ON public.roles
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.veil_prune_sender_keys_for_server_scope();

DROP TRIGGER IF EXISTS channel_overwrites_sender_key_target_prune ON public.channel_overwrites;
CREATE CONSTRAINT TRIGGER channel_overwrites_sender_key_target_prune
AFTER INSERT OR UPDATE OR DELETE ON public.channel_overwrites
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.veil_prune_sender_keys_for_channel_overwrite();

DROP TRIGGER IF EXISTS servers_sender_key_target_prune ON public.servers;
CREATE CONSTRAINT TRIGGER servers_sender_key_target_prune
AFTER INSERT OR UPDATE OR DELETE ON public.servers
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.veil_prune_sender_keys_for_server_row();

DROP TRIGGER IF EXISTS channels_sender_key_target_prune ON public.channels;
CREATE CONSTRAINT TRIGGER channels_sender_key_target_prune
AFTER INSERT OR UPDATE OR DELETE ON public.channels
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.veil_prune_sender_keys_for_channel_row();

DROP TRIGGER IF EXISTS conversations_sender_key_target_prune ON public.conversations;
CREATE CONSTRAINT TRIGGER conversations_sender_key_target_prune
AFTER INSERT OR UPDATE OR DELETE ON public.conversations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.veil_prune_sender_keys_for_conversation_row();
