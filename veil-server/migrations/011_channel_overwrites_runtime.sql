-- Make channel permission overwrites safe to consume at runtime.
-- Channel-scoped permission bits are VIEW, SEND, MANAGE_MESSAGES,
-- MENTION_EVERYONE, MANAGE_CHANNELS and READ_MESSAGE_HISTORY (mask 1055).

-- Remove legacy rows that cannot be interpreted unambiguously. The table has
-- never been consumed by the runtime before this migration, so retaining an
-- invalid row would only turn dormant corrupt data into an authorization rule.
DELETE FROM channel_overwrites overwrite
WHERE overwrite.target_type NOT IN (0, 1)
   OR overwrite.allow < 0
   OR overwrite.deny < 0
   OR (overwrite.allow & overwrite.deny) <> 0
   OR (overwrite.allow & ~1055::bigint) <> 0
   OR (overwrite.deny & ~1055::bigint) <> 0
   OR (
       overwrite.target_type = 0
       AND NOT EXISTS (
           SELECT 1
           FROM channels channel
           JOIN roles role
             ON role.server_id = channel.server_id
            AND role.id = overwrite.target_id
           WHERE channel.id = overwrite.channel_id
       )
   )
   OR (
       overwrite.target_type = 1
       AND NOT EXISTS (
           SELECT 1
           FROM channels channel
           JOIN server_members member
             ON member.server_id = channel.server_id
            AND member.user_id = overwrite.target_id
           WHERE channel.id = overwrite.channel_id
       )
   );

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'channel_overwrites_target_type_check'
    ) THEN
        ALTER TABLE channel_overwrites
            ADD CONSTRAINT channel_overwrites_target_type_check
            CHECK (target_type IN (0, 1));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'channel_overwrites_masks_check'
    ) THEN
        ALTER TABLE channel_overwrites
            ADD CONSTRAINT channel_overwrites_masks_check
            CHECK (
                allow >= 0 AND deny >= 0
                AND (allow & deny) = 0
                AND (allow & ~1055::bigint) = 0
                AND (deny & ~1055::bigint) = 0
            );
    END IF;
END $$;

CREATE OR REPLACE FUNCTION validate_channel_overwrite_target()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    channel_server_id UUID;
BEGIN
    SELECT server_id INTO channel_server_id
    FROM channels
    WHERE id = NEW.channel_id;

    IF channel_server_id IS NULL THEN
        RAISE EXCEPTION 'channel overwrite references an unknown channel'
            USING ERRCODE = '23503';
    END IF;

    IF NEW.target_type = 0 THEN
        IF NOT EXISTS (
            SELECT 1 FROM roles
            WHERE id = NEW.target_id AND server_id = channel_server_id
        ) THEN
            RAISE EXCEPTION 'channel overwrite role belongs to another server or does not exist'
                USING ERRCODE = '23503';
        END IF;
    ELSIF NEW.target_type = 1 THEN
        IF NOT EXISTS (
            SELECT 1 FROM server_members
            WHERE server_id = channel_server_id AND user_id = NEW.target_id
        ) THEN
            RAISE EXCEPTION 'channel overwrite user is not a member of the channel server'
                USING ERRCODE = '23503';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid channel overwrite target type'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS channel_overwrites_validate_target ON channel_overwrites;
CREATE TRIGGER channel_overwrites_validate_target
BEFORE INSERT OR UPDATE ON channel_overwrites
FOR EACH ROW EXECUTE FUNCTION validate_channel_overwrite_target();

-- Polymorphic targets cannot use a normal foreign key. Keep the rows tidy when
-- their role or server membership is deleted.
CREATE OR REPLACE FUNCTION delete_role_channel_overwrites()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM channel_overwrites
    WHERE target_type = 0 AND target_id = OLD.id;
    RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS roles_delete_channel_overwrites ON roles;
CREATE TRIGGER roles_delete_channel_overwrites
AFTER DELETE ON roles
FOR EACH ROW EXECUTE FUNCTION delete_role_channel_overwrites();

CREATE OR REPLACE FUNCTION delete_member_channel_overwrites()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM channel_overwrites overwrite
    USING channels channel
    WHERE overwrite.channel_id = channel.id
      AND overwrite.target_type = 1
      AND overwrite.target_id = OLD.user_id
      AND channel.server_id = OLD.server_id;
    RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS server_members_delete_channel_overwrites ON server_members;
CREATE TRIGGER server_members_delete_channel_overwrites
AFTER DELETE ON server_members
FOR EACH ROW EXECUTE FUNCTION delete_member_channel_overwrites();

CREATE INDEX IF NOT EXISTS idx_channel_overwrites_target
    ON channel_overwrites(target_type, target_id);
