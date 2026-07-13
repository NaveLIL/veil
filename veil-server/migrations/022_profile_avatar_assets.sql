-- Phase 4D: separately bounded profile-avatar storage.
-- Avatar bytes are presentation metadata and never participate in identity,
-- authorization, ACL decisions or cryptographic state.

CREATE TABLE profile_avatar_assets (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content_type TEXT NOT NULL CHECK (content_type = 'image/jpeg'),
    sha256 BYTEA NOT NULL CHECK (octet_length(sha256) = 32),
    width INTEGER NOT NULL CHECK (width = 512),
    height INTEGER NOT NULL CHECK (height = 512),
    data BYTEA NOT NULL CHECK (octet_length(data) BETWEEN 1 AND 262144),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    orphaned_at TIMESTAMPTZ
);

CREATE INDEX profile_avatar_assets_orphaned_idx
    ON profile_avatar_assets(orphaned_at)
    WHERE orphaned_at IS NOT NULL;

CREATE INDEX profile_avatar_assets_owner_idx
    ON profile_avatar_assets(owner_id);

ALTER TABLE users
    ADD COLUMN avatar_upload_window_started_at TIMESTAMPTZ,
    ADD COLUMN avatar_upload_count SMALLINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT users_avatar_upload_quota_state CHECK (
        (avatar_upload_count = 0 AND avatar_upload_window_started_at IS NULL)
        OR (avatar_upload_count BETWEEN 1 AND 12 AND avatar_upload_window_started_at IS NOT NULL)
    ),
    ADD CONSTRAINT users_avatar_asset_fk
    FOREIGN KEY (avatar_asset_id) REFERENCES profile_avatar_assets(id)
    ON DELETE SET NULL;

CREATE INDEX users_avatar_asset_idx
    ON users(avatar_asset_id)
    WHERE avatar_asset_id IS NOT NULL;

CREATE FUNCTION veil_enforce_avatar_asset_owner()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.avatar_asset_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM profile_avatar_assets
        WHERE id = NEW.avatar_asset_id AND owner_id = NEW.id
    ) THEN
        RAISE EXCEPTION 'profile avatar owner mismatch'
            USING ERRCODE = '23514', CONSTRAINT = 'users_avatar_asset_owner';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER users_avatar_asset_owner_trigger
BEFORE INSERT OR UPDATE OF avatar_asset_id ON users
FOR EACH ROW EXECUTE FUNCTION veil_enforce_avatar_asset_owner();

CREATE FUNCTION veil_reject_avatar_asset_owner_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.owner_id <> OLD.owner_id THEN
        RAISE EXCEPTION 'profile avatar owner is immutable'
            USING ERRCODE = '23514', CONSTRAINT = 'profile_avatar_asset_owner_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER profile_avatar_asset_owner_immutable_trigger
BEFORE UPDATE OF owner_id ON profile_avatar_assets
FOR EACH ROW EXECUTE FUNCTION veil_reject_avatar_asset_owner_change();

COMMENT ON TABLE profile_avatar_assets IS
    'Server-visible, normalized presentation images; never an identity or trust input';
COMMENT ON COLUMN profile_avatar_assets.sha256 IS
    'Integrity digest for the normalized bytes, not a public asset locator';
COMMENT ON COLUMN users.avatar_upload_count IS
    'At most 12 normalized avatar uploads per fixed 24-hour window';
