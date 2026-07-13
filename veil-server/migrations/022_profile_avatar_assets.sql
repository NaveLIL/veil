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

ALTER TABLE users
    ADD CONSTRAINT users_avatar_asset_fk
    FOREIGN KEY (avatar_asset_id) REFERENCES profile_avatar_assets(id)
    ON DELETE SET NULL;

COMMENT ON TABLE profile_avatar_assets IS
    'Server-visible, normalized presentation images; never an identity or trust input';
COMMENT ON COLUMN profile_avatar_assets.sha256 IS
    'Integrity digest for the normalized bytes, not a public asset locator';
