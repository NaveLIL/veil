-- Phase 4D: origin-local, versioned presentation metadata.
-- Profile fields never participate in identity, ACL or cryptographic state.

ALTER TABLE users
    ADD COLUMN display_name TEXT,
    ADD COLUMN about TEXT NOT NULL DEFAULT '',
    ADD COLUMN avatar_asset_id UUID,
    ADD COLUMN profile_version BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN profile_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD CONSTRAINT users_profile_version_nonnegative CHECK (profile_version >= 0),
    ADD CONSTRAINT users_display_name_byte_limit
        CHECK (display_name IS NULL OR octet_length(display_name) <= 512),
    ADD CONSTRAINT users_about_byte_limit CHECK (octet_length(about) <= 2048);

COMMENT ON COLUMN users.display_name IS
    'Mutable public presentation text; never an identity or authorization input';
COMMENT ON COLUMN users.about IS
    'Mutable public plain text; never HTML, Markdown or an authorization input';
COMMENT ON COLUMN users.avatar_asset_id IS
    'Reserved for the separately reviewed Phase 4D avatar pipeline';
COMMENT ON COLUMN users.profile_version IS
    'Server-controlled monotonic revision for optimistic concurrency';
