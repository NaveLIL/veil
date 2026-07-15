-- Closed-Preview Node Access invitations.
--
-- The bearer secret is 256 random bits and is never persisted. Only its
-- SHA-256 digest is stored, so a database read cannot recover unused invites.

CREATE TABLE node_access_invites (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash      BYTEA UNIQUE NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    used_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT node_access_invite_hash_length
        CHECK (octet_length(token_hash) = 32),
    CONSTRAINT node_access_invite_expiry_order
        CHECK (expires_at > created_at),
    CONSTRAINT node_access_invite_used_after_creation
        CHECK (used_at IS NULL OR used_at >= created_at),
    CONSTRAINT node_access_invite_used_before_expiry
        CHECK (used_at IS NULL OR used_at <= expires_at),
    CONSTRAINT node_access_invite_usage_state
        CHECK (used_at IS NOT NULL OR used_by_user_id IS NULL)
);

CREATE INDEX idx_node_access_invites_unused_expiry
    ON node_access_invites (expires_at)
    WHERE used_at IS NULL;
