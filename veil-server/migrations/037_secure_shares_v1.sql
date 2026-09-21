-- Phase 4G: Secure Share v1 capabilities, atomic redemption leases and lifecycle.

-- Drop the legacy unauthenticated prototype shares table
DROP TABLE IF EXISTS shares;

CREATE TABLE secure_shares_v1 (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_selector        TEXT NOT NULL UNIQUE,
    redemption_hash        BYTEA NOT NULL,
    report_capability_hash BYTEA NOT NULL,
    creator_user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ciphertext             BYTEA NOT NULL,
    size_bytes             BIGINT NOT NULL,
    content_type           TEXT NOT NULL DEFAULT 'text',
    max_claims             INTEGER NOT NULL DEFAULT 1,
    consumed_claims        INTEGER NOT NULL DEFAULT 0,
    status                 TEXT NOT NULL DEFAULT 'active',
    expires_at             TIMESTAMPTZ NOT NULL,
    revoked_at             TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT secure_shares_selector_v1 CHECK (public_selector ~ '^[A-Za-z0-9_-]{16,64}$'),
    CONSTRAINT secure_shares_redemption_hash_v1 CHECK (octet_length(redemption_hash) = 32),
    CONSTRAINT secure_shares_report_capability_hash_v1 CHECK (octet_length(report_capability_hash) = 32),
    CONSTRAINT secure_shares_content_type_v1 CHECK (content_type IN ('text', 'file')),
    CONSTRAINT secure_shares_bounded_claims CHECK (max_claims BETWEEN 1 AND 100),
    CONSTRAINT secure_shares_consumed_claims CHECK (consumed_claims BETWEEN 0 AND max_claims),
    CONSTRAINT secure_shares_status_v1 CHECK (status IN ('active', 'burned', 'expired', 'revoked', 'purging')),
    CONSTRAINT secure_shares_bounded_expiry CHECK (
        expires_at > created_at
        AND expires_at <= created_at + interval '30 days'
    )
);

CREATE INDEX idx_secure_shares_creator_active
    ON secure_shares_v1(creator_user_id, created_at DESC)
    WHERE status = 'active';

CREATE INDEX idx_secure_shares_expires
    ON secure_shares_v1(expires_at)
    WHERE status IN ('active', 'burned');

CREATE TABLE secure_share_leases_v1 (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    share_id         UUID NOT NULL REFERENCES secure_shares_v1(id) ON DELETE CASCADE,
    lease_token_hash BYTEA NOT NULL UNIQUE,
    expires_at       TIMESTAMPTZ NOT NULL,
    status           TEXT NOT NULL DEFAULT 'issued',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT secure_share_leases_token_hash_v1 CHECK (octet_length(lease_token_hash) = 32),
    CONSTRAINT secure_share_leases_status_v1 CHECK (status IN ('issued', 'expired', 'revoked')),
    CONSTRAINT secure_share_leases_bounded_expiry CHECK (expires_at > created_at)
);

CREATE INDEX idx_secure_share_leases_share_active
    ON secure_share_leases_v1(share_id, expires_at)
    WHERE status = 'issued';

CREATE INDEX idx_secure_share_leases_expires
    ON secure_share_leases_v1(expires_at)
    WHERE status = 'issued';
