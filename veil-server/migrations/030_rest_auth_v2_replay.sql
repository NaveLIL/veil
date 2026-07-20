-- Cross-process replay markers for signed REST authentication v2.
--
-- A marker is inserted only after a valid account signature. The account and
-- nonce primary key gives every gateway process one atomic winner; expiry is
-- maintenance metadata and never permits eviction of a live marker.
CREATE TABLE rest_auth_v2_replay_nonces (
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    nonce      BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, nonce),
    CONSTRAINT rest_auth_v2_replay_nonce_length
        CHECK (octet_length(nonce) = 32),
    CONSTRAINT rest_auth_v2_replay_nonce_nonzero
        CHECK (nonce <> decode(repeat('00', 32), 'hex')),
    CONSTRAINT rest_auth_v2_replay_expiry_order
        CHECK (expires_at > created_at),
    CONSTRAINT rest_auth_v2_replay_retention_bound
        CHECK (expires_at <= created_at + interval '10 minutes')
);

CREATE INDEX idx_rest_auth_v2_replay_expiry
    ON rest_auth_v2_replay_nonces (expires_at);
