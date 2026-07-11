-- Cryptographic per-device identity foundation. Legacy devices remain in the
-- devices table, but are intentionally absent from device_crypto_keys and are
-- therefore ineligible for per-device-secure rosters.
CREATE TABLE device_crypto_keys (
    device_id            UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    device_identity_key  BYTEA UNIQUE NOT NULL,
    device_signing_key   BYTEA UNIQUE NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT device_crypto_identity_key_length CHECK (octet_length(device_identity_key) = 32),
    CONSTRAINT device_crypto_signing_key_length CHECK (octet_length(device_signing_key) = 32)
);

CREATE TABLE device_binding_versions (
    device_id            UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    binding_version      BIGINT NOT NULL,
    capabilities         BIGINT NOT NULL,
    binding_status       SMALLINT NOT NULL,
    account_signature    BYTEA NOT NULL,
    binding_commitment   BYTEA NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, binding_version),
    CONSTRAINT device_binding_version_range CHECK (binding_version BETWEEN 1 AND 9223372036854775807),
    CONSTRAINT device_binding_capabilities_range CHECK (capabilities BETWEEN 0 AND 9223372036854775807),
    CONSTRAINT device_binding_status_range CHECK (binding_status BETWEEN 1 AND 3),
    CONSTRAINT device_binding_signature_length CHECK (octet_length(account_signature) = 64),
    CONSTRAINT device_binding_commitment_length CHECK (octet_length(binding_commitment) = 32)
);

CREATE TABLE device_binding_heads (
    device_id        UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    binding_version  BIGINT NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT device_binding_head_fk FOREIGN KEY (device_id, binding_version)
        REFERENCES device_binding_versions(device_id, binding_version) ON DELETE CASCADE,
    CONSTRAINT device_binding_head_version_range CHECK (binding_version BETWEEN 1 AND 9223372036854775807)
);

CREATE TABLE conversation_device_rosters (
    conversation_id   UUID PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    roster_version    BIGINT NOT NULL,
    roster_commitment BYTEA NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT conversation_roster_version_range CHECK (roster_version BETWEEN 1 AND 9223372036854775807),
    CONSTRAINT conversation_roster_commitment_length CHECK (octet_length(roster_commitment) = 32)
);

CREATE INDEX idx_device_binding_versions_latest
    ON device_binding_versions (device_id, binding_version DESC);
