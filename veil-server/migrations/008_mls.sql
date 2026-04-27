-- 008_mls.sql — Phase 6: OpenMLS support.
--
-- Conversations opt into MLS via the new `crypto_mode` column. Existing
-- rows default to 'sender_key' so behaviour for already-running rooms is
-- unchanged. Three new tables back the per-device key-package pool, the
-- per-recipient Welcome inbox, and the append-only Commit log fanned out
-- to the rest of the membership.
--
-- All blobs are TLS-encoded MLS structures and the server treats them as
-- opaque bytes. The 30-day TTLs are enforced by the chat sweeper.

ALTER TABLE conversations
    ADD COLUMN IF NOT EXISTS crypto_mode TEXT NOT NULL DEFAULT 'sender_key'
        CHECK (crypto_mode IN ('sender_key', 'mls'));

-- Per-device pool of unused KeyPackages. Clients should keep the pool
-- topped up; consumers DELETE..RETURNING one row atomically.
CREATE TABLE IF NOT EXISTS mls_key_packages (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     TEXT        NOT NULL,
    device_id   BYTEA       NOT NULL,
    kp_blob     BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mls_kp_user_device
    ON mls_key_packages(user_id, device_id);
CREATE INDEX IF NOT EXISTS idx_mls_kp_created_at
    ON mls_key_packages(created_at);

-- Per-recipient Welcome inbox. Cleared after the recipient confirms
-- processing (DELETE) or after the 30-day TTL expires.
CREATE TABLE IF NOT EXISTS mls_welcomes (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient_user_id    TEXT        NOT NULL,
    recipient_device_id  BYTEA       NOT NULL,
    conversation_id      TEXT        NOT NULL,
    blob                 BYTEA       NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mls_welcomes_recipient
    ON mls_welcomes(recipient_user_id, recipient_device_id);
CREATE INDEX IF NOT EXISTS idx_mls_welcomes_created_at
    ON mls_welcomes(created_at);

-- Append-only commit log per conversation. (conversation_id, epoch) is
-- the natural primary key — at most one commit can advance a given
-- epoch. Members fetch all commits with epoch > local_epoch on
-- reconnect to catch up.
CREATE TABLE IF NOT EXISTS mls_commits (
    conversation_id TEXT        NOT NULL,
    epoch           BIGINT      NOT NULL,
    sender_user_id  TEXT        NOT NULL,
    blob            BYTEA       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, epoch)
);
CREATE INDEX IF NOT EXISTS idx_mls_commits_created_at
    ON mls_commits(created_at);
