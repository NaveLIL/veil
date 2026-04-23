-- Phase 3 — tus.io resumable uploads (E2EE files).
--
-- Each row is one file uploaded by `user_id`. Server stores no
-- plaintext: ciphertext lives on the upload backend (local FS or S3
-- in a future rev), and only opaque metadata sits here.
--
-- Quotas are enforced in the pre-create hook via
-- SUM(size_bytes) WHERE created_at >= now() - 24h GROUP BY user_id.
-- Daily quota is configurable (UPLOAD_USER_DAILY_QUOTA_BYTES env).
--
-- A nightly sweeper deletes rows + backend blobs where:
--   - finished_at IS NULL AND created_at < now() - '24h'   (aborted)
--   - finished_at IS NOT NULL AND finished_at < now() - retention

CREATE TABLE IF NOT EXISTS tus_uploads (
    file_id         TEXT       PRIMARY KEY,         -- tusd-generated upload ID (URL-safe)
    user_id         UUID       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    size_bytes      BIGINT     NOT NULL,            -- declared at create-time (Upload-Length)
    received_bytes  BIGINT     NOT NULL DEFAULT 0,  -- bumped on every PATCH
    backend         TEXT       NOT NULL DEFAULT 'local',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL            -- aborted-upload TTL or content retention
);

CREATE INDEX IF NOT EXISTS idx_tus_uploads_user_recent
    ON tus_uploads(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_tus_uploads_expires
    ON tus_uploads(expires_at);
