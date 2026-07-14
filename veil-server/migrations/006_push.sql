-- Phase 4 — UnifiedPush + ntfy push notifications.
--
-- Historical initial subscription schema. Migration 025 performs the
-- pre-release hard cutover to RFC 8291 Web Push key material and deletes every
-- endpoint-only row; this file remains immutable in the ordered chain.
--
-- push_kind reserves room for future transports (raw 'webpush', 'apns')
-- without another migration; the worker dispatches by kind.

CREATE TABLE IF NOT EXISTS push_subscriptions (
    id              BIGSERIAL PRIMARY KEY,
    user_id         UUID    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint_url    TEXT    NOT NULL,
    device_label    TEXT,
    push_kind       TEXT    NOT NULL DEFAULT 'unifiedpush',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used       TIMESTAMPTZ,
    UNIQUE (user_id, endpoint_url)
);

CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user
    ON push_subscriptions(user_id);
