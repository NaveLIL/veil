-- Phase 4 — UnifiedPush + ntfy push notifications.
--
-- Each row binds a (user, distributor endpoint URL) pair to which the
-- delivery worker POSTs encrypted envelopes when the user has no live
-- WebSocket session. The endpoint is opaque to us — UnifiedPush spec —
-- so we never store WebPush ECDH material here. Encryption of the
-- payload happens *above* this layer (XChaCha20-Poly1305 with K_push
-- HKDF-derived from the conversation ratchet root, keyed per device).
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
