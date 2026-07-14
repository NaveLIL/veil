-- Phase 4P — server-enforced per-device push delivery policy.
--
-- UI-only mute is insufficient: an offline gateway would still disclose
-- delivery timing to the distributor. Dispatcher selection therefore filters
-- disabled and currently muted endpoints before constructing any envelope.

ALTER TABLE push_subscriptions
    ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS muted_until TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_push_subscriptions_delivery
    ON push_subscriptions(user_id, muted_until)
    WHERE enabled = TRUE;

