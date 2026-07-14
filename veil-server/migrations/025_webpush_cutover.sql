-- Phase 4P / Android cutover: UnifiedPush uses RFC 8291 Web Push.
--
-- Endpoint-only rows were created by a pre-release, non-interoperable
-- transport. Veil has never shipped to production, so fail closed and remove
-- them instead of retaining an unsafe compatibility path.

DELETE FROM push_subscriptions;

ALTER TABLE push_subscriptions
    ADD COLUMN webpush_public_key TEXT NOT NULL,
    ADD COLUMN webpush_auth_secret TEXT NOT NULL,
    ADD COLUMN validated_at TIMESTAMPTZ,
    ADD COLUMN validation_token_hash BYTEA,
    ADD COLUMN validation_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT push_webpush_public_key_shape
        CHECK (webpush_public_key ~ '^[A-Za-z0-9_-]{87}$'),
    ADD CONSTRAINT push_webpush_auth_secret_shape
        CHECK (webpush_auth_secret ~ '^[A-Za-z0-9_-]{22}$'),
    ADD CONSTRAINT push_validation_state_consistent CHECK (
        (validated_at IS NOT NULL AND validation_token_hash IS NULL AND validation_expires_at IS NULL)
        OR
        (validated_at IS NULL AND validation_token_hash IS NOT NULL AND validation_expires_at IS NOT NULL)
    );

DROP INDEX IF EXISTS idx_push_subscriptions_delivery;
CREATE INDEX idx_push_subscriptions_delivery
    ON push_subscriptions(user_id, muted_until)
    WHERE enabled = TRUE AND validated_at IS NOT NULL;
