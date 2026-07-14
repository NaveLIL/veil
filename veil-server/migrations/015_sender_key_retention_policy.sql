-- Bounded retained-SKDM policy. Expiry is an admission deadline, not silent
-- deletion: the runtime refuses a newer generation while an expired
-- unacknowledged row exists. Exact device receipts, target-device
-- exclusion/revocation, and a committed loss of the TARGET's channel-read
-- authorization are the only automatic pruning paths. Removing only the
-- sender/owner never prunes an already-authorized target's retained history.
--
-- Migration 014 deliberately made pre-cutover rows visible through a NULL
-- device-route tuple. The new runtime cannot authenticate or acknowledge
-- those account-routed envelopes. Do not silently delete them and do not put
-- them under a retention policy that can never complete: stop the cutover and
-- require the operator procedure documented in
-- docs/operations/sender-key-device-routing-cutover.md.
CREATE OR REPLACE FUNCTION veil_assert_sender_key_device_routing_cutover()
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    legacy_count BIGINT;
BEGIN
    SELECT COUNT(*) INTO legacy_count
    FROM public.sender_keys
    WHERE roster_version IS NULL
       OR roster_commitment IS NULL
       OR owner_binding_version IS NULL
       OR target_binding_version IS NULL;

    IF legacy_count <> 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'check_violation',
            MESSAGE = format(
                'sender-key device-routing cutover blocked: %s legacy or partial rows require an explicit backup/audit decision',
                legacy_count
            ),
            HINT = 'Back up the affected rows, confirm that legacy offline delivery is being sacrificed, delete only sender_keys rows with a NULL route tuple, preserve sender_key_heads, then rerun the migration.';
    END IF;
END;
$$;

SELECT veil_assert_sender_key_device_routing_cutover();

-- The explicit cutover is one-way. Once the preflight proves that no legacy
-- or partial route remains, make regression structurally impossible for all
-- future writers instead of relying only on the gateway implementation.
-- Recreate the transitional 014 constraint as a strict post-cutover
-- invariant; this also repairs an operator-disabled constraint after the
-- preflight has forced the affected rows through an explicit audit.
ALTER TABLE sender_keys
    DROP CONSTRAINT IF EXISTS sender_keys_device_route_complete;

ALTER TABLE sender_keys ADD CONSTRAINT sender_keys_device_route_complete
    CHECK (
        roster_version BETWEEN 1 AND 9223372036854775807
        AND octet_length(roster_commitment) = 32
        AND owner_binding_version BETWEEN 1 AND 9223372036854775807
        AND target_binding_version BETWEEN 1 AND 9223372036854775807
    ) NOT VALID;

ALTER TABLE sender_keys
    ALTER COLUMN roster_version SET NOT NULL,
    ALTER COLUMN roster_commitment SET NOT NULL,
    ALTER COLUMN owner_binding_version SET NOT NULL,
    ALTER COLUMN target_binding_version SET NOT NULL;

ALTER TABLE sender_keys VALIDATE CONSTRAINT sender_keys_device_route_complete;

ALTER TABLE sender_keys
    ADD COLUMN created_at TIMESTAMPTZ,
    ADD COLUMN expires_at TIMESTAMPTZ;

UPDATE sender_keys
SET created_at = COALESCE(created_at, now()),
    expires_at = COALESCE(expires_at, now() + INTERVAL '90 days');

ALTER TABLE sender_keys
    ALTER COLUMN created_at SET DEFAULT now(),
    ALTER COLUMN created_at SET NOT NULL,
    ALTER COLUMN expires_at SET DEFAULT (now() + INTERVAL '90 days'),
    ALTER COLUMN expires_at SET NOT NULL;

ALTER TABLE sender_keys ADD CONSTRAINT sender_keys_retention_window
    CHECK (expires_at > created_at) NOT VALID;

ALTER TABLE sender_keys VALIDATE CONSTRAINT sender_keys_retention_window;

CREATE INDEX idx_sender_keys_retention_deadline
    ON sender_keys (expires_at, conversation_id, owner_device_id, target_device_id)
    WHERE roster_version IS NOT NULL;
