-- Bind every new Sender-Key distribution to the exact rollback-resistant
-- device roster that authorized it. Existing rows remain visibly legacy
-- (all four columns NULL) and are never restored by the v1 device runtime.
ALTER TABLE sender_keys
    ADD COLUMN roster_version BIGINT,
    ADD COLUMN roster_commitment BYTEA,
    ADD COLUMN owner_binding_version BIGINT,
    ADD COLUMN target_binding_version BIGINT;

ALTER TABLE sender_keys ADD CONSTRAINT sender_keys_device_route_complete
    CHECK (
        (roster_version IS NULL
         AND roster_commitment IS NULL
         AND owner_binding_version IS NULL
         AND target_binding_version IS NULL)
        OR
        (roster_version BETWEEN 1 AND 9223372036854775807
         AND octet_length(roster_commitment) = 32
         AND owner_binding_version BETWEEN 1 AND 9223372036854775807
         AND target_binding_version BETWEEN 1 AND 9223372036854775807)
    ) NOT VALID;

CREATE INDEX idx_sender_keys_device_routed_pending
    ON sender_keys (target_device_id, conversation_id, roster_version, generation)
    WHERE roster_version IS NOT NULL;
