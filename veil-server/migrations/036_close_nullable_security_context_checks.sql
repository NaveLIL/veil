-- PostgreSQL CHECK constraints accept an UNKNOWN result. Earlier shape checks
-- used length/range expressions without first proving every required column
-- non-NULL, so a deliberately partial security context could evaluate to
-- UNKNOWN and pass. Rebuild the live constraints with explicit NULL presence
-- predicates. Historical all-NULL rows remain valid.

ALTER TABLE identity_transparency_log_leaves
    DROP CONSTRAINT identity_transparency_event_shape;

ALTER TABLE identity_transparency_log_leaves
    ADD CONSTRAINT identity_transparency_event_shape CHECK (
        (event_kind = 1 AND subject_device_id IS NULL AND binding_version IS NULL)
        OR
        (event_kind = 2 AND subject_device_id IS NOT NULL AND binding_version IS NOT NULL)
        OR
        (event_kind IN (3, 4)
         AND subject_device_id IS NULL
         AND binding_version IS NULL)
    ) NOT VALID;

ALTER TABLE identity_transparency_log_leaves
    VALIDATE CONSTRAINT identity_transparency_event_shape;

ALTER TABLE conversation_membership_epochs_v1
    DROP CONSTRAINT membership_epoch_bootstrap_owner_shape;

ALTER TABLE conversation_membership_epochs_v1
    ADD CONSTRAINT membership_epoch_bootstrap_owner_shape
    CHECK (
        (epoch_number = 1
         AND bootstrap_owner_id IS NOT NULL
         AND bootstrap_owner_signing_key IS NOT NULL
         AND octet_length(bootstrap_owner_signing_key) = 32)
        OR
        (epoch_number > 1
         AND bootstrap_owner_id IS NULL
         AND bootstrap_owner_signing_key IS NULL)
    ) NOT VALID;

ALTER TABLE conversation_membership_epochs_v1
    VALIDATE CONSTRAINT membership_epoch_bootstrap_owner_shape;

ALTER TABLE messages DROP CONSTRAINT messages_security_context_all_or_none;

ALTER TABLE messages ADD CONSTRAINT messages_security_context_all_or_none
    CHECK (
        (
            crypto_profile IS NULL AND crypto_era IS NULL
            AND roster_version IS NULL AND roster_commitment IS NULL
            AND sender_device_id IS NULL AND sender_binding_version IS NULL
            AND target_device_id IS NULL AND target_binding_version IS NULL
            AND direct_session_id IS NULL
            AND sender_device_identity_key IS NULL
            AND sender_device_signing_key IS NULL
            AND sender_device_capabilities IS NULL
            AND sender_device_binding_status IS NULL
            AND sender_account_signature IS NULL
            AND membership_epoch IS NULL AND membership_epoch_hash IS NULL
        )
        OR
        (
            crypto_profile IS NOT NULL AND crypto_era IS NOT NULL
            AND roster_version IS NOT NULL AND roster_commitment IS NOT NULL
            AND sender_device_id IS NOT NULL AND sender_binding_version IS NOT NULL
            AND crypto_profile = 'sender_key_v5' AND crypto_era = 1
            AND roster_version BETWEEN 1 AND 9223372036854775807
            AND octet_length(roster_commitment) = 32
            AND roster_commitment <> decode(repeat('00', 32), 'hex')
            AND octet_length(sender_device_id) = 16
            AND sender_device_id <> decode(repeat('00', 16), 'hex')
            AND sender_binding_version BETWEEN 1 AND 9223372036854775807
            AND target_device_id IS NULL AND target_binding_version IS NULL
            AND direct_session_id IS NULL
            AND sender_device_identity_key IS NULL
            AND sender_device_signing_key IS NULL
            AND sender_device_capabilities IS NULL
            AND sender_device_binding_status IS NULL
            AND sender_account_signature IS NULL
            AND membership_epoch IS NULL AND membership_epoch_hash IS NULL
        )
        OR
        (
            crypto_profile IS NOT NULL AND crypto_era IS NOT NULL
            AND roster_version IS NOT NULL AND roster_commitment IS NOT NULL
            AND sender_device_id IS NOT NULL AND sender_binding_version IS NOT NULL
            AND membership_epoch IS NOT NULL AND membership_epoch_hash IS NOT NULL
            AND crypto_profile = 'sender_key_v6' AND crypto_era = 1
            AND roster_version BETWEEN 1 AND 9223372036854775807
            AND octet_length(roster_commitment) = 32
            AND roster_commitment <> decode(repeat('00', 32), 'hex')
            AND octet_length(sender_device_id) = 16
            AND sender_device_id <> decode(repeat('00', 16), 'hex')
            AND sender_binding_version BETWEEN 1 AND 9223372036854775807
            AND target_device_id IS NULL AND target_binding_version IS NULL
            AND direct_session_id IS NULL
            AND sender_device_identity_key IS NULL
            AND sender_device_signing_key IS NULL
            AND sender_device_capabilities IS NULL
            AND sender_device_binding_status IS NULL
            AND sender_account_signature IS NULL
            AND membership_epoch BETWEEN 1 AND 9223372036854775807
            AND octet_length(membership_epoch_hash) = 32
            AND membership_epoch_hash <> decode(repeat('00', 32), 'hex')
        )
        OR
        (
            crypto_profile IS NOT NULL AND crypto_era IS NOT NULL
            AND sender_device_id IS NOT NULL AND sender_binding_version IS NOT NULL
            AND sender_device_identity_key IS NOT NULL
            AND sender_device_signing_key IS NOT NULL
            AND sender_device_capabilities IS NOT NULL
            AND sender_device_binding_status IS NOT NULL
            AND sender_account_signature IS NOT NULL
            AND target_device_id IS NOT NULL AND target_binding_version IS NOT NULL
            AND direct_session_id IS NOT NULL
            AND crypto_profile = 'direct_v2' AND crypto_era = 1
            AND roster_version IS NULL AND roster_commitment IS NULL
            AND octet_length(sender_device_id) = 16
            AND sender_device_id <> decode(repeat('00', 16), 'hex')
            AND sender_binding_version BETWEEN 1 AND 9223372036854775807
            AND octet_length(sender_device_identity_key) = 32
            AND sender_device_identity_key <> decode(repeat('00', 32), 'hex')
            AND octet_length(sender_device_signing_key) = 32
            AND sender_device_signing_key <> decode(repeat('00', 32), 'hex')
            AND sender_device_identity_key <> sender_device_signing_key
            AND sender_device_capabilities BETWEEN 1 AND 9223372036854775807
            AND sender_device_binding_status = 1
            AND octet_length(sender_account_signature) = 64
            AND sender_account_signature <> decode(repeat('00', 64), 'hex')
            AND octet_length(target_device_id) = 16
            AND target_device_id <> decode(repeat('00', 16), 'hex')
            AND target_binding_version BETWEEN 1 AND 9223372036854775807
            AND sender_device_id <> target_device_id
            AND octet_length(direct_session_id) = 32
            AND direct_session_id <> decode(repeat('00', 32), 'hex')
            AND membership_epoch IS NULL AND membership_epoch_hash IS NULL
        )
    ) NOT VALID;

ALTER TABLE messages VALIDATE CONSTRAINT messages_security_context_all_or_none;

ALTER TABLE sender_keys DROP CONSTRAINT sender_keys_membership_context_shape;

ALTER TABLE sender_keys ADD CONSTRAINT sender_keys_membership_context_shape
    CHECK (
        (membership_epoch IS NULL AND membership_epoch_hash IS NULL)
        OR
        (membership_epoch IS NOT NULL AND membership_epoch_hash IS NOT NULL
         AND membership_epoch BETWEEN 1 AND 9223372036854775807
         AND octet_length(membership_epoch_hash) = 32
         AND membership_epoch_hash <> decode(repeat('00', 32), 'hex'))
    ) NOT VALID;

ALTER TABLE sender_keys VALIDATE CONSTRAINT sender_keys_membership_context_shape;

ALTER TABLE message_send_idempotency
    DROP CONSTRAINT message_send_ack_membership_shape;

ALTER TABLE message_send_idempotency
    ADD CONSTRAINT message_send_ack_membership_shape
    CHECK (
        (ack_membership_epoch IS NULL AND ack_membership_epoch_hash IS NULL)
        OR
        (ack_roster_version IS NOT NULL
         AND ack_membership_epoch IS NOT NULL
         AND ack_membership_epoch_hash IS NOT NULL
         AND ack_membership_epoch BETWEEN 1 AND 9223372036854775807
         AND octet_length(ack_membership_epoch_hash) = 32
         AND ack_membership_epoch_hash <> decode(repeat('00', 32), 'hex'))
    ) NOT VALID;

ALTER TABLE message_send_idempotency
    VALIDATE CONSTRAINT message_send_ack_membership_shape;
