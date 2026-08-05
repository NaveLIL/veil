-- Bind every post-activation Sender-Key distribution and message to the
-- exact client-authorized membership epoch. Historical Sender-Key v5 rows
-- remain readable and are never relabelled.

ALTER TABLE messages
    ADD COLUMN membership_epoch BIGINT,
    ADD COLUMN membership_epoch_hash BYTEA;

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
            crypto_profile = 'sender_key_v5' AND crypto_era = 1
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
            crypto_profile = 'sender_key_v6' AND crypto_era = 1
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
            crypto_profile = 'direct_v2' AND crypto_era = 1
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

CREATE OR REPLACE FUNCTION veil_validate_message_security_context()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    conversation_type SMALLINT;
    active_membership_epoch BIGINT;
    active_membership_hash BYTEA;
BEGIN
    SELECT conv_type INTO STRICT conversation_type
    FROM public.conversations
    WHERE id = NEW.conversation_id;

    IF conversation_type IN (1, 2) THEN
        SELECT epoch_number, epoch_hash
          INTO active_membership_epoch, active_membership_hash
          FROM public.conversation_membership_epoch_heads_v1
         WHERE conversation_id = NEW.conversation_id;
        IF active_membership_epoch IS NULL THEN
            IF NEW.crypto_profile IS DISTINCT FROM 'sender_key_v5'
               OR NEW.membership_epoch IS NOT NULL
               OR NEW.membership_epoch_hash IS NOT NULL THEN
                RAISE EXCEPTION 'legacy group/channel requires Sender-Key v5 without membership coordinates'
                    USING ERRCODE = '23514';
            END IF;
        ELSIF NEW.crypto_profile IS DISTINCT FROM 'sender_key_v6'
           OR NEW.membership_epoch IS DISTINCT FROM active_membership_epoch
           OR NEW.membership_epoch_hash IS DISTINCT FROM active_membership_hash THEN
            RAISE EXCEPTION 'activated group/channel requires exact current membership epoch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF conversation_type = 0 THEN
        IF NEW.crypto_profile IS NOT NULL
           AND NEW.crypto_profile IS DISTINCT FROM 'direct_v2' THEN
            RAISE EXCEPTION 'direct-message row has an invalid crypto profile'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'message conversation type is unsupported'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS messages_validate_security_context_insert ON messages;
CREATE TRIGGER messages_validate_security_context_insert
BEFORE INSERT ON messages
FOR EACH ROW EXECUTE FUNCTION veil_validate_message_security_context();

DROP TRIGGER IF EXISTS messages_validate_security_context_scope_update ON messages;
CREATE TRIGGER messages_validate_security_context_scope_update
BEFORE UPDATE OF conversation_id, crypto_profile, crypto_era, roster_version,
                 roster_commitment, sender_device_id, sender_binding_version,
                 target_device_id, target_binding_version, direct_session_id,
                 sender_device_identity_key, sender_device_signing_key,
                 sender_device_capabilities, sender_device_binding_status,
                 sender_account_signature, membership_epoch,
                 membership_epoch_hash
ON messages
FOR EACH ROW EXECUTE FUNCTION veil_validate_message_security_context();

CREATE INDEX idx_messages_sender_key_v6_epoch
    ON messages (conversation_id, membership_epoch, sender_device_id, created_at)
    WHERE crypto_profile = 'sender_key_v6';

ALTER TABLE sender_keys
    ADD COLUMN membership_epoch BIGINT,
    ADD COLUMN membership_epoch_hash BYTEA;

ALTER TABLE sender_keys ADD CONSTRAINT sender_keys_membership_context_shape
    CHECK (
        (membership_epoch IS NULL AND membership_epoch_hash IS NULL)
        OR
        (membership_epoch BETWEEN 1 AND 9223372036854775807
         AND octet_length(membership_epoch_hash) = 32
         AND membership_epoch_hash <> decode(repeat('00', 32), 'hex'))
    ) NOT VALID;

ALTER TABLE sender_keys VALIDATE CONSTRAINT sender_keys_membership_context_shape;

ALTER TABLE sender_keys ADD CONSTRAINT sender_keys_membership_epoch_fk
    FOREIGN KEY (conversation_id, membership_epoch, membership_epoch_hash)
    REFERENCES conversation_membership_epochs_v1
        (conversation_id, epoch_number, epoch_hash)
    NOT VALID;

CREATE INDEX idx_sender_keys_membership_epoch
    ON sender_keys (conversation_id, membership_epoch, target_device_id)
    WHERE membership_epoch IS NOT NULL;

ALTER TABLE message_send_idempotency
    ADD COLUMN ack_membership_epoch BIGINT,
    ADD COLUMN ack_membership_epoch_hash BYTEA;

ALTER TABLE message_send_idempotency ADD CONSTRAINT message_send_ack_membership_shape
    CHECK (
        (ack_membership_epoch IS NULL AND ack_membership_epoch_hash IS NULL)
        OR
        (ack_roster_version IS NOT NULL
         AND ack_membership_epoch BETWEEN 1 AND 9223372036854775807
         AND octet_length(ack_membership_epoch_hash) = 32
         AND ack_membership_epoch_hash <> decode(repeat('00', 32), 'hex'))
    );
