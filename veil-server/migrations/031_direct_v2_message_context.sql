-- Persist exact per-device Direct v2 routing/session context. Existing Direct
-- v1 rows remain all-NULL and are explicitly legacy; no migration invents a
-- device or session binding for historical ciphertext.

ALTER TABLE messages
    ADD COLUMN target_device_id BYTEA,
    ADD COLUMN target_binding_version BIGINT,
    ADD COLUMN direct_session_id BYTEA,
    ADD COLUMN sender_device_identity_key BYTEA,
    ADD COLUMN sender_device_signing_key BYTEA,
    ADD COLUMN sender_device_capabilities BIGINT,
    ADD COLUMN sender_device_binding_status SMALLINT,
    ADD COLUMN sender_account_signature BYTEA;

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
BEGIN
    SELECT conv_type INTO STRICT conversation_type
    FROM public.conversations
    WHERE id = NEW.conversation_id;

    IF conversation_type IN (1, 2) THEN
        IF NEW.crypto_profile IS DISTINCT FROM 'sender_key_v5' THEN
            RAISE EXCEPTION 'new group/channel message requires persisted Sender-Key security context'
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
                 sender_account_signature
ON messages
FOR EACH ROW EXECUTE FUNCTION veil_validate_message_security_context();

CREATE OR REPLACE FUNCTION veil_reject_secure_message_ciphertext_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF OLD.crypto_profile IN ('sender_key_v5', 'direct_v2')
       AND (
           NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
           OR NEW.header IS DISTINCT FROM OLD.header
       ) THEN
        RAISE EXCEPTION 'versioned secure ciphertext edits require a new exact routing protocol'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS messages_reject_secure_ciphertext_update ON messages;
CREATE TRIGGER messages_reject_secure_ciphertext_update
BEFORE UPDATE OF ciphertext, header ON messages
FOR EACH ROW EXECUTE FUNCTION veil_reject_secure_message_ciphertext_update();

CREATE INDEX idx_messages_direct_v2_target
    ON messages (conversation_id, target_device_id, created_at)
    WHERE crypto_profile = 'direct_v2';
