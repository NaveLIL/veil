-- Persist the authenticated security context that authorized every new
-- Sender-Key group/channel ciphertext. Existing rows remain all-NULL and are
-- explicitly legacy/unknown; this migration never invents roster/device state
-- for historical ciphertext.

ALTER TABLE messages
    ADD COLUMN crypto_profile TEXT,
    ADD COLUMN crypto_era BIGINT,
    ADD COLUMN roster_version BIGINT,
    ADD COLUMN roster_commitment BYTEA,
    ADD COLUMN sender_device_id BYTEA,
    ADD COLUMN sender_binding_version BIGINT;

ALTER TABLE messages ADD CONSTRAINT messages_security_context_all_or_none
    CHECK (
        (
            crypto_profile IS NULL
            AND crypto_era IS NULL
            AND roster_version IS NULL
            AND roster_commitment IS NULL
            AND sender_device_id IS NULL
            AND sender_binding_version IS NULL
        )
        OR
        (
            crypto_profile IS NOT NULL
            AND crypto_era IS NOT NULL
            AND roster_version IS NOT NULL
            AND roster_commitment IS NOT NULL
            AND sender_device_id IS NOT NULL
            AND sender_binding_version IS NOT NULL
            AND crypto_profile = 'sender_key_v5'
            AND crypto_era = 1
            AND roster_version BETWEEN 1 AND 9223372036854775807
            AND octet_length(roster_commitment) = 32
            AND octet_length(sender_device_id) = 16
            AND sender_binding_version BETWEEN 1 AND 9223372036854775807
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
    context_fields INTEGER;
BEGIN
    SELECT conv_type INTO STRICT conversation_type
    FROM public.conversations
    WHERE id = NEW.conversation_id;

    context_fields := num_nonnulls(
        NEW.crypto_profile, NEW.crypto_era, NEW.roster_version,
        NEW.roster_commitment, NEW.sender_device_id,
        NEW.sender_binding_version
    );
    IF conversation_type IN (1, 2) AND context_fields <> 6 THEN
        RAISE EXCEPTION 'new group/channel message requires persisted Sender-Key security context'
            USING ERRCODE = '23514';
    END IF;
    IF conversation_type = 0 AND context_fields <> 0 THEN
        RAISE EXCEPTION 'direct-message row cannot carry Sender-Key security context'
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
                 roster_commitment, sender_device_id, sender_binding_version
ON messages
FOR EACH ROW EXECUTE FUNCTION veil_validate_message_security_context();

-- Group/channel edits are disabled until an exact device-routed edit request
-- can carry and persist a fresh authenticated roster snapshot. Protect the
-- invariant below the service layer as well, so a future alternate handler
-- cannot silently replace Sender-Key ciphertext through the legacy mutation.
CREATE OR REPLACE FUNCTION veil_reject_secure_message_ciphertext_update()
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

    IF conversation_type IN (1, 2)
       AND (
           NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
           OR NEW.header IS DISTINCT FROM OLD.header
       ) THEN
        RAISE EXCEPTION 'group/channel ciphertext edits require an exact device-routed edit protocol'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS messages_reject_secure_ciphertext_update ON messages;
CREATE TRIGGER messages_reject_secure_ciphertext_update
BEFORE UPDATE OF ciphertext, header ON messages
FOR EACH ROW EXECUTE FUNCTION veil_reject_secure_message_ciphertext_update();

CREATE INDEX idx_messages_sender_key_context
    ON messages (conversation_id, roster_version, sender_device_id, created_at)
    WHERE crypto_profile = 'sender_key_v5';
