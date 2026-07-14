-- Security and protocol-integrity constraints.
--
-- protocol_key_id is selected by the client and identifies the matching
-- private SPK/OPK kept on that device.  The prekeys.id BIGSERIAL remains an
-- internal database row id and must never be used in an X3DH message.
ALTER TABLE prekeys
    ADD COLUMN IF NOT EXISTS protocol_key_id BIGINT;

UPDATE prekeys
SET protocol_key_id = id
WHERE protocol_key_id IS NULL;

ALTER TABLE prekeys
    ALTER COLUMN protocol_key_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_prekeys_device_protocol_id
    ON prekeys (device_id, key_type, protocol_key_id);

ALTER TABLE sender_keys
    ALTER COLUMN generation TYPE BIGINT;

CREATE INDEX IF NOT EXISTS idx_sender_keys_target_device
    ON sender_keys (target_device_id);

-- Add constraints as NOT VALID so an upgrade never fails solely because of
-- legacy bad rows. PostgreSQL still enforces NOT VALID constraints for every
-- new row; operators can clean legacy data and VALIDATE them independently.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_identity_key_length') THEN
        ALTER TABLE users ADD CONSTRAINT users_identity_key_length
            CHECK (octet_length(identity_key) = 32) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_signing_key_length') THEN
        ALTER TABLE users ADD CONSTRAINT users_signing_key_length
            CHECK (octet_length(signing_key) = 32) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'devices_device_key_length') THEN
        ALTER TABLE devices ADD CONSTRAINT devices_device_key_length
            CHECK (octet_length(device_key) = 16) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'prekeys_public_key_length') THEN
        ALTER TABLE prekeys ADD CONSTRAINT prekeys_public_key_length
            CHECK (octet_length(public_key) = 32) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'prekeys_signature_length') THEN
        ALTER TABLE prekeys ADD CONSTRAINT prekeys_signature_length
            CHECK (signature IS NULL OR octet_length(signature) = 64) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'prekeys_protocol_key_id_range') THEN
        ALTER TABLE prekeys ADD CONSTRAINT prekeys_protocol_key_id_range
            CHECK (protocol_key_id BETWEEN 0 AND 4294967295) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sender_keys_generation_range') THEN
        ALTER TABLE sender_keys ADD CONSTRAINT sender_keys_generation_range
            CHECK (generation BETWEEN 1 AND 4294967295) NOT VALID;
    END IF;
END $$;

-- A reaction's conversation must be the conversation containing its message.
-- The composite unique key is redundant with messages(id), but is required as
-- the target of the composite foreign key.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'messages_id_conversation_unique') THEN
        ALTER TABLE messages ADD CONSTRAINT messages_id_conversation_unique
            UNIQUE (id, conversation_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'reactions_message_conversation_fk') THEN
        ALTER TABLE reactions ADD CONSTRAINT reactions_message_conversation_fk
            FOREIGN KEY (message_id, conversation_id)
            REFERENCES messages (id, conversation_id) ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'reactions_user_fk') THEN
        ALTER TABLE reactions ADD CONSTRAINT reactions_user_fk
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sender_keys_conversation_fk') THEN
        ALTER TABLE sender_keys ADD CONSTRAINT sender_keys_conversation_fk
            FOREIGN KEY (conversation_id) REFERENCES conversations (id) ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sender_keys_owner_device_fk') THEN
        ALTER TABLE sender_keys ADD CONSTRAINT sender_keys_owner_device_fk
            FOREIGN KEY (owner_device_id) REFERENCES devices (id) ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sender_keys_target_device_fk') THEN
        ALTER TABLE sender_keys ADD CONSTRAINT sender_keys_target_device_fk
            FOREIGN KEY (target_device_id) REFERENCES devices (id) ON DELETE CASCADE NOT VALID;
    END IF;
END $$;
