-- Preserve every Sender-Key generation needed by an offline device.
--
-- Older schemas kept only one row per (conversation, owner device, target
-- device), so generation N+1 overwrote generation N.  Expanding the primary
-- key is an in-place migration: the one legacy row remains valid and becomes
-- the initial retained generation for its stream.
ALTER TABLE sender_keys
    ADD COLUMN envelope_commitment BYTEA;

UPDATE sender_keys
SET envelope_commitment = digest(encrypted_key, 'sha256')
WHERE envelope_commitment IS NULL;

ALTER TABLE sender_keys
    ALTER COLUMN envelope_commitment SET NOT NULL;

ALTER TABLE sender_keys
    DROP CONSTRAINT sender_keys_pkey;

ALTER TABLE sender_keys
    ADD CONSTRAINT sender_keys_pkey PRIMARY KEY
        (conversation_id, owner_device_id, target_device_id, generation);

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'sender_keys_commitment_length'
    ) THEN
        ALTER TABLE sender_keys ADD CONSTRAINT sender_keys_commitment_length
            CHECK (octet_length(envelope_commitment) = 32) NOT VALID;
    END IF;
END $$;

-- A separate durable stream head keeps the monotonic high-water mark even
-- after a future authenticated receipt permits old retained envelopes to be
-- collected.  It also records the only commitment accepted for the current
-- generation, making equal-generation retries immutable.
CREATE TABLE sender_key_heads (
    conversation_id    UUID NOT NULL,
    owner_device_id    UUID NOT NULL,
    target_device_id   UUID NOT NULL,
    max_generation     BIGINT NOT NULL,
    max_commitment     BYTEA NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, owner_device_id, target_device_id),
    CONSTRAINT sender_key_heads_generation_range
        CHECK (max_generation BETWEEN 1 AND 4294967295),
    CONSTRAINT sender_key_heads_commitment_length
        CHECK (octet_length(max_commitment) = 32)
);

-- Seed the stream head from the newest legacy row without rewriting or
-- discarding the retained envelope itself.
INSERT INTO sender_key_heads (
    conversation_id,
    owner_device_id,
    target_device_id,
    max_generation,
    max_commitment
)
SELECT DISTINCT ON (conversation_id, owner_device_id, target_device_id)
       conversation_id,
       owner_device_id,
       target_device_id,
       generation,
       envelope_commitment
FROM sender_keys
WHERE generation BETWEEN 1 AND 4294967295
ORDER BY conversation_id, owner_device_id, target_device_id, generation DESC;

-- NOT VALID keeps the upgrade tolerant of pre-existing orphan rows while new
-- writes are still checked immediately. Operators can clean and VALIDATE old
-- data separately, matching the compatibility policy in migration 009.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sender_key_heads_conversation_fk') THEN
        ALTER TABLE sender_key_heads ADD CONSTRAINT sender_key_heads_conversation_fk
            FOREIGN KEY (conversation_id) REFERENCES conversations (id) ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sender_key_heads_owner_device_fk') THEN
        ALTER TABLE sender_key_heads ADD CONSTRAINT sender_key_heads_owner_device_fk
            FOREIGN KEY (owner_device_id) REFERENCES devices (id) ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sender_key_heads_target_device_fk') THEN
        ALTER TABLE sender_key_heads ADD CONSTRAINT sender_key_heads_target_device_fk
            FOREIGN KEY (target_device_id) REFERENCES devices (id) ON DELETE CASCADE NOT VALID;
    END IF;
END $$;

CREATE INDEX idx_sender_keys_pending_order
    ON sender_keys (target_device_id, conversation_id, owner_device_id, generation);
