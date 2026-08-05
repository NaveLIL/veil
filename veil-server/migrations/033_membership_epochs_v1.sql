-- Client-authorized, predecessor-linked membership epochs for encrypted
-- group/channel conversations. Existing conversations remain on their
-- historical crypto era until an explicit epoch-1 ceremony creates a head.

CREATE TABLE conversation_membership_epochs_v1 (
    conversation_id     UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    epoch_number        BIGINT NOT NULL,
    canonical_origin    TEXT NOT NULL,
    conversation_kind   SMALLINT NOT NULL,
    predecessor_hash    BYTEA NOT NULL,
    roster_version      BIGINT NOT NULL,
    roster_commitment   BYTEA NOT NULL,
    policy_threshold    INTEGER NOT NULL,
    policy_signer_count INTEGER NOT NULL,
    crypto_profile      SMALLINT NOT NULL,
    crypto_era          INTEGER NOT NULL,
    mutation_nonce      BYTEA NOT NULL,
    epoch_hash          BYTEA NOT NULL,
    canonical_unsigned  BYTEA NOT NULL,
    bootstrap_owner_id  UUID,
    bootstrap_owner_signing_key BYTEA,
    submitted_by        UUID NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, epoch_number),
    UNIQUE (conversation_id, epoch_hash),
    UNIQUE (conversation_id, mutation_nonce),
    UNIQUE (conversation_id, epoch_number, epoch_hash),
    CONSTRAINT membership_epoch_number_range
        CHECK (epoch_number BETWEEN 1 AND 9223372036854775807),
    CONSTRAINT membership_epoch_origin_bounds
        CHECK (octet_length(canonical_origin) BETWEEN 1 AND 2048),
    CONSTRAINT membership_epoch_kind
        CHECK (conversation_kind IN (1, 2)),
    CONSTRAINT membership_epoch_predecessor_shape
        CHECK (octet_length(predecessor_hash) = 32),
    CONSTRAINT membership_epoch_roster_version_range
        CHECK (roster_version BETWEEN 1 AND 9223372036854775807),
    CONSTRAINT membership_epoch_roster_commitment_shape
        CHECK (octet_length(roster_commitment) = 32),
    CONSTRAINT membership_epoch_policy_bounds
        CHECK (policy_signer_count BETWEEN 1 AND 1024
           AND policy_threshold BETWEEN 1 AND policy_signer_count),
    CONSTRAINT membership_epoch_profile_v1
        CHECK (crypto_profile = 1 AND crypto_era = 1),
    CONSTRAINT membership_epoch_nonce_shape
        CHECK (octet_length(mutation_nonce) = 32),
    CONSTRAINT membership_epoch_hash_shape
        CHECK (octet_length(epoch_hash) = 32),
    CONSTRAINT membership_epoch_canonical_bounds
        CHECK (octet_length(canonical_unsigned) BETWEEN 1 AND 65536),
    CONSTRAINT membership_epoch_bootstrap_owner_shape
        CHECK (
            (epoch_number = 1
             AND bootstrap_owner_id IS NOT NULL
             AND octet_length(bootstrap_owner_signing_key) = 32)
            OR
            (epoch_number > 1
             AND bootstrap_owner_id IS NULL
             AND bootstrap_owner_signing_key IS NULL)
        )
);

CREATE TABLE conversation_membership_policy_signers_v1 (
    conversation_id     UUID NOT NULL,
    epoch_number        BIGINT NOT NULL,
    signer_index        INTEGER NOT NULL,
    account_id          UUID NOT NULL,
    account_signing_key BYTEA NOT NULL,
    PRIMARY KEY (conversation_id, epoch_number, signer_index),
    UNIQUE (conversation_id, epoch_number, account_id),
    UNIQUE (conversation_id, epoch_number, account_signing_key),
    FOREIGN KEY (conversation_id, epoch_number)
        REFERENCES conversation_membership_epochs_v1(conversation_id, epoch_number)
        ON DELETE CASCADE,
    CONSTRAINT membership_policy_signer_index_range
        CHECK (signer_index BETWEEN 0 AND 1023),
    CONSTRAINT membership_policy_signing_key_shape
        CHECK (octet_length(account_signing_key) = 32)
);

CREATE TABLE conversation_membership_signatures_v1 (
    conversation_id  UUID NOT NULL,
    epoch_number     BIGINT NOT NULL,
    signature_index INTEGER NOT NULL,
    signer_account_id UUID NOT NULL,
    signature        BYTEA NOT NULL,
    PRIMARY KEY (conversation_id, epoch_number, signature_index),
    UNIQUE (conversation_id, epoch_number, signer_account_id),
    FOREIGN KEY (conversation_id, epoch_number)
        REFERENCES conversation_membership_epochs_v1(conversation_id, epoch_number)
        ON DELETE CASCADE,
    CONSTRAINT membership_signature_index_range
        CHECK (signature_index BETWEEN 0 AND 1023),
    CONSTRAINT membership_signature_shape
        CHECK (octet_length(signature) = 64)
);

CREATE TABLE conversation_membership_epoch_heads_v1 (
    conversation_id   UUID PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    epoch_number      BIGINT NOT NULL,
    epoch_hash        BYTEA NOT NULL,
    roster_version    BIGINT NOT NULL,
    roster_commitment BYTEA NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (conversation_id, epoch_number, epoch_hash)
        REFERENCES conversation_membership_epochs_v1(conversation_id, epoch_number, epoch_hash),
    CONSTRAINT membership_head_epoch_range
        CHECK (epoch_number BETWEEN 1 AND 9223372036854775807),
    CONSTRAINT membership_head_hash_shape
        CHECK (octet_length(epoch_hash) = 32),
    CONSTRAINT membership_head_roster_version_range
        CHECK (roster_version BETWEEN 1 AND 9223372036854775807),
    CONSTRAINT membership_head_roster_commitment_shape
        CHECK (octet_length(roster_commitment) = 32)
);

CREATE INDEX conversation_membership_epochs_roster_v1
    ON conversation_membership_epochs_v1(conversation_id, roster_version);

CREATE OR REPLACE FUNCTION veil_reject_membership_epoch_history_mutation_v1()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND NOT EXISTS (
        SELECT 1 FROM public.conversations
         WHERE id = OLD.conversation_id
    ) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'membership epoch history is immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER membership_epochs_immutable_v1
BEFORE UPDATE OR DELETE ON conversation_membership_epochs_v1
FOR EACH ROW EXECUTE FUNCTION veil_reject_membership_epoch_history_mutation_v1();

CREATE TRIGGER membership_policy_signers_immutable_v1
BEFORE UPDATE OR DELETE ON conversation_membership_policy_signers_v1
FOR EACH ROW EXECUTE FUNCTION veil_reject_membership_epoch_history_mutation_v1();

CREATE TRIGGER membership_signatures_immutable_v1
BEFORE UPDATE OR DELETE ON conversation_membership_signatures_v1
FOR EACH ROW EXECUTE FUNCTION veil_reject_membership_epoch_history_mutation_v1();

CREATE OR REPLACE FUNCTION veil_validate_membership_epoch_children_v1()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    expected_policy_count INTEGER;
    actual_policy_count INTEGER;
    minimum_policy_index INTEGER;
    maximum_policy_index INTEGER;
    actual_signature_count INTEGER;
    minimum_signature_index INTEGER;
    maximum_signature_index INTEGER;
    target_conversation UUID;
    target_epoch BIGINT;
BEGIN
    target_conversation := NEW.conversation_id;
    target_epoch := NEW.epoch_number;
    SELECT policy_signer_count
      INTO expected_policy_count
      FROM public.conversation_membership_epochs_v1
     WHERE conversation_id = target_conversation
       AND epoch_number = target_epoch;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT count(*), min(signer_index), max(signer_index)
      INTO actual_policy_count, minimum_policy_index, maximum_policy_index
      FROM public.conversation_membership_policy_signers_v1
     WHERE conversation_id = target_conversation
       AND epoch_number = target_epoch;
    SELECT count(*), min(signature_index), max(signature_index)
      INTO actual_signature_count, minimum_signature_index, maximum_signature_index
      FROM public.conversation_membership_signatures_v1
     WHERE conversation_id = target_conversation
       AND epoch_number = target_epoch;
    IF actual_policy_count <> expected_policy_count
       OR minimum_policy_index <> 0
       OR maximum_policy_index <> expected_policy_count - 1
       OR actual_signature_count < 1
       OR actual_signature_count > 1024
       OR minimum_signature_index <> 0
       OR maximum_signature_index <> actual_signature_count - 1 THEN
        RAISE EXCEPTION 'membership epoch child rows are incomplete'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER membership_epoch_children_complete_v1
AFTER INSERT ON conversation_membership_epochs_v1
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION veil_validate_membership_epoch_children_v1();

CREATE CONSTRAINT TRIGGER membership_policy_children_complete_v1
AFTER INSERT ON conversation_membership_policy_signers_v1
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION veil_validate_membership_epoch_children_v1();

CREATE CONSTRAINT TRIGGER membership_signature_children_complete_v1
AFTER INSERT ON conversation_membership_signatures_v1
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION veil_validate_membership_epoch_children_v1();

CREATE OR REPLACE FUNCTION veil_validate_membership_epoch_head_advance_v1()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND NOT EXISTS (
        SELECT 1 FROM public.conversations
         WHERE id = OLD.conversation_id
    ) THEN
        RETURN OLD;
    END IF;
    IF TG_OP = 'DELETE' OR NEW.conversation_id <> OLD.conversation_id
       OR NEW.epoch_number <> OLD.epoch_number + 1 THEN
        RAISE EXCEPTION 'membership epoch head must advance by exactly one'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER membership_epoch_head_linear_v1
BEFORE UPDATE OR DELETE ON conversation_membership_epoch_heads_v1
FOR EACH ROW EXECUTE FUNCTION veil_validate_membership_epoch_head_advance_v1();
