-- Defense in depth for client-authorized membership history.
--
-- The gateway already verifies canonical encodings and Ed25519 signatures.
-- These constraints make the durable topology fail closed as well: a direct
-- SQL writer cannot fork the predecessor chain, publish a head with different
-- roster coordinates, or insert a legacy Sender-Key distribution after a
-- conversation has activated membership epochs.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM conversation_membership_epochs_v1 AS epoch
          JOIN conversations AS conversation ON conversation.id = epoch.conversation_id
          LEFT JOIN conversation_membership_epochs_v1 AS predecessor
            ON predecessor.conversation_id = epoch.conversation_id
           AND predecessor.epoch_number = epoch.epoch_number - 1
         WHERE epoch.conversation_kind <> conversation.conv_type
            OR (
                epoch.epoch_number = 1
                AND epoch.predecessor_hash <> decode(repeat('00', 32), 'hex')
            )
            OR (
                epoch.epoch_number > 1
                AND (
                    predecessor.epoch_number IS NULL
                    OR epoch.predecessor_hash <> predecessor.epoch_hash
                    OR epoch.canonical_origin <> predecessor.canonical_origin
                    OR epoch.conversation_kind <> predecessor.conversation_kind
                    OR epoch.roster_version < predecessor.roster_version
                    OR (
                        epoch.roster_version = predecessor.roster_version
                        AND epoch.roster_commitment <> predecessor.roster_commitment
                    )
                )
            )
    ) THEN
        RAISE EXCEPTION 'membership epoch topology preflight failed'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM conversation_membership_epoch_heads_v1 AS head
          JOIN conversation_membership_epochs_v1 AS epoch
            ON epoch.conversation_id = head.conversation_id
           AND epoch.epoch_number = head.epoch_number
           AND epoch.epoch_hash = head.epoch_hash
         WHERE head.roster_version <> epoch.roster_version
            OR head.roster_commitment <> epoch.roster_commitment
    ) THEN
        RAISE EXCEPTION 'membership epoch head coordinates preflight failed'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

ALTER TABLE conversation_membership_epochs_v1
    ADD CONSTRAINT membership_epoch_exact_head_coordinates_v1
    UNIQUE (
        conversation_id,
        epoch_number,
        epoch_hash,
        roster_version,
        roster_commitment
    );

ALTER TABLE conversation_membership_epoch_heads_v1
    ADD CONSTRAINT membership_epoch_head_exact_coordinates_v1
    FOREIGN KEY (
        conversation_id,
        epoch_number,
        epoch_hash,
        roster_version,
        roster_commitment
    )
    REFERENCES conversation_membership_epochs_v1 (
        conversation_id,
        epoch_number,
        epoch_hash,
        roster_version,
        roster_commitment
    );

CREATE OR REPLACE FUNCTION veil_validate_membership_epoch_topology_v1()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    stored_conversation_kind SMALLINT;
    current_head_epoch BIGINT;
    current_head_hash BYTEA;
    predecessor_origin TEXT;
    predecessor_kind SMALLINT;
    predecessor_roster_version BIGINT;
    predecessor_roster_commitment BYTEA;
BEGIN
    SELECT conv_type
      INTO STRICT stored_conversation_kind
      FROM public.conversations
     WHERE id = NEW.conversation_id;

    IF stored_conversation_kind NOT IN (1, 2)
       OR NEW.conversation_kind <> stored_conversation_kind THEN
        RAISE EXCEPTION 'membership epoch conversation kind is invalid'
            USING ERRCODE = '23514';
    END IF;

    SELECT epoch_number, epoch_hash
      INTO current_head_epoch, current_head_hash
      FROM public.conversation_membership_epoch_heads_v1
     WHERE conversation_id = NEW.conversation_id
     FOR UPDATE;

    IF NEW.epoch_number = 1 THEN
        IF NEW.predecessor_hash <> decode(repeat('00', 32), 'hex')
           OR current_head_epoch IS NOT NULL
           OR EXISTS (
               SELECT 1
                 FROM public.conversation_membership_epochs_v1
                WHERE conversation_id = NEW.conversation_id
           ) THEN
            RAISE EXCEPTION 'membership epoch bootstrap topology is invalid'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF current_head_epoch IS NULL
       OR current_head_epoch <> NEW.epoch_number - 1
       OR current_head_hash <> NEW.predecessor_hash THEN
        RAISE EXCEPTION 'membership epoch does not extend the current head'
            USING ERRCODE = '23514';
    END IF;

    SELECT canonical_origin, conversation_kind, roster_version, roster_commitment
      INTO STRICT predecessor_origin, predecessor_kind,
                  predecessor_roster_version, predecessor_roster_commitment
      FROM public.conversation_membership_epochs_v1
     WHERE conversation_id = NEW.conversation_id
       AND epoch_number = NEW.epoch_number - 1
       AND epoch_hash = NEW.predecessor_hash;

    IF NEW.canonical_origin <> predecessor_origin
       OR NEW.conversation_kind <> predecessor_kind
       OR NEW.roster_version < predecessor_roster_version
       OR (
           NEW.roster_version = predecessor_roster_version
           AND NEW.roster_commitment <> predecessor_roster_commitment
       ) THEN
        RAISE EXCEPTION 'membership epoch predecessor coordinates are invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER membership_epoch_topology_v1
BEFORE INSERT ON conversation_membership_epochs_v1
FOR EACH ROW EXECUTE FUNCTION veil_validate_membership_epoch_topology_v1();

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
    IF TG_OP = 'INSERT' THEN
        IF NEW.epoch_number <> 1 THEN
            RAISE EXCEPTION 'membership epoch head must start at one'
                USING ERRCODE = '55000';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' OR NEW.conversation_id <> OLD.conversation_id
       OR NEW.epoch_number <> OLD.epoch_number + 1 THEN
        RAISE EXCEPTION 'membership epoch head must advance by exactly one'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER membership_epoch_head_linear_v1
    ON conversation_membership_epoch_heads_v1;
CREATE TRIGGER membership_epoch_head_linear_v1
BEFORE INSERT OR UPDATE OR DELETE ON conversation_membership_epoch_heads_v1
FOR EACH ROW EXECUTE FUNCTION veil_validate_membership_epoch_head_advance_v1();

CREATE OR REPLACE FUNCTION veil_validate_sender_key_membership_context_v1()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    active_epoch BIGINT;
    active_hash BYTEA;
BEGIN
    SELECT epoch_number, epoch_hash
      INTO active_epoch, active_hash
      FROM public.conversation_membership_epoch_heads_v1
     WHERE conversation_id = NEW.conversation_id;

    IF active_epoch IS NULL THEN
        IF NEW.membership_epoch IS NOT NULL
           OR NEW.membership_epoch_hash IS NOT NULL THEN
            RAISE EXCEPTION 'legacy Sender-Key distribution cannot claim a membership epoch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.membership_epoch IS DISTINCT FROM active_epoch
       OR NEW.membership_epoch_hash IS DISTINCT FROM active_hash THEN
        RAISE EXCEPTION 'Sender-Key distribution requires the exact active membership epoch'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sender_keys_exact_membership_epoch_v1
BEFORE INSERT OR UPDATE OF conversation_id, membership_epoch, membership_epoch_hash
ON sender_keys
FOR EACH ROW EXECUTE FUNCTION veil_validate_sender_key_membership_context_v1();
