-- Keep server reaction history within the strict mobile parser's per-message
-- bound. The table lock makes cleanup, pruning, FK validation and trigger
-- installation one write-free cutover for legacy deployments.
LOCK TABLE public.reactions IN SHARE ROW EXCLUSIVE MODE;

-- Migration 009 installed these foreign keys NOT VALID so legacy rows could
-- survive that rollout. Remove only rows that cannot have a valid reaction
-- scope before validating the constraints permanently.
DELETE FROM public.reactions AS reaction
WHERE NOT EXISTS (
        SELECT 1
        FROM public.messages AS message
        WHERE message.id = reaction.message_id
          AND message.conversation_id = reaction.conversation_id
      )
   OR NOT EXISTS (
        SELECT 1
        FROM public.users AS account
        WHERE account.id = reaction.user_id
      );

-- Preserve the oldest 256 rows deterministically. created_at is the product
-- ordering; UUID and C-collated emoji are stable tie-breakers for legacy rows
-- that share a timestamp.
WITH ranked AS (
    SELECT message_id,
           user_id,
           emoji,
           row_number() OVER (
               PARTITION BY message_id
               ORDER BY created_at ASC,
                        user_id ASC,
                        emoji COLLATE "C" ASC
           ) AS reaction_rank
    FROM public.reactions
)
DELETE FROM public.reactions AS reaction
USING ranked
WHERE reaction.message_id = ranked.message_id
  AND reaction.user_id = ranked.user_id
  AND reaction.emoji = ranked.emoji
  AND ranked.reaction_rank > 256;

-- A physical 0..255 slot is the isolation-independent cap invariant. The
-- unique key is checked against concurrent committed rows even when a raw
-- writer uses REPEATABLE READ and its ordinary SELECT snapshot is stale.
ALTER TABLE public.reactions
    ADD COLUMN history_slot SMALLINT;

WITH ranked AS (
    SELECT message_id,
           user_id,
           emoji,
           row_number() OVER (
               PARTITION BY message_id
               ORDER BY created_at ASC,
                        user_id ASC,
                        emoji COLLATE "C" ASC
           ) - 1 AS history_slot
    FROM public.reactions
)
UPDATE public.reactions AS reaction
SET history_slot = ranked.history_slot::SMALLINT
FROM ranked
WHERE reaction.message_id = ranked.message_id
  AND reaction.user_id = ranked.user_id
  AND reaction.emoji = ranked.emoji;

ALTER TABLE public.reactions
    ALTER COLUMN history_slot SET NOT NULL,
    ADD CONSTRAINT reactions_history_slot_range
        CHECK (history_slot BETWEEN 0 AND 255),
    ADD CONSTRAINT reactions_message_history_slot_unique
        UNIQUE (message_id, history_slot);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conrelid = 'public.reactions'::regclass
          AND conname = 'reactions_message_conversation_fk'
    ) THEN
        ALTER TABLE public.reactions
            ADD CONSTRAINT reactions_message_conversation_fk
            FOREIGN KEY (message_id, conversation_id)
            REFERENCES public.messages (id, conversation_id)
            ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conrelid = 'public.reactions'::regclass
          AND conname = 'reactions_user_fk'
    ) THEN
        ALTER TABLE public.reactions
            ADD CONSTRAINT reactions_user_fk
            FOREIGN KEY (user_id)
            REFERENCES public.users (id)
            ON DELETE CASCADE NOT VALID;
    END IF;
END;
$$;

ALTER TABLE public.reactions
    VALIDATE CONSTRAINT reactions_message_conversation_fk;
ALTER TABLE public.reactions
    VALIDATE CONSTRAINT reactions_user_fk;

-- Application writers take the same transaction-level advisory lock. This
-- trigger is the invariant backstop for SQL tools and future code paths. An
-- exact existing reaction remains an idempotent no-op even at the limit.
CREATE OR REPLACE FUNCTION public.veil_enforce_reaction_history_bound()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    available_slot SMALLINT;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(NEW.message_id::text, 73)
    );

    IF EXISTS (
        SELECT 1
        FROM public.reactions AS existing
        WHERE existing.message_id = NEW.message_id
          AND existing.conversation_id = NEW.conversation_id
          AND existing.user_id = NEW.user_id
          AND existing.emoji = NEW.emoji
    ) THEN
        RETURN NULL;
    END IF;

    -- Ignore any caller-supplied slot. Under READ COMMITTED the advisory lock
    -- makes this the true lowest free slot. Under an older snapshot, choosing
    -- a newly occupied slot fails closed on the physical unique constraint.
    SELECT candidate.slot::SMALLINT
    INTO available_slot
    FROM pg_catalog.generate_series(0, 255) AS candidate(slot)
    WHERE NOT EXISTS (
        SELECT 1
        FROM public.reactions AS occupied
        WHERE occupied.message_id = NEW.message_id
          AND occupied.history_slot = candidate.slot
    )
    ORDER BY candidate.slot
    LIMIT 1;

    IF available_slot IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'reactions_per_message_limit',
            MESSAGE = 'message reaction limit reached';
    END IF;
    NEW.history_slot := available_slot;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS reactions_enforce_history_bound ON public.reactions;
CREATE TRIGGER reactions_enforce_history_bound
BEFORE INSERT ON public.reactions
FOR EACH ROW
EXECUTE FUNCTION public.veil_enforce_reaction_history_bound();

-- Reaction identity changes are modeled as an authorized remove plus add.
-- Making the identity columns immutable prevents a raw UPDATE from moving a
-- row into a message that is already at the admission bound.
CREATE OR REPLACE FUNCTION public.veil_reject_reaction_identity_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF OLD.message_id IS DISTINCT FROM NEW.message_id
       OR OLD.conversation_id IS DISTINCT FROM NEW.conversation_id
       OR OLD.user_id IS DISTINCT FROM NEW.user_id
       OR OLD.emoji IS DISTINCT FROM NEW.emoji
       OR OLD.history_slot IS DISTINCT FROM NEW.history_slot THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'reactions_identity_immutable',
            MESSAGE = 'reaction identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS reactions_reject_identity_update ON public.reactions;
CREATE TRIGGER reactions_reject_identity_update
BEFORE UPDATE OF message_id, conversation_id, user_id, emoji, history_slot
ON public.reactions
FOR EACH ROW
EXECUTE FUNCTION public.veil_reject_reaction_identity_update();
