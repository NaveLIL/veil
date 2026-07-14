-- Canonical account/device keys and signed binding history are protocol
-- identity, not mutable profile metadata.  The current protocol has no
-- account-key rotation ceremony and no old-account proof chain, so an UPDATE
-- would make retained Sender-Key distributions unverifiable.  Rotation of a
-- device binding remains append-only: insert the next version and advance the
-- head; never rewrite a historical version.

CREATE OR REPLACE FUNCTION public.veil_reject_account_identity_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.identity_key IS DISTINCT FROM OLD.identity_key
       OR NEW.signing_key IS DISTINCT FROM OLD.signing_key THEN
        RAISE EXCEPTION USING
            ERRCODE = 'check_violation',
            MESSAGE = 'account cryptographic identity is immutable; use a versioned rotation protocol';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS users_reject_identity_update ON public.users;
CREATE TRIGGER users_reject_identity_update
BEFORE UPDATE OF identity_key, signing_key ON public.users
FOR EACH ROW EXECUTE FUNCTION public.veil_reject_account_identity_update();

CREATE OR REPLACE FUNCTION public.veil_reject_device_route_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.device_key IS DISTINCT FROM OLD.device_key THEN
        RAISE EXCEPTION USING
            ERRCODE = 'check_violation',
            MESSAGE = 'device ownership and protocol identifier are immutable; register a new device';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS devices_reject_route_update ON public.devices;
CREATE TRIGGER devices_reject_route_update
BEFORE UPDATE OF user_id, device_key ON public.devices
FOR EACH ROW EXECUTE FUNCTION public.veil_reject_device_route_update();

CREATE OR REPLACE FUNCTION public.veil_reject_device_crypto_key_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.device_identity_key IS DISTINCT FROM OLD.device_identity_key
       OR NEW.device_signing_key IS DISTINCT FROM OLD.device_signing_key THEN
        RAISE EXCEPTION USING
            ERRCODE = 'check_violation',
            MESSAGE = 'device cryptographic keys are immutable; register a new device';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS device_crypto_keys_reject_key_update ON public.device_crypto_keys;
CREATE TRIGGER device_crypto_keys_reject_key_update
BEFORE UPDATE OF device_identity_key, device_signing_key ON public.device_crypto_keys
FOR EACH ROW EXECUTE FUNCTION public.veil_reject_device_crypto_key_update();

CREATE OR REPLACE FUNCTION public.veil_reject_device_binding_version_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION USING
            ERRCODE = 'check_violation',
            MESSAGE = 'device binding history is append-only; insert a new binding version';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS device_binding_versions_reject_update ON public.device_binding_versions;
CREATE TRIGGER device_binding_versions_reject_update
BEFORE UPDATE ON public.device_binding_versions
FOR EACH ROW EXECUTE FUNCTION public.veil_reject_device_binding_version_update();

-- A no-op UPDATE remains legal, and must not dirty every conversation roster.
-- Real identity/history changes are rejected by the BEFORE triggers above.
CREATE OR REPLACE FUNCTION public.veil_dirty_roster_for_user_identity()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.identity_key IS NOT DISTINCT FROM OLD.identity_key
       AND NEW.signing_key IS NOT DISTINCT FROM OLD.signing_key THEN
        RETURN NEW;
    END IF;
    PERFORM public.veil_dirty_rosters_for_users(ARRAY[OLD.id, NEW.id]);
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.veil_dirty_roster_for_device()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM public.veil_dirty_rosters_for_users(ARRAY[NEW.user_id]);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM public.veil_dirty_rosters_for_users(ARRAY[OLD.user_id]);
        RETURN OLD;
    ELSIF NEW.user_id IS NOT DISTINCT FROM OLD.user_id
          AND NEW.device_key IS NOT DISTINCT FROM OLD.device_key THEN
        RETURN NEW;
    END IF;
    PERFORM public.veil_dirty_rosters_for_users(ARRAY[OLD.user_id, NEW.user_id]);
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.veil_dirty_roster_for_device_crypto_state()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    owner_ids UUID[];
BEGIN
    IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    SELECT COALESCE(array_agg(DISTINCT device.user_id ORDER BY device.user_id), ARRAY[]::UUID[])
    INTO owner_ids
    FROM public.devices AS device
    WHERE device.id = ANY(ARRAY[
        CASE WHEN TG_OP <> 'INSERT' THEN OLD.device_id ELSE NULL END,
        CASE WHEN TG_OP <> 'DELETE' THEN NEW.device_id ELSE NULL END
    ]);
    PERFORM public.veil_dirty_rosters_for_users(owner_ids);
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

-- Retained rows must point to the exact immutable binding versions that
-- authenticated their owner and target.  Give an operator-readable preflight
-- failure before adding the structural constraints.
DO $$
DECLARE
    missing_count BIGINT;
BEGIN
    SELECT COUNT(*)
    INTO missing_count
    FROM public.sender_keys AS sender_key
    LEFT JOIN public.device_binding_versions AS owner_binding
      ON owner_binding.device_id = sender_key.owner_device_id
     AND owner_binding.binding_version = sender_key.owner_binding_version
    LEFT JOIN public.device_binding_versions AS target_binding
      ON target_binding.device_id = sender_key.target_device_id
     AND target_binding.binding_version = sender_key.target_binding_version
    WHERE owner_binding.device_id IS NULL
       OR target_binding.device_id IS NULL;

    IF missing_count <> 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'check_violation',
            MESSAGE = format(
                'sender-key binding-history migration blocked: %s retained rows reference missing binding versions',
                missing_count
            ),
            HINT = 'Back up and audit the affected retained rows; restore the exact signed binding history or explicitly discard those rows before retrying.';
    END IF;
END;
$$;

ALTER TABLE public.sender_keys
    ADD CONSTRAINT sender_keys_owner_binding_version_fk
    FOREIGN KEY (owner_device_id, owner_binding_version)
    REFERENCES public.device_binding_versions (device_id, binding_version)
    ON DELETE NO ACTION
    DEFERRABLE INITIALLY DEFERRED
    NOT VALID;

ALTER TABLE public.sender_keys
    ADD CONSTRAINT sender_keys_target_binding_version_fk
    FOREIGN KEY (target_device_id, target_binding_version)
    REFERENCES public.device_binding_versions (device_id, binding_version)
    ON DELETE NO ACTION
    DEFERRABLE INITIALLY DEFERRED
    NOT VALID;

ALTER TABLE public.sender_keys
    VALIDATE CONSTRAINT sender_keys_owner_binding_version_fk;
ALTER TABLE public.sender_keys
    VALIDATE CONSTRAINT sender_keys_target_binding_version_fk;

-- The existing device/user ON DELETE CASCADE path intentionally remains the
-- explicit hard-delete protocol.  sender_keys are removed by their device FKs
-- in the same transaction before these deferred NO ACTION constraints are
-- checked, so no retained row can outlive its historical account/device.
