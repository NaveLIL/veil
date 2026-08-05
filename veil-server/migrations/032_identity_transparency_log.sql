-- Staged storage for the append-only per-origin identity transparency log.
-- No existing identity is retroactively claimed as transparent. Activation
-- performs an explicit audited bootstrap ceremony before live writes use it.

CREATE TABLE identity_transparency_log_state (
    singleton               BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    log_id                  BYTEA NOT NULL CHECK (
        octet_length(log_id) = 32
        AND log_id <> decode(repeat('00', 32), 'hex')
    ),
    node_signing_key        BYTEA NOT NULL CHECK (
        octet_length(node_signing_key) = 32
        AND node_signing_key <> decode(repeat('00', 32), 'hex')
    ),
    tree_size               BIGINT NOT NULL CHECK (tree_size BETWEEN 0 AND 9223372036854775807),
    root_hash               BYTEA NOT NULL CHECK (
        octet_length(root_hash) = 32
        AND root_hash <> decode(repeat('00', 32), 'hex')
    ),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE identity_transparency_log_leaves (
    leaf_index              BIGINT PRIMARY KEY CHECK (leaf_index BETWEEN 0 AND 9223372036854775806),
    event_kind              SMALLINT NOT NULL CHECK (event_kind BETWEEN 1 AND 4),
    subject_user_id         UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    subject_device_id       UUID REFERENCES devices(id) ON DELETE RESTRICT,
    binding_version         BIGINT CHECK (binding_version BETWEEN 1 AND 9223372036854775807),
    canonical_event         BYTEA NOT NULL CHECK (octet_length(canonical_event) BETWEEN 1 AND 4096),
    leaf_hash               BYTEA NOT NULL CHECK (
        octet_length(leaf_hash) = 32
        AND leaf_hash <> decode(repeat('00', 32), 'hex')
    ),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT identity_transparency_device_binding_fk
        FOREIGN KEY (subject_device_id, binding_version)
        REFERENCES device_binding_versions (device_id, binding_version)
        ON DELETE RESTRICT,
    CONSTRAINT identity_transparency_event_shape CHECK (
        (event_kind = 1 AND subject_device_id IS NULL AND binding_version IS NULL)
        OR
        (event_kind = 2 AND subject_device_id IS NOT NULL AND binding_version IS NOT NULL)
        OR
        (event_kind IN (3, 4) AND subject_device_id IS NULL)
    )
);

CREATE UNIQUE INDEX identity_transparency_one_account_registration
    ON identity_transparency_log_leaves (subject_user_id)
    WHERE event_kind = 1;

CREATE UNIQUE INDEX identity_transparency_one_device_binding_version
    ON identity_transparency_log_leaves (subject_device_id, binding_version)
    WHERE event_kind = 2;

-- Perfect subtree nodes. Level zero stores leaf hashes; a node at level L and
-- index I covers [I*2^L, (I+1)*2^L). Keeping every completed node permits
-- logarithmic inclusion and consistency proof generation without reading the
-- complete event history.
CREATE TABLE identity_transparency_log_nodes (
    node_level              SMALLINT NOT NULL CHECK (node_level BETWEEN 0 AND 62),
    node_index              BIGINT NOT NULL CHECK (node_index BETWEEN 0 AND 9223372036854775806),
    node_hash               BYTEA NOT NULL CHECK (
        octet_length(node_hash) = 32
        AND node_hash <> decode(repeat('00', 32), 'hex')
    ),
    PRIMARY KEY (node_level, node_index)
);

CREATE OR REPLACE FUNCTION veil_reject_transparency_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'identity transparency history is append-only'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER identity_transparency_leaves_no_update_delete
BEFORE UPDATE OR DELETE ON identity_transparency_log_leaves
FOR EACH ROW EXECUTE FUNCTION veil_reject_transparency_history_mutation();

CREATE TRIGGER identity_transparency_nodes_no_update_delete
BEFORE UPDATE OR DELETE ON identity_transparency_log_nodes
FOR EACH ROW EXECUTE FUNCTION veil_reject_transparency_history_mutation();

CREATE OR REPLACE FUNCTION veil_validate_transparency_head_advance()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.singleton IS DISTINCT FROM OLD.singleton
       OR NEW.log_id IS DISTINCT FROM OLD.log_id
       OR NEW.node_signing_key IS DISTINCT FROM OLD.node_signing_key
       OR NEW.tree_size <> OLD.tree_size + 1
       OR NEW.root_hash IS NOT DISTINCT FROM OLD.root_hash THEN
        RAISE EXCEPTION 'identity transparency head transition is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_transparency_state_exact_advance
BEFORE UPDATE ON identity_transparency_log_state
FOR EACH ROW EXECUTE FUNCTION veil_validate_transparency_head_advance();

CREATE OR REPLACE FUNCTION veil_reject_transparency_head_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'identity transparency head cannot be deleted'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER identity_transparency_state_no_delete
BEFORE DELETE ON identity_transparency_log_state
FOR EACH ROW EXECUTE FUNCTION veil_reject_transparency_head_delete();
