-- Phase 4E: pre-release hard cutover from plaintext 48-bit invite codes to
-- bounded Veil Link v1 capabilities, plus authoritative Space bans.

DROP TABLE IF EXISTS server_invites;

-- Voice Rooms have no Phase 7 media runtime yet. Pre-release fixtures must
-- not survive as clickable product affordances that cannot provide a secure
-- call, so 4E keeps only text Rooms and categories.
DELETE FROM channels WHERE channel_type = 1;

-- Space artwork is intentionally local and deterministic in Phase 4E.
-- Remote image loading requires a separate schema/privacy/security review, so
-- the unpublished URL column is removed instead of retained as legacy surface.
ALTER TABLE servers DROP COLUMN icon_url;

CREATE TABLE server_invites (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_selector TEXT NOT NULL UNIQUE,
    secret_hash     BYTEA NOT NULL,
    version         SMALLINT NOT NULL DEFAULT 1,
    link_type       TEXT NOT NULL DEFAULT 'space',
    server_id       UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    created_by      UUID NOT NULL REFERENCES users(id),
    max_uses        INTEGER NOT NULL,
    uses            INTEGER NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT server_invites_selector_v1 CHECK (public_selector ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT server_invites_secret_hash_v1 CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT server_invites_version_v1 CHECK (version = 1),
    CONSTRAINT server_invites_type_v1 CHECK (link_type = 'space'),
    CONSTRAINT server_invites_bounded_uses CHECK (max_uses BETWEEN 1 AND 100),
    CONSTRAINT server_invites_use_counter CHECK (uses BETWEEN 0 AND max_uses),
    CONSTRAINT server_invites_bounded_expiry CHECK (
        expires_at >= created_at + interval '5 minutes'
        AND expires_at <= created_at + interval '7 days'
    )
);
CREATE INDEX idx_veil_links_server_active
    ON server_invites(server_id, created_at DESC) WHERE revoked_at IS NULL;

-- A deliberately narrow lifecycle journal. It cannot contain selectors,
-- secrets, arbitrary JSON, Space descriptions, IP addresses, or user-agent
-- strings. Retention and row count are both bounded per Space.
CREATE TABLE veil_link_events (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id  UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    link_id    UUID,
    actor_id   UUID NOT NULL REFERENCES users(id),
    event_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT veil_link_events_type_v1 CHECK (
        event_type IN ('created', 'joined', 'revoked', 'revoked_all')
    ),
    CONSTRAINT veil_link_events_link_shape_v1 CHECK (
        (event_type = 'revoked_all' AND link_id IS NULL)
        OR (event_type <> 'revoked_all' AND link_id IS NOT NULL)
    )
);
CREATE INDEX idx_veil_link_events_space_time
    ON veil_link_events(server_id, created_at DESC, id DESC);

CREATE FUNCTION bound_veil_link_events_v1() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- Serialize pruning for one Space so concurrent joins cannot exceed the
    -- hard 10,000-row cap. The journal is diagnostic, never authorization.
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.server_id::text, 4389));
    DELETE FROM veil_link_events
     WHERE server_id = NEW.server_id
       AND created_at < now() - interval '90 days';
    DELETE FROM veil_link_events
     WHERE id IN (
        SELECT id FROM veil_link_events
         WHERE server_id = NEW.server_id
         ORDER BY created_at DESC, id DESC
         OFFSET 9999
     );
    RETURN NEW;
END;
$$;
CREATE TRIGGER veil_link_events_bound_v1
BEFORE INSERT ON veil_link_events
FOR EACH ROW EXECUTE FUNCTION bound_veil_link_events_v1();

CREATE TABLE server_bans (
    server_id  UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    banned_by  UUID NOT NULL REFERENCES users(id),
    reason     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, user_id),
    CONSTRAINT server_bans_reason_byte_limit CHECK (
        reason IS NULL OR octet_length(reason) BETWEEN 1 AND 512
    )
);
CREATE INDEX idx_server_bans_user ON server_bans(user_id, server_id);

-- Ordinary members must not mint admission capabilities. Owners and explicitly
-- privileged roles retain PermCreateInvite (bit 8).
UPDATE roles
SET permissions = permissions & ~256::bigint
WHERE is_default = TRUE;
