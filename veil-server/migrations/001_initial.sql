-- Veil Server Schema — PostgreSQL
-- Version 1

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_key    BYTEA UNIQUE NOT NULL,
    signing_key     BYTEA UNIQUE NOT NULL,
    username        TEXT NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_key      BYTEA UNIQUE NOT NULL,
    device_name     TEXT,
    last_seen       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_devices_user ON devices(user_id);

CREATE TABLE conversations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conv_type       SMALLINT NOT NULL,  -- 0=DM, 1=GROUP, 2=CHANNEL
    server_id       UUID,
    name            TEXT,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE conversation_members (
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            SMALLINT DEFAULT 0,  -- 0=member, 1=admin, 2=owner
    joined_at       TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (conversation_id, user_id)
);

CREATE TABLE messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations(id),
    sender_id       UUID NOT NULL REFERENCES users(id),
    ciphertext      BYTEA NOT NULL,
    header          BYTEA,
    msg_type        SMALLINT DEFAULT 0,
    reply_to_id     UUID,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_messages_conv ON messages(conversation_id, created_at);
CREATE INDEX idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE prekeys (
    id              BIGSERIAL PRIMARY KEY,
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_type        SMALLINT NOT NULL, -- 0=signed, 1=one-time
    public_key      BYTEA NOT NULL,
    signature       BYTEA,
    used            BOOLEAN DEFAULT false
);

CREATE INDEX idx_prekeys_device ON prekeys(device_id, key_type, used);

CREATE TABLE servers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    icon_url        TEXT,
    owner_id        UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE server_members (
    server_id       UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at       TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (server_id, user_id)
);

CREATE TABLE roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    permissions     BIGINT DEFAULT 0,
    position        SMALLINT DEFAULT 0,
    color           INTEGER
);

CREATE TABLE channels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    conversation_id UUID UNIQUE REFERENCES conversations(id),
    name            TEXT NOT NULL,
    channel_type    SMALLINT DEFAULT 0, -- 0=text, 1=voice, 2=category
    category_id     UUID,
    position        SMALLINT DEFAULT 0,
    topic           TEXT
);

CREATE INDEX idx_channels_server ON channels(server_id);

CREATE TABLE sender_keys (
    conversation_id UUID NOT NULL,
    owner_device_id UUID NOT NULL,
    target_device_id UUID NOT NULL,
    encrypted_key   BYTEA NOT NULL,
    generation      INTEGER DEFAULT 0,
    PRIMARY KEY (conversation_id, owner_device_id, target_device_id)
);

CREATE TABLE shares (
    id              TEXT PRIMARY KEY,
    ciphertext      BYTEA NOT NULL,
    has_password    BOOLEAN DEFAULT false,
    max_views       INTEGER DEFAULT 1,
    views           INTEGER DEFAULT 0,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_shares_expires ON shares(expires_at);
