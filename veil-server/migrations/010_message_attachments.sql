-- Bind encrypted tus blobs to the message/conversation that authorizes their
-- recipients. This table is server-visible metadata only; file bytes and
-- wrapped content keys remain opaque.
CREATE TABLE IF NOT EXISTS message_attachments (
    message_id     UUID      NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    file_id        TEXT      NOT NULL REFERENCES tus_uploads(file_id) ON DELETE CASCADE,
    position       SMALLINT  NOT NULL CHECK (position BETWEEN 0 AND 31),
    encrypted_key  BYTEA     NOT NULL CHECK (octet_length(encrypted_key) BETWEEN 1 AND 4096),
    nonce          BYTEA     NOT NULL CHECK (octet_length(nonce) BETWEEN 1 AND 64),
    size_bytes     BIGINT    NOT NULL CHECK (size_bytes >= 0),
    content_type   TEXT      NOT NULL CHECK (content_type = 'application/octet-stream'),
    PRIMARY KEY (message_id, position),
    UNIQUE (message_id, file_id)
);

CREATE INDEX IF NOT EXISTS idx_message_attachments_file
    ON message_attachments(file_id, message_id);
