-- Durable, account-scoped outcome tombstones for exact SendMessage replay.
--
-- message_id deliberately has no foreign key to messages: an acknowledged
-- outcome must survive TTL cleanup or deletion of the message row. The server
-- writes the tombstone and its explicit message row in one transaction, so a
-- committed tombstone can never be an orphan created by the send path.
CREATE TABLE message_send_idempotency (
    sender_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_message_id  UUID NOT NULL,
    request_digest     BYTEA NOT NULL
        CONSTRAINT message_send_idempotency_digest_length
        CHECK (octet_length(request_digest) = 32),
    message_id         UUID NOT NULL,
    server_timestamp   TIMESTAMPTZ NOT NULL,
    ack_roster_version BIGINT
        CONSTRAINT message_send_idempotency_roster_version
        CHECK (ack_roster_version > 0),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (sender_id, client_message_id),
    CONSTRAINT message_send_idempotency_message_id_unique UNIQUE (message_id)
);

