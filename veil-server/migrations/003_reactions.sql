-- Message reactions
CREATE TABLE IF NOT EXISTS reactions (
    message_id      UUID NOT NULL,
    conversation_id UUID NOT NULL,
    user_id         UUID NOT NULL,
    emoji           TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (message_id, user_id, emoji)
);

CREATE INDEX idx_reactions_message ON reactions (message_id);
