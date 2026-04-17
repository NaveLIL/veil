-- Friends & friend requests
-- Version 4

CREATE TABLE friend_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message         TEXT,
    status          SMALLINT NOT NULL DEFAULT 0,  -- 0=pending, 1=accepted, 2=rejected
    created_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE (from_user_id, to_user_id)
);

CREATE INDEX idx_friend_requests_to   ON friend_requests(to_user_id, status);
CREATE INDEX idx_friend_requests_from ON friend_requests(from_user_id, status);

CREATE TABLE friendships (
    user_id_1       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_id_2       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (user_id_1, user_id_2),
    CHECK (user_id_1 < user_id_2)  -- canonical ordering to prevent duplicates
);

CREATE INDEX idx_friendships_user1 ON friendships(user_id_1);
CREATE INDEX idx_friendships_user2 ON friendships(user_id_2);
