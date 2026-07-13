-- Relationship-scoped ProfileUpdated fanout needs reverse membership lookups
-- by account. The existing primary keys start with conversation/server ID and
-- cannot efficiently serve these predicates on larger instances.

CREATE INDEX IF NOT EXISTS idx_conversation_members_user_conversation
    ON conversation_members (user_id, conversation_id);

CREATE INDEX IF NOT EXISTS idx_server_members_user_server
    ON server_members (user_id, server_id);
