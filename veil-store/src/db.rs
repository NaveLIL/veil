use rusqlite::Connection;
use std::path::Path;
use zeroize::Zeroize;

/// Encrypted SQLite database using SQLCipher.
pub struct VeilDb {
    conn: Connection,
}

impl VeilDb {
    /// Open (or create) an encrypted database at the given path.
    /// The `key` is a 32-byte encryption key derived from user identity.
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self, String> {
        match Self::open_inner(path, key) {
            Ok(db) => Ok(db),
            Err(e) if path.exists() && e.contains("not a database") => {
                // Stale/unencrypted DB from a previous run — remove and retry.
                let _ = std::fs::remove_file(path);
                // Also remove WAL/SHM journals if present.
                let wal = path.with_extension("db-wal");
                let shm = path.with_extension("db-shm");
                let _ = std::fs::remove_file(wal);
                let _ = std::fs::remove_file(shm);
                Self::open_inner(path, key)
            }
            Err(e) => Err(e),
        }
    }

    fn open_inner(path: &Path, key: &[u8; 32]) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("open db: {e}"))?;

        // Set SQLCipher encryption key
        let mut hex_key = hex::encode(key);
        let res = conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";\n", hex_key));
        hex_key.zeroize();
        res.map_err(|e| format!("set key: {e}"))?;

        // SQLCipher hardening
        conn.execute_batch(
            "PRAGMA cipher_page_size = 4096;
             PRAGMA kdf_iter = 256000;
             PRAGMA cipher_memory_security = ON;",
        )
        .map_err(|e| format!("cipher pragmas: {e}"))?;

        // Performance settings
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(|e| format!("pragmas: {e}"))?;

        let db = Self { conn };
        db.run_migrations()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory(key: &[u8; 32]) -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| format!("open memory db: {e}"))?;

        let mut hex_key = hex::encode(key);
        let res = conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";\n", hex_key));
        hex_key.zeroize();
        res.map_err(|e| format!("set key: {e}"))?;

        conn.execute_batch(
            "PRAGMA cipher_page_size = 4096;
             PRAGMA kdf_iter = 256000;
             PRAGMA cipher_memory_security = ON;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(|e| format!("pragmas: {e}"))?;

        let db = Self { conn };
        db.run_migrations()?;
        Ok(db)
    }

    fn run_migrations(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                conv_type INTEGER NOT NULL,  -- 0=DM, 1=GROUP, 2=CHANNEL
                peer_identity_key BLOB,      -- DM: peer's X25519 public key
                server_id TEXT,
                name TEXT,
                last_message_at TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL REFERENCES conversations(id),
                sender_key BLOB NOT NULL,
                plaintext TEXT,              -- Decrypted on client, stored encrypted by SQLCipher
                msg_type INTEGER DEFAULT 0,
                reply_to_id TEXT,
                is_outgoing INTEGER DEFAULT 0,
                status INTEGER DEFAULT 0,    -- 0=sending, 1=sent, 2=delivered, 3=read
                expires_at TEXT,
                server_timestamp INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_messages_conv
                ON messages(conversation_id, server_timestamp);

            CREATE TABLE IF NOT EXISTS ratchet_sessions (
                peer_identity_key BLOB PRIMARY KEY,
                session_data BLOB NOT NULL,  -- Serialized RatchetSession (encrypted by SQLCipher)
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS contacts (
                identity_key BLOB PRIMARY KEY,
                signing_key BLOB NOT NULL,
                username TEXT NOT NULL,
                verified INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS pending_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT NOT NULL,
                plaintext TEXT NOT NULL,
                msg_type INTEGER DEFAULT 0,
                reply_to_id TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT NOT NULL REFERENCES conversations(id),
                identity_key BLOB NOT NULL,
                role INTEGER NOT NULL DEFAULT 0,  -- 0=member, 1=admin, 2=owner
                joined_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (group_id, identity_key)
            );

            CREATE TABLE IF NOT EXISTS sender_keys_local (
                group_id TEXT NOT NULL,
                sender_identity_key BLOB NOT NULL,
                key_data BLOB NOT NULL,           -- Serialized SenderKeyState
                is_outgoing INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (group_id, sender_identity_key)
            );",
            )
            .map_err(|e| format!("migrations: {e}"))
    }

    /// Get a reference to the underlying connection (for advanced queries).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    // ─── CRUD: Conversations ──────────────────────────────

    pub fn insert_conversation(
        &self,
        id: &str,
        conv_type: u8,
        name: Option<&str>,
        peer_identity_key: Option<&[u8]>,
        server_id: Option<&str>,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO conversations (id, conv_type, name, peer_identity_key, server_id)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![id, conv_type, name, peer_identity_key, server_id],
            )
            .map_err(|e| format!("insert conversation: {e}"))?;
        Ok(())
    }

    pub fn get_conversations(&self) -> Result<Vec<crate::models::Conversation>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, conv_type, peer_identity_key, server_id, name, last_message_at, created_at
                 FROM conversations ORDER BY last_message_at DESC NULLS LAST",
            )
            .map_err(|e| format!("prepare: {e}"))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(crate::models::Conversation {
                    id: row.get(0)?,
                    conv_type: match row.get::<_, u8>(1)? {
                        1 => crate::models::ConversationType::Group,
                        2 => crate::models::ConversationType::Channel,
                        _ => crate::models::ConversationType::DM,
                    },
                    peer_identity_key: row.get(2)?,
                    server_id: row.get(3)?,
                    name: row.get(4)?,
                    last_message_at: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })
            .map_err(|e| format!("query: {e}"))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect: {e}"))
    }

    // ─── CRUD: Messages ───────────────────────────────────

    pub fn insert_message(
        &self,
        id: &str,
        conversation_id: &str,
        sender_key: &[u8],
        plaintext: &str,
        is_outgoing: bool,
        server_timestamp: Option<i64>,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO messages (id, conversation_id, sender_key, plaintext, is_outgoing, status, server_timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    id,
                    conversation_id,
                    sender_key,
                    plaintext,
                    is_outgoing as u8,
                    if is_outgoing { 1u8 } else { 0u8 },
                    server_timestamp,
                ],
            )
            .map_err(|e| format!("insert message: {e}"))?;

        self.conn
            .execute(
                "UPDATE conversations SET last_message_at = datetime('now') WHERE id = ?1",
                rusqlite::params![conversation_id],
            )
            .map_err(|e| format!("update last_message_at: {e}"))?;

        Ok(())
    }

    pub fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
    ) -> Result<Vec<crate::models::Message>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, conversation_id, sender_key, plaintext, msg_type, reply_to_id,
                        is_outgoing, status, expires_at, server_timestamp, created_at
                 FROM messages
                 WHERE conversation_id = ?1
                 ORDER BY server_timestamp ASC, created_at ASC
                 LIMIT ?2",
            )
            .map_err(|e| format!("prepare: {e}"))?;

        let rows = stmt
            .query_map(rusqlite::params![conversation_id, limit], |row| {
                Ok(crate::models::Message {
                    id: row.get(0)?,
                    conversation_id: row.get(1)?,
                    sender_key: row.get(2)?,
                    plaintext: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    msg_type: row.get(4)?,
                    reply_to_id: row.get(5)?,
                    is_outgoing: row.get::<_, u8>(6)? != 0,
                    status: match row.get::<_, u8>(7)? {
                        1 => crate::models::MessageStatus::Sent,
                        2 => crate::models::MessageStatus::Delivered,
                        3 => crate::models::MessageStatus::Read,
                        _ => crate::models::MessageStatus::Sending,
                    },
                    expires_at: row.get(8)?,
                    server_timestamp: row.get(9)?,
                    created_at: row.get(10)?,
                })
            })
            .map_err(|e| format!("query: {e}"))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect: {e}"))
    }

    // ─── CRUD: Ratchet Sessions ───────────────────────────

    pub fn save_ratchet_session(
        &self,
        peer_identity_key: &[u8],
        session_data: &[u8],
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO ratchet_sessions (peer_identity_key, session_data, updated_at)
                 VALUES (?1, ?2, datetime('now'))",
                rusqlite::params![peer_identity_key, session_data],
            )
            .map_err(|e| format!("save ratchet session: {e}"))?;
        Ok(())
    }

    pub fn load_ratchet_session(
        &self,
        peer_identity_key: &[u8],
    ) -> Result<Option<Vec<u8>>, String> {
        match self.conn.query_row(
            "SELECT session_data FROM ratchet_sessions WHERE peer_identity_key = ?1",
            rusqlite::params![peer_identity_key],
            |row| row.get(0),
        ) {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("load ratchet session: {e}")),
        }
    }

    // ─── CRUD: Group Members ──────────────────────────────

    pub fn insert_group_member(
        &self,
        group_id: &str,
        identity_key: &[u8],
        role: u8,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO group_members (group_id, identity_key, role)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![group_id, identity_key, role],
            )
            .map_err(|e| format!("insert group member: {e}"))?;
        Ok(())
    }

    pub fn get_group_members(
        &self,
        group_id: &str,
    ) -> Result<Vec<crate::models::GroupMember>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT group_id, identity_key, role, joined_at
                 FROM group_members WHERE group_id = ?1 ORDER BY joined_at ASC",
            )
            .map_err(|e| format!("prepare: {e}"))?;

        let rows = stmt
            .query_map(rusqlite::params![group_id], |row| {
                Ok(crate::models::GroupMember {
                    group_id: row.get(0)?,
                    identity_key: row.get(1)?,
                    role: match row.get::<_, u8>(2)? {
                        1 => crate::models::GroupRole::Admin,
                        2 => crate::models::GroupRole::Owner,
                        _ => crate::models::GroupRole::Member,
                    },
                    joined_at: row.get(3)?,
                })
            })
            .map_err(|e| format!("query: {e}"))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect: {e}"))
    }

    pub fn remove_group_member(&self, group_id: &str, identity_key: &[u8]) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM group_members WHERE group_id = ?1 AND identity_key = ?2",
                rusqlite::params![group_id, identity_key],
            )
            .map_err(|e| format!("remove group member: {e}"))?;
        Ok(())
    }

    // ─── CRUD: Sender Keys ───────────────────────────────

    pub fn save_sender_key(
        &self,
        group_id: &str,
        sender_identity_key: &[u8],
        key_data: &[u8],
        is_outgoing: bool,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO sender_keys_local
                    (group_id, sender_identity_key, key_data, is_outgoing, updated_at)
                 VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                rusqlite::params![group_id, sender_identity_key, key_data, is_outgoing as u8],
            )
            .map_err(|e| format!("save sender key: {e}"))?;
        Ok(())
    }

    pub fn load_sender_key(
        &self,
        group_id: &str,
        sender_identity_key: &[u8],
    ) -> Result<Option<Vec<u8>>, String> {
        match self.conn.query_row(
            "SELECT key_data FROM sender_keys_local
             WHERE group_id = ?1 AND sender_identity_key = ?2",
            rusqlite::params![group_id, sender_identity_key],
            |row| row.get(0),
        ) {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("load sender key: {e}")),
        }
    }

    pub fn delete_sender_keys_for_group(&self, group_id: &str) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM sender_keys_local WHERE group_id = ?1",
                rusqlite::params![group_id],
            )
            .map_err(|e| format!("delete sender keys: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    #[test]
    fn test_open_memory_db() {
        let key = [42u8; 32];
        let db = VeilDb::open_memory(&key).unwrap();
        // Verify tables exist
        let count: i64 = db
            .conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='conversations'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_insert_conversation() {
        let key = [42u8; 32];
        let db = VeilDb::open_memory(&key).unwrap();

        db.conn
            .execute(
                "INSERT INTO conversations (id, conv_type, name) VALUES (?1, ?2, ?3)",
                params!["conv-1", 1, "Test Group"],
            )
            .unwrap();

        let name: String = db
            .conn
            .query_row(
                "SELECT name FROM conversations WHERE id = ?1",
                params!["conv-1"],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(name, "Test Group");
    }
}
