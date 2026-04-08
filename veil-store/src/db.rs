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
        let conn = Connection::open(path)
            .map_err(|e| format!("open db: {e}"))?;

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
        ).map_err(|e| format!("cipher pragmas: {e}"))?;

        // Performance settings
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        ).map_err(|e| format!("pragmas: {e}"))?;

        let db = Self { conn };
        db.run_migrations()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory(key: &[u8; 32]) -> Result<Self, String> {
        let conn = Connection::open_in_memory()
            .map_err(|e| format!("open memory db: {e}"))?;

        let mut hex_key = hex::encode(key);
        let res = conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";\n", hex_key));
        hex_key.zeroize();
        res.map_err(|e| format!("set key: {e}"))?;

        conn.execute_batch(
            "PRAGMA cipher_page_size = 4096;
             PRAGMA kdf_iter = 256000;
             PRAGMA cipher_memory_security = ON;
             PRAGMA foreign_keys = ON;",
        ).map_err(|e| format!("pragmas: {e}"))?;

        let db = Self { conn };
        db.run_migrations()?;
        Ok(db)
    }

    fn run_migrations(&self) -> Result<(), String> {
        self.conn.execute_batch(
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
            );",
        ).map_err(|e| format!("migrations: {e}"))
    }

    /// Get a reference to the underlying connection (for advanced queries).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_memory_db() {
        let key = [42u8; 32];
        let db = VeilDb::open_memory(&key).unwrap();
        // Verify tables exist
        let count: i64 = db.conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='conversations'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_insert_conversation() {
        let key = [42u8; 32];
        let db = VeilDb::open_memory(&key).unwrap();

        db.conn.execute(
            "INSERT INTO conversations (id, conv_type, name) VALUES (?1, ?2, ?3)",
            params!["conv-1", 1, "Test Group"],
        ).unwrap();

        let name: String = db.conn.query_row(
            "SELECT name FROM conversations WHERE id = ?1",
            params!["conv-1"],
            |row| row.get(0),
        ).unwrap();

        assert_eq!(name, "Test Group");
    }
}
