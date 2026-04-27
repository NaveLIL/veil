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
            );

            CREATE TABLE IF NOT EXISTS reactions (
                message_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                emoji TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (message_id, user_id, emoji)
            );

            -- ─── Discord-like servers (cache) ─────────────────
            -- Server is source of truth; rows here are an offline cache so the
            -- UI can render instantly. Background sync replaces rows wholesale.
            CREATE TABLE IF NOT EXISTS servers_cache (
                id           TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                description  TEXT,
                icon_url     TEXT,
                owner_id     TEXT NOT NULL,
                position     INTEGER NOT NULL DEFAULT 0,
                created_at   TEXT NOT NULL DEFAULT (datetime('now')),
                synced_at    TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS server_channels_cache (
                id              TEXT PRIMARY KEY,
                server_id       TEXT NOT NULL REFERENCES servers_cache(id) ON DELETE CASCADE,
                conversation_id TEXT,
                name            TEXT NOT NULL,
                channel_type    INTEGER NOT NULL DEFAULT 0,
                category_id     TEXT,
                position        INTEGER NOT NULL DEFAULT 0,
                topic           TEXT,
                nsfw            INTEGER NOT NULL DEFAULT 0,
                slowmode_secs   INTEGER NOT NULL DEFAULT 0,
                synced_at       TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_chcache_server
                ON server_channels_cache(server_id, position);

            CREATE TABLE IF NOT EXISTS server_roles_cache (
                id           TEXT NOT NULL,
                server_id    TEXT NOT NULL REFERENCES servers_cache(id) ON DELETE CASCADE,
                name         TEXT NOT NULL,
                permissions  INTEGER NOT NULL DEFAULT 0,
                position     INTEGER NOT NULL DEFAULT 0,
                color        INTEGER,
                is_default   INTEGER NOT NULL DEFAULT 0,
                hoist        INTEGER NOT NULL DEFAULT 0,
                mentionable  INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (server_id, id)
            );

            CREATE TABLE IF NOT EXISTS server_members_cache (
                server_id    TEXT NOT NULL REFERENCES servers_cache(id) ON DELETE CASCADE,
                user_id      TEXT NOT NULL,
                username     TEXT NOT NULL,
                nickname     TEXT,
                role_ids     TEXT NOT NULL DEFAULT '[]',  -- JSON array
                joined_at    TEXT NOT NULL,
                PRIMARY KEY (server_id, user_id)
            );

            -- ─── Phase 6: OpenMLS support ─────────────────────
            -- Long-lived signature keypair (TLS-encoded SignatureKeyPair).
            CREATE TABLE IF NOT EXISTS mls_signer (
                leaf       BLOB PRIMARY KEY,
                blob       BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Locally generated KeyPackages awaiting publication / consumption.
            -- After server confirms publish we set published=1; after the
            -- server hands one out to a peer the peer's Welcome arrives and
            -- the local copy is deleted (private state already inside openmls).
            CREATE TABLE IF NOT EXISTS mls_key_packages_local (
                id         TEXT PRIMARY KEY,
                kp_blob    BLOB NOT NULL,
                published  INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Cached current epoch per MLS group, for cheap UI lookups.
            CREATE TABLE IF NOT EXISTS mls_state (
                group_id   BLOB PRIMARY KEY,
                epoch      INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Opaque byte snapshot of the openmls in-memory storage
            -- (all groups, secrets and key material owned by this leaf).
            -- Encrypted at rest by SQLCipher.
            CREATE TABLE IF NOT EXISTS mls_provider_snapshot (
                leaf       BLOB PRIMARY KEY,
                snapshot   BLOB NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
            )
            .map_err(|e| format!("migrations: {e}"))?;

        // Add `crypto_mode` to conversations if missing. Older DBs created
        // before Phase 6 don't have this column. SQLite has no
        // `ADD COLUMN IF NOT EXISTS`, so we attempt and ignore the error.
        let _ = self.conn.execute_batch(
            "ALTER TABLE conversations ADD COLUMN crypto_mode TEXT NOT NULL DEFAULT 'sender_key';",
        );

        Ok(())
    }

    // ─── CRUD: MLS ────────────────────────────────────────

    pub fn mls_save_signer(&self, leaf: &[u8], blob: &[u8]) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO mls_signer (leaf, blob) VALUES (?1, ?2)
                 ON CONFLICT(leaf) DO UPDATE SET blob = excluded.blob",
                rusqlite::params![leaf, blob],
            )
            .map(|_| ())
            .map_err(|e| format!("mls_save_signer: {e}"))
    }

    pub fn mls_load_signer(&self, leaf: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.conn
            .query_row(
                "SELECT blob FROM mls_signer WHERE leaf = ?1",
                rusqlite::params![leaf],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(format!("mls_load_signer: {other}")),
            })
    }

    /// Persist an opaque storage snapshot for the given leaf identity.
    /// Bytes are produced by `MlsClient::snapshot()` and contain raw
    /// key material — only safe at rest because the SQLCipher database
    /// is encrypted with the user's identity key.
    pub fn mls_save_snapshot(&self, leaf: &[u8], snapshot: &[u8]) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO mls_provider_snapshot (leaf, snapshot) VALUES (?1, ?2)
                 ON CONFLICT(leaf) DO UPDATE SET
                    snapshot = excluded.snapshot,
                    updated_at = datetime('now')",
                rusqlite::params![leaf, snapshot],
            )
            .map(|_| ())
            .map_err(|e| format!("mls_save_snapshot: {e}"))
    }

    /// Load the most recent snapshot for the given leaf identity, if any.
    pub fn mls_load_snapshot(&self, leaf: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.conn
            .query_row(
                "SELECT snapshot FROM mls_provider_snapshot WHERE leaf = ?1",
                rusqlite::params![leaf],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(format!("mls_load_snapshot: {other}")),
            })
    }

    pub fn mls_insert_local_kp(&self, id: &str, kp_blob: &[u8]) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO mls_key_packages_local (id, kp_blob) VALUES (?1, ?2)",
                rusqlite::params![id, kp_blob],
            )
            .map(|_| ())
            .map_err(|e| format!("mls_insert_local_kp: {e}"))
    }

    pub fn mls_count_unpublished_kp(&self) -> Result<u32, String> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM mls_key_packages_local WHERE published = 0",
                [],
                |row| row.get::<_, u32>(0),
            )
            .map_err(|e| format!("mls_count_unpublished_kp: {e}"))
    }

    pub fn mls_mark_published(&self, id: &str) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE mls_key_packages_local SET published = 1 WHERE id = ?1",
                rusqlite::params![id],
            )
            .map(|_| ())
            .map_err(|e| format!("mls_mark_published: {e}"))
    }

    pub fn mls_set_state(&self, group_id: &[u8], epoch: u64) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO mls_state (group_id, epoch) VALUES (?1, ?2)
                 ON CONFLICT(group_id) DO UPDATE SET
                    epoch = excluded.epoch,
                    updated_at = datetime('now')",
                rusqlite::params![group_id, epoch as i64],
            )
            .map(|_| ())
            .map_err(|e| format!("mls_set_state: {e}"))
    }

    pub fn mls_get_epoch(&self, group_id: &[u8]) -> Result<Option<u64>, String> {
        self.conn
            .query_row(
                "SELECT epoch FROM mls_state WHERE group_id = ?1",
                rusqlite::params![group_id],
                |row| row.get::<_, i64>(0),
            )
            .map(|v| Some(v as u64))
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(format!("mls_get_epoch: {other}")),
            })
    }

    pub fn set_conversation_crypto_mode(&self, conv_id: &str, mode: &str) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE conversations SET crypto_mode = ?2 WHERE id = ?1",
                rusqlite::params![conv_id, mode],
            )
            .map(|_| ())
            .map_err(|e| format!("set_conversation_crypto_mode: {e}"))
    }

    pub fn get_conversation_crypto_mode(&self, conv_id: &str) -> Result<Option<String>, String> {
        self.conn
            .query_row(
                "SELECT crypto_mode FROM conversations WHERE id = ?1",
                rusqlite::params![conv_id],
                |row| row.get::<_, String>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(format!("get_conversation_crypto_mode: {other}")),
            })
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
        reply_to_id: Option<&str>,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO messages (id, conversation_id, sender_key, plaintext, is_outgoing, status, server_timestamp, reply_to_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    id,
                    conversation_id,
                    sender_key,
                    plaintext,
                    is_outgoing as u8,
                    if is_outgoing { 1u8 } else { 0u8 },
                    server_timestamp,
                    reply_to_id,
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

    /// Update the plaintext of an existing message (edit).
    pub fn update_message_text(&self, message_id: &str, new_text: &str) -> Result<(), String> {
        let updated = self
            .conn
            .execute(
                "UPDATE messages SET plaintext = ?1 WHERE id = ?2",
                rusqlite::params![new_text, message_id],
            )
            .map_err(|e| format!("update message text: {e}"))?;
        if updated == 0 {
            return Err("message not found".to_string());
        }
        Ok(())
    }

    /// Delete a message by ID (hard delete from local store).
    pub fn delete_message(&self, message_id: &str) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM messages WHERE id = ?1",
                rusqlite::params![message_id],
            )
            .map_err(|e| format!("delete message: {e}"))?;
        Ok(())
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

    /// Load every saved sender key entry for a group (incoming + outgoing).
    /// Returns a list of `(sender_identity_key, key_data, is_outgoing)`.
    pub fn load_sender_keys_for_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>, bool)>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sender_identity_key, key_data, is_outgoing
                 FROM sender_keys_local WHERE group_id = ?1",
            )
            .map_err(|e| format!("prepare load sender keys: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![group_id], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, u8>(2)? != 0,
                ))
            })
            .map_err(|e| format!("query sender keys: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect sender keys: {e}"))
    }

    // ─── CRUD: Reactions ──────────────────────────────────

    pub fn add_reaction(
        &self,
        message_id: &str,
        user_id: &str,
        emoji: &str,
        username: &str,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO reactions (message_id, user_id, emoji, username)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![message_id, user_id, emoji, username],
            )
            .map_err(|e| format!("add reaction: {e}"))?;
        Ok(())
    }

    pub fn remove_reaction(
        &self,
        message_id: &str,
        user_id: &str,
        emoji: &str,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM reactions WHERE message_id = ?1 AND user_id = ?2 AND emoji = ?3",
                rusqlite::params![message_id, user_id, emoji],
            )
            .map_err(|e| format!("remove reaction: {e}"))?;
        Ok(())
    }

    /// Returns all reactions for a given message: Vec<(emoji, user_id, username)>
    pub fn get_reactions(&self, message_id: &str) -> Result<Vec<(String, String, String)>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT emoji, user_id, username FROM reactions WHERE message_id = ?1")
            .map_err(|e| format!("prepare reactions: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![message_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|e| format!("query reactions: {e}"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| format!("read reaction: {e}"))?);
        }
        Ok(out)
    }

    // ─── CRUD: Servers cache ──────────────────────────────

    /// Replace the entire servers cache with the provided list (full sync).
    /// Channels/roles/members for stale servers are deleted via FK CASCADE.
    pub fn replace_servers(
        &mut self,
        servers: &[crate::models::CachedServer],
    ) -> Result<(), String> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("begin tx: {e}"))?;
        tx.execute("DELETE FROM servers_cache", [])
            .map_err(|e| format!("clear servers: {e}"))?;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO servers_cache (id, name, description, icon_url, owner_id, position, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )
                .map_err(|e| format!("prepare insert server: {e}"))?;
            for s in servers {
                stmt.execute(rusqlite::params![
                    s.id,
                    s.name,
                    s.description,
                    s.icon_url,
                    s.owner_id,
                    s.position,
                    s.created_at,
                ])
                .map_err(|e| format!("insert server: {e}"))?;
            }
        }
        tx.commit().map_err(|e| format!("commit: {e}"))?;
        Ok(())
    }

    /// Insert or replace a single server (used on WS ServerEvent::CREATED/UPDATED).
    pub fn upsert_server(&self, s: &crate::models::CachedServer) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO servers_cache (id, name, description, icon_url, owner_id, position, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    description=excluded.description,
                    icon_url=excluded.icon_url,
                    owner_id=excluded.owner_id,
                    position=excluded.position,
                    synced_at=datetime('now')",
                rusqlite::params![
                    s.id,
                    s.name,
                    s.description,
                    s.icon_url,
                    s.owner_id,
                    s.position,
                    s.created_at,
                ],
            )
            .map_err(|e| format!("upsert server: {e}"))?;
        Ok(())
    }

    pub fn delete_server(&self, server_id: &str) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM servers_cache WHERE id = ?1",
                rusqlite::params![server_id],
            )
            .map_err(|e| format!("delete server: {e}"))?;
        Ok(())
    }

    pub fn list_servers(&self) -> Result<Vec<crate::models::CachedServer>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, name, description, icon_url, owner_id, position, created_at
                 FROM servers_cache ORDER BY position ASC, created_at ASC",
            )
            .map_err(|e| format!("prepare list servers: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(crate::models::CachedServer {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    icon_url: row.get(3)?,
                    owner_id: row.get(4)?,
                    position: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })
            .map_err(|e| format!("query servers: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect servers: {e}"))
    }

    // ─── CRUD: Channels cache ─────────────────────────────

    /// Replace all channels for a single server (full per-server sync).
    pub fn replace_channels(
        &mut self,
        server_id: &str,
        channels: &[crate::models::CachedChannel],
    ) -> Result<(), String> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("begin tx: {e}"))?;
        tx.execute(
            "DELETE FROM server_channels_cache WHERE server_id = ?1",
            rusqlite::params![server_id],
        )
        .map_err(|e| format!("clear channels: {e}"))?;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO server_channels_cache
                       (id, server_id, conversation_id, name, channel_type, category_id,
                        position, topic, nsfw, slowmode_secs)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                )
                .map_err(|e| format!("prepare insert channel: {e}"))?;
            for c in channels {
                stmt.execute(rusqlite::params![
                    c.id,
                    c.server_id,
                    c.conversation_id,
                    c.name,
                    c.channel_type,
                    c.category_id,
                    c.position,
                    c.topic,
                    c.nsfw as u8,
                    c.slowmode_secs,
                ])
                .map_err(|e| format!("insert channel: {e}"))?;
            }
        }
        tx.commit().map_err(|e| format!("commit channels: {e}"))?;
        Ok(())
    }

    pub fn upsert_channel(&self, c: &crate::models::CachedChannel) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO server_channels_cache
                   (id, server_id, conversation_id, name, channel_type, category_id,
                    position, topic, nsfw, slowmode_secs)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
                 ON CONFLICT(id) DO UPDATE SET
                    server_id=excluded.server_id,
                    conversation_id=excluded.conversation_id,
                    name=excluded.name,
                    channel_type=excluded.channel_type,
                    category_id=excluded.category_id,
                    position=excluded.position,
                    topic=excluded.topic,
                    nsfw=excluded.nsfw,
                    slowmode_secs=excluded.slowmode_secs,
                    synced_at=datetime('now')",
                rusqlite::params![
                    c.id,
                    c.server_id,
                    c.conversation_id,
                    c.name,
                    c.channel_type,
                    c.category_id,
                    c.position,
                    c.topic,
                    c.nsfw as u8,
                    c.slowmode_secs,
                ],
            )
            .map_err(|e| format!("upsert channel: {e}"))?;
        Ok(())
    }

    pub fn delete_channel(&self, channel_id: &str) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM server_channels_cache WHERE id = ?1",
                rusqlite::params![channel_id],
            )
            .map_err(|e| format!("delete channel: {e}"))?;
        Ok(())
    }

    pub fn list_channels(
        &self,
        server_id: &str,
    ) -> Result<Vec<crate::models::CachedChannel>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, server_id, conversation_id, name, channel_type, category_id,
                        position, topic, nsfw, slowmode_secs
                 FROM server_channels_cache
                 WHERE server_id = ?1
                 ORDER BY position ASC, name ASC",
            )
            .map_err(|e| format!("prepare list channels: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![server_id], |row| {
                Ok(crate::models::CachedChannel {
                    id: row.get(0)?,
                    server_id: row.get(1)?,
                    conversation_id: row.get(2)?,
                    name: row.get(3)?,
                    channel_type: row.get(4)?,
                    category_id: row.get(5)?,
                    position: row.get(6)?,
                    topic: row.get(7)?,
                    nsfw: row.get::<_, u8>(8)? != 0,
                    slowmode_secs: row.get(9)?,
                })
            })
            .map_err(|e| format!("query channels: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect channels: {e}"))
    }

    // ─── CRUD: Roles cache ────────────────────────────────

    pub fn replace_roles(
        &mut self,
        server_id: &str,
        roles: &[crate::models::CachedRole],
    ) -> Result<(), String> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("begin tx: {e}"))?;
        tx.execute(
            "DELETE FROM server_roles_cache WHERE server_id = ?1",
            rusqlite::params![server_id],
        )
        .map_err(|e| format!("clear roles: {e}"))?;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO server_roles_cache
                       (id, server_id, name, permissions, position, color, is_default, hoist, mentionable)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                )
                .map_err(|e| format!("prepare insert role: {e}"))?;
            for r in roles {
                stmt.execute(rusqlite::params![
                    r.id,
                    r.server_id,
                    r.name,
                    r.permissions as i64,
                    r.position,
                    r.color,
                    r.is_default as u8,
                    r.hoist as u8,
                    r.mentionable as u8,
                ])
                .map_err(|e| format!("insert role: {e}"))?;
            }
        }
        tx.commit().map_err(|e| format!("commit roles: {e}"))?;
        Ok(())
    }

    pub fn list_roles(&self, server_id: &str) -> Result<Vec<crate::models::CachedRole>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, server_id, name, permissions, position, color, is_default, hoist, mentionable
                 FROM server_roles_cache
                 WHERE server_id = ?1
                 ORDER BY position DESC",
            )
            .map_err(|e| format!("prepare list roles: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![server_id], |row| {
                Ok(crate::models::CachedRole {
                    id: row.get(0)?,
                    server_id: row.get(1)?,
                    name: row.get(2)?,
                    permissions: row.get::<_, i64>(3)? as u64,
                    position: row.get(4)?,
                    color: row.get(5)?,
                    is_default: row.get::<_, u8>(6)? != 0,
                    hoist: row.get::<_, u8>(7)? != 0,
                    mentionable: row.get::<_, u8>(8)? != 0,
                })
            })
            .map_err(|e| format!("query roles: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect roles: {e}"))
    }

    // ─── CRUD: Members cache ──────────────────────────────

    pub fn replace_server_members(
        &mut self,
        server_id: &str,
        members: &[crate::models::CachedServerMember],
    ) -> Result<(), String> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("begin tx: {e}"))?;
        tx.execute(
            "DELETE FROM server_members_cache WHERE server_id = ?1",
            rusqlite::params![server_id],
        )
        .map_err(|e| format!("clear members: {e}"))?;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO server_members_cache
                       (server_id, user_id, username, nickname, role_ids, joined_at)
                     VALUES (?1,?2,?3,?4,?5,?6)",
                )
                .map_err(|e| format!("prepare insert member: {e}"))?;
            for m in members {
                let role_ids = serde_json::to_string(&m.role_ids)
                    .map_err(|e| format!("encode role_ids: {e}"))?;
                stmt.execute(rusqlite::params![
                    m.server_id,
                    m.user_id,
                    m.username,
                    m.nickname,
                    role_ids,
                    m.joined_at,
                ])
                .map_err(|e| format!("insert member: {e}"))?;
            }
        }
        tx.commit().map_err(|e| format!("commit members: {e}"))?;
        Ok(())
    }

    pub fn upsert_server_member(
        &self,
        m: &crate::models::CachedServerMember,
    ) -> Result<(), String> {
        let role_ids =
            serde_json::to_string(&m.role_ids).map_err(|e| format!("encode role_ids: {e}"))?;
        self.conn
            .execute(
                "INSERT INTO server_members_cache
                   (server_id, user_id, username, nickname, role_ids, joined_at)
                 VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(server_id, user_id) DO UPDATE SET
                    username=excluded.username,
                    nickname=excluded.nickname,
                    role_ids=excluded.role_ids",
                rusqlite::params![
                    m.server_id,
                    m.user_id,
                    m.username,
                    m.nickname,
                    role_ids,
                    m.joined_at,
                ],
            )
            .map_err(|e| format!("upsert member: {e}"))?;
        Ok(())
    }

    pub fn delete_server_member(&self, server_id: &str, user_id: &str) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM server_members_cache WHERE server_id = ?1 AND user_id = ?2",
                rusqlite::params![server_id, user_id],
            )
            .map_err(|e| format!("delete member: {e}"))?;
        Ok(())
    }

    pub fn list_server_members(
        &self,
        server_id: &str,
    ) -> Result<Vec<crate::models::CachedServerMember>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT server_id, user_id, username, nickname, role_ids, joined_at
                 FROM server_members_cache
                 WHERE server_id = ?1
                 ORDER BY joined_at ASC",
            )
            .map_err(|e| format!("prepare list members: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![server_id], |row| {
                let role_ids_json: String = row.get(4)?;
                let role_ids: Vec<String> =
                    serde_json::from_str(&role_ids_json).unwrap_or_default();
                Ok(crate::models::CachedServerMember {
                    server_id: row.get(0)?,
                    user_id: row.get(1)?,
                    username: row.get(2)?,
                    nickname: row.get(3)?,
                    role_ids,
                    joined_at: row.get(5)?,
                })
            })
            .map_err(|e| format!("query members: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect members: {e}"))
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
