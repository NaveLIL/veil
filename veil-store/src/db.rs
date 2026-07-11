use rusqlite::Connection;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// X3DH private prekey material. Rows live only inside SQLCipher; consumed
/// one-time secrets are nulled atomically when the initial ratchet is stored.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LocalPreKey {
    pub key_type: u8, // 0=signed, 1=one-time
    pub protocol_key_id: u32,
    pub secret_key: [u8; 32],
    pub public_key: [u8; 32],
    pub signature: Option<[u8; 64]>,
}

/// Encrypted SQLite database using SQLCipher.
pub struct VeilDb {
    conn: Connection,
}

pub type PendingInitialHeaderRow = ([u8; 32], Vec<u8>);
pub type MessageBinding = (String, Vec<u8>, bool, Option<i64>);
pub type TrustedSigningKeyBinding = ([u8; 32], [u8; 32]);
pub type StoredSenderKey = (Vec<u8>, Vec<u8>, bool);

impl VeilDb {
    /// Open (or create) an encrypted database at the given path.
    /// The `key` is a 32-byte encryption key derived from user identity.
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self, String> {
        // Never delete a database automatically. With SQLCipher, a wrong key
        // is intentionally indistinguishable from a corrupt/non-database file;
        // treating that error as disposable data can destroy message history.
        Self::open_inner(path, key).map_err(|e| {
            if path.exists() && e.contains("not a database") {
                format!(
                    "encrypted database could not be opened (wrong identity key or corruption); file was left untouched: {e}"
                )
            } else {
                e
            }
        })
    }

    fn open_inner(path: &Path, key: &[u8; 32]) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("open db: {e}"))?;

        // Set SQLCipher encryption key
        let mut hex_key = hex::encode(key);
        let key_pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";\n", hex_key));
        let res = conn.execute_batch(&key_pragma);
        hex_key.zeroize();
        res.map_err(|e| format!("set key: {e}"))?;

        // SQLCipher hardening
        conn.execute_batch(
            "PRAGMA cipher_page_size = 4096;
             PRAGMA kdf_iter = 256000;
             PRAGMA cipher_memory_security = ON;",
        )
        .map_err(|e| format!("cipher pragmas: {e}"))?;

        // Ratchet and Sender-Key state is committed before its ciphertext is
        // released to the transport. WAL + FULL is therefore a protocol
        // safety requirement: NORMAL may lose the latest commit on power loss
        // and cause message-key/nonce reuse after restart.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
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
        let key_pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";\n", hex_key));
        let res = conn.execute_batch(&key_pragma);
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

            CREATE TABLE IF NOT EXISTS remote_message_state (
                message_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_key BLOB NOT NULL CHECK(length(sender_key) = 32),
                revision_ms INTEGER NOT NULL,
                state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3)),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS ratchet_sessions (
                peer_identity_key BLOB PRIMARY KEY,
                session_data BLOB NOT NULL,  -- Serialized RatchetSession (encrypted by SQLCipher)
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS pending_initial_headers (
                peer_identity_key BLOB PRIMARY KEY CHECK(length(peer_identity_key) = 32),
                header_data BLOB NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS client_state (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS local_prekeys (
                key_type INTEGER NOT NULL CHECK(key_type IN (0, 1)),
                protocol_key_id INTEGER NOT NULL CHECK(protocol_key_id > 0),
                secret_key BLOB,
                public_key BLOB NOT NULL,
                signature BLOB,
                consumed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (key_type, protocol_key_id),
                CHECK((consumed = 0 AND length(secret_key) = 32) OR
                      (consumed = 1 AND secret_key IS NULL))
            );

            CREATE TABLE IF NOT EXISTS trusted_identity_keys (
                identity_key BLOB PRIMARY KEY CHECK(length(identity_key) = 32),
                signing_key BLOB NOT NULL CHECK(length(signing_key) = 32),
                first_seen_at TEXT NOT NULL DEFAULT (datetime('now'))
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

    /// Insert or refresh a conversation learned from the authenticated server
    /// directory.  Cryptographic bindings are immutable: a signed response may
    /// fill a previously-unknown DM peer/server, but it may never silently
    /// replace an existing binding or change the conversation kind.
    pub fn upsert_directory_conversation(
        &self,
        id: &str,
        conv_type: u8,
        name: Option<&str>,
        peer_identity_key: Option<&[u8]>,
        server_id: Option<&str>,
        created_at: &str,
    ) -> Result<(), String> {
        if id.is_empty() || created_at.is_empty() {
            return Err("directory conversation id and created_at must not be empty".to_string());
        }
        if conv_type > 2 {
            return Err("invalid directory conversation type".to_string());
        }
        if conv_type == 0 && peer_identity_key.map(|key| key.len()) != Some(32) {
            return Err("DM directory entry must contain a 32-byte peer identity key".to_string());
        }
        if conv_type != 0 && peer_identity_key.is_some() {
            return Err("non-DM directory entry must not contain a peer identity key".to_string());
        }

        let existing = self.conn.query_row(
            "SELECT conv_type, peer_identity_key, server_id FROM conversations WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok((
                    row.get::<_, u8>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        );

        match existing {
            Ok((stored_type, stored_peer, stored_server)) => {
                if stored_type != conv_type {
                    return Err("authenticated directory changed the conversation type".to_string());
                }
                if let (Some(stored), Some(received)) = (stored_peer.as_deref(), peer_identity_key)
                {
                    if stored != received {
                        return Err(
                            "authenticated directory changed the pinned DM peer".to_string()
                        );
                    }
                }
                if let (Some(stored), Some(received)) = (stored_server.as_deref(), server_id) {
                    if stored != received {
                        return Err("authenticated directory changed the pinned server".to_string());
                    }
                }

                self.conn
                    .execute(
                        "UPDATE conversations
                         SET name = ?2,
                             peer_identity_key = COALESCE(peer_identity_key, ?3),
                             server_id = COALESCE(server_id, ?4),
                             created_at = ?5
                         WHERE id = ?1",
                        rusqlite::params![id, name, peer_identity_key, server_id, created_at],
                    )
                    .map_err(|e| format!("update directory conversation: {e}"))?;
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                self.conn
                    .execute(
                        "INSERT INTO conversations
                           (id, conv_type, name, peer_identity_key, server_id, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        rusqlite::params![
                            id,
                            conv_type,
                            name,
                            peer_identity_key,
                            server_id,
                            created_at
                        ],
                    )
                    .map_err(|e| format!("insert directory conversation: {e}"))?;
            }
            Err(e) => return Err(format!("load directory conversation: {e}")),
        }
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

    // The parameters mirror the persisted protocol record explicitly. Keeping
    // them separate avoids constructing an additional plaintext-owning DTO.
    #[allow(clippy::too_many_arguments)]
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

    /// Whether an authoritative server message UUID is already present.
    /// Offline sync checks this before decrypting so a replay cannot advance a
    /// Double Ratchet or Sender Key state twice.
    pub fn message_exists(&self, message_id: &str) -> Result<bool, String> {
        self.conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE id = ?1)",
                rusqlite::params![message_id],
                |row| row.get(0),
            )
            .map_err(|e| format!("check message existence: {e}"))
    }

    pub fn get_remote_message_state(
        &self,
        message_id: &str,
    ) -> Result<Option<crate::models::RemoteMessageState>, String> {
        self.conn
            .query_row(
                "SELECT message_id, conversation_id, sender_key, revision_ms, state
                 FROM remote_message_state WHERE message_id = ?1",
                rusqlite::params![message_id],
                |row| {
                    let raw_state: u8 = row.get(4)?;
                    Ok(crate::models::RemoteMessageState {
                        message_id: row.get(0)?,
                        conversation_id: row.get(1)?,
                        sender_key: row.get(2)?,
                        revision_ms: row.get(3)?,
                        state: match raw_state {
                            1 => crate::models::RemoteMessageStateKind::Deleted,
                            2 => crate::models::RemoteMessageStateKind::Expired,
                            3 => crate::models::RemoteMessageStateKind::Unavailable,
                            _ => crate::models::RemoteMessageStateKind::Active,
                        },
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(format!("load remote message state: {other}")),
            })
    }

    pub fn get_message_binding(&self, message_id: &str) -> Result<Option<MessageBinding>, String> {
        self.conn
            .query_row(
                "SELECT conversation_id, sender_key, is_outgoing, server_timestamp
                 FROM messages WHERE id = ?1",
                rusqlite::params![message_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get::<_, u8>(2)? != 0,
                        row.get(3)?,
                    ))
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(format!("load message binding: {other}")),
            })
    }

    pub fn record_remote_message_state(
        &self,
        message_id: &str,
        conversation_id: &str,
        sender_key: &[u8; 32],
        revision_ms: i64,
        state: crate::models::RemoteMessageStateKind,
    ) -> Result<(), String> {
        if message_id.is_empty() || conversation_id.is_empty() || revision_ms < 0 {
            return Err("invalid remote message state".to_string());
        }
        if let Some(existing) = self.get_remote_message_state(message_id)? {
            if existing.conversation_id != conversation_id || existing.sender_key != sender_key {
                return Err("remote message UUID changed its conversation or sender".to_string());
            }
            if revision_ms < existing.revision_ms {
                return Err("remote message revision moved backwards".to_string());
            }
            if revision_ms == existing.revision_ms
                && existing.state != state
                && !(existing.state == crate::models::RemoteMessageStateKind::Unavailable
                    && state == crate::models::RemoteMessageStateKind::Active)
                // Expiration is a deterministic time transition and older
                // servers report the content revision (created/edited time),
                // not a new mutation timestamp. It is terminal, so allowing
                // Active -> Expired at equal revision cannot resurrect data.
                && !(existing.state == crate::models::RemoteMessageStateKind::Active
                    && state == crate::models::RemoteMessageStateKind::Expired)
            {
                return Err("remote message changed state without a new revision".to_string());
            }
        }
        self.conn
            .execute(
                "INSERT INTO remote_message_state
                   (message_id, conversation_id, sender_key, revision_ms, state, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))
                 ON CONFLICT(message_id) DO UPDATE SET
                   revision_ms=excluded.revision_ms,
                   state=excluded.state,
                   updated_at=datetime('now')",
                rusqlite::params![
                    message_id,
                    conversation_id,
                    sender_key.as_slice(),
                    revision_ms,
                    state as u8,
                ],
            )
            .map(|_| ())
            .map_err(|e| format!("record remote message state: {e}"))
    }

    /// Authoritatively replace reactions for one server message. A nested
    /// SAVEPOINT keeps this atomic both standalone and inside receive sync.
    pub fn replace_message_reactions(
        &self,
        message_id: &str,
        reactions: &[crate::models::RemoteReaction],
    ) -> Result<(), String> {
        self.conn
            .execute_batch("SAVEPOINT veil_replace_reactions")
            .map_err(|e| format!("begin reaction replace: {e}"))?;
        let operation = (|| {
            self.conn
                .execute(
                    "DELETE FROM reactions WHERE message_id = ?1",
                    rusqlite::params![message_id],
                )
                .map_err(|e| format!("clear message reactions: {e}"))?;
            for reaction in reactions {
                if reaction.emoji.is_empty()
                    || reaction.emoji.len() > 64
                    || reaction.user_id.is_empty()
                    || reaction.username.len() > 256
                {
                    return Err("invalid authoritative reaction row".to_string());
                }
                self.conn
                    .execute(
                        "INSERT INTO reactions (message_id, user_id, emoji, username)
                         VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![
                            message_id,
                            reaction.user_id,
                            reaction.emoji,
                            reaction.username,
                        ],
                    )
                    .map_err(|e| format!("insert authoritative reaction: {e}"))?;
            }
            Ok(())
        })();
        if let Err(error) = operation {
            let rollback = self.conn.execute_batch(
                "ROLLBACK TO SAVEPOINT veil_replace_reactions;
                 RELEASE SAVEPOINT veil_replace_reactions;",
            );
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback_error) => {
                    format!("{error}; reaction rollback failed: {rollback_error}")
                }
            });
        }
        self.conn
            .execute_batch("RELEASE SAVEPOINT veil_replace_reactions")
            .map_err(|e| format!("commit reaction replace: {e}"))
    }

    pub fn update_incoming_message_text_scoped(
        &self,
        message_id: &str,
        conversation_id: &str,
        sender_key: &[u8; 32],
        new_text: &str,
    ) -> Result<(), String> {
        let changed = self
            .conn
            .execute(
                "UPDATE messages SET plaintext = ?1
                 WHERE id = ?2 AND conversation_id = ?3 AND sender_key = ?4
                   AND is_outgoing = 0",
                rusqlite::params![new_text, message_id, conversation_id, sender_key.as_slice(),],
            )
            .map_err(|e| format!("update incoming message text: {e}"))?;
        if changed != 1 {
            return Err("scoped incoming message for edit was not found".to_string());
        }
        Ok(())
    }

    pub fn delete_message_scoped(
        &self,
        message_id: &str,
        conversation_id: &str,
    ) -> Result<(), String> {
        let changed = self
            .conn
            .execute(
                "DELETE FROM messages WHERE id = ?1 AND conversation_id = ?2",
                rusqlite::params![message_id, conversation_id],
            )
            .map_err(|e| format!("delete scoped message: {e}"))?;
        if changed > 1 {
            return Err("scoped message delete affected multiple rows".to_string());
        }
        Ok(())
    }

    /// Begin the single-client receive savepoint. The VeilClient mutex
    /// serializes callers, so a fixed name is safe and lets crypto-state writes
    /// performed by existing helpers participate in the same SQLite unit.
    pub fn begin_receive_savepoint(&self) -> Result<(), String> {
        self.conn
            .execute_batch("SAVEPOINT veil_receive_message")
            .map_err(|e| format!("begin receive savepoint: {e}"))
    }

    pub fn commit_receive_savepoint(&self) -> Result<(), String> {
        self.conn
            .execute_batch("RELEASE SAVEPOINT veil_receive_message")
            .map_err(|e| format!("commit receive savepoint: {e}"))
    }

    pub fn rollback_receive_savepoint(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "ROLLBACK TO SAVEPOINT veil_receive_message;
                 RELEASE SAVEPOINT veil_receive_message;",
            )
            .map_err(|e| format!("rollback receive savepoint: {e}"))
    }

    /// Ensure the FK parent and its crypto binding inside the active receive
    /// savepoint. Existing bindings are verified, never overwritten.
    pub fn ensure_receive_conversation(
        &self,
        conversation_id: &str,
        sender_key_mode: bool,
        sender_identity_key: &[u8; 32],
        fallback_name: Option<&str>,
    ) -> Result<(), String> {
        if conversation_id.is_empty() {
            return Err("receive conversation id must not be empty".to_string());
        }
        let existing = self.conn.query_row(
            "SELECT conv_type, peer_identity_key FROM conversations WHERE id = ?1",
            rusqlite::params![conversation_id],
            |row| Ok((row.get::<_, u8>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
        );
        match existing {
            Ok((conv_type, peer)) => {
                if sender_key_mode {
                    if !matches!(conv_type, 1 | 2) || peer.is_some() {
                        return Err(
                            "sender-key message conflicts with the pinned conversation type"
                                .to_string(),
                        );
                    }
                } else if conv_type != 0 || peer.as_deref() != Some(sender_identity_key.as_slice())
                {
                    return Err("DM sender conflicts with the pinned conversation peer".to_string());
                }
                self.conn
                    .execute(
                        "UPDATE conversations SET name = COALESCE(name, ?2) WHERE id = ?1",
                        rusqlite::params![conversation_id, fallback_name],
                    )
                    .map_err(|e| format!("refresh receive conversation: {e}"))?;
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                self.conn
                    .execute(
                        "INSERT INTO conversations
                           (id, conv_type, name, peer_identity_key)
                         VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![
                            conversation_id,
                            if sender_key_mode { 2u8 } else { 0u8 },
                            fallback_name,
                            if sender_key_mode {
                                None::<&[u8]>
                            } else {
                                Some(sender_identity_key.as_slice())
                            },
                        ],
                    )
                    .map_err(|e| format!("insert receive conversation: {e}"))?;
            }
            Err(e) => return Err(format!("load receive conversation: {e}")),
        }
        Ok(())
    }

    pub fn insert_outgoing_pending_message(
        &self,
        id: &str,
        conversation_id: &str,
        sender_key: &[u8; 32],
        plaintext: &str,
        reply_to_id: Option<&str>,
    ) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin pending message transaction: {e}"))?;
        tx.execute(
            "INSERT INTO messages
               (id, conversation_id, sender_key, plaintext, is_outgoing, status, reply_to_id)
             VALUES (?1, ?2, ?3, ?4, 1, 0, ?5)",
            rusqlite::params![
                id,
                conversation_id,
                sender_key.as_slice(),
                plaintext,
                reply_to_id,
            ],
        )
        .map_err(|e| format!("insert pending outgoing message: {e}"))?;
        tx.execute(
            "UPDATE conversations SET last_message_at = datetime('now') WHERE id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| format!("update pending conversation timestamp: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit pending outgoing message: {e}"))
    }

    /// Replace the optimistic local UUID with the authoritative server UUID
    /// and mark it sent. References are migrated in the same transaction.
    pub fn acknowledge_outgoing_message(
        &self,
        local_message_id: &str,
        server_message_id: &str,
        server_timestamp_ms: i64,
    ) -> Result<(), String> {
        if local_message_id.is_empty() || server_message_id.is_empty() {
            return Err("message ids must not be empty".to_string());
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin message ACK transaction: {e}"))?;
        if local_message_id != server_message_id {
            let collision: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM messages WHERE id = ?1)",
                    rusqlite::params![server_message_id],
                    |row| row.get(0),
                )
                .map_err(|e| format!("check server message id collision: {e}"))?;
            if collision {
                return Err("server message id already exists locally".to_string());
            }
        }
        let changed = tx
            .execute(
                "UPDATE messages
                 SET id = ?1, server_timestamp = ?2, status = 1
                 WHERE id = ?3 AND is_outgoing = 1 AND status = 0",
                rusqlite::params![server_message_id, server_timestamp_ms, local_message_id],
            )
            .map_err(|e| format!("acknowledge outgoing message: {e}"))?;
        if changed != 1 {
            return Err("pending outgoing message not found".to_string());
        }
        tx.execute(
            "UPDATE messages SET reply_to_id = ?1 WHERE reply_to_id = ?2",
            rusqlite::params![server_message_id, local_message_id],
        )
        .map_err(|e| format!("migrate message reply references: {e}"))?;
        tx.execute(
            "UPDATE reactions SET message_id = ?1 WHERE message_id = ?2",
            rusqlite::params![server_message_id, local_message_id],
        )
        .map_err(|e| format!("migrate reaction references: {e}"))?;
        tx.commit().map_err(|e| format!("commit message ACK: {e}"))
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

    /// Persist a newly initiated ratchet together with the X3DH metadata that
    /// must remain on outgoing messages until peer possession is proven.
    pub fn save_initiator_session(
        &self,
        peer_identity_key: &[u8; 32],
        session_data: &[u8],
        initial_header_data: &[u8],
    ) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin initiator session transaction: {e}"))?;
        tx.execute(
            "INSERT OR REPLACE INTO ratchet_sessions
               (peer_identity_key, session_data, updated_at)
             VALUES (?1, ?2, datetime('now'))",
            rusqlite::params![peer_identity_key.as_slice(), session_data],
        )
        .map_err(|e| format!("save initiator ratchet session: {e}"))?;
        tx.execute(
            "INSERT OR REPLACE INTO pending_initial_headers
               (peer_identity_key, header_data, updated_at)
             VALUES (?1, ?2, datetime('now'))",
            rusqlite::params![peer_identity_key.as_slice(), initial_header_data],
        )
        .map_err(|e| format!("save pending X3DH header: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit initiator session transaction: {e}"))
    }

    pub fn load_pending_initial_headers(&self) -> Result<Vec<PendingInitialHeaderRow>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT peer_identity_key, header_data FROM pending_initial_headers")
            .map_err(|e| format!("prepare pending X3DH headers: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| format!("query pending X3DH headers: {e}"))?;
        let mut result = Vec::new();
        for row in rows {
            let (peer, data) = row.map_err(|e| format!("read pending X3DH header: {e}"))?;
            let peer: [u8; 32] = peer
                .try_into()
                .map_err(|peer: Vec<u8>| format!("invalid pending peer length: {}", peer.len()))?;
            result.push((peer, data));
        }
        Ok(result)
    }

    pub fn clear_pending_initial_header(&self, peer_identity_key: &[u8; 32]) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM pending_initial_headers WHERE peer_identity_key = ?1",
                rusqlite::params![peer_identity_key.as_slice()],
            )
            .map(|_| ())
            .map_err(|e| format!("clear pending X3DH header: {e}"))
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

    /// Return the stable per-install device ID stored inside SQLCipher, or
    /// atomically initialize it from `proposed` on first use.
    pub fn get_or_create_device_id(&self, proposed: [u8; 16]) -> Result<[u8; 16], String> {
        if proposed == [0u8; 16] {
            return Err("refusing an all-zero device id".to_string());
        }
        self.conn
            .execute(
                "INSERT OR IGNORE INTO client_state (key, value) VALUES ('device_id', ?1)",
                rusqlite::params![proposed.as_slice()],
            )
            .map_err(|e| format!("store device id: {e}"))?;
        let bytes: Vec<u8> = self
            .conn
            .query_row(
                "SELECT value FROM client_state WHERE key = 'device_id'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("load device id: {e}"))?;
        let persisted: [u8; 16] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| format!("invalid persisted device id length: {}", v.len()))?;
        if persisted != [0u8; 16] {
            return Ok(persisted);
        }

        // Repair the fail-open value produced by older Windows builds when
        // the OS RNG failed. A fresh ID is safer than keeping a globally
        // colliding device identity.
        self.conn
            .execute(
                "UPDATE client_state SET value = ?1 WHERE key = 'device_id' AND value = ?2",
                rusqlite::params![proposed.as_slice(), [0u8; 16].as_slice()],
            )
            .map_err(|e| format!("repair all-zero device id: {e}"))?;
        Ok(proposed)
    }

    /// Trust-on-authenticated-directory: insert the first observed Ed25519 key
    /// for an X25519 identity and reject any later substitution.
    pub fn pin_trusted_signing_key(
        &self,
        identity_key: &[u8; 32],
        signing_key: &[u8; 32],
    ) -> Result<(), String> {
        let existing: Option<Vec<u8>> = match self.conn.query_row(
            "SELECT signing_key FROM trusted_identity_keys WHERE identity_key = ?1",
            rusqlite::params![identity_key.as_slice()],
            |row| row.get(0),
        ) {
            Ok(value) => Some(value),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(format!("load trusted signing key: {e}")),
        };
        if let Some(existing) = existing {
            if existing.as_slice() != signing_key {
                return Err("trusted signing key changed for pinned identity".to_string());
            }
            return Ok(());
        }
        self.conn
            .execute(
                "INSERT INTO trusted_identity_keys (identity_key, signing_key) VALUES (?1, ?2)",
                rusqlite::params![identity_key.as_slice(), signing_key.as_slice()],
            )
            .map_err(|e| format!("pin trusted signing key: {e}"))?;
        Ok(())
    }

    pub fn load_trusted_signing_keys(&self) -> Result<Vec<TrustedSigningKeyBinding>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT identity_key, signing_key FROM trusted_identity_keys")
            .map_err(|e| format!("prepare trusted signing keys: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| format!("query trusted signing keys: {e}"))?;
        let mut result = Vec::new();
        for row in rows {
            let (identity, signing) = row.map_err(|e| format!("read trusted key: {e}"))?;
            let identity = identity.try_into().map_err(|v: Vec<u8>| {
                format!("invalid trusted identity key length: {}", v.len())
            })?;
            let signing = signing
                .try_into()
                .map_err(|v: Vec<u8>| format!("invalid trusted signing key length: {}", v.len()))?;
            result.push((identity, signing));
        }
        Ok(result)
    }

    /// Store freshly generated X3DH prekeys as one transaction. Private bytes
    /// are protected by SQLCipher and zeroized by `LocalPreKey` on drop.
    pub fn save_local_prekeys(&self, keys: &[LocalPreKey]) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin local prekey transaction: {e}"))?;
        for key in keys {
            let signature = key.signature.as_ref().map(|value| value.as_slice());
            tx.execute(
                "INSERT INTO local_prekeys
                   (key_type, protocol_key_id, secret_key, public_key, signature, consumed)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)
                 ON CONFLICT(key_type, protocol_key_id) DO UPDATE SET
                   secret_key=excluded.secret_key,
                   public_key=excluded.public_key,
                   signature=excluded.signature,
                   consumed=0",
                rusqlite::params![
                    key.key_type,
                    i64::from(key.protocol_key_id),
                    key.secret_key.as_slice(),
                    key.public_key.as_slice(),
                    signature,
                ],
            )
            .map_err(|e| format!("save local prekey {}: {e}", key.protocol_key_id))?;
        }
        tx.commit()
            .map_err(|e| format!("commit local prekeys: {e}"))
    }

    /// Load only live prekeys. Consumed OTK rows retain their public IDs for
    /// monotonic allocation but never retain their private bytes.
    pub fn load_local_prekeys(&self) -> Result<Vec<LocalPreKey>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT key_type, protocol_key_id, secret_key, public_key, signature
                 FROM local_prekeys WHERE consumed = 0 ORDER BY key_type, protocol_key_id",
            )
            .map_err(|e| format!("prepare local prekeys: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, u8>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })
            .map_err(|e| format!("query local prekeys: {e}"))?;

        let mut result = Vec::new();
        for row in rows {
            let (key_type, protocol_key_id, secret, public, signature) =
                row.map_err(|e| format!("read local prekey: {e}"))?;
            let secret = Zeroizing::new(secret);
            let secret_key = secret.as_slice().try_into().map_err(|_| {
                format!(
                    "invalid local prekey secret length for {protocol_key_id}: {}",
                    secret.len()
                )
            })?;
            let public_key = public.try_into().map_err(|v: Vec<u8>| {
                format!(
                    "invalid local prekey public length for {protocol_key_id}: {}",
                    v.len()
                )
            })?;
            let signature = signature
                .map(|value| {
                    value.try_into().map_err(|v: Vec<u8>| {
                        format!(
                            "invalid local prekey signature length for {protocol_key_id}: {}",
                            v.len()
                        )
                    })
                })
                .transpose()?;
            result.push(LocalPreKey {
                key_type,
                protocol_key_id,
                secret_key,
                public_key,
                signature,
            });
        }
        Ok(result)
    }

    pub fn max_local_prekey_id(&self, key_type: u8) -> Result<u32, String> {
        let value: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(protocol_key_id), 0) FROM local_prekeys WHERE key_type = ?1",
                rusqlite::params![key_type],
                |row| row.get(0),
            )
            .map_err(|e| format!("load local prekey counter: {e}"))?;
        u32::try_from(value).map_err(|_| "local prekey id exceeds u32".to_string())
    }

    /// Atomically persist the authenticated first ratchet state and destroy the
    /// claimed one-time private key. Either both changes commit or neither does.
    pub fn commit_initial_ratchet_session(
        &self,
        peer_identity_key: &[u8; 32],
        session_data: &[u8],
        one_time_prekey_id: Option<u32>,
    ) -> Result<(), String> {
        // SAVEPOINT composes with the outer atomic receive savepoint while
        // still providing standalone all-or-nothing semantics in direct use.
        self.conn
            .execute_batch("SAVEPOINT veil_initial_ratchet")
            .map_err(|e| format!("begin initial ratchet savepoint: {e}"))?;
        let operation = (|| {
            self.conn
                .execute(
                    "INSERT OR REPLACE INTO ratchet_sessions
                       (peer_identity_key, session_data, updated_at)
                     VALUES (?1, ?2, datetime('now'))",
                    rusqlite::params![peer_identity_key.as_slice(), session_data],
                )
                .map_err(|e| format!("save initial ratchet session: {e}"))?;
            if let Some(id) = one_time_prekey_id {
                let changed = self
                    .conn
                    .execute(
                        "UPDATE local_prekeys
                         SET secret_key = NULL, consumed = 1
                         WHERE key_type = 1 AND protocol_key_id = ?1 AND consumed = 0",
                        rusqlite::params![i64::from(id)],
                    )
                    .map_err(|e| format!("consume local one-time prekey: {e}"))?;
                if changed != 1 {
                    return Err(format!(
                        "one-time prekey {id} was missing or already consumed"
                    ));
                }
            }
            Ok(())
        })();
        if let Err(error) = operation {
            let rollback = self.conn.execute_batch(
                "ROLLBACK TO SAVEPOINT veil_initial_ratchet;
                 RELEASE SAVEPOINT veil_initial_ratchet;",
            );
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback_error) => {
                    format!("{error}; initial ratchet rollback failed: {rollback_error}")
                }
            });
        }
        self.conn
            .execute_batch("RELEASE SAVEPOINT veil_initial_ratchet")
            .map_err(|e| format!("commit initial ratchet: {e}"))
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
    ) -> Result<Vec<StoredSenderKey>, String> {
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

    #[test]
    fn device_id_is_stable_across_reinitialization() {
        let db = VeilDb::open_memory(&[7u8; 32]).unwrap();
        assert_eq!(db.get_or_create_device_id([1u8; 16]).unwrap(), [1u8; 16]);
        assert_eq!(db.get_or_create_device_id([2u8; 16]).unwrap(), [1u8; 16]);
    }

    #[test]
    fn device_id_rejects_and_repairs_legacy_zero_value() {
        let db = VeilDb::open_memory(&[8u8; 32]).unwrap();
        assert!(db.get_or_create_device_id([0u8; 16]).is_err());
        db.conn
            .execute(
                "INSERT INTO client_state (key, value) VALUES ('device_id', ?1)",
                rusqlite::params![[0u8; 16].as_slice()],
            )
            .unwrap();
        assert_eq!(db.get_or_create_device_id([3u8; 16]).unwrap(), [3u8; 16]);
        assert_eq!(db.get_or_create_device_id([4u8; 16]).unwrap(), [3u8; 16]);
    }

    #[test]
    fn trusted_signing_key_is_pinned_per_identity() {
        let db = VeilDb::open_memory(&[9u8; 32]).unwrap();
        db.pin_trusted_signing_key(&[1u8; 32], &[2u8; 32]).unwrap();
        db.pin_trusted_signing_key(&[1u8; 32], &[2u8; 32]).unwrap();
        assert!(db.pin_trusted_signing_key(&[1u8; 32], &[3u8; 32]).is_err());
        assert_eq!(
            db.load_trusted_signing_keys().unwrap(),
            vec![([1u8; 32], [2u8; 32])]
        );
    }

    #[test]
    fn outgoing_ack_replaces_local_id_atomically() {
        let db = VeilDb::open_memory(&[10u8; 32]).unwrap();
        db.insert_conversation("conv-ack", 0, None, Some(&[4u8; 32]), None)
            .unwrap();
        db.insert_outgoing_pending_message("local-id", "conv-ack", &[5u8; 32], "pending", None)
            .unwrap();
        let before = db.get_messages("conv-ack", 10).unwrap();
        assert_eq!(before[0].id, "local-id");
        assert_eq!(before[0].status, crate::models::MessageStatus::Sending);

        db.acknowledge_outgoing_message("local-id", "server-id", 1234)
            .unwrap();
        let after = db.get_messages("conv-ack", 10).unwrap();
        assert_eq!(after[0].id, "server-id");
        assert_eq!(after[0].status, crate::models::MessageStatus::Sent);
        assert_eq!(after[0].server_timestamp, Some(1234));
        assert!(db
            .acknowledge_outgoing_message("local-id", "different-server-id", 1235)
            .is_err());
    }

    #[test]
    fn directory_upsert_fills_but_never_replaces_crypto_bindings() {
        let db = VeilDb::open_memory(&[11u8; 32]).unwrap();
        let peer = [4u8; 32];
        db.upsert_directory_conversation(
            "dm-directory",
            0,
            Some("Alice"),
            Some(&peer),
            None,
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        db.upsert_directory_conversation(
            "dm-directory",
            0,
            Some("Alice renamed"),
            Some(&peer),
            None,
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(
            db.get_conversations().unwrap()[0].name.as_deref(),
            Some("Alice renamed")
        );
        assert!(db
            .upsert_directory_conversation(
                "dm-directory",
                0,
                Some("Mallory"),
                Some(&[5u8; 32]),
                None,
                "2026-01-01T00:00:00Z",
            )
            .is_err());
        assert!(db
            .upsert_directory_conversation(
                "dm-directory",
                1,
                Some("type swap"),
                None,
                None,
                "2026-01-01T00:00:00Z",
            )
            .is_err());
    }

    #[test]
    fn message_exists_supports_replay_safe_offline_sync() {
        let db = VeilDb::open_memory(&[12u8; 32]).unwrap();
        db.insert_conversation("sync-conv", 1, Some("Group"), None, None)
            .unwrap();
        assert!(!db.message_exists("server-message").unwrap());
        db.insert_message(
            "server-message",
            "sync-conv",
            &[6u8; 32],
            "hello",
            false,
            Some(123),
            None,
        )
        .unwrap();
        assert!(db.message_exists("server-message").unwrap());
    }

    #[test]
    fn remote_revisions_and_reactions_reconcile_authoritatively() {
        use crate::models::{RemoteMessageStateKind, RemoteReaction};

        let db = VeilDb::open_memory(&[13u8; 32]).unwrap();
        db.insert_conversation("remote-conv", 0, None, Some(&[8u8; 32]), None)
            .unwrap();
        db.insert_message(
            "remote-message",
            "remote-conv",
            &[8u8; 32],
            "hello",
            false,
            Some(100),
            None,
        )
        .unwrap();
        db.record_remote_message_state(
            "remote-message",
            "remote-conv",
            &[8u8; 32],
            100,
            RemoteMessageStateKind::Active,
        )
        .unwrap();
        db.replace_message_reactions(
            "remote-message",
            &[
                RemoteReaction {
                    emoji: "👍".to_string(),
                    user_id: "u1".to_string(),
                    username: "Alice".to_string(),
                },
                RemoteReaction {
                    emoji: "🔥".to_string(),
                    user_id: "u2".to_string(),
                    username: "Bob".to_string(),
                },
            ],
        )
        .unwrap();
        assert_eq!(db.get_reactions("remote-message").unwrap().len(), 2);
        db.replace_message_reactions(
            "remote-message",
            &[RemoteReaction {
                emoji: "👍".to_string(),
                user_id: "u1".to_string(),
                username: "Alice".to_string(),
            }],
        )
        .unwrap();
        assert_eq!(db.get_reactions("remote-message").unwrap().len(), 1);
        assert!(db
            .record_remote_message_state(
                "remote-message",
                "other-conv",
                &[8u8; 32],
                101,
                RemoteMessageStateKind::Active,
            )
            .is_err());
        assert!(db
            .record_remote_message_state(
                "remote-message",
                "remote-conv",
                &[8u8; 32],
                99,
                RemoteMessageStateKind::Active,
            )
            .is_err());
        db.record_remote_message_state(
            "remote-message",
            "remote-conv",
            &[8u8; 32],
            100,
            RemoteMessageStateKind::Expired,
        )
        .unwrap();
        assert!(db
            .record_remote_message_state(
                "remote-message",
                "remote-conv",
                &[8u8; 32],
                100,
                RemoteMessageStateKind::Active,
            )
            .is_err());
    }

    #[test]
    fn failed_open_never_deletes_or_replaces_existing_file() {
        let path =
            std::env::temp_dir().join(format!("veil-preserve-db-{}.db", uuid::Uuid::new_v4()));
        let original = b"existing encrypted or corrupt user data";
        std::fs::write(&path, original).unwrap();

        assert!(VeilDb::open(&path, &[42u8; 32]).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn file_database_uses_full_wal_durability_for_crypto_state() {
        let path =
            std::env::temp_dir().join(format!("veil-durable-db-{}.db", uuid::Uuid::new_v4()));
        let db = VeilDb::open(&path, &[43u8; 32]).unwrap();
        let journal_mode: String = db
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        let synchronous: i64 = db
            .conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(synchronous, 2, "SQLite FULL synchronous mode is 2");
        drop(db);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn initial_ratchet_commit_atomically_consumes_otk_secret() {
        let db = VeilDb::open_memory(&[8u8; 32]).unwrap();
        db.save_local_prekeys(&[
            LocalPreKey {
                key_type: 0,
                protocol_key_id: 3,
                secret_key: [10u8; 32],
                public_key: [11u8; 32],
                signature: Some([12u8; 64]),
            },
            LocalPreKey {
                key_type: 1,
                protocol_key_id: 9,
                secret_key: [20u8; 32],
                public_key: [21u8; 32],
                signature: None,
            },
        ])
        .unwrap();
        assert_eq!(db.max_local_prekey_id(0).unwrap(), 3);
        assert_eq!(db.max_local_prekey_id(1).unwrap(), 9);
        assert_eq!(db.load_local_prekeys().unwrap().len(), 2);

        let peer = [30u8; 32];
        db.commit_initial_ratchet_session(&peer, b"ratchet-one", Some(9))
            .unwrap();
        let remaining = db.load_local_prekeys().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].key_type, 0);
        assert_eq!(
            db.load_ratchet_session(&peer).unwrap().unwrap(),
            b"ratchet-one"
        );
        let erased: (Option<Vec<u8>>, u8) = db
            .conn
            .query_row(
                "SELECT secret_key, consumed FROM local_prekeys
                 WHERE key_type = 1 AND protocol_key_id = 9",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(erased.0.is_none());
        assert_eq!(erased.1, 1);

        // Reusing the OTK fails and rolls back the attempted session update.
        assert!(db
            .commit_initial_ratchet_session(&peer, b"ratchet-two", Some(9))
            .is_err());
        assert_eq!(
            db.load_ratchet_session(&peer).unwrap().unwrap(),
            b"ratchet-one"
        );
    }
}
