use crate::models::{
    AccountSnapshot, AccountSnapshotSource, AuthenticatedDirectDirectoryEntry,
    AuthenticatedDirectHistoryScopeV1, HistoricalAccountContinuity, LocalIdentityVerification,
    Message, MessageAuthorContext, NetworkProfile, ProfileLocator,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
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

type PersistedLocalSignedPreKeyRow = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, u8);

/// Durable, origin-scoped exact-byte outbox for one X3DH publication.
///
/// The body contains public material only, but it remains inside SQLCipher so
/// request capabilities and unpublished device metadata cannot leak through a
/// renderer cache. `acknowledged` is set only after a strictly validated HTTP
/// 200 response for the exact body digest and signed-prekey id.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LocalPreKeyPublicationV1 {
    pub canonical_server_origin: String,
    pub user_id: String,
    pub device_id: [u8; 16],
    pub signed_prekey_id: u32,
    pub one_time_prekey_count: u32,
    pub request_body: Vec<u8>,
    pub body_sha256: [u8; 32],
    pub acknowledged: bool,
}

/// Exact authenticated account/device scope of the durable Direct outbox.
///
/// The server origin is part of the account locator: UUIDs issued by different
/// self-hosted nodes are deliberately never treated as interchangeable.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DirectMessageOutboxScopeV1 {
    pub canonical_server_origin: String,
    pub user_id: String,
    pub device_id: [u8; 16],
}

/// All state required to publish one new Direct ciphertext without exposing a
/// ratchet/message split-brain window.
///
/// `exact_send_message_payload` is the serialized `SendMessage` payload, not a
/// surrounding transport envelope. `veil-store` intentionally treats it as an
/// opaque bounded byte string and authenticates only its domain-separated
/// digest; protobuf interpretation remains owned by the protocol crate.
/// `expected_ratchet_revision` and `expected_ratchet_session` form one exact
/// CAS precondition; neither is sufficient by itself against same-revision
/// state replacement.
#[derive(Clone)]
pub struct DirectMessageOutboxEnqueueV1 {
    pub scope: DirectMessageOutboxScopeV1,
    pub conversation_id: String,
    pub client_message_id: String,
    pub local_message_id: String,
    pub request_digest: [u8; 32],
    pub exact_send_message_payload: Vec<u8>,
    pub expected_ratchet_revision: u64,
    pub expected_ratchet_session: Vec<u8>,
    pub advanced_ratchet_session: Vec<u8>,
    pub plaintext: String,
    pub reply_to_id: Option<String>,
    pub attachments: Vec<crate::models::MessageAttachment>,
    pub author_snapshot: Option<AccountSnapshot>,
}

impl Zeroize for DirectMessageOutboxEnqueueV1 {
    fn zeroize(&mut self) {
        self.scope.zeroize();
        self.conversation_id.zeroize();
        self.client_message_id.zeroize();
        self.local_message_id.zeroize();
        self.request_digest.zeroize();
        self.exact_send_message_payload.zeroize();
        self.expected_ratchet_revision.zeroize();
        self.expected_ratchet_session.zeroize();
        self.advanced_ratchet_session.zeroize();
        self.plaintext.zeroize();
        self.reply_to_id.zeroize();
        for attachment in &mut self.attachments {
            attachment.ordinal.zeroize();
            attachment.media_id.zeroize();
            attachment.file_name.zeroize();
            attachment.detected_mime.zeroize();
            attachment.format_version.zeroize();
            attachment.nonce_prefix.zeroize();
            attachment.chunk_count.zeroize();
            attachment.plaintext_size.zeroize();
            attachment.ciphertext_size.zeroize();
            attachment.content_key.zeroize();
        }
        self.attachments.clear();
        if let Some(snapshot) = self.author_snapshot.as_mut() {
            snapshot.locator.canonical_server_origin.zeroize();
            snapshot.locator.user_id.zeroize();
            snapshot.locator.identity_key.zeroize();
            snapshot.signing_key.zeroize();
            snapshot.username.zeroize();
            snapshot.display_name.zeroize();
            snapshot.profile_version.zeroize();
            snapshot.profile_origin.zeroize();
            snapshot.observed_at.zeroize();
        }
        self.author_snapshot = None;
    }
}

impl Drop for DirectMessageOutboxEnqueueV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Durable FIFO row returned to a reconnecting native runtime.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PendingDirectMessageOutboxV1 {
    pub queue_order: u64,
    pub scope: DirectMessageOutboxScopeV1,
    pub conversation_id: String,
    pub peer_user_id: String,
    pub peer_identity_key: [u8; 32],
    pub peer_signing_key: [u8; 32],
    pub client_message_id: String,
    pub local_message_id: String,
    pub request_digest: [u8; 32],
    pub exact_send_message_payload: Vec<u8>,
    pub ratchet_revision: u64,
    /// SQLCipher projection used only to repair the local search document
    /// when an ACK renames the provisional UUID after process restart.
    pub plaintext: String,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DirectMessageOutboxEnqueueResultV1 {
    pub queue_order: u64,
    pub client_message_id: String,
    pub local_message_id: String,
    pub ratchet_revision: u64,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DirectMessageOutboxAckResultV1 {
    pub client_message_id: String,
    pub local_message_id: String,
    pub server_message_id: String,
    pub server_timestamp_ms: i64,
    pub already_acknowledged: bool,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DirectMessageOutboxRejectResultV1 {
    pub client_message_id: String,
    pub local_message_id: String,
    pub rejection_reason: String,
    pub already_rejected: bool,
}

/// Read-only durable state used by the authenticated client to distinguish a
/// harmless repeated receipt from an unknown or conflicting wire result
/// before any ACK/Error reconciliation mutates SQLCipher or process memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub enum DirectMessageOutboxReceiptV1 {
    Pending {
        local_message_id: String,
    },
    Acknowledged {
        local_message_id: String,
        server_message_id: String,
        server_timestamp_ms: i64,
    },
    Rejected {
        local_message_id: String,
        rejection_reason: String,
    },
}

/// Serialized ratchet state and the CAS revision that protects its next write.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RatchetSessionWithRevisionV1 {
    pub session_data: Vec<u8>,
    pub revision: u64,
}

/// Public, non-secret Direct v2 session coordinates stored beside one ratchet.
/// `binding_data` is a strictly parsed client-owned record; SQLCipher treats it
/// as opaque bytes but independently pins the session and device identifiers
/// needed to detect row substitution before hydration.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DirectSessionBindingBlobV2 {
    pub peer_identity_key: [u8; 32],
    pub session_id: [u8; 32],
    pub local_device_id: [u8; 16],
    pub peer_device_id: [u8; 16],
    pub binding_data: Vec<u8>,
}

/// One immutable reservation from the SQLCipher-backed prekey allocator.
///
/// Reservations are committed before key generation. Consequently a crash or
/// persistence failure may leave gaps, but two clients opening the same local
/// database can never assign one protocol id to different private material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalPreKeyIdReservationV1 {
    pub signed_prekey_id: u32,
    pub one_time_prekey_start_id: u32,
    pub next_signed_prekey_id: u32,
    pub next_one_time_prekey_id: u32,
}

/// One immutable reservation for an OPK-only inventory refill. The current
/// signed prekey stays pinned, so delayed initial messages remain decryptable
/// while replenishment advances only the one-time-key namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalOneTimePreKeyIdReservationV1 {
    pub one_time_prekey_start_id: u32,
    pub next_one_time_prekey_id: u32,
}

/// Exact Node-signed proof accepted into SQLCipher only after signature,
/// inclusion, pinned-log and append-only consistency checks all pass.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdentityTransparencyProofV1 {
    pub canonical_server_origin: String,
    pub log_id: [u8; 32],
    pub node_signing_key: [u8; 32],
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    pub issued_at_ms: u64,
    pub tree_head_signature: [u8; 64],
    pub canonical_event: Vec<u8>,
    pub leaf_index: u64,
    pub inclusion_proof: Vec<[u8; 32]>,
    pub consistency_from: u64,
    pub consistency_proof: Vec<[u8; 32]>,
    /// Hash of the independently configured witness key set and threshold.
    /// All-zero with quorum zero means no witness policy was configured.
    pub witness_policy_hash: [u8; 32],
    pub witness_quorum: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityTransparencyAcceptanceV1 {
    FirstContactPinned,
    CurrentHeadConfirmed,
    AppendOnlyAdvancePinned,
    /// SQLCipher was behind a valid OS-secure monotonic anchor and has been
    /// advanced to an exact Node-signed head extending that stronger anchor.
    RollbackAnchorRecovered,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdentityTransparencyPinnedHeadV1 {
    pub canonical_server_origin: String,
    pub log_id: [u8; 32],
    pub node_signing_key: [u8; 32],
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    pub issued_at_ms: u64,
    pub tree_head_signature: [u8; 64],
    pub witness_policy_hash: [u8; 32],
    /// Zero until a separately configured independent witness quorum has
    /// confirmed this exact head. Node signatures alone are never counted.
    pub witness_quorum: u32,
}

const LOCAL_PREKEY_PUBLICATION_BODY_LIMIT: usize = 64 * 1024;
const LOCAL_PREKEY_PUBLICATION_BATCH_SIZE: usize = 20;
pub const DIRECT_MESSAGE_OUTBOX_MAX_PAYLOAD_BYTES_V1: usize = 256 * 1024;
pub const DIRECT_MESSAGE_OUTBOX_MAX_PENDING_V1: usize = 256;
pub const DIRECT_MESSAGE_OUTBOX_MAX_LOAD_V1: usize = 256;
const DIRECT_MESSAGE_RATCHET_MAX_BYTES_V1: usize = 1024 * 1024;
const DIRECT_SESSION_BINDING_MAX_BYTES_V2: usize = 4096;
const DIRECT_MESSAGE_RATCHET_MAX_BYTES_SQLITE_V1: i64 = 1024 * 1024;
const DIRECT_MESSAGE_RATCHET_UPDATED_AT_MAX_CHARS_SQLITE_V1: i64 = 64;
/// Maximum number of durable pairwise ratchets hydrated into one native epoch.
pub const DIRECT_RATCHET_SESSION_MAX_ROWS_V1: usize = 4096;
/// Maximum aggregate serialized ratchet bytes hydrated into one native epoch.
pub const DIRECT_RATCHET_SESSION_MAX_TOTAL_BYTES_V1: usize = 64 * 1024 * 1024;
const DIRECT_RATCHET_SESSION_MAX_ROWS_SQLITE_V1: i64 = 4096;
const DIRECT_RATCHET_SESSION_MAX_TOTAL_BYTES_SQLITE_V1: i64 = 64 * 1024 * 1024;
const DIRECT_MESSAGE_PLAINTEXT_MAX_BYTES_V1: usize = 32 * 1024;
const DIRECT_MESSAGE_REJECTION_REASON_MAX_BYTES_V1: usize = 128;
const DIRECT_MESSAGE_DIGEST_DOMAIN_V1: &[u8] = b"veil.message.send.v1\x00";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RatchetSessionSchemaShapeV1 {
    LegacyWithoutRevision,
    LegacyWithRevision,
    HardenedWithoutRowid,
}

impl RatchetSessionSchemaShapeV1 {
    fn has_revision(self) -> bool {
        !matches!(self, Self::LegacyWithoutRevision)
    }
}

const RATCHET_SESSION_LEGACY_NO_REVISION_DDL_V1: &str = concat!(
    "create table ratchet_sessions(",
    "peer_identity_key blob primary key,",
    "session_data blob not null,",
    "updated_at text not null default(datetime('now'))",
    ")"
);
const RATCHET_SESSION_LEGACY_REVISION_BEFORE_UPDATED_DDL_V1: &str = concat!(
    "create table ratchet_sessions(",
    "peer_identity_key blob primary key,",
    "session_data blob not null,",
    "revision integer not null default 0 check(revision>=0),",
    "updated_at text not null default(datetime('now'))",
    ")"
);
const RATCHET_SESSION_LEGACY_REVISION_AFTER_UPDATED_DDL_V1: &str = concat!(
    "create table ratchet_sessions(",
    "peer_identity_key blob primary key,",
    "session_data blob not null,",
    "updated_at text not null default(datetime('now')),",
    "revision integer not null default 0 check(revision>=0)",
    ")"
);
const RATCHET_SESSION_HARDENED_DDL_V1: &str = concat!(
    "create table ratchet_sessions(",
    "peer_identity_key blob not null primary key ",
    "check(typeof(peer_identity_key)='blob' and length(peer_identity_key)=32),",
    "session_data blob not null ",
    "check(typeof(session_data)='blob' and length(session_data)between 1 and 1048576),",
    "revision integer not null default 0 check(revision>=0),",
    "updated_at text not null default(datetime('now'))",
    "check(typeof(updated_at)='text' and length(updated_at)between 1 and 64)",
    ")without rowid"
);
const RATCHET_SESSION_CAPACITY_TRIGGER_NAMES_V1: [&str; 6] = [
    "ratchet_session_capacity_insert_v1",
    "ratchet_session_capacity_insert_commit_v1",
    "ratchet_session_capacity_update_v1",
    "ratchet_session_capacity_update_commit_v1",
    "ratchet_session_capacity_delete_v1",
    "ratchet_session_capacity_delete_commit_v1",
];

/// Normalize only the exact ASCII DDL emitted by Veil's historical migrations.
/// Comments and non-separating whitespace are discarded; token-separating
/// whitespace is canonicalized so distinct declarations cannot alias after
/// compaction. Quoted bytes stay exact to preserve string/collation semantics.
fn normalize_ratchet_session_ddl_v1(sql: &str) -> Result<String, String> {
    fn token_edge(byte: u8) -> bool {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'_' | b'$' | b'\'' | b'"' | b'`' | b'[' | b']')
    }

    if !sql.is_ascii() {
        return Err("ratchet session table DDL is not canonical ASCII".to_string());
    }
    let bytes = sql.as_bytes();
    let mut normalized = String::with_capacity(bytes.len());
    let mut index = 0usize;
    let mut quoted_until: Option<u8> = None;
    let mut separator_pending = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(quote_end) = quoted_until {
            normalized.push(char::from(byte));
            if byte == quote_end {
                if quote_end != b']' && bytes.get(index + 1) == Some(&quote_end) {
                    normalized.push(char::from(quote_end));
                    index += 2;
                    continue;
                }
                quoted_until = None;
            }
            index += 1;
            continue;
        }

        if separator_pending {
            if normalized
                .as_bytes()
                .last()
                .copied()
                .is_some_and(token_edge)
                && token_edge(byte)
            {
                normalized.push(' ');
            }
            separator_pending = false;
        }

        match byte {
            b'\'' | b'"' | b'`' => {
                quoted_until = Some(byte);
                normalized.push(char::from(byte));
                index += 1;
            }
            b'[' => {
                quoted_until = Some(b']');
                normalized.push('[');
                index += 1;
            }
            b'-' if bytes.get(index + 1) == Some(&b'-') => {
                separator_pending = true;
                index += 2;
                while index < bytes.len() && !matches!(bytes[index], b'\r' | b'\n') {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                separator_pending = true;
                index += 2;
                let mut closed = false;
                while index + 1 < bytes.len() {
                    if bytes[index] == b'*' && bytes[index + 1] == b'/' {
                        index += 2;
                        closed = true;
                        break;
                    }
                    index += 1;
                }
                if !closed {
                    return Err("ratchet session table DDL has an unterminated comment".to_string());
                }
            }
            byte if byte.is_ascii_whitespace() => {
                separator_pending = true;
                index += 1;
            }
            _ => {
                normalized.push(char::from(byte.to_ascii_lowercase()));
                index += 1;
            }
        }
    }
    if quoted_until.is_some() {
        return Err("ratchet session table DDL has an unterminated quote".to_string());
    }
    if normalized.ends_with(';') {
        normalized.pop();
    }
    Ok(normalized)
}

fn classify_ratchet_session_schema_v1(
    without_rowid: i64,
    strict: i64,
    sql: &str,
) -> Result<RatchetSessionSchemaShapeV1, String> {
    if strict != 0 {
        return Err("ratchet session table has unsupported STRICT semantics".to_string());
    }
    let normalized = normalize_ratchet_session_ddl_v1(sql)?;
    match (without_rowid, normalized.as_str()) {
        (0, RATCHET_SESSION_LEGACY_NO_REVISION_DDL_V1) => {
            Ok(RatchetSessionSchemaShapeV1::LegacyWithoutRevision)
        }
        (
            0,
            RATCHET_SESSION_LEGACY_REVISION_BEFORE_UPDATED_DDL_V1
            | RATCHET_SESSION_LEGACY_REVISION_AFTER_UPDATED_DDL_V1,
        ) => Ok(RatchetSessionSchemaShapeV1::LegacyWithRevision),
        (1, RATCHET_SESSION_HARDENED_DDL_V1) => {
            Ok(RatchetSessionSchemaShapeV1::HardenedWithoutRowid)
        }
        (0 | 1, _) => {
            Err("ratchet session table DDL is not an exact supported historical shape".to_string())
        }
        _ => Err("ratchet session table has an invalid WITHOUT ROWID marker".to_string()),
    }
}

fn validate_ratchet_session_blob_v1(session_data: &[u8]) -> Result<(), String> {
    if session_data.is_empty() || session_data.len() > DIRECT_MESSAGE_RATCHET_MAX_BYTES_V1 {
        return Err("ratchet session is empty or oversized".to_string());
    }
    Ok(())
}

fn validate_direct_session_binding_blob_v2(
    peer_identity_key: &[u8; 32],
    binding: &DirectSessionBindingBlobV2,
) -> Result<(), String> {
    if binding.peer_identity_key != *peer_identity_key
        || binding.peer_identity_key == [0u8; 32]
        || binding.session_id == [0u8; 32]
        || binding.local_device_id == [0u8; 16]
        || binding.peer_device_id == [0u8; 16]
        || binding.local_device_id == binding.peer_device_id
        || binding.binding_data.is_empty()
        || binding.binding_data.len() > DIRECT_SESSION_BINDING_MAX_BYTES_V2
    {
        return Err("Direct v2 session binding is malformed".to_string());
    }
    Ok(())
}

fn insert_direct_session_binding_v2(
    connection: &Connection,
    binding: &DirectSessionBindingBlobV2,
) -> Result<(), String> {
    validate_direct_session_binding_blob_v2(&binding.peer_identity_key, binding)?;
    connection
        .execute(
            "INSERT INTO direct_session_bindings_v2
               (peer_identity_key, wire_version, session_id, local_device_id,
                peer_device_id, binding_data)
             VALUES (?1, 2, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                binding.peer_identity_key.as_slice(),
                binding.session_id.as_slice(),
                binding.local_device_id.as_slice(),
                binding.peer_device_id.as_slice(),
                &binding.binding_data,
            ],
        )
        .map(|_| ())
        .map_err(|error| format!("insert Direct v2 session binding: {error}"))
}

fn create_direct_session_binding_table_v2(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS direct_session_bindings_v2 (
                peer_identity_key BLOB NOT NULL PRIMARY KEY
                    CHECK(typeof(peer_identity_key) = 'blob' AND length(peer_identity_key) = 32)
                    REFERENCES ratchet_sessions(peer_identity_key)
                    ON UPDATE RESTRICT ON DELETE CASCADE,
                wire_version INTEGER NOT NULL DEFAULT 2 CHECK(wire_version = 2),
                session_id BLOB NOT NULL
                    CHECK(typeof(session_id) = 'blob' AND length(session_id) = 32),
                local_device_id BLOB NOT NULL
                    CHECK(typeof(local_device_id) = 'blob' AND length(local_device_id) = 16),
                peer_device_id BLOB NOT NULL
                    CHECK(typeof(peer_device_id) = 'blob' AND length(peer_device_id) = 16),
                binding_data BLOB NOT NULL
                    CHECK(typeof(binding_data) = 'blob' AND length(binding_data) BETWEEN 1 AND 4096),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                CHECK(local_device_id <> peer_device_id)
            ) WITHOUT ROWID;",
        )
        .map_err(|error| format!("create Direct v2 binding schema: {error}"))
}

fn validate_direct_session_binding_schema_v2(connection: &Connection) -> Result<(), String> {
    let (without_rowid, strict, sql): (i64, i64, String) = connection
        .query_row(
            "SELECT table_list.wr, table_list.strict, schema.sql
             FROM pragma_table_list AS table_list
             JOIN sqlite_schema AS schema ON schema.name = table_list.name
             WHERE table_list.schema = 'main'
               AND table_list.type = 'table'
               AND table_list.name = 'direct_session_bindings_v2'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| format!("inspect Direct v2 binding table: {error}"))?;
    if without_rowid != 1 || strict != 0 {
        return Err("Direct v2 binding table kind is unsupported".to_string());
    }
    let normalized = normalize_ratchet_session_ddl_v1(&sql)?;
    for required in [
        "typeof(peer_identity_key)='blob'",
        "length(peer_identity_key)=32",
        "references ratchet_sessions(peer_identity_key)",
        "on update restrict on delete cascade",
        "check(wire_version=2)",
        "typeof(session_id)='blob'",
        "length(session_id)=32",
        "typeof(local_device_id)='blob'",
        "length(local_device_id)=16",
        "typeof(peer_device_id)='blob'",
        "length(peer_device_id)=16",
        "typeof(binding_data)='blob'",
        "length(binding_data)between 1 and 4096",
        "check(local_device_id<>peer_device_id)",
    ] {
        if !normalized.contains(required) {
            return Err(format!(
                "Direct v2 binding table DDL is missing required invariant {required}"
            ));
        }
    }
    let columns: Vec<(String, String, i64, i64, i64)> = {
        let mut statement = connection
            .prepare(
                "SELECT name, lower(type), \"notnull\", pk, hidden
                 FROM pragma_table_xinfo('direct_session_bindings_v2')
                 ORDER BY cid",
            )
            .map_err(|error| format!("inspect Direct v2 binding columns: {error}"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .map_err(|error| format!("query Direct v2 binding columns: {error}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("read Direct v2 binding columns: {error}"))?
    };
    let expected = [
        ("peer_identity_key", "blob", 1, 1, 0),
        ("wire_version", "integer", 1, 0, 0),
        ("session_id", "blob", 1, 0, 0),
        ("local_device_id", "blob", 1, 0, 0),
        ("peer_device_id", "blob", 1, 0, 0),
        ("binding_data", "blob", 1, 0, 0),
        ("created_at", "text", 1, 0, 0),
    ];
    if columns.len() != expected.len()
        || columns.iter().zip(expected).any(
            |((name, kind, not_null, primary_key, hidden), expected)| {
                name != expected.0
                    || kind != expected.1
                    || *not_null != expected.2
                    || *primary_key != expected.3
                    || *hidden != expected.4
            },
        )
    {
        return Err("Direct v2 binding table columns are unsupported".to_string());
    }
    let foreign_keys: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list('direct_session_bindings_v2')
             WHERE lower(\"table\") = 'ratchet_sessions'
               AND \"from\" = 'peer_identity_key' AND \"to\" = 'peer_identity_key'
               AND upper(on_update) = 'RESTRICT' AND upper(on_delete) = 'CASCADE'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("inspect Direct v2 binding foreign key: {error}"))?;
    let all_foreign_keys: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list('direct_session_bindings_v2')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("count Direct v2 binding foreign keys: {error}"))?;
    let external_objects: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE lower(tbl_name) = 'direct_session_bindings_v2'
               AND type IN ('trigger', 'view')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("inspect Direct v2 binding schema objects: {error}"))?;
    if foreign_keys != 1 || all_foreign_keys != 1 || external_objects != 0 {
        return Err("Direct v2 binding table dependencies are unsupported".to_string());
    }
    Ok(())
}

fn validate_ratchet_session_load_preflight_v1(
    row_count: i64,
    total_session_bytes: i64,
    invalid_rows: i64,
) -> Result<usize, String> {
    if invalid_rows != 0 {
        return Err("persisted ratchet session row is malformed".to_string());
    }
    if !(0..=DIRECT_RATCHET_SESSION_MAX_ROWS_SQLITE_V1).contains(&row_count) {
        return Err("persisted ratchet session row limit exceeded".to_string());
    }
    if !(0..=DIRECT_RATCHET_SESSION_MAX_TOTAL_BYTES_SQLITE_V1).contains(&total_session_bytes) {
        return Err("persisted ratchet session aggregate byte limit exceeded".to_string());
    }
    usize::try_from(row_count)
        .map_err(|_| "persisted ratchet session row count is invalid".to_string())
}

pub fn direct_message_request_digest_v1(payload: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DIRECT_MESSAGE_DIGEST_DOMAIN_V1);
    digest.update(payload);
    digest.finalize().into()
}

fn begin_immediate<'conn>(
    conn: &'conn Connection,
    operation: &str,
) -> Result<Transaction<'conn>, String> {
    Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .map_err(|error| format!("begin {operation}: {error}"))
}

fn max_local_prekey_id_on(conn: &Connection, key_type: u8) -> Result<u32, String> {
    let value: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(protocol_key_id), 0) FROM local_prekeys WHERE key_type = ?1",
            rusqlite::params![key_type],
            |row| row.get(0),
        )
        .map_err(|error| format!("load local prekey counter: {error}"))?;
    u32::try_from(value).map_err(|_| "local prekey id exceeds u32".to_string())
}

fn next_after_max_local_prekey_id(conn: &Connection, key_type: u8) -> Result<u32, String> {
    max_local_prekey_id_on(conn, key_type)?
        .checked_add(1)
        .ok_or_else(|| "local prekey id allocator is exhausted".to_string())
}

fn synchronize_local_prekey_allocator_on(conn: &Connection) -> Result<(u32, u32), String> {
    let persisted = conn
        .query_row(
            "SELECT next_signed_prekey_id, next_one_time_prekey_id
             FROM local_prekey_allocator_v1 WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|error| format!("load local prekey allocator: {error}"))?;
    let (persisted_signed, persisted_one_time) = match persisted {
        Some((signed, one_time)) => (
            u32::try_from(signed)
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| "persisted signed prekey allocator is invalid".to_string())?,
            u32::try_from(one_time)
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| "persisted one-time prekey allocator is invalid".to_string())?,
        ),
        None => (1, 1),
    };
    let next_signed = persisted_signed.max(next_after_max_local_prekey_id(conn, 0)?);
    let next_one_time = persisted_one_time.max(next_after_max_local_prekey_id(conn, 1)?);
    conn.execute(
        "INSERT INTO local_prekey_allocator_v1
           (singleton, next_signed_prekey_id, next_one_time_prekey_id, updated_at)
         VALUES (1, ?1, ?2, datetime('now'))
         ON CONFLICT(singleton) DO UPDATE SET
           next_signed_prekey_id = excluded.next_signed_prekey_id,
           next_one_time_prekey_id = excluded.next_one_time_prekey_id,
           updated_at = datetime('now')",
        rusqlite::params![i64::from(next_signed), i64::from(next_one_time)],
    )
    .map_err(|error| format!("synchronize local prekey allocator: {error}"))?;
    Ok((next_signed, next_one_time))
}

fn validate_local_prekey_publication_record(
    publication: &LocalPreKeyPublicationV1,
) -> Result<(), String> {
    validate_canonical_server_origin(&publication.canonical_server_origin)?;
    validate_canonical_uuid("local prekey publication user id", &publication.user_id)?;
    if publication.device_id == [0u8; 16] {
        return Err("local prekey publication device is invalid".to_string());
    }
    if publication.signed_prekey_id == 0 {
        return Err("local prekey publication SPK id is invalid".to_string());
    }
    if publication.one_time_prekey_count as usize != LOCAL_PREKEY_PUBLICATION_BATCH_SIZE {
        return Err("local prekey publication OPK count is invalid".to_string());
    }
    if publication.request_body.is_empty()
        || publication.request_body.len() > LOCAL_PREKEY_PUBLICATION_BODY_LIMIT
    {
        return Err("local prekey publication body is empty or oversized".to_string());
    }
    let calculated: [u8; 32] = Sha256::digest(&publication.request_body).into();
    if calculated != publication.body_sha256 {
        return Err("local prekey publication body digest is invalid".to_string());
    }
    Ok(())
}

fn validate_local_prekey_publication_input(
    keys: &[LocalPreKey],
    publication: &LocalPreKeyPublicationV1,
) -> Result<(), String> {
    validate_local_prekey_publication_record(publication)?;
    if publication.acknowledged {
        return Err("a newly generated prekey publication cannot be acknowledged".to_string());
    }
    if keys.len() != LOCAL_PREKEY_PUBLICATION_BATCH_SIZE + 1 {
        return Err("local prekey publication must contain one SPK and 20 OPKs".to_string());
    }

    let mut seen = HashSet::with_capacity(keys.len());
    let mut signed_count = 0usize;
    let mut one_time_count = 0usize;
    for key in keys {
        if key.protocol_key_id == 0 || !seen.insert((key.key_type, key.protocol_key_id)) {
            return Err("local prekey publication contains an invalid or duplicate id".to_string());
        }
        if key.secret_key == [0u8; 32] || key.public_key == [0u8; 32] {
            return Err("local prekey publication contains invalid key material".to_string());
        }
        match key.key_type {
            0 => {
                signed_count += 1;
                if key.protocol_key_id != publication.signed_prekey_id
                    || key.signature.is_none_or(|signature| signature == [0u8; 64])
                {
                    return Err(
                        "local prekey publication SPK does not match its outbox".to_string()
                    );
                }
            }
            1 => {
                one_time_count += 1;
                if key.signature.is_some() {
                    return Err("local one-time prekeys must not contain signatures".to_string());
                }
            }
            _ => return Err("local prekey publication contains an invalid key type".to_string()),
        }
    }
    if signed_count != 1 || one_time_count != LOCAL_PREKEY_PUBLICATION_BATCH_SIZE {
        return Err("local prekey publication batch shape is invalid".to_string());
    }
    Ok(())
}

fn validate_local_prekey_refill_input(
    signed_prekey: &LocalPreKey,
    one_time_prekeys: &[LocalPreKey],
    publication: &LocalPreKeyPublicationV1,
) -> Result<(), String> {
    validate_local_prekey_publication_record(publication)?;
    if publication.acknowledged {
        return Err("a newly generated prekey refill cannot be acknowledged".to_string());
    }
    if signed_prekey.key_type != 0
        || signed_prekey.protocol_key_id != publication.signed_prekey_id
        || signed_prekey.protocol_key_id == 0
        || signed_prekey.secret_key == [0u8; 32]
        || signed_prekey.public_key == [0u8; 32]
        || signed_prekey
            .signature
            .is_none_or(|signature| signature == [0u8; 64])
    {
        return Err("local prekey refill SPK is invalid or differs from its outbox".to_string());
    }
    if one_time_prekeys.len() != LOCAL_PREKEY_PUBLICATION_BATCH_SIZE {
        return Err("local prekey refill must contain 20 OPKs".to_string());
    }
    let mut seen = HashSet::with_capacity(one_time_prekeys.len());
    for key in one_time_prekeys {
        if key.key_type != 1
            || key.protocol_key_id == 0
            || !seen.insert(key.protocol_key_id)
            || key.secret_key == [0u8; 32]
            || key.public_key == [0u8; 32]
            || key.signature.is_some()
        {
            return Err("local prekey refill contains an invalid or duplicate OPK".to_string());
        }
    }
    Ok(())
}

fn validate_local_prekey_publication_scope_on(
    tx: &Transaction<'_>,
    publication: &LocalPreKeyPublicationV1,
) -> Result<(), String> {
    let authenticated = load_authenticated_self_binding(tx, &publication.canonical_server_origin)?
        .ok_or("authenticated self binding is unavailable for prekey publication")?;
    if authenticated.user_id != publication.user_id {
        return Err("prekey publication user differs from authenticated self".to_string());
    }

    let persisted_device: Vec<u8> = tx
        .query_row(
            "SELECT device_id FROM device_identity_v1 WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|e| format!("load local device for prekey publication: {e}"))?;
    if persisted_device.as_slice() != publication.device_id.as_slice() {
        return Err("prekey publication device differs from the local installation".to_string());
    }

    let existing_pending: Option<u8> = tx
        .query_row(
            "SELECT acknowledged FROM local_prekey_publications_v1
             WHERE canonical_server_origin = ?1 AND user_id = ?2 AND device_id = ?3",
            rusqlite::params![
                publication.canonical_server_origin,
                publication.user_id,
                publication.device_id.as_slice(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("load existing local prekey publication: {e}"))?;
    if existing_pending == Some(0) {
        return Err(
            "an unacknowledged prekey publication already exists for this node".to_string(),
        );
    }
    Ok(())
}

fn save_local_prekey_publication_outbox_on(
    tx: &Transaction<'_>,
    publication: &LocalPreKeyPublicationV1,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO local_prekey_publications_v1
           (canonical_server_origin, user_id, device_id, signed_prekey_id,
            one_time_prekey_count, request_body, body_sha256, acknowledged,
            created_at, acknowledged_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, datetime('now'), NULL, datetime('now'))
         ON CONFLICT(canonical_server_origin, user_id, device_id) DO UPDATE SET
            signed_prekey_id=excluded.signed_prekey_id,
            one_time_prekey_count=excluded.one_time_prekey_count,
            request_body=excluded.request_body,
            body_sha256=excluded.body_sha256,
            acknowledged=0,
            created_at=datetime('now'),
            acknowledged_at=NULL,
            updated_at=datetime('now')",
        rusqlite::params![
            publication.canonical_server_origin,
            publication.user_id,
            publication.device_id.as_slice(),
            i64::from(publication.signed_prekey_id),
            i64::from(publication.one_time_prekey_count),
            publication.request_body.as_slice(),
            publication.body_sha256.as_slice(),
        ],
    )
    .map_err(|e| format!("save local prekey publication outbox: {e}"))?;
    Ok(())
}

/// Private per-install device identity stored only inside SQLCipher. Public
/// fields and the account signature are duplicated deliberately: loading code
/// can derive the public keys again and reject silent private-key corruption.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LocalDeviceIdentityV1 {
    pub device_id: [u8; 16],
    pub version: u64,
    pub x25519_secret: [u8; 32],
    pub ed25519_secret: [u8; 32],
    pub device_identity_key: [u8; 32],
    pub device_signing_key: [u8; 32],
    pub capabilities: u64,
    pub status: u8,
    pub account_identity_key: [u8; 32],
    pub account_signing_key: [u8; 32],
    pub account_signature: [u8; 64],
}

/// Encrypted SQLite database using SQLCipher.
pub struct VeilDb {
    conn: Connection,
}

/// Durable mobile reconnect selection resolved through the immutable
/// authenticated-self binding for the selected canonical origin.
///
/// No credential, bearer token, WebSocket URL, or caller-controlled endpoint
/// is persisted here. The expected user ID is returned from the pinned
/// authenticated-self row after its account keys have been revalidated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileReconnectTargetV1 {
    pub canonical_server_origin: String,
    pub expected_user_id: String,
}

pub type PendingInitialHeaderRow = ([u8; 32], Vec<u8>);
pub type MessageBinding = (String, Vec<u8>, bool, Option<i64>);
pub type TrustedSigningKeyBinding = ([u8; 32], [u8; 32]);
pub type StoredSenderKey = (Vec<u8>, Vec<u8>, bool);
type StoredSenderKeyMaterial = ([u8; 32], Zeroizing<Vec<u8>>);

/// Exact-origin SQLCipher context for one current search result.
///
/// The native layer serializes these messages through the same renderer
/// mapper as `get_messages`; this storage type deliberately contains no
/// search-index data or navigation authority.
#[derive(Debug, Clone)]
pub struct SearchResultContext {
    pub conversation_type: crate::models::ConversationType,
    pub server_id: Option<String>,
    pub messages: Vec<Message>,
}

const MAX_RETAINED_SENDER_KEY_GENERATIONS_PER_SENDER: usize = 128;
const MAX_CANONICAL_SERVER_ORIGIN_BYTES: usize = 512;
const MAX_PROFILE_ORIGIN_BYTES: usize = 512;
const MAX_ACCOUNT_PRESENTATION_BYTES: usize = 256;
const MAX_NETWORK_PROFILE_DISPLAY_BYTES: usize = 512;
const MAX_NETWORK_PROFILE_ABOUT_BYTES: usize = 2048;
const MAX_OBSERVED_AT_BYTES: usize = 64;

struct RawAccountSnapshot {
    canonical_server_origin: String,
    user_id: String,
    identity_key: Vec<u8>,
    signing_key: Vec<u8>,
    username: Option<String>,
    display_name: Option<String>,
    profile_version: Option<Vec<u8>>,
    profile_origin: String,
    source: u8,
    observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthenticatedSelfBinding {
    user_id: String,
    identity_key: [u8; 32],
    signing_key: [u8; 32],
}

impl RawAccountSnapshot {
    fn decode(self) -> Result<AccountSnapshot, String> {
        let identity_key = fixed_bytes::<32>("account identity key", self.identity_key)?;
        let signing_key = fixed_bytes::<32>("account signing key", self.signing_key)?;
        let profile_version = self
            .profile_version
            .map(|value| fixed_bytes::<8>("account profile version", value).map(u64::from_be_bytes))
            .transpose()?;
        let source = AccountSnapshotSource::from_u8(self.source)
            .ok_or_else(|| format!("invalid persisted account snapshot source: {}", self.source))?;
        let snapshot = AccountSnapshot {
            locator: ProfileLocator {
                canonical_server_origin: self.canonical_server_origin,
                user_id: self.user_id,
                identity_key,
            },
            signing_key,
            username: self.username,
            display_name: self.display_name,
            profile_version,
            profile_origin: self.profile_origin,
            source,
            observed_at: self.observed_at,
        };
        validate_account_snapshot(&snapshot)?;
        Ok(snapshot)
    }
}

fn raw_account_snapshot_from_row(
    row: &Row<'_>,
    first_column: usize,
) -> rusqlite::Result<Option<RawAccountSnapshot>> {
    let canonical_server_origin: Option<String> = row.get(first_column)?;
    Ok(match canonical_server_origin {
        Some(canonical_server_origin) => Some(RawAccountSnapshot {
            canonical_server_origin,
            user_id: row.get(first_column + 1)?,
            identity_key: row.get(first_column + 2)?,
            signing_key: row.get(first_column + 3)?,
            username: row.get(first_column + 4)?,
            display_name: row.get(first_column + 5)?,
            profile_version: row.get(first_column + 6)?,
            profile_origin: row.get(first_column + 7)?,
            source: row.get(first_column + 8)?,
            observed_at: row.get(first_column + 9)?,
        }),
        None => None,
    })
}

fn raw_account_snapshot_required_from_row(
    row: &Row<'_>,
    first_column: usize,
) -> rusqlite::Result<RawAccountSnapshot> {
    Ok(RawAccountSnapshot {
        canonical_server_origin: row.get(first_column)?,
        user_id: row.get(first_column + 1)?,
        identity_key: row.get(first_column + 2)?,
        signing_key: row.get(first_column + 3)?,
        username: row.get(first_column + 4)?,
        display_name: row.get(first_column + 5)?,
        profile_version: row.get(first_column + 6)?,
        profile_origin: row.get(first_column + 7)?,
        source: row.get(first_column + 8)?,
        observed_at: row.get(first_column + 9)?,
    })
}

fn validate_canonical_uuid(label: &str, value: &str) -> Result<(), String> {
    let parsed =
        uuid::Uuid::parse_str(value).map_err(|_| format!("{label} must be a canonical UUID"))?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(format!("{label} must be a non-nil canonical UUID"));
    }
    Ok(())
}

fn validate_canonical_server_origin(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_CANONICAL_SERVER_ORIGIN_BYTES
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err("canonical server origin is empty, oversized, or non-canonical".to_string());
    }
    let authority = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or_else(|| "canonical server origin must use http or https".to_string())?;
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || authority.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err("canonical server origin must contain only an authority".to_string());
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, port) = bracketed.split_once("]:").ok_or_else(|| {
            "canonical IPv6 server origin must include an explicit port".to_string()
        })?;
        if host.is_empty()
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.'))
        {
            return Err("canonical server origin contains an invalid IPv6 host".to_string());
        }
        (host, port)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| "canonical server origin must include an explicit port".to_string())?;
        if host.is_empty()
            || !host.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
            })
        {
            return Err("canonical server origin contains an invalid host".to_string());
        }
        (host, port)
    };
    if host.is_empty()
        || port
            .parse::<u16>()
            .ok()
            .is_none_or(|parsed| parsed == 0 || parsed.to_string() != port)
    {
        return Err("canonical server origin contains an invalid port".to_string());
    }
    Ok(())
}

fn validate_bounded_text(
    label: &str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), String> {
    if value.len() > max_bytes
        || (!allow_empty && value.is_empty())
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} is empty, oversized, or contains control characters"
        ));
    }
    Ok(())
}

fn validate_optional_presentation(label: &str, value: Option<&str>) -> Result<(), String> {
    if let Some(value) = value {
        validate_bounded_text(label, value, MAX_ACCOUNT_PRESENTATION_BYTES, false)?;
    }
    Ok(())
}

fn validate_profile_locator(locator: &ProfileLocator) -> Result<(), String> {
    validate_canonical_server_origin(&locator.canonical_server_origin)?;
    validate_canonical_uuid("profile locator user id", &locator.user_id)?;
    if locator.identity_key == [0u8; 32] {
        return Err("profile locator identity key must not be all zero".to_string());
    }
    Ok(())
}

fn is_directional_control(value: char) -> bool {
    matches!(
        value,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'
            | '\u{202b}'
            | '\u{202c}'
            | '\u{202d}'
            | '\u{202e}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
            | '\u{206a}'
            | '\u{206b}'
            | '\u{206c}'
            | '\u{206d}'
            | '\u{206e}'
            | '\u{206f}'
    )
}

fn is_unsafe_profile_invisible(value: char) -> bool {
    matches!(
        value,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{180e}'
            | '\u{200b}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{2060}'
            | '\u{feff}'
    )
}

fn validate_network_profile(profile: &NetworkProfile) -> Result<(), String> {
    validate_profile_locator(&profile.locator)?;
    if profile.profile_version > i64::MAX as u64 {
        return Err("network profile version exceeds the server contract".to_string());
    }
    validate_bounded_text(
        "network profile username",
        &profile.username,
        MAX_ACCOUNT_PRESENTATION_BYTES,
        false,
    )?;
    if let Some(display_name) = profile.display_name.as_deref() {
        validate_bounded_text(
            "network profile display name",
            display_name,
            MAX_NETWORK_PROFILE_DISPLAY_BYTES,
            false,
        )?;
    }
    if profile.about.len() > MAX_NETWORK_PROFILE_ABOUT_BYTES {
        return Err("network profile presentation text is oversized".to_string());
    }
    match (
        profile.avatar_asset_id.as_deref(),
        profile.avatar_digest,
        profile.avatar_content_type.as_deref(),
    ) {
        (None, None, None) => {}
        (Some(asset_id), Some(digest), Some("image/jpeg")) => {
            let parsed = uuid::Uuid::parse_str(asset_id)
                .map_err(|_| "network profile avatar id is invalid".to_string())?;
            if parsed.hyphenated().to_string() != asset_id || digest == [0u8; 32] {
                return Err("network profile avatar metadata is invalid".to_string());
            }
        }
        _ => return Err("network profile avatar metadata is incomplete".to_string()),
    }
    for value in std::iter::once(&profile.username)
        .chain(profile.display_name.iter())
        .chain(std::iter::once(&profile.about))
    {
        if value.chars().any(|character| {
            is_directional_control(character) || is_unsafe_profile_invisible(character)
        }) {
            return Err("network profile contains unsafe invisible characters".to_string());
        }
    }
    if profile
        .about
        .chars()
        .any(|character| character != '\n' && character.is_control())
    {
        return Err("network profile about contains control characters".to_string());
    }
    validate_bounded_text(
        "network profile update timestamp",
        &profile.profile_updated_at,
        MAX_OBSERVED_AT_BYTES,
        false,
    )?;
    validate_bounded_text(
        "network profile observation timestamp",
        &profile.observed_at,
        MAX_OBSERVED_AT_BYTES,
        false,
    )
}

fn validate_account_snapshot_envelope(snapshot: &AccountSnapshot) -> Result<(), String> {
    validate_profile_locator(&snapshot.locator)?;
    validate_optional_presentation("account username", snapshot.username.as_deref())?;
    validate_optional_presentation("account display name", snapshot.display_name.as_deref())?;
    if snapshot.profile_origin.len() > MAX_PROFILE_ORIGIN_BYTES {
        return Err("account profile origin is oversized".to_string());
    }
    validate_canonical_server_origin(&snapshot.profile_origin)?;
    if snapshot.profile_origin != snapshot.locator.canonical_server_origin {
        return Err("account profile origin differs from its locator origin".to_string());
    }
    validate_bounded_text(
        "account observation timestamp",
        &snapshot.observed_at,
        MAX_OBSERVED_AT_BYTES,
        false,
    )
}

fn validate_account_snapshot(snapshot: &AccountSnapshot) -> Result<(), String> {
    validate_account_snapshot_envelope(snapshot)?;
    if !veil_crypto::public_key::valid_ed25519_public_key(&snapshot.signing_key) {
        return Err("account signing key is not a valid prime-order Ed25519 key".to_string());
    }
    Ok(())
}

fn load_account_by_origin_user(
    conn: &Connection,
    canonical_server_origin: &str,
    user_id: &str,
) -> Result<Option<AccountSnapshot>, String> {
    conn.query_row(
        "SELECT canonical_server_origin, user_id, identity_key, signing_key,
                username, display_name, profile_version, profile_origin,
                source, observed_at
         FROM identity_directory_v1
         WHERE canonical_server_origin = ?1 AND user_id = ?2",
        rusqlite::params![canonical_server_origin, user_id],
        |row| raw_account_snapshot_required_from_row(row, 0),
    )
    .optional()
    .map_err(|e| format!("load account directory entry by user: {e}"))?
    .map(RawAccountSnapshot::decode)
    .transpose()
}

fn load_account_by_origin_identity(
    conn: &Connection,
    canonical_server_origin: &str,
    identity_key: &[u8; 32],
) -> Result<Option<AccountSnapshot>, String> {
    conn.query_row(
        "SELECT canonical_server_origin, user_id, identity_key, signing_key,
                username, display_name, profile_version, profile_origin,
                source, observed_at
         FROM identity_directory_v1
         WHERE canonical_server_origin = ?1 AND identity_key = ?2",
        rusqlite::params![canonical_server_origin, identity_key.as_slice()],
        |row| raw_account_snapshot_required_from_row(row, 0),
    )
    .optional()
    .map_err(|e| format!("load account directory entry by identity: {e}"))?
    .map(RawAccountSnapshot::decode)
    .transpose()
}

fn load_account_by_origin_signing(
    conn: &Connection,
    canonical_server_origin: &str,
    signing_key: &[u8; 32],
) -> Result<Option<AccountSnapshot>, String> {
    conn.query_row(
        "SELECT canonical_server_origin, user_id, identity_key, signing_key,
                username, display_name, profile_version, profile_origin,
                source, observed_at
         FROM identity_directory_v1
         WHERE canonical_server_origin = ?1 AND signing_key = ?2",
        rusqlite::params![canonical_server_origin, signing_key.as_slice()],
        |row| raw_account_snapshot_required_from_row(row, 0),
    )
    .optional()
    .map_err(|e| format!("load account directory entry by signing key: {e}"))?
    .map(RawAccountSnapshot::decode)
    .transpose()
}

fn load_exact_account(
    conn: &Connection,
    locator: &ProfileLocator,
) -> Result<Option<AccountSnapshot>, String> {
    conn.query_row(
        "SELECT canonical_server_origin, user_id, identity_key, signing_key,
                username, display_name, profile_version, profile_origin,
                source, observed_at
         FROM identity_directory_v1
         WHERE canonical_server_origin = ?1 AND user_id = ?2 AND identity_key = ?3",
        rusqlite::params![
            locator.canonical_server_origin,
            locator.user_id,
            locator.identity_key.as_slice(),
        ],
        |row| raw_account_snapshot_required_from_row(row, 0),
    )
    .optional()
    .map_err(|e| format!("load exact account directory entry: {e}"))?
    .map(RawAccountSnapshot::decode)
    .transpose()
}

fn load_authenticated_self_binding(
    conn: &Connection,
    canonical_server_origin: &str,
) -> Result<Option<AuthenticatedSelfBinding>, String> {
    let binding = conn
        .query_row(
            "SELECT user_id, identity_key, signing_key
         FROM authenticated_self_bindings_v1
         WHERE canonical_server_origin = ?1",
            rusqlite::params![canonical_server_origin],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| format!("load authenticated self binding: {error}"))?
        .map(|(user_id, identity_key, signing_key)| {
            Ok::<AuthenticatedSelfBinding, String>(AuthenticatedSelfBinding {
                user_id,
                identity_key: fixed_bytes::<32>("authenticated self identity key", identity_key)?,
                signing_key: fixed_bytes::<32>("authenticated self signing key", signing_key)?,
            })
        })
        .transpose()?;
    if let Some(binding) = binding.as_ref() {
        validate_canonical_uuid("authenticated self user id", &binding.user_id)?;
        if binding.identity_key == [0u8; 32]
            || binding.identity_key == binding.signing_key
            || !veil_crypto::public_key::valid_ed25519_public_key(&binding.signing_key)
        {
            return Err("persisted authenticated self binding has invalid keys".to_string());
        }
    }
    Ok(binding)
}

fn ensure_self_binding_directory_compatible(
    conn: &Connection,
    canonical_server_origin: &str,
    binding: &AuthenticatedSelfBinding,
) -> Result<(), String> {
    let conflict = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM identity_directory_v1
                WHERE canonical_server_origin = ?1
                  AND (user_id = ?2 OR identity_key = ?3 OR signing_key = ?4)
                  AND NOT (user_id = ?2 AND identity_key = ?3 AND signing_key = ?4)
            )",
            rusqlite::params![
                canonical_server_origin,
                &binding.user_id,
                binding.identity_key.as_slice(),
                binding.signing_key.as_slice(),
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| format!("validate authenticated self directory binding: {error}"))?;
    if conflict {
        return Err(
            "persisted identity directory conflicts with the authenticated self binding"
                .to_string(),
        );
    }
    Ok(())
}

fn validated_self_binding_for_origin(
    conn: &Connection,
    canonical_server_origin: &str,
) -> Result<Option<AuthenticatedSelfBinding>, String> {
    let binding = load_authenticated_self_binding(conn, canonical_server_origin)?;
    if let Some(binding) = binding.as_ref() {
        ensure_self_binding_directory_compatible(conn, canonical_server_origin, binding)?;
    }
    Ok(binding)
}

fn validate_authenticated_self_coordinates(
    canonical_server_origin: &str,
    user_id: &str,
    identity_key: &[u8; 32],
    signing_key: &[u8; 32],
) -> Result<(), String> {
    validate_canonical_server_origin(canonical_server_origin)?;
    validate_canonical_uuid("authenticated self user id", user_id)?;
    if identity_key == &[0u8; 32] || !veil_crypto::public_key::valid_ed25519_public_key(signing_key)
    {
        return Err("authenticated self keys are not valid account public keys".to_string());
    }
    if identity_key == signing_key {
        return Err("authenticated self identity and signing keys must be distinct".to_string());
    }
    Ok(())
}

fn bind_authenticated_self_in_transaction(
    tx: &Transaction<'_>,
    canonical_server_origin: &str,
    user_id: &str,
    identity_key: &[u8; 32],
    signing_key: &[u8; 32],
) -> Result<(), String> {
    let existing = load_authenticated_self_binding(tx, canonical_server_origin)?;

    match existing {
        Some(stored) => {
            if stored.user_id != user_id
                || stored.identity_key != *identity_key
                || stored.signing_key != *signing_key
            {
                return Err(
                    "authenticated server attempted to remap the durable self account".to_string(),
                );
            }
            ensure_self_binding_directory_compatible(tx, canonical_server_origin, &stored)?;
            tx.execute(
                "UPDATE authenticated_self_bindings_v1
                 SET last_authenticated_at = datetime('now')
                 WHERE canonical_server_origin = ?1",
                rusqlite::params![canonical_server_origin],
            )
            .map_err(|error| format!("refresh authenticated self binding: {error}"))?;
        }
        None => {
            let pending = AuthenticatedSelfBinding {
                user_id: user_id.to_string(),
                identity_key: *identity_key,
                signing_key: *signing_key,
            };
            ensure_self_binding_directory_compatible(tx, canonical_server_origin, &pending)?;
            tx.execute(
                "INSERT INTO authenticated_self_bindings_v1
                    (canonical_server_origin, user_id, identity_key, signing_key)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    canonical_server_origin,
                    user_id,
                    identity_key.as_slice(),
                    signing_key.as_slice(),
                ],
            )
            .map_err(|error| format!("insert authenticated self binding: {error}"))?;
        }
    }
    Ok(())
}

#[derive(Clone)]
struct DurableDirectOutboxRouteV1 {
    self_binding: AuthenticatedSelfBinding,
    peer_user_id: String,
    peer_identity_key: [u8; 32],
    peer_signing_key: [u8; 32],
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct StoredDirectMessageOutboxRowV1 {
    queue_order: i64,
    canonical_server_origin: String,
    user_id: String,
    device_id: Vec<u8>,
    conversation_id: String,
    peer_user_id: String,
    peer_identity_key: Vec<u8>,
    peer_signing_key: Vec<u8>,
    client_message_id: String,
    local_message_id: String,
    request_digest: Vec<u8>,
    exact_send_message_payload: Option<Vec<u8>>,
    ratchet_revision: i64,
    state: i64,
    server_message_id: Option<String>,
    server_timestamp_ms: Option<i64>,
    rejection_reason: Option<String>,
}

fn stored_direct_message_outbox_row_v1(
    row: &Row<'_>,
) -> rusqlite::Result<StoredDirectMessageOutboxRowV1> {
    Ok(StoredDirectMessageOutboxRowV1 {
        queue_order: row.get(0)?,
        canonical_server_origin: row.get(1)?,
        user_id: row.get(2)?,
        device_id: row.get(3)?,
        conversation_id: row.get(4)?,
        peer_user_id: row.get(5)?,
        peer_identity_key: row.get(6)?,
        peer_signing_key: row.get(7)?,
        client_message_id: row.get(8)?,
        local_message_id: row.get(9)?,
        request_digest: row.get(10)?,
        exact_send_message_payload: row.get(11)?,
        ratchet_revision: row.get(12)?,
        state: row.get(13)?,
        server_message_id: row.get(14)?,
        server_timestamp_ms: row.get(15)?,
        rejection_reason: row.get(16)?,
    })
}

const DIRECT_MESSAGE_OUTBOX_SELECT_V1: &str =
    "queue_order, canonical_server_origin, user_id, device_id,
     conversation_id, peer_user_id, peer_identity_key, peer_signing_key,
     client_message_id, local_message_id, request_digest,
     exact_send_message_payload, ratchet_revision, state,
     server_message_id, server_timestamp_ms, rejection_reason";

fn validate_direct_message_outbox_scope_v1(
    scope: &DirectMessageOutboxScopeV1,
) -> Result<(), String> {
    validate_canonical_server_origin(&scope.canonical_server_origin)?;
    validate_canonical_uuid("Direct outbox authenticated user id", &scope.user_id)?;
    if scope.device_id == [0u8; 16] {
        return Err("Direct outbox device id is invalid".to_string());
    }
    Ok(())
}

fn validate_direct_message_rejection_reason_v1(reason: &str) -> Result<(), String> {
    if reason.is_empty()
        || reason.len() > DIRECT_MESSAGE_REJECTION_REASON_MAX_BYTES_V1
        || !reason.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
    {
        return Err("Direct outbox rejection reason is not a stable bounded token".to_string());
    }
    Ok(())
}

fn validate_direct_message_outbox_enqueue_v1(
    input: &DirectMessageOutboxEnqueueV1,
) -> Result<(), String> {
    validate_direct_message_outbox_scope_v1(&input.scope)?;
    validate_canonical_uuid("Direct outbox conversation id", &input.conversation_id)?;
    validate_canonical_uuid("Direct outbox client message id", &input.client_message_id)?;
    validate_canonical_uuid("Direct outbox local message id", &input.local_message_id)?;
    if input.client_message_id != input.local_message_id {
        return Err(
            "Direct outbox client message id must equal its initial local message id".to_string(),
        );
    }
    if let Some(reply_to_id) = input.reply_to_id.as_deref() {
        validate_canonical_uuid("Direct outbox reply target id", reply_to_id)?;
    }
    if input.exact_send_message_payload.is_empty()
        || input.exact_send_message_payload.len() > DIRECT_MESSAGE_OUTBOX_MAX_PAYLOAD_BYTES_V1
    {
        return Err("Direct outbox payload is empty or oversized".to_string());
    }
    if direct_message_request_digest_v1(&input.exact_send_message_payload) != input.request_digest {
        return Err("Direct outbox request digest does not match its exact payload".to_string());
    }
    validate_ratchet_session_blob_v1(&input.expected_ratchet_session)
        .map_err(|error| format!("Direct outbox expected {error}"))?;
    validate_ratchet_session_blob_v1(&input.advanced_ratchet_session)
        .map_err(|error| format!("Direct outbox advanced {error}"))?;
    if input.plaintext.len() > DIRECT_MESSAGE_PLAINTEXT_MAX_BYTES_V1
        || (input.plaintext.is_empty() && input.attachments.is_empty())
    {
        return Err("Direct outbox plaintext is empty or oversized".to_string());
    }
    if input.attachments.len() > 16 {
        return Err("Direct outbox contains too many attachments".to_string());
    }
    i64::try_from(input.expected_ratchet_revision).map_err(|_| {
        "Direct outbox expected ratchet revision exceeds SQLite integer".to_string()
    })?;
    input
        .expected_ratchet_revision
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| "Direct outbox ratchet revision is exhausted".to_string())?;
    if let Some(snapshot) = input.author_snapshot.as_ref() {
        validate_account_snapshot(snapshot)?;
    }
    Ok(())
}

/// Validate the exact durable account and local device binding from one SQLite
/// transaction. No caller-provided public key participates in this decision.
fn require_current_direct_outbox_self_v1(
    conn: &Connection,
    scope: &DirectMessageOutboxScopeV1,
) -> Result<AuthenticatedSelfBinding, String> {
    validate_direct_message_outbox_scope_v1(scope)?;
    let self_binding = validated_self_binding_for_origin(conn, &scope.canonical_server_origin)?
        .ok_or("Direct outbox origin has no authenticated self binding")?;
    if self_binding.user_id != scope.user_id {
        return Err("Direct outbox caller differs from authenticated self".to_string());
    }
    // A newly registered account can legitimately have an empty conversation
    // directory, so its presentation row is only a corroborating cache. The
    // immutable authenticated-self binding remains the authority, and
    // `validated_self_binding_for_origin` has already rejected every directory
    // row that aliases or conflicts with that exact origin/user/key tuple.
    if let Some(self_account) =
        load_account_by_origin_user(conn, &scope.canonical_server_origin, &scope.user_id)?
    {
        if self_account.locator.identity_key != self_binding.identity_key
            || self_account.signing_key != self_binding.signing_key
        {
            return Err("Direct outbox authenticated directory tuple changed".to_string());
        }
    }

    type DeviceScopeRow = (
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    );
    let device: DeviceScopeRow = conn
        .query_row(
            "SELECT d.device_id, d.status, d.account_identity_key, d.account_signing_key,
                    (SELECT value FROM client_state WHERE key = 'device_binding_v1_created'),
                    (SELECT value FROM client_state WHERE key = 'device_id')
             FROM device_identity_v1 AS d WHERE d.singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|error| format!("load Direct outbox device scope: {error}"))?
        .ok_or("Direct outbox local device identity is absent")?;
    let device_id = fixed_bytes::<16>("Direct outbox device id", device.0)?;
    let status = u8::try_from(device.1)
        .map_err(|_| "Direct outbox local device status is invalid".to_string())?;
    let account_identity_key =
        fixed_bytes::<32>("Direct outbox device account identity key", device.2)?;
    let account_signing_key =
        fixed_bytes::<32>("Direct outbox device account signing key", device.3)?;
    let marker = fixed_bytes::<16>(
        "Direct outbox device binding marker",
        device
            .4
            .ok_or("Direct outbox device binding marker is absent")?,
    )?;
    let installation_id = fixed_bytes::<16>(
        "Direct outbox installation device id",
        device
            .5
            .ok_or("Direct outbox installation device id is absent")?,
    )?;
    if status != 1
        || device_id != scope.device_id
        || marker != device_id
        || installation_id != device_id
        || account_identity_key != self_binding.identity_key
        || account_signing_key != self_binding.signing_key
    {
        return Err("Direct outbox local device scope changed or is not active".to_string());
    }
    Ok(self_binding)
}

fn resolve_current_direct_outbox_route_v1(
    conn: &Connection,
    scope: &DirectMessageOutboxScopeV1,
    self_binding: &AuthenticatedSelfBinding,
    conversation_id: &str,
) -> Result<DurableDirectOutboxRouteV1, String> {
    validate_canonical_uuid("Direct outbox conversation id", conversation_id)?;
    let route = conn
        .query_row(
            "SELECT conv_type, server_origin, peer_user_id, peer_identity_key
             FROM conversations WHERE id = ?1",
            rusqlite::params![conversation_id],
            |row| {
                Ok((
                    row.get::<_, u8>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|error| format!("load Direct outbox conversation route: {error}"))?
        .ok_or("Direct outbox conversation is absent from SQLCipher")?;
    if route.0 != 0 || route.1.as_deref() != Some(scope.canonical_server_origin.as_str()) {
        return Err("Direct outbox conversation has the wrong type or origin".to_string());
    }
    let peer_user_id = route
        .2
        .ok_or("Direct outbox conversation has no peer user")?;
    validate_canonical_uuid("Direct outbox peer user id", &peer_user_id)?;
    if peer_user_id == self_binding.user_id {
        return Err("Direct outbox conversation points to authenticated self".to_string());
    }
    let peer_identity_key = fixed_bytes::<32>(
        "Direct outbox peer identity key",
        route
            .3
            .ok_or("Direct outbox conversation has no peer identity")?,
    )?;
    if peer_identity_key == [0u8; 32] {
        return Err("Direct outbox peer identity key is invalid".to_string());
    }
    let peer_account =
        load_account_by_origin_user(conn, &scope.canonical_server_origin, &peer_user_id)?
            .ok_or("Direct outbox peer account is absent from the directory")?;
    if peer_account.locator.identity_key != peer_identity_key {
        return Err("Direct outbox peer route differs from its directory tuple".to_string());
    }
    Ok(DurableDirectOutboxRouteV1 {
        self_binding: self_binding.clone(),
        peer_user_id,
        peer_identity_key,
        peer_signing_key: peer_account.signing_key,
    })
}

struct ValidatedDirectOutboxRowV1 {
    queue_order: u64,
    peer_identity_key: [u8; 32],
    peer_signing_key: [u8; 32],
    request_digest: [u8; 32],
    ratchet_revision: u64,
}

fn validate_stored_direct_outbox_row_v1(
    row: &StoredDirectMessageOutboxRowV1,
    expected_scope: &DirectMessageOutboxScopeV1,
    route: Option<&DurableDirectOutboxRouteV1>,
) -> Result<ValidatedDirectOutboxRowV1, String> {
    let queue_order = u64::try_from(row.queue_order)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| "persisted Direct outbox queue order is invalid".to_string())?;
    validate_canonical_server_origin(&row.canonical_server_origin)?;
    validate_canonical_uuid("persisted Direct outbox user id", &row.user_id)?;
    validate_canonical_uuid(
        "persisted Direct outbox conversation id",
        &row.conversation_id,
    )?;
    validate_canonical_uuid("persisted Direct outbox peer user id", &row.peer_user_id)?;
    validate_canonical_uuid(
        "persisted Direct outbox client message id",
        &row.client_message_id,
    )?;
    validate_canonical_uuid(
        "persisted Direct outbox local message id",
        &row.local_message_id,
    )?;
    if row.client_message_id != row.local_message_id {
        return Err("persisted Direct outbox client/local correlation changed".to_string());
    }
    if let Some(server_message_id) = row.server_message_id.as_deref() {
        validate_canonical_uuid(
            "persisted Direct outbox server message id",
            server_message_id,
        )?;
    }
    let device_id = fixed_bytes::<16>("persisted Direct outbox device id", row.device_id.clone())?;
    let peer_identity_key = fixed_bytes::<32>(
        "persisted Direct outbox peer identity key",
        row.peer_identity_key.clone(),
    )?;
    let peer_signing_key = fixed_bytes::<32>(
        "persisted Direct outbox peer signing key",
        row.peer_signing_key.clone(),
    )?;
    let request_digest = fixed_bytes::<32>(
        "persisted Direct outbox request digest",
        row.request_digest.clone(),
    )?;
    let ratchet_revision = u64::try_from(row.ratchet_revision)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| "persisted Direct outbox ratchet revision is invalid".to_string())?;
    if row.canonical_server_origin != expected_scope.canonical_server_origin
        || row.user_id != expected_scope.user_id
        || device_id != expected_scope.device_id
        || row.peer_user_id == expected_scope.user_id
        || peer_identity_key == [0u8; 32]
        || peer_signing_key == [0u8; 32]
    {
        return Err("persisted Direct outbox scope or peer binding is invalid".to_string());
    }
    if route.is_some_and(|route| {
        row.peer_user_id != route.peer_user_id
            || peer_identity_key != route.peer_identity_key
            || peer_signing_key != route.peer_signing_key
    }) {
        return Err("persisted Direct outbox peer route changed".to_string());
    }
    match row.state {
        0 => {
            let payload = row
                .exact_send_message_payload
                .as_deref()
                .ok_or("pending Direct outbox row has no exact payload")?;
            if payload.is_empty() || payload.len() > DIRECT_MESSAGE_OUTBOX_MAX_PAYLOAD_BYTES_V1 {
                return Err("pending Direct outbox payload is empty or oversized".to_string());
            }
            if direct_message_request_digest_v1(payload) != request_digest {
                return Err("pending Direct outbox payload digest is invalid".to_string());
            }
            if row.server_message_id.is_some() || row.server_timestamp_ms.is_some() {
                return Err("pending Direct outbox row contains an ACK result".to_string());
            }
            if row.rejection_reason.is_some() {
                return Err("pending Direct outbox row contains a rejection result".to_string());
            }
        }
        1 => {
            if row.exact_send_message_payload.is_some()
                || row.server_message_id.is_none()
                || row
                    .server_timestamp_ms
                    .is_none_or(|timestamp| timestamp <= 0)
                || row.rejection_reason.is_some()
            {
                return Err("acknowledged Direct outbox receipt has an invalid shape".to_string());
            }
        }
        2 => {
            if row.exact_send_message_payload.is_some()
                || row.server_message_id.is_some()
                || row.server_timestamp_ms.is_some()
            {
                return Err("rejected Direct outbox receipt has an invalid shape".to_string());
            }
            validate_direct_message_rejection_reason_v1(
                row.rejection_reason
                    .as_deref()
                    .ok_or("rejected Direct outbox receipt has no reason")?,
            )?;
        }
        _ => return Err("persisted Direct outbox state is invalid".to_string()),
    }
    Ok(ValidatedDirectOutboxRowV1 {
        queue_order,
        peer_identity_key,
        peer_signing_key,
        request_digest,
        ratchet_revision,
    })
}

fn ensure_account_snapshot_compatible_with_self(
    incoming: &AccountSnapshot,
    binding: Option<&AuthenticatedSelfBinding>,
) -> Result<(), String> {
    let Some(binding) = binding else {
        return Ok(());
    };
    let overlaps_self = incoming.locator.user_id == binding.user_id
        || incoming.locator.identity_key == binding.identity_key
        || incoming.signing_key == binding.signing_key;
    let exact_self = incoming.locator.user_id == binding.user_id
        && incoming.locator.identity_key == binding.identity_key
        && incoming.signing_key == binding.signing_key;
    if overlaps_self && !exact_self {
        return Err(
            "account directory entry conflicts with the authenticated self binding".to_string(),
        );
    }
    Ok(())
}

fn load_message_author(
    conn: &Connection,
    message_id: &str,
) -> Result<Option<AccountSnapshot>, String> {
    conn.query_row(
        "SELECT canonical_server_origin, user_id, identity_key, signing_key,
                username, display_name, profile_version, profile_origin,
                source, observed_at
         FROM message_author_snapshots_v1
         WHERE message_id = ?1",
        rusqlite::params![message_id],
        |row| raw_account_snapshot_required_from_row(row, 0),
    )
    .optional()
    .map_err(|e| format!("load message author snapshot: {e}"))?
    .map(RawAccountSnapshot::decode)
    .transpose()
}

fn merge_account_presentation(
    existing: &AccountSnapshot,
    incoming: &AccountSnapshot,
) -> Result<AccountSnapshot, String> {
    if let (Some(existing_version), Some(incoming_version)) =
        (existing.profile_version, incoming.profile_version)
    {
        if incoming_version < existing_version {
            return Err("account profile version rollback rejected".to_string());
        }
        if incoming_version == existing_version
            && (incoming.username != existing.username
                || incoming.display_name != existing.display_name
                || incoming.profile_origin != existing.profile_origin)
        {
            return Err("account profile changed without a version advance".to_string());
        }
    }

    if incoming.source < existing.source {
        return Ok(existing.clone());
    }

    // A source which truthfully reports no version cannot erase or reinterpret
    // presentation metadata which was already accepted at an exact version.
    if existing.profile_version.is_some() && incoming.profile_version.is_none() {
        return Ok(existing.clone());
    }

    Ok(incoming.clone())
}

fn account_snapshot_continuity_conflict_users(
    conn: &Connection,
    incoming: &AccountSnapshot,
) -> Result<std::collections::BTreeSet<String>, String> {
    let mut users = std::collections::BTreeSet::new();
    let origin = &incoming.locator.canonical_server_origin;
    if let Some(existing) = load_account_by_origin_user(conn, origin, &incoming.locator.user_id)? {
        if existing.locator.identity_key != incoming.locator.identity_key
            || existing.signing_key != incoming.signing_key
        {
            users.insert(existing.locator.user_id);
        }
    }
    if let Some(existing) =
        load_account_by_origin_identity(conn, origin, &incoming.locator.identity_key)?
    {
        if existing.locator.user_id != incoming.locator.user_id
            || existing.signing_key != incoming.signing_key
        {
            users.insert(existing.locator.user_id);
        }
    }
    if let Some(existing) = load_account_by_origin_signing(conn, origin, &incoming.signing_key)? {
        if existing.locator.user_id != incoming.locator.user_id
            || existing.locator.identity_key != incoming.locator.identity_key
        {
            users.insert(existing.locator.user_id);
        }
    }
    if let Some(binding) = load_authenticated_self_binding(conn, origin)? {
        let overlaps_self = incoming.locator.user_id == binding.user_id
            || incoming.locator.identity_key == binding.identity_key
            || incoming.signing_key == binding.signing_key;
        let exact_self = incoming.locator.user_id == binding.user_id
            && incoming.locator.identity_key == binding.identity_key
            && incoming.signing_key == binding.signing_key;
        if overlaps_self && !exact_self {
            users.insert(binding.user_id);
        }
    }
    Ok(users)
}

fn record_identity_change_observation_for(
    conn: &Connection,
    alarm_user_id: &str,
    incoming: &AccountSnapshot,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO identity_change_observations_v1
            (canonical_server_origin, user_id, observed_identity_key,
             observed_signing_key, source, observed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(canonical_server_origin, user_id)
         DO UPDATE SET observed_identity_key = excluded.observed_identity_key,
                       observed_signing_key = excluded.observed_signing_key,
                       source = excluded.source,
                       observed_at = excluded.observed_at",
        rusqlite::params![
            incoming.locator.canonical_server_origin,
            alarm_user_id,
            incoming.locator.identity_key.as_slice(),
            incoming.signing_key.as_slice(),
            incoming.source.as_u8(),
            incoming.observed_at,
        ],
    )
    .map_err(|error| format!("record blocking identity change observation: {error}"))?;
    Ok(())
}

fn has_identity_change_observation(
    conn: &Connection,
    canonical_server_origin: &str,
    user_id: &str,
) -> Result<bool, String> {
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM identity_change_observations_v1
             WHERE canonical_server_origin = ?1 AND user_id = ?2
         )",
        rusqlite::params![canonical_server_origin, user_id],
        |row| row.get(0),
    )
    .map_err(|error| format!("load blocking identity change observation: {error}"))
}

fn merge_account_snapshot(
    conn: &Connection,
    incoming: &AccountSnapshot,
) -> Result<AccountSnapshot, String> {
    validate_account_snapshot(incoming)?;
    let self_binding =
        validated_self_binding_for_origin(conn, &incoming.locator.canonical_server_origin)?;
    ensure_account_snapshot_compatible_with_self(incoming, self_binding.as_ref())?;
    merge_prevalidated_account_snapshot(conn, incoming)
}

fn merge_prevalidated_account_snapshot(
    conn: &Connection,
    incoming: &AccountSnapshot,
) -> Result<AccountSnapshot, String> {
    let existing_user = load_account_by_origin_user(
        conn,
        &incoming.locator.canonical_server_origin,
        &incoming.locator.user_id,
    )?;
    if let Some(existing) = existing_user.as_ref() {
        if existing.locator.identity_key != incoming.locator.identity_key {
            return Err("account identity changed for an origin-scoped user".to_string());
        }
        if existing.signing_key != incoming.signing_key {
            return Err("account signing key changed for an origin-scoped user".to_string());
        }
    }
    if let Some(existing) = load_account_by_origin_identity(
        conn,
        &incoming.locator.canonical_server_origin,
        &incoming.locator.identity_key,
    )? {
        if existing.locator.user_id != incoming.locator.user_id {
            return Err("account identity maps to another user on this server origin".to_string());
        }
        if existing.signing_key != incoming.signing_key {
            return Err("account identity maps to another signing key".to_string());
        }
    }
    if let Some(existing) = load_account_by_origin_signing(
        conn,
        &incoming.locator.canonical_server_origin,
        &incoming.signing_key,
    )? {
        if existing.locator.user_id != incoming.locator.user_id
            || existing.locator.identity_key != incoming.locator.identity_key
        {
            return Err(
                "account signing key maps to another user or identity on this server origin"
                    .to_string(),
            );
        }
    }

    let effective = match existing_user {
        Some(existing) => merge_account_presentation(&existing, incoming)?,
        None => incoming.clone(),
    };
    let profile_version = effective.profile_version.map(u64::to_be_bytes);
    if load_exact_account(conn, &effective.locator)?.is_some() {
        conn.execute(
            "UPDATE identity_directory_v1
             SET username = ?4, display_name = ?5, profile_version = ?6,
                 profile_origin = ?7, source = ?8, observed_at = ?9
             WHERE canonical_server_origin = ?1 AND user_id = ?2 AND identity_key = ?3",
            rusqlite::params![
                effective.locator.canonical_server_origin,
                effective.locator.user_id,
                effective.locator.identity_key.as_slice(),
                effective.username,
                effective.display_name,
                profile_version.as_ref().map(<[u8; 8]>::as_slice),
                effective.profile_origin,
                effective.source.as_u8(),
                effective.observed_at,
            ],
        )
        .map_err(|e| format!("update account directory entry: {e}"))?;
    } else {
        conn.execute(
            "INSERT INTO identity_directory_v1
                (canonical_server_origin, user_id, identity_key, signing_key,
                 username, display_name, profile_version, profile_origin,
                 source, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                effective.locator.canonical_server_origin,
                effective.locator.user_id,
                effective.locator.identity_key.as_slice(),
                effective.signing_key.as_slice(),
                effective.username,
                effective.display_name,
                profile_version.as_ref().map(<[u8; 8]>::as_slice),
                effective.profile_origin,
                effective.source.as_u8(),
                effective.observed_at,
            ],
        )
        .map_err(|e| format!("insert account directory entry: {e}"))?;
    }
    Ok(effective)
}

fn run_savepoint<T>(
    conn: &Connection,
    name: &'static str,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    conn.execute_batch(&format!("SAVEPOINT {name}"))
        .map_err(|e| format!("begin {name}: {e}"))?;
    match operation() {
        Ok(value) => match conn.execute_batch(&format!("RELEASE SAVEPOINT {name}")) {
            Ok(()) => Ok(value),
            Err(commit_error) => {
                let rollback = conn.execute_batch(&format!(
                    "ROLLBACK TO SAVEPOINT {name}; RELEASE SAVEPOINT {name};"
                ));
                Err(match rollback {
                    Ok(()) => format!("commit {name}: {commit_error}"),
                    Err(rollback_error) => format!(
                        "commit {name}: {commit_error}; rollback also failed: {rollback_error}"
                    ),
                })
            }
        },
        Err(error) => {
            let rollback = conn.execute_batch(&format!(
                "ROLLBACK TO SAVEPOINT {name}; RELEASE SAVEPOINT {name};"
            ));
            Err(match rollback {
                Ok(()) => error,
                Err(rollback_error) => {
                    format!("{error}; {name} rollback also failed: {rollback_error}")
                }
            })
        }
    }
}

pub struct StoredIncomingSenderKeyGeneration {
    pub sender_identity_key: [u8; 32],
    pub generation: u32,
    pub iteration: u32,
    pub state_revision: u64,
    /// All-zero is reserved for a migrated legacy state whose original
    /// distribution commitment cannot be reconstructed after ratcheting.
    pub distribution_commitment: [u8; 32],
    pub key_data: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceBindingPinV1 {
    pub device_id: [u8; 16],
    pub account_identity_key: [u8; 32],
    pub account_signing_key: [u8; 32],
    pub device_identity_key: [u8; 32],
    pub device_signing_key: [u8; 32],
    pub binding_version: u64,
    pub capabilities: u64,
    pub status: u8,
    pub account_signature: [u8; 64],
}

pub struct DeviceRosterSnapshotV1<'a> {
    pub conversation_id: &'a str,
    pub roster_version: u64,
    pub roster_commitment: [u8; 32],
    pub required_capabilities: u64,
    pub canonical_snapshot: &'a [u8],
    pub bindings: &'a [DeviceBindingPinV1],
}

pub struct MembershipEpochPinV1 {
    pub conversation_id: String,
    pub epoch: u64,
    pub epoch_hash: [u8; 32],
    pub predecessor_hash: [u8; 32],
    pub roster_version: u64,
    pub roster_commitment: [u8; 32],
    pub canonical_unsigned: Vec<u8>,
    pub bootstrap_owner_id: Option<[u8; 16]>,
    pub bootstrap_owner_signing_key: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipEpochPinnedHeadV1 {
    pub epoch: u64,
    pub epoch_hash: [u8; 32],
    pub roster_version: u64,
    pub roster_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalDeviceBindingProofV1 {
    pub sender_account_signing_key: [u8; 32],
    pub sender_device_capabilities: u64,
    pub sender_device_binding_status: u8,
    pub sender_account_signature: [u8; 64],
    pub target_device_identity_key: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingSenderKeyRouteV1 {
    pub sender_account_identity_key: [u8; 32],
    pub sender_device_id: [u8; 16],
    pub sender_device_identity_key: [u8; 32],
    pub sender_device_signing_key: [u8; 32],
    pub sender_binding_version: u64,
    pub target_device_id: [u8; 16],
    pub target_binding_version: u64,
    pub roster_version: u64,
    pub roster_commitment: [u8; 32],
    pub membership_epoch: u64,
    pub membership_epoch_hash: [u8; 32],
    pub envelope_commitment: [u8; 32],
    /// `None` exists only for routes installed by an interim development
    /// schema. Any newly received SKDM must atomically upgrade it to `Some`.
    pub historical_sender_binding: Option<HistoricalDeviceBindingProofV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSenderKeyDeviceEnvelopeV1 {
    pub conversation_id: String,
    pub generation: u32,
    pub target_account_identity_key: [u8; 32],
    pub target_device_id: [u8; 16],
    pub target_device_identity_key: [u8; 32],
    pub target_binding_version: u64,
    pub sender_device_id: [u8; 16],
    pub sender_device_identity_key: [u8; 32],
    pub sender_binding_version: u64,
    pub roster_version: u64,
    pub roster_commitment: [u8; 32],
    pub membership_epoch: u64,
    pub membership_epoch_hash: [u8; 32],
    pub envelope_commitment: [u8; 32],
    pub sealed_envelope: Vec<u8>,
}

fn fixed_bytes<const N: usize>(label: &str, value: Vec<u8>) -> Result<[u8; N], String> {
    let actual = value.len();
    value
        .try_into()
        .map_err(|_| format!("invalid persisted {label} length: expected {N}, got {actual}"))
}

fn valid_membership_coordinate_v1(epoch: u64, hash: &[u8; 32]) -> bool {
    epoch == 0 && *hash == [0u8; 32] || epoch > 0 && epoch <= i64::MAX as u64 && *hash != [0u8; 32]
}

fn load_identity_transparency_head_on(
    conn: &Connection,
    canonical_server_origin: &str,
) -> Result<Option<IdentityTransparencyPinnedHeadV1>, String> {
    let row = conn
        .query_row(
            "SELECT log_id, node_signing_key, tree_size, root_hash,
                    issued_at_ms, tree_head_signature, witness_policy_hash,
                    witness_quorum
             FROM identity_transparency_heads_v1
             WHERE canonical_server_origin = ?1",
            rusqlite::params![canonical_server_origin],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|error| format!("load identity transparency head: {error}"))?;
    let Some((
        log_id,
        node_key,
        tree_size,
        root_hash,
        issued_at_ms,
        signature,
        witness_policy_hash,
        witness_quorum,
    )) = row
    else {
        return Ok(None);
    };
    if tree_size <= 0 || issued_at_ms <= 0 || !(0..=32).contains(&witness_quorum) {
        return Err("persisted identity transparency head is malformed".to_string());
    }
    Ok(Some(IdentityTransparencyPinnedHeadV1 {
        canonical_server_origin: canonical_server_origin.to_string(),
        log_id: fixed_bytes("identity transparency log id", log_id)?,
        node_signing_key: fixed_bytes("identity transparency Node signing key", node_key)?,
        tree_size: u64::try_from(tree_size)
            .map_err(|_| "persisted identity transparency tree size is invalid".to_string())?,
        root_hash: fixed_bytes("identity transparency root hash", root_hash)?,
        issued_at_ms: u64::try_from(issued_at_ms)
            .map_err(|_| "persisted identity transparency issue time is invalid".to_string())?,
        tree_head_signature: fixed_bytes("identity transparency signature", signature)?,
        witness_policy_hash: fixed_bytes(
            "identity transparency witness policy hash",
            witness_policy_hash,
        )?,
        witness_quorum: u32::try_from(witness_quorum)
            .map_err(|_| "persisted identity transparency witness quorum is invalid".to_string())?,
    }))
}

fn validate_identity_transparency_anchor_v1(
    expected_origin: &str,
    anchor: &IdentityTransparencyPinnedHeadV1,
) -> Result<(), String> {
    use veil_crypto::transparency::{
        log_id_v1, TransparencyTreeHeadV1, MAX_TRANSPARENCY_TREE_SIZE_V1,
    };

    if anchor.canonical_server_origin != expected_origin
        || anchor.tree_size == 0
        || anchor.tree_size > MAX_TRANSPARENCY_TREE_SIZE_V1
        || anchor.issued_at_ms == 0
        || anchor.issued_at_ms > i64::MAX as u64
        || anchor.witness_quorum > 32
        || (anchor.witness_policy_hash == [0u8; 32]) != (anchor.witness_quorum == 0)
        || log_id_v1(expected_origin, &anchor.node_signing_key)? != anchor.log_id
    {
        return Err("identity transparency rollback anchor is invalid".to_string());
    }
    let head = TransparencyTreeHeadV1 {
        log_id: anchor.log_id,
        tree_size: anchor.tree_size,
        root_hash: anchor.root_hash,
        issued_at_ms: anchor.issued_at_ms,
    };
    if !head.verify_node_signature(
        expected_origin,
        &anchor.node_signing_key,
        &anchor.tree_head_signature,
    ) {
        return Err("identity transparency rollback anchor signature is invalid".to_string());
    }
    Ok(())
}

fn record_identity_transparency_alarm_on(
    tx: &Transaction<'_>,
    alarm_kind: i64,
    pinned: &IdentityTransparencyPinnedHeadV1,
    observed: &IdentityTransparencyProofV1,
) -> Result<(), String> {
    tx.execute(
        "INSERT OR IGNORE INTO identity_transparency_alarms_v1
           (canonical_server_origin, alarm_kind,
            pinned_log_id, pinned_node_signing_key, pinned_tree_size, pinned_root_hash,
            observed_log_id, observed_node_signing_key, observed_tree_size,
            observed_root_hash, observed_tree_head_signature)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            observed.canonical_server_origin,
            alarm_kind,
            pinned.log_id.as_slice(),
            pinned.node_signing_key.as_slice(),
            i64::try_from(pinned.tree_size)
                .map_err(|_| "pinned identity transparency size is invalid".to_string())?,
            pinned.root_hash.as_slice(),
            observed.log_id.as_slice(),
            observed.node_signing_key.as_slice(),
            i64::try_from(observed.tree_size)
                .map_err(|_| "observed identity transparency size is invalid".to_string())?,
            observed.root_hash.as_slice(),
            observed.tree_head_signature.as_slice(),
        ],
    )
    .map_err(|error| format!("record identity transparency alarm: {error}"))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn upsert_incoming_sender_key_generation(
    conn: &Connection,
    group_id: &str,
    sender_identity_key: &[u8; 32],
    generation: u32,
    iteration: u32,
    state_revision: u64,
    distribution_commitment: &[u8; 32],
    key_data: &[u8],
) -> Result<(), String> {
    if group_id.is_empty() || generation == 0 || iteration > 2000 {
        return Err("invalid incoming sender-key generation scope".to_string());
    }
    if key_data.is_empty() || key_data.len() > 65_536 {
        return Err("invalid incoming sender-key state size".to_string());
    }

    let existing = conn
        .query_row(
            "SELECT iteration, state_revision, distribution_commitment, key_data
             FROM sender_key_incoming_generations
             WHERE group_id = ?1 AND sender_identity_key = ?2 AND generation = ?3",
            rusqlite::params![
                group_id,
                sender_identity_key.as_slice(),
                i64::from(generation),
            ],
            |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    Zeroizing::new(row.get::<_, Vec<u8>>(3)?),
                ))
            },
        )
        .optional()
        .map_err(|e| format!("load incoming sender-key generation before save: {e}"))?;

    let is_new_generation = existing.is_none();
    if let Some((old_iteration, old_revision, old_commitment, old_data)) = existing {
        let old_revision = u64::from_be_bytes(fixed_bytes::<8>(
            "incoming sender-key revision",
            old_revision,
        )?);
        let old_commitment = fixed_bytes::<32>(
            "incoming sender-key distribution commitment",
            old_commitment,
        )?;
        if old_commitment != *distribution_commitment {
            return Err("incoming sender-key generation commitment changed".to_string());
        }
        if state_revision < old_revision || iteration < old_iteration {
            return Err("incoming sender-key state rollback rejected".to_string());
        }
        if state_revision == old_revision {
            if iteration != old_iteration || old_data.as_slice() != key_data {
                return Err(
                    "incoming sender-key state changed without a revision advance".to_string(),
                );
            }
            return Ok(());
        }
    }
    if is_new_generation {
        let retained: i64 = conn
            .query_row(
                "SELECT count(*) FROM sender_key_incoming_generations
                 WHERE group_id = ?1 AND sender_identity_key = ?2",
                rusqlite::params![group_id, sender_identity_key.as_slice()],
                |row| row.get(0),
            )
            .map_err(|e| format!("count retained incoming sender-key generations: {e}"))?;
        if retained >= MAX_RETAINED_SENDER_KEY_GENERATIONS_PER_SENDER as i64 {
            return Err("incoming sender-key generation retention limit reached".to_string());
        }
    }

    conn.execute(
        "INSERT INTO sender_key_incoming_generations
            (group_id, sender_identity_key, generation, iteration,
             state_revision, distribution_commitment, key_data, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'))
         ON CONFLICT(group_id, sender_identity_key, generation) DO UPDATE SET
            iteration = excluded.iteration,
            state_revision = excluded.state_revision,
            distribution_commitment = excluded.distribution_commitment,
            key_data = excluded.key_data,
            updated_at = datetime('now')",
        rusqlite::params![
            group_id,
            sender_identity_key.as_slice(),
            i64::from(generation),
            iteration,
            state_revision.to_be_bytes().as_slice(),
            distribution_commitment.as_slice(),
            key_data,
        ],
    )
    .map_err(|e| format!("save incoming sender-key generation: {e}"))?;
    Ok(())
}

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
                server_origin TEXT,
                peer_user_id TEXT,
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
                status INTEGER DEFAULT 0,    -- 0=sending, 1=sent, 2=delivered, 3=read, 4=failed, 5=delivery unknown
                expires_at TEXT,
                server_timestamp INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_messages_conv
                ON messages(conversation_id, server_timestamp);

            -- Attachment secrets and private metadata live only in SQLCipher.
            -- The authoritative message UUID may replace a local optimistic
            -- UUID, so the FK follows ON UPDATE as well as ON DELETE.
            CREATE TABLE IF NOT EXISTS message_attachments_v1 (
                message_id TEXT NOT NULL
                    REFERENCES messages(id) ON UPDATE CASCADE ON DELETE CASCADE,
                ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 15),
                media_id TEXT NOT NULL
                    CHECK(length(media_id) = 32 AND media_id = lower(media_id)),
                file_name TEXT NOT NULL
                    CHECK(length(CAST(file_name AS BLOB)) BETWEEN 1 AND 1024),
                detected_mime TEXT NOT NULL
                    CHECK(length(CAST(detected_mime AS BLOB)) BETWEEN 1 AND 255),
                format_version INTEGER NOT NULL CHECK(format_version BETWEEN 1 AND 255),
                nonce_prefix BLOB NOT NULL CHECK(length(nonce_prefix) = 16),
                chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 1 AND 32769),
                plaintext_size INTEGER NOT NULL CHECK(plaintext_size BETWEEN 0 AND 2147483648),
                ciphertext_size INTEGER NOT NULL CHECK(ciphertext_size BETWEEN 16 AND 2148007952),
                content_key BLOB NOT NULL CHECK(length(content_key) = 32),
                PRIMARY KEY (message_id, ordinal),
                UNIQUE (message_id, media_id)
            );

            -- Origin-scoped, authoritative account directory. Account and
            -- signing keys are immutable continuity bindings; only
            -- presentation metadata can advance under the merge policy in
            -- Rust. The exact locator remains explicit even though the
            -- current immutable account model also makes origin/user unique.
            CREATE TABLE IF NOT EXISTS identity_directory_v1 (
                canonical_server_origin TEXT NOT NULL
                    CHECK(length(canonical_server_origin) BETWEEN 1 AND 512),
                user_id TEXT NOT NULL CHECK(length(user_id) = 36),
                identity_key BLOB NOT NULL CHECK(length(identity_key) = 32),
                signing_key BLOB NOT NULL CHECK(length(signing_key) = 32),
                username TEXT CHECK(username IS NULL OR length(username) BETWEEN 1 AND 256),
                display_name TEXT CHECK(display_name IS NULL OR length(display_name) BETWEEN 1 AND 256),
                profile_version BLOB CHECK(profile_version IS NULL OR length(profile_version) = 8),
                profile_origin TEXT NOT NULL CHECK(length(profile_origin) BETWEEN 1 AND 512),
                source INTEGER NOT NULL CHECK(source IN (1, 2)),
                observed_at TEXT NOT NULL CHECK(length(observed_at) BETWEEN 1 AND 64),
                PRIMARY KEY (canonical_server_origin, user_id, identity_key),
                UNIQUE (canonical_server_origin, user_id),
                UNIQUE (canonical_server_origin, identity_key)
            );

            -- Pre-release hard cutover: an existing same-origin signing-key
            -- alias is ambiguous, so index creation must fail instead of
            -- guessing which development row to retain.
            CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_directory_v1_origin_signing
                ON identity_directory_v1(canonical_server_origin, signing_key);

            -- Signed network profile cache. It is presentation-only and may
            -- exist only for an exact account already pinned in the directory.
            CREATE TABLE IF NOT EXISTS network_profiles_v1 (
                canonical_server_origin TEXT NOT NULL
                    CHECK(length(canonical_server_origin) BETWEEN 1 AND 512),
                user_id TEXT NOT NULL CHECK(length(user_id) = 36),
                identity_key BLOB NOT NULL CHECK(length(identity_key) = 32),
                username TEXT NOT NULL
                    CHECK(length(CAST(username AS BLOB)) BETWEEN 1 AND 256),
                display_name TEXT
                    CHECK(display_name IS NULL OR
                          length(CAST(display_name AS BLOB)) BETWEEN 1 AND 512),
                about TEXT NOT NULL
                    CHECK(length(CAST(about AS BLOB)) <= 2048),
                avatar_asset_id TEXT,
                avatar_digest BLOB CHECK(avatar_digest IS NULL OR length(avatar_digest) = 32),
                avatar_content_type TEXT CHECK(avatar_content_type IS NULL OR avatar_content_type = 'image/jpeg'),
                profile_version BLOB NOT NULL CHECK(length(profile_version) = 8),
                profile_updated_at TEXT NOT NULL
                    CHECK(length(profile_updated_at) BETWEEN 1 AND 64),
                observed_at TEXT NOT NULL CHECK(length(observed_at) BETWEEN 1 AND 64),
                PRIMARY KEY (canonical_server_origin, user_id, identity_key),
                FOREIGN KEY (canonical_server_origin, user_id, identity_key)
                    REFERENCES identity_directory_v1
                        (canonical_server_origin, user_id, identity_key)
                    ON DELETE CASCADE
            );

            -- X25519-only v1 comparisons did not authenticate the independent
            -- Ed25519 account key. Pre-release cutover deliberately discards
            -- them instead of silently upgrading a weaker proof.
            DROP TABLE IF EXISTS local_identity_verifications_v1;

            -- Explicit physical/out-of-band account comparison made on this
            -- device. No foreign key is intentional: the verified old tuple
            -- must remain available to diagnose a later key change.
            CREATE TABLE IF NOT EXISTS local_account_verifications_v2 (
                canonical_server_origin TEXT NOT NULL
                    CHECK(length(canonical_server_origin) BETWEEN 1 AND 512),
                user_id TEXT NOT NULL CHECK(length(user_id) = 36),
                verified_identity_key BLOB NOT NULL
                    CHECK(length(verified_identity_key) = 32),
                verified_signing_key BLOB NOT NULL
                    CHECK(length(verified_signing_key) = 32),
                verified_at TEXT NOT NULL CHECK(length(verified_at) BETWEEN 1 AND 64),
                PRIMARY KEY (canonical_server_origin, user_id)
            );

            -- An authenticated directory may present a different key for an
            -- already pinned origin/user. The candidate is never promoted to
            -- the account directory or crypto routing state, but the durable
            -- observation makes the blocking Identity changed state reachable
            -- after restart. There is intentionally no FK: the alarm must
            -- survive cleanup of presentation/cache rows.
            CREATE TABLE IF NOT EXISTS identity_change_observations_v1 (
                canonical_server_origin TEXT NOT NULL
                    CHECK(length(canonical_server_origin) BETWEEN 1 AND 512),
                user_id TEXT NOT NULL CHECK(length(user_id) = 36),
                observed_identity_key BLOB NOT NULL
                    CHECK(length(observed_identity_key) = 32),
                observed_signing_key BLOB NOT NULL
                    CHECK(length(observed_signing_key) = 32),
                source INTEGER NOT NULL CHECK(source IN (1, 2)),
                observed_at TEXT NOT NULL CHECK(length(observed_at) BETWEEN 1 AND 64),
                PRIMARY KEY (canonical_server_origin, user_id)
            );

            -- Per-origin transparency trust-on-first-use anchor. Witness
            -- quorum starts at zero and cannot be inferred from a Node's own
            -- signature. All values are public, but SQLCipher protects the
            -- user's browsing/social graph and rollback history.
            CREATE TABLE IF NOT EXISTS identity_transparency_heads_v1 (
                canonical_server_origin TEXT PRIMARY KEY
                    CHECK(length(canonical_server_origin) BETWEEN 1 AND 512),
                log_id BLOB NOT NULL CHECK(length(log_id) = 32),
                node_signing_key BLOB NOT NULL CHECK(length(node_signing_key) = 32),
                tree_size INTEGER NOT NULL CHECK(tree_size BETWEEN 1 AND 9223372036854775807),
                root_hash BLOB NOT NULL CHECK(length(root_hash) = 32),
                issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms > 0),
                tree_head_signature BLOB NOT NULL CHECK(length(tree_head_signature) = 64),
                witness_policy_hash BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
                    CHECK(length(witness_policy_hash) = 32),
                witness_quorum INTEGER NOT NULL DEFAULT 0 CHECK(witness_quorum BETWEEN 0 AND 32),
                first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            ) WITHOUT ROWID;

            -- Permanent local evidence of a Node-signed log replacement,
            -- rollback, same-size split view, or non-append-only advance.
            CREATE TABLE IF NOT EXISTS identity_transparency_alarms_v1 (
                alarm_id INTEGER PRIMARY KEY AUTOINCREMENT,
                canonical_server_origin TEXT NOT NULL
                    CHECK(length(canonical_server_origin) BETWEEN 1 AND 512),
                alarm_kind INTEGER NOT NULL CHECK(alarm_kind BETWEEN 1 AND 4),
                pinned_log_id BLOB NOT NULL CHECK(length(pinned_log_id) = 32),
                pinned_node_signing_key BLOB NOT NULL CHECK(length(pinned_node_signing_key) = 32),
                pinned_tree_size INTEGER NOT NULL CHECK(pinned_tree_size > 0),
                pinned_root_hash BLOB NOT NULL CHECK(length(pinned_root_hash) = 32),
                observed_log_id BLOB NOT NULL CHECK(length(observed_log_id) = 32),
                observed_node_signing_key BLOB NOT NULL CHECK(length(observed_node_signing_key) = 32),
                observed_tree_size INTEGER NOT NULL CHECK(observed_tree_size > 0),
                observed_root_hash BLOB NOT NULL CHECK(length(observed_root_hash) = 32),
                observed_tree_head_signature BLOB NOT NULL CHECK(length(observed_tree_head_signature) = 64),
                detected_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE (
                    canonical_server_origin, alarm_kind,
                    pinned_log_id, pinned_tree_size, pinned_root_hash,
                    observed_log_id, observed_tree_size, observed_root_hash
                )
            );

            CREATE TRIGGER IF NOT EXISTS identity_transparency_alarms_no_update_v1
            BEFORE UPDATE ON identity_transparency_alarms_v1
            BEGIN
                SELECT RAISE(ABORT, 'identity transparency alarm history is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS identity_transparency_alarms_no_delete_v1
            BEFORE DELETE ON identity_transparency_alarms_v1
            BEGIN
                SELECT RAISE(ABORT, 'identity transparency alarm history is immutable');
            END;

            -- Durable binding between this SQLCipher identity and the account
            -- assigned by each authenticated server origin. The first
            -- successful WebSocket authentication pins all account
            -- coordinates; later reconnects and process restarts may only
            -- refresh the observation timestamp, never remap the account.
            CREATE TABLE IF NOT EXISTS authenticated_self_bindings_v1 (
                canonical_server_origin TEXT PRIMARY KEY
                    CHECK(length(canonical_server_origin) BETWEEN 1 AND 512),
                user_id TEXT NOT NULL CHECK(length(user_id) = 36),
                identity_key BLOB NOT NULL CHECK(length(identity_key) = 32),
                signing_key BLOB NOT NULL CHECK(length(signing_key) = 32),
                first_authenticated_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_authenticated_at TEXT NOT NULL DEFAULT (datetime('now')),
                CHECK(identity_key <> signing_key)
            );

            -- The one canonical origin selected by a successful mobile
            -- authentication. Account coordinates remain owned by the
            -- immutable authenticated-self binding above; this table stores
            -- no Node Access Pass, token, WebSocket URL, or key material.
            CREATE TABLE IF NOT EXISTS mobile_reconnect_target_v1 (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                canonical_server_origin TEXT NOT NULL UNIQUE
                    CHECK(length(canonical_server_origin) BETWEEN 1 AND 512)
                    REFERENCES authenticated_self_bindings_v1(canonical_server_origin)
                    ON UPDATE RESTRICT ON DELETE RESTRICT,
                selected_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Immutable author attribution captured when plaintext is
            -- committed. It follows an outgoing local UUID when the server
            -- ACK replaces that UUID and is removed with the message.
            CREATE TABLE IF NOT EXISTS message_author_snapshots_v1 (
                message_id TEXT PRIMARY KEY
                    REFERENCES messages(id) ON UPDATE CASCADE ON DELETE CASCADE,
                canonical_server_origin TEXT NOT NULL
                    CHECK(length(canonical_server_origin) BETWEEN 1 AND 512),
                user_id TEXT NOT NULL CHECK(length(user_id) = 36),
                identity_key BLOB NOT NULL CHECK(length(identity_key) = 32),
                signing_key BLOB NOT NULL CHECK(length(signing_key) = 32),
                username TEXT CHECK(username IS NULL OR length(username) BETWEEN 1 AND 256),
                display_name TEXT CHECK(display_name IS NULL OR length(display_name) BETWEEN 1 AND 256),
                profile_version BLOB CHECK(profile_version IS NULL OR length(profile_version) = 8),
                profile_origin TEXT NOT NULL CHECK(length(profile_origin) BETWEEN 1 AND 512),
                source INTEGER NOT NULL CHECK(source IN (1, 2)),
                author_context INTEGER CHECK(author_context IN (1, 2)),
                observed_at TEXT NOT NULL CHECK(length(observed_at) BETWEEN 1 AND 64),
                FOREIGN KEY (canonical_server_origin, user_id, identity_key)
                    REFERENCES identity_directory_v1
                        (canonical_server_origin, user_id, identity_key)
            );

            CREATE TABLE IF NOT EXISTS remote_message_state (
                message_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_key BLOB NOT NULL CHECK(length(sender_key) = 32),
                revision_ms INTEGER NOT NULL,
                state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3)),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS ratchet_sessions (
                peer_identity_key BLOB NOT NULL PRIMARY KEY
                    CHECK(typeof(peer_identity_key) = 'blob' AND length(peer_identity_key) = 32),
                session_data BLOB NOT NULL
                    CHECK(typeof(session_data) = 'blob' AND length(session_data) BETWEEN 1 AND 1048576),
                    -- Serialized RatchetSession (encrypted by SQLCipher)
                revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                    CHECK(typeof(updated_at) = 'text' AND length(updated_at) BETWEEN 1 AND 64)
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS pending_initial_headers (
                peer_identity_key BLOB PRIMARY KEY CHECK(length(peer_identity_key) = 32),
                header_data BLOB NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Direct v2 is a sticky upgrade for an established pairwise
            -- ratchet. The opaque canonical record is encrypted by SQLCipher;
            -- duplicated fixed-size commitments make malformed or substituted
            -- rows rejectable before the client publishes a session.
            CREATE TABLE IF NOT EXISTS direct_session_bindings_v2 (
                peer_identity_key BLOB NOT NULL PRIMARY KEY
                    CHECK(typeof(peer_identity_key) = 'blob' AND length(peer_identity_key) = 32)
                    REFERENCES ratchet_sessions(peer_identity_key)
                    ON UPDATE RESTRICT ON DELETE CASCADE,
                wire_version INTEGER NOT NULL DEFAULT 2 CHECK(wire_version = 2),
                session_id BLOB NOT NULL
                    CHECK(typeof(session_id) = 'blob' AND length(session_id) = 32),
                local_device_id BLOB NOT NULL
                    CHECK(typeof(local_device_id) = 'blob' AND length(local_device_id) = 16),
                peer_device_id BLOB NOT NULL
                    CHECK(typeof(peer_device_id) = 'blob' AND length(peer_device_id) = 16),
                binding_data BLOB NOT NULL
                    CHECK(typeof(binding_data) = 'blob' AND length(binding_data) BETWEEN 1 AND 4096),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                CHECK(local_device_id <> peer_device_id)
            ) WITHOUT ROWID;

            -- Durable exact-byte FIFO for Direct sends. Acknowledged rows keep
            -- the compact identity/digest/result receipt forever, while the
            -- bounded serialized payload is erased in the ACK transaction.
            CREATE TABLE IF NOT EXISTS direct_message_outbox_v1 (
                queue_order INTEGER PRIMARY KEY AUTOINCREMENT,
                canonical_server_origin TEXT NOT NULL
                    CHECK(length(canonical_server_origin) BETWEEN 1 AND 512),
                user_id TEXT NOT NULL
                    CHECK(length(user_id) = 36 AND user_id = lower(user_id)),
                device_id BLOB NOT NULL CHECK(length(device_id) = 16),
                conversation_id TEXT NOT NULL
                    CHECK(length(conversation_id) = 36 AND conversation_id = lower(conversation_id)),
                peer_user_id TEXT NOT NULL
                    CHECK(length(peer_user_id) = 36 AND peer_user_id = lower(peer_user_id)),
                peer_identity_key BLOB NOT NULL CHECK(length(peer_identity_key) = 32),
                peer_signing_key BLOB NOT NULL CHECK(length(peer_signing_key) = 32),
                client_message_id TEXT NOT NULL UNIQUE
                    CHECK(length(client_message_id) = 36 AND client_message_id = lower(client_message_id)),
                local_message_id TEXT NOT NULL UNIQUE
                    CHECK(length(local_message_id) = 36 AND local_message_id = lower(local_message_id)),
                request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
                exact_send_message_payload BLOB,
                ratchet_revision INTEGER NOT NULL CHECK(ratchet_revision > 0),
                state INTEGER NOT NULL DEFAULT 0 CHECK(state IN (0, 1, 2)),
                server_message_id TEXT UNIQUE
                    CHECK(server_message_id IS NULL OR
                          (length(server_message_id) = 36 AND server_message_id = lower(server_message_id))),
                server_timestamp_ms INTEGER,
                rejection_reason TEXT
                    CHECK(rejection_reason IS NULL OR
                          length(CAST(rejection_reason AS BLOB)) BETWEEN 1 AND 128),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                CHECK(client_message_id = local_message_id),
                CHECK(
                    (state = 0 AND
                     exact_send_message_payload IS NOT NULL AND
                     length(exact_send_message_payload) BETWEEN 1 AND 262144 AND
                     server_message_id IS NULL AND server_timestamp_ms IS NULL AND
                     rejection_reason IS NULL)
                    OR
                    (state = 1 AND exact_send_message_payload IS NULL AND
                     server_message_id IS NOT NULL AND server_timestamp_ms > 0 AND
                     rejection_reason IS NULL)
                    OR
                    (state = 2 AND exact_send_message_payload IS NULL AND
                     server_message_id IS NULL AND server_timestamp_ms IS NULL AND
                     rejection_reason IS NOT NULL)
                )
            );

            CREATE INDEX IF NOT EXISTS idx_direct_message_outbox_v1_pending_scope
                ON direct_message_outbox_v1
                    (canonical_server_origin, user_id, device_id, state, queue_order);

            CREATE UNIQUE INDEX IF NOT EXISTS idx_direct_message_outbox_v1_ratchet_revision
                ON direct_message_outbox_v1
                    (canonical_server_origin, user_id, device_id,
                     peer_identity_key, ratchet_revision);

            CREATE TABLE IF NOT EXISTS client_state (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            -- Independent per-install X25519 + Ed25519 identity. Creation is
            -- performed only by the unlocked client after the account identity
            -- is available; schema migration itself never invents key material.
            CREATE TABLE IF NOT EXISTS device_identity_v1 (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                device_id BLOB NOT NULL UNIQUE CHECK(length(device_id) = 16),
                version BLOB NOT NULL CHECK(length(version) = 8),
                x25519_secret BLOB NOT NULL CHECK(length(x25519_secret) = 32),
                ed25519_secret BLOB NOT NULL CHECK(length(ed25519_secret) = 32),
                device_identity_key BLOB NOT NULL CHECK(length(device_identity_key) = 32),
                device_signing_key BLOB NOT NULL CHECK(length(device_signing_key) = 32),
                capabilities BLOB NOT NULL CHECK(length(capabilities) = 8),
                status INTEGER NOT NULL CHECK(status BETWEEN 1 AND 3),
                account_identity_key BLOB NOT NULL CHECK(length(account_identity_key) = 32),
                account_signing_key BLOB NOT NULL CHECK(length(account_signing_key) = 32),
                account_signature BLOB NOT NULL CHECK(length(account_signature) = 64),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS device_binding_pins_v1 (
                device_id BLOB PRIMARY KEY CHECK(length(device_id) = 16),
                account_identity_key BLOB NOT NULL CHECK(length(account_identity_key) = 32),
                account_signing_key BLOB NOT NULL CHECK(length(account_signing_key) = 32),
                device_identity_key BLOB NOT NULL CHECK(length(device_identity_key) = 32),
                device_signing_key BLOB NOT NULL CHECK(length(device_signing_key) = 32),
                binding_version BLOB NOT NULL CHECK(length(binding_version) = 8),
                capabilities BLOB NOT NULL CHECK(length(capabilities) = 8),
                status INTEGER NOT NULL CHECK(status BETWEEN 1 AND 3),
                account_signature BLOB NOT NULL CHECK(length(account_signature) = 64),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS conversation_device_roster_snapshots_v1 (
                conversation_id TEXT PRIMARY KEY,
                roster_version BLOB NOT NULL CHECK(length(roster_version) = 8),
                roster_commitment BLOB NOT NULL CHECK(length(roster_commitment) = 32),
                required_capabilities BLOB NOT NULL CHECK(length(required_capabilities) = 8),
                canonical_snapshot BLOB NOT NULL CHECK(length(canonical_snapshot) BETWEEN 1 AND 1048576),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS conversation_membership_epoch_history_v1 (
                conversation_id TEXT NOT NULL,
                epoch BLOB NOT NULL CHECK(length(epoch) = 8),
                epoch_hash BLOB NOT NULL CHECK(length(epoch_hash) = 32),
                predecessor_hash BLOB NOT NULL CHECK(length(predecessor_hash) = 32),
                roster_version BLOB NOT NULL CHECK(length(roster_version) = 8),
                roster_commitment BLOB NOT NULL CHECK(length(roster_commitment) = 32),
                canonical_unsigned BLOB NOT NULL
                    CHECK(length(canonical_unsigned) BETWEEN 1 AND 65536),
                bootstrap_owner_id BLOB,
                bootstrap_owner_signing_key BLOB,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (conversation_id, epoch),
                UNIQUE (conversation_id, epoch_hash),
                CHECK(
                    (epoch = x'0000000000000001'
                     AND length(bootstrap_owner_id) = 16
                     AND length(bootstrap_owner_signing_key) = 32)
                    OR
                    (epoch <> x'0000000000000001'
                     AND bootstrap_owner_id IS NULL
                     AND bootstrap_owner_signing_key IS NULL)
                )
            );

            CREATE TABLE IF NOT EXISTS conversation_membership_epoch_heads_v1 (
                conversation_id TEXT PRIMARY KEY,
                epoch BLOB NOT NULL CHECK(length(epoch) = 8),
                epoch_hash BLOB NOT NULL CHECK(length(epoch_hash) = 32),
                roster_version BLOB NOT NULL CHECK(length(roster_version) = 8),
                roster_commitment BLOB NOT NULL CHECK(length(roster_commitment) = 32),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TRIGGER IF NOT EXISTS membership_epoch_history_reject_update_v1
            BEFORE UPDATE ON conversation_membership_epoch_history_v1
            BEGIN
                SELECT RAISE(ABORT, 'membership epoch history is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS membership_epoch_history_reject_delete_v1
            BEFORE DELETE ON conversation_membership_epoch_history_v1
            BEGIN
                SELECT RAISE(ABORT, 'membership epoch history is immutable');
            END;

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

            -- Persisted protocol-id allocator. Values are the next ids which
            -- have not yet been reserved. Reservation commits independently
            -- before generation, so failures create safe gaps instead of id
            -- reuse. Existing key rows remain the authoritative lower bound.
            CREATE TABLE IF NOT EXISTS local_prekey_allocator_v1 (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                next_signed_prekey_id INTEGER NOT NULL
                    CHECK(next_signed_prekey_id BETWEEN 1 AND 4294967295),
                next_one_time_prekey_id INTEGER NOT NULL
                    CHECK(next_one_time_prekey_id BETWEEN 1 AND 4294967295),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Exact-byte X3DH publication outbox. A batch belongs to one
            -- authenticated node/account/device scope: reusing an OPK batch
            -- across independent nodes would violate its one-time property.
            CREATE TABLE IF NOT EXISTS local_prekey_publications_v1 (
                canonical_server_origin TEXT NOT NULL
                    CHECK(length(canonical_server_origin) BETWEEN 1 AND 512),
                user_id TEXT NOT NULL CHECK(length(user_id) = 36),
                device_id BLOB NOT NULL CHECK(length(device_id) = 16),
                signed_prekey_id INTEGER NOT NULL CHECK(signed_prekey_id > 0),
                one_time_prekey_count INTEGER NOT NULL
                    CHECK(one_time_prekey_count = 20),
                request_body BLOB NOT NULL
                    CHECK(length(request_body) BETWEEN 1 AND 65536),
                body_sha256 BLOB NOT NULL CHECK(length(body_sha256) = 32),
                acknowledged INTEGER NOT NULL DEFAULT 0
                    CHECK(acknowledged IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                acknowledged_at TEXT,
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (canonical_server_origin, user_id, device_id)
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

            -- Incoming Sender-Key receive state is retained by exact
            -- generation. `sender_keys_local` remains authoritative only for
            -- outgoing state and as a read-once legacy source for old clients.
            CREATE TABLE IF NOT EXISTS sender_key_incoming_generations (
                group_id TEXT NOT NULL,
                sender_identity_key BLOB NOT NULL CHECK(length(sender_identity_key) = 32),
                generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 4294967295),
                iteration INTEGER NOT NULL CHECK(iteration BETWEEN 0 AND 2000),
                state_revision BLOB NOT NULL CHECK(length(state_revision) = 8),
                distribution_commitment BLOB NOT NULL CHECK(length(distribution_commitment) = 32),
                key_data BLOB NOT NULL CHECK(length(key_data) BETWEEN 1 AND 65536),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (group_id, sender_identity_key, generation)
            );

            -- Immutable authenticated route proof for each installed incoming
            -- device-owned Sender-Key generation. It remains available after
            -- the live roster advances so REST history can be checked against
            -- the exact historical device/binding/roster context.
            CREATE TABLE IF NOT EXISTS sender_key_incoming_routes_v1 (
                group_id TEXT NOT NULL,
                sender_identity_key BLOB NOT NULL CHECK(length(sender_identity_key) = 32),
                generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 4294967295),
                sender_account_identity_key BLOB NOT NULL CHECK(length(sender_account_identity_key) = 32),
                sender_device_id BLOB NOT NULL CHECK(length(sender_device_id) = 16),
                sender_device_signing_key BLOB NOT NULL CHECK(length(sender_device_signing_key) = 32),
                sender_binding_version BLOB NOT NULL CHECK(length(sender_binding_version) = 8),
                target_device_id BLOB NOT NULL CHECK(length(target_device_id) = 16),
                target_binding_version BLOB NOT NULL CHECK(length(target_binding_version) = 8),
                roster_version BLOB NOT NULL CHECK(length(roster_version) = 8),
                roster_commitment BLOB NOT NULL CHECK(length(roster_commitment) = 32),
                membership_epoch BLOB CHECK(membership_epoch IS NULL OR length(membership_epoch) = 8),
                membership_epoch_hash BLOB CHECK(membership_epoch_hash IS NULL OR length(membership_epoch_hash) = 32),
                envelope_commitment BLOB NOT NULL CHECK(length(envelope_commitment) = 32),
                installed_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (group_id, sender_identity_key, generation),
                FOREIGN KEY (group_id, sender_identity_key, generation)
                    REFERENCES sender_key_incoming_generations
                        (group_id, sender_identity_key, generation)
                    ON DELETE CASCADE
            );

            -- Exact authenticated SKDM bytes awaiting the gateway's durable
            -- storage ACK. The first envelope for a generation/recipient is
            -- immutable because a randomized re-seal of the same generation
            -- would create conflicting receiver state.
            CREATE TABLE IF NOT EXISTS pending_sender_key_envelopes (
                conversation_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 4294967295),
                target_identity_key BLOB NOT NULL CHECK(length(target_identity_key) = 32),
                sender_identity_key BLOB NOT NULL CHECK(length(sender_identity_key) = 32),
                sealed_envelope BLOB NOT NULL CHECK(length(sealed_envelope) BETWEEN 1 AND 4096),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (conversation_id, generation, target_identity_key)
            );

            -- Upgraded exact-device retry cache. Every routing and roster
            -- coordinate is part of the immutable row; randomized re-sealing
            -- for the same target/generation is rejected.
            CREATE TABLE IF NOT EXISTS pending_sender_key_device_envelopes_v1 (
                conversation_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 4294967295),
                target_account_identity_key BLOB NOT NULL CHECK(length(target_account_identity_key) = 32),
                target_device_id BLOB NOT NULL CHECK(length(target_device_id) = 16),
                target_device_identity_key BLOB NOT NULL CHECK(length(target_device_identity_key) = 32),
                target_binding_version BLOB NOT NULL CHECK(length(target_binding_version) = 8),
                sender_device_id BLOB NOT NULL CHECK(length(sender_device_id) = 16),
                sender_device_identity_key BLOB NOT NULL CHECK(length(sender_device_identity_key) = 32),
                sender_binding_version BLOB NOT NULL CHECK(length(sender_binding_version) = 8),
                roster_version BLOB NOT NULL CHECK(length(roster_version) = 8),
                roster_commitment BLOB NOT NULL CHECK(length(roster_commitment) = 32),
                membership_epoch BLOB CHECK(membership_epoch IS NULL OR length(membership_epoch) = 8),
                membership_epoch_hash BLOB CHECK(membership_epoch_hash IS NULL OR length(membership_epoch_hash) = 32),
                envelope_commitment BLOB NOT NULL CHECK(length(envelope_commitment) = 32),
                sealed_envelope BLOB NOT NULL CHECK(length(sealed_envelope) BETWEEN 1 AND 4096),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (conversation_id, generation, target_device_id)
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

        self.ensure_ratchet_sessions_without_rowid_schema()?;
        validate_direct_session_binding_schema_v2(&self.conn)?;
        self.ensure_conversation_identity_schema()?;
        self.ensure_conversation_read_state_schema()?;
        self.ensure_network_profile_avatar_schema()?;
        self.ensure_message_author_context_schema()?;
        self.ensure_identity_transparency_witness_schema()?;
        self.rebuild_interim_sender_key_tables()?;
        self.ensure_sender_key_membership_context_schema()?;
        self.ensure_sender_key_historical_proof_schema()?;

        // Add `crypto_mode` to conversations if missing. Older DBs created
        // before Phase 6 don't have this column. SQLite has no
        // `ADD COLUMN IF NOT EXISTS`, so we attempt and ignore the error.
        let _ = self.conn.execute_batch(
            "ALTER TABLE conversations ADD COLUMN crypto_mode TEXT NOT NULL DEFAULT 'sender_key';",
        );

        // Legacy incoming rows used status=0 even though only locally-created
        // outgoing rows can be in flight. Normalize them before any UI read so
        // a disconnect can never label received history as DeliveryUnknown.
        self.conn
            .execute(
                "UPDATE messages SET status = 2 WHERE is_outgoing = 0 AND status = 0",
                [],
            )
            .map_err(|e| format!("normalize incoming message status: {e}"))?;

        Ok(())
    }

    fn validate_absence_of_temp_ratchet_schema_on(tx: &Transaction<'_>) -> Result<(), String> {
        let conflicting_objects: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sqlite_temp_schema
                 WHERE lower(name) IN (
                           'ratchet_sessions',
                           'ratchet_sessions_rowid_legacy_v1',
                           'ratchet_session_capacity_v1',
                           'ratchet_session_capacity_insert_v1',
                           'ratchet_session_capacity_insert_commit_v1',
                           'ratchet_session_capacity_update_v1',
                           'ratchet_session_capacity_update_commit_v1',
                           'ratchet_session_capacity_delete_v1',
                           'ratchet_session_capacity_delete_commit_v1'
                       )
                    OR lower(COALESCE(tbl_name, '')) IN (
                           'ratchet_sessions',
                           'ratchet_session_capacity_v1'
                       )
                    OR instr(lower(COALESCE(sql, '')), 'ratchet_sessions') > 0
                    OR instr(
                           lower(COALESCE(sql, '')),
                           'ratchet_session_capacity_v1'
                       ) > 0",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("inspect temporary ratchet schema objects: {error}"))?;
        if conflicting_objects != 0 {
            return Err("temporary schema has a ratchet object or dependency".to_string());
        }
        Ok(())
    }

    fn validate_existing_ratchet_capacity_schema_on(
        tx: &Transaction<'_>,
        schema_shape: RatchetSessionSchemaShapeV1,
    ) -> Result<(), String> {
        let dependent_views: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'view'
                   AND instr(lower(COALESCE(sql, '')), 'ratchet_session_capacity_v1') > 0",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("inspect ratchet capacity dependent views: {error}"))?;
        let dependent_external_triggers: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'trigger'
                   AND lower(name) NOT IN (
                       'ratchet_session_capacity_insert_v1',
                       'ratchet_session_capacity_insert_commit_v1',
                       'ratchet_session_capacity_update_v1',
                       'ratchet_session_capacity_update_commit_v1',
                       'ratchet_session_capacity_delete_v1',
                       'ratchet_session_capacity_delete_commit_v1'
                   )
                   AND instr(lower(COALESCE(sql, '')), 'ratchet_session_capacity_v1') > 0",
                [],
                |row| row.get(0),
            )
            .map_err(|error| {
                format!("inspect ratchet capacity dependent external triggers: {error}")
            })?;
        let outbound_foreign_keys: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_list('ratchet_session_capacity_v1')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("inspect ratchet capacity outbound foreign keys: {error}"))?;
        let inbound_foreign_keys: i64 = tx
            .query_row(
                "SELECT COUNT(*)
                 FROM sqlite_schema AS owner
                 JOIN pragma_foreign_key_list(owner.name) AS foreign_key
                 WHERE owner.type = 'table'
                   AND lower(owner.name) != 'ratchet_session_capacity_v1'
                   AND lower(foreign_key.\"table\") = 'ratchet_session_capacity_v1'",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("inspect ratchet capacity inbound foreign keys: {error}"))?;
        let dependent_objects: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE lower(tbl_name) = 'ratchet_session_capacity_v1'
                   AND type IN ('index', 'trigger')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("inspect ratchet capacity owned objects: {error}"))?;
        if dependent_views != 0
            || dependent_external_triggers != 0
            || outbound_foreign_keys != 0
            || inbound_foreign_keys != 0
            || dependent_objects != 0
        {
            return Err("ratchet capacity schema has unsupported dependencies".to_string());
        }

        let reserved_count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE lower(name) = 'ratchet_session_capacity_v1'
                    OR lower(name) IN (
                       'ratchet_session_capacity_insert_v1',
                       'ratchet_session_capacity_insert_commit_v1',
                       'ratchet_session_capacity_update_v1',
                       'ratchet_session_capacity_update_commit_v1',
                       'ratchet_session_capacity_delete_v1',
                       'ratchet_session_capacity_delete_commit_v1'
                    )",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("inspect reserved ratchet capacity objects: {error}"))?;
        if reserved_count == 0 {
            return Ok(());
        }
        if schema_shape != RatchetSessionSchemaShapeV1::HardenedWithoutRowid || reserved_count != 7
        {
            return Err("reserved ratchet capacity schema is incomplete or unexpected".to_string());
        }

        let expected = Connection::open_in_memory()
            .map_err(|error| format!("open expected ratchet capacity schema: {error}"))?;
        expected
            .execute_batch(
                "CREATE TABLE ratchet_sessions (
                     peer_identity_key BLOB NOT NULL PRIMARY KEY
                         CHECK(typeof(peer_identity_key) = 'blob'
                               AND length(peer_identity_key) = 32),
                     session_data BLOB NOT NULL
                         CHECK(typeof(session_data) = 'blob'
                               AND length(session_data) BETWEEN 1 AND 1048576),
                     revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
                     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                         CHECK(typeof(updated_at) = 'text'
                               AND length(updated_at) BETWEEN 1 AND 64)
                 ) WITHOUT ROWID;",
            )
            .map_err(|error| format!("create expected ratchet session schema: {error}"))?;
        let expected_tx = begin_immediate(&expected, "expected ratchet capacity schema")?;
        Self::install_ratchet_session_capacity_schema_on(&expected_tx, 0, 0)?;
        expected_tx
            .commit()
            .map_err(|error| format!("commit expected ratchet capacity schema: {error}"))?;

        for name in std::iter::once("ratchet_session_capacity_v1")
            .chain(RATCHET_SESSION_CAPACITY_TRIGGER_NAMES_V1)
        {
            let load = |connection: &Connection| {
                connection
                    .query_row(
                        "SELECT type, tbl_name, sql FROM sqlite_schema WHERE name = ?1",
                        rusqlite::params![name],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<String>>(2)?,
                            ))
                        },
                    )
                    .optional()
            };
            let actual = tx
                .query_row(
                    "SELECT type, tbl_name, sql FROM sqlite_schema
                     WHERE name = ?1 COLLATE NOCASE",
                    rusqlite::params![name],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| format!("load ratchet capacity object {name}: {error}"))?
                .ok_or_else(|| format!("ratchet capacity object {name} is absent"))?;
            let expected_object = load(&expected)
                .map_err(|error| format!("load expected ratchet capacity object {name}: {error}"))?
                .ok_or_else(|| format!("expected ratchet capacity object {name} is absent"))?;
            let actual_sql = actual
                .2
                .as_deref()
                .ok_or_else(|| format!("ratchet capacity object {name} has no DDL"))?;
            let expected_sql = expected_object
                .2
                .as_deref()
                .ok_or_else(|| format!("expected ratchet capacity object {name} has no DDL"))?;
            if actual.0 != expected_object.0
                || actual.1 != expected_object.1
                || normalize_ratchet_session_ddl_v1(actual_sql)?
                    != normalize_ratchet_session_ddl_v1(expected_sql)?
            {
                return Err(format!(
                    "ratchet capacity object {name} has unsupported DDL"
                ));
            }
        }
        Ok(())
    }

    /// Rebuild either exact historical rowid-backed ratchet table into the
    /// hardened V1 WITHOUT ROWID shape and publish revision/capacity state in
    /// one IMMEDIATE transaction. DDL, indexes and external dependencies are
    /// allowlisted before any schema mutation so an older binary cannot erase
    /// constraints introduced by an unknown schema.
    fn ensure_ratchet_sessions_without_rowid_schema(&self) -> Result<(), String> {
        let tx = begin_immediate(&self.conn, "ratchet session WITHOUT ROWID schema upgrade")?;
        Self::validate_absence_of_temp_ratchet_schema_on(&tx)?;
        let (without_rowid, strict, table_sql) = tx
            .query_row(
                "SELECT table_list.wr, table_list.strict, schema.sql
                 FROM pragma_table_list AS table_list
                 JOIN sqlite_schema AS schema
                   ON schema.type = 'table' AND schema.name = table_list.name
                 WHERE table_list.schema = 'main'
                   AND table_list.name = 'ratchet_sessions'
                   AND table_list.type = 'table'",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| format!("inspect ratchet session table kind: {error}"))?
            .ok_or_else(|| "ratchet session table is absent".to_string())?;
        let schema_shape = classify_ratchet_session_schema_v1(without_rowid, strict, &table_sql)?;
        if !matches!(
            schema_shape,
            RatchetSessionSchemaShapeV1::HardenedWithoutRowid
        ) {
            let direct_table_exists: bool = tx
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM sqlite_schema
                        WHERE type = 'table' AND lower(name) = 'direct_session_bindings_v2'
                     )",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| format!("inspect pre-upgrade Direct v2 table: {error}"))?;
            if direct_table_exists {
                let direct_rows: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM direct_session_bindings_v2 LIMIT 1",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|error| format!("inspect pre-upgrade Direct v2 rows: {error}"))?;
                if direct_rows != 0 {
                    return Err(
                        "legacy ratchet schema unexpectedly contains Direct v2 bindings"
                            .to_string(),
                    );
                }
                tx.execute_batch("DROP TABLE direct_session_bindings_v2;")
                    .map_err(|error| format!("drop empty pre-upgrade Direct v2 table: {error}"))?;
            }
        }

        let mut index_statement = tx
            .prepare(
                "SELECT name, \"unique\", origin, partial
                 FROM pragma_index_list('ratchet_sessions') ORDER BY seq",
            )
            .map_err(|error| format!("inspect ratchet session indexes: {error}"))?;
        let indexes = index_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|error| format!("query ratchet session indexes: {error}"))?;
        let mut index_count = 0usize;
        for index in indexes {
            let (name, unique, origin, partial) =
                index.map_err(|error| format!("read ratchet session index: {error}"))?;
            index_count += 1;
            if name != "sqlite_autoindex_ratchet_sessions_1"
                || unique != 1
                || origin != "pk"
                || partial != 0
            {
                return Err(format!(
                    "ratchet session table has an unsupported index: {name}"
                ));
            }
        }
        drop(index_statement);
        if index_count != 1 {
            return Err(
                "ratchet session table does not have its exact primary-key index".to_string(),
            );
        }
        let mut index_topology_statement = tx
            .prepare(
                "SELECT seqno, cid, name, \"desc\", coll, key
                 FROM pragma_index_xinfo('sqlite_autoindex_ratchet_sessions_1')
                 ORDER BY seqno",
            )
            .map_err(|error| format!("inspect ratchet primary-key topology: {error}"))?;
        let index_topology = index_topology_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(|error| format!("query ratchet primary-key topology: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("read ratchet primary-key topology: {error}"))?;
        drop(index_topology_statement);
        let binary = Some("BINARY".to_string());
        let expected_index_topology = match schema_shape {
            RatchetSessionSchemaShapeV1::LegacyWithoutRevision
            | RatchetSessionSchemaShapeV1::LegacyWithRevision => vec![
                (
                    0,
                    0,
                    Some("peer_identity_key".to_string()),
                    0,
                    binary.clone(),
                    1,
                ),
                (1, -1, None, 0, binary.clone(), 0),
            ],
            RatchetSessionSchemaShapeV1::HardenedWithoutRowid => vec![
                (
                    0,
                    0,
                    Some("peer_identity_key".to_string()),
                    0,
                    binary.clone(),
                    1,
                ),
                (1, 1, Some("session_data".to_string()), 0, binary.clone(), 0),
                (2, 2, Some("revision".to_string()), 0, binary.clone(), 0),
                (3, 3, Some("updated_at".to_string()), 0, binary, 0),
            ],
        };
        if index_topology != expected_index_topology {
            return Err("ratchet session primary-key index topology is unsupported".to_string());
        }

        let mut object_statement = tx
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE lower(tbl_name) = 'ratchet_sessions' AND type = 'trigger'",
            )
            .map_err(|error| format!("inspect ratchet session schema objects: {error}"))?;
        let objects = object_statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| format!("query ratchet session schema objects: {error}"))?;
        let mut capacity_trigger_count = 0usize;
        for object in objects {
            let name =
                object.map_err(|error| format!("read ratchet session schema object: {error}"))?;
            if !RATCHET_SESSION_CAPACITY_TRIGGER_NAMES_V1
                .iter()
                .any(|expected| name.eq_ignore_ascii_case(expected))
            {
                return Err(format!(
                    "ratchet session table has an unsupported trigger: {name}"
                ));
            }
            capacity_trigger_count += 1;
        }
        drop(object_statement);
        let valid_trigger_count = match schema_shape {
            RatchetSessionSchemaShapeV1::HardenedWithoutRowid => {
                matches!(capacity_trigger_count, 0 | 6)
            }
            RatchetSessionSchemaShapeV1::LegacyWithoutRevision
            | RatchetSessionSchemaShapeV1::LegacyWithRevision => capacity_trigger_count == 0,
        };
        if !valid_trigger_count {
            return Err(
                "ratchet session capacity trigger set is incomplete or unexpected".to_string(),
            );
        }
        Self::validate_existing_ratchet_capacity_schema_on(&tx, schema_shape)?;

        let dependent_views: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'view'
                   AND instr(lower(COALESCE(sql, '')), 'ratchet_sessions') > 0",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("inspect ratchet session dependent views: {error}"))?;
        let dependent_external_triggers: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'trigger' AND lower(tbl_name) != 'ratchet_sessions'
                   AND instr(lower(COALESCE(sql, '')), 'ratchet_sessions') > 0",
                [],
                |row| row.get(0),
            )
            .map_err(|error| {
                format!("inspect ratchet session dependent external triggers: {error}")
            })?;
        let outbound_foreign_keys: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_list('ratchet_sessions')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("inspect ratchet session outbound foreign keys: {error}"))?;
        let inbound_foreign_keys: i64 = tx
            .query_row(
                "SELECT COUNT(*)
                 FROM sqlite_schema AS owner
                 JOIN pragma_foreign_key_list(owner.name) AS foreign_key
                 WHERE owner.type = 'table' AND owner.name != 'ratchet_sessions'
                   AND lower(owner.name) != 'direct_session_bindings_v2'
                   AND lower(foreign_key.\"table\") = 'ratchet_sessions'",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("inspect ratchet session inbound foreign keys: {error}"))?;
        if dependent_views != 0
            || dependent_external_triggers != 0
            || outbound_foreign_keys != 0
            || inbound_foreign_keys != 0
        {
            return Err("ratchet session table has unsupported schema dependencies".to_string());
        }

        let reserved_object_exists: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema
                    WHERE lower(name) = 'ratchet_sessions_rowid_legacy_v1'
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("inspect ratchet migration object: {error}"))?;
        if reserved_object_exists {
            return Err("unexpected ratchet session migration object exists".to_string());
        }

        let revision_projection = if schema_shape.has_revision() {
            "revision"
        } else {
            "0"
        };
        let preflight_sql = format!(
            "SELECT COUNT(*),
                        COALESCE(SUM(
                            CASE
                                WHEN typeof(session_data) = 'blob'
                                 AND length(session_data) BETWEEN 1 AND ?1
                                THEN length(session_data)
                                ELSE 0
                            END
                        ), 0),
                        COALESCE(MAX(
                            CASE
                                WHEN typeof(peer_identity_key) != 'blob'
                                  OR length(peer_identity_key) != 32
                                  OR typeof(session_data) != 'blob'
                                  OR length(session_data) NOT BETWEEN 1 AND ?1
                                  OR typeof(revision) != 'integer'
                                  OR revision < 0
                                  OR typeof(updated_at) != 'text'
                                  OR length(updated_at) NOT BETWEEN 1 AND ?2
                                THEN 1
                                ELSE 0
                            END
                        ), 0)
                 FROM (
                     SELECT peer_identity_key, session_data,
                            {revision_projection} AS revision, updated_at
                     FROM ratchet_sessions
                     LIMIT ?3
                 )"
        );
        let (row_count, total_session_bytes, invalid_rows): (i64, i64, i64) = tx
            .query_row(
                &preflight_sql,
                rusqlite::params![
                    DIRECT_MESSAGE_RATCHET_MAX_BYTES_SQLITE_V1,
                    DIRECT_MESSAGE_RATCHET_UPDATED_AT_MAX_CHARS_SQLITE_V1,
                    DIRECT_RATCHET_SESSION_MAX_ROWS_SQLITE_V1 + 1,
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| format!("preflight ratchet session table upgrade: {error}"))?;
        validate_ratchet_session_load_preflight_v1(row_count, total_session_bytes, invalid_rows)?;

        if !matches!(
            schema_shape,
            RatchetSessionSchemaShapeV1::HardenedWithoutRowid
        ) {
            let rebuild_sql = format!(
                "DROP TRIGGER IF EXISTS ratchet_session_capacity_insert_v1;
                 DROP TRIGGER IF EXISTS ratchet_session_capacity_insert_commit_v1;
                 DROP TRIGGER IF EXISTS ratchet_session_capacity_update_v1;
                 DROP TRIGGER IF EXISTS ratchet_session_capacity_update_commit_v1;
                 DROP TRIGGER IF EXISTS ratchet_session_capacity_delete_v1;
                 DROP TRIGGER IF EXISTS ratchet_session_capacity_delete_commit_v1;

                 ALTER TABLE ratchet_sessions
                     RENAME TO ratchet_sessions_rowid_legacy_v1;
                 CREATE TABLE ratchet_sessions (
                     peer_identity_key BLOB NOT NULL PRIMARY KEY
                         CHECK(typeof(peer_identity_key) = 'blob'
                               AND length(peer_identity_key) = 32),
                     session_data BLOB NOT NULL
                         CHECK(typeof(session_data) = 'blob'
                               AND length(session_data) BETWEEN 1 AND 1048576),
                     revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
                     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                         CHECK(typeof(updated_at) = 'text'
                               AND length(updated_at) BETWEEN 1 AND 64)
                 ) WITHOUT ROWID;
                 INSERT INTO ratchet_sessions
                     (peer_identity_key, session_data, revision, updated_at)
                 SELECT peer_identity_key, session_data,
                        {revision_projection} AS revision, updated_at
                 FROM ratchet_sessions_rowid_legacy_v1;"
            );
            tx.execute_batch(&rebuild_sql)
                .map_err(|error| format!("rebuild ratchet session table WITHOUT ROWID: {error}"))?;

            let copied_rows: i64 = tx
                .query_row("SELECT COUNT(*) FROM ratchet_sessions", [], |row| {
                    row.get(0)
                })
                .map_err(|error| format!("count rebuilt ratchet session rows: {error}"))?;
            let comparison_sql = format!(
                "SELECT
                         EXISTS(
                             SELECT peer_identity_key, session_data,
                                    {revision_projection} AS revision, updated_at
                             FROM ratchet_sessions_rowid_legacy_v1
                             EXCEPT
                             SELECT peer_identity_key, session_data, revision, updated_at
                             FROM ratchet_sessions
                         ),
                         EXISTS(
                             SELECT peer_identity_key, session_data, revision, updated_at
                             FROM ratchet_sessions
                             EXCEPT
                             SELECT peer_identity_key, session_data,
                                    {revision_projection} AS revision, updated_at
                             FROM ratchet_sessions_rowid_legacy_v1
                         )"
            );
            let (legacy_missing, rebuilt_missing): (bool, bool) = tx
                .query_row(&comparison_sql, [], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(|error| format!("compare rebuilt ratchet session rows: {error}"))?;
            if copied_rows != row_count || legacy_missing || rebuilt_missing {
                return Err("rebuilt ratchet session rows differ from legacy bytes".to_string());
            }
            tx.execute_batch("DROP TABLE ratchet_sessions_rowid_legacy_v1;")
                .map_err(|error| format!("drop legacy ratchet session table: {error}"))?;
        }

        create_direct_session_binding_table_v2(&tx)?;
        Self::install_ratchet_session_capacity_schema_on(&tx, row_count, total_session_bytes)?;
        tx.commit()
            .map_err(|error| format!("commit ratchet session storage schema upgrade: {error}"))
    }

    /// Install the derived capacity table and every mutation trigger inside an
    /// already-held schema transaction. The caller supplies counters computed
    /// directly from the bounded ratchet table snapshot.
    fn install_ratchet_session_capacity_schema_on(
        tx: &Transaction<'_>,
        row_count: i64,
        total_session_bytes: i64,
    ) -> Result<(), String> {
        let schema = format!(
            "DROP TRIGGER IF EXISTS ratchet_session_capacity_insert_v1;
             DROP TRIGGER IF EXISTS ratchet_session_capacity_insert_commit_v1;
             DROP TRIGGER IF EXISTS ratchet_session_capacity_update_v1;
             DROP TRIGGER IF EXISTS ratchet_session_capacity_update_commit_v1;
             DROP TRIGGER IF EXISTS ratchet_session_capacity_delete_v1;
             DROP TRIGGER IF EXISTS ratchet_session_capacity_delete_commit_v1;
             DROP TABLE IF EXISTS ratchet_session_capacity_v1;

             CREATE TABLE ratchet_session_capacity_v1 (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 row_count INTEGER NOT NULL
                     CHECK(row_count BETWEEN 0 AND {max_rows}),
                 total_session_bytes INTEGER NOT NULL
                     CHECK(total_session_bytes BETWEEN 0 AND {max_total_bytes})
             );
             INSERT INTO ratchet_session_capacity_v1
                 (singleton, row_count, total_session_bytes)
             VALUES (1, {row_count}, {total_session_bytes});

             CREATE TRIGGER ratchet_session_capacity_insert_v1
             BEFORE INSERT ON ratchet_sessions
             BEGIN
                 SELECT CASE
                     WHEN typeof(NEW.peer_identity_key) != 'blob'
                       OR length(NEW.peer_identity_key) != 32
                       OR typeof(NEW.session_data) != 'blob'
                       OR length(NEW.session_data) NOT BETWEEN 1 AND {max_blob_bytes}
                       OR typeof(NEW.revision) != 'integer'
                       OR NEW.revision < 0
                       OR typeof(NEW.updated_at) != 'text'
                       OR length(NEW.updated_at) NOT BETWEEN 1 AND {max_updated_at_chars}
                     THEN RAISE(ABORT, 'invalid ratchet session row')
                 END;
                 SELECT CASE
                     WHEN (SELECT COUNT(*) FROM ratchet_session_capacity_v1
                           WHERE singleton = 1) != 1
                     THEN RAISE(ABORT, 'ratchet capacity metadata is absent')
                 END;
                 SELECT CASE
                     WHEN EXISTS(
                         SELECT 1 FROM ratchet_sessions
                         WHERE peer_identity_key = NEW.peer_identity_key
                     )
                     THEN RAISE(ABORT, 'ratchet session already exists')
                 END;
                 SELECT CASE
                     WHEN (SELECT row_count FROM ratchet_session_capacity_v1
                           WHERE singleton = 1) >= {max_rows}
                       OR (SELECT total_session_bytes FROM ratchet_session_capacity_v1
                           WHERE singleton = 1)
                          > {max_total_bytes} - length(NEW.session_data)
                     THEN RAISE(ABORT, 'ratchet session capacity exceeded')
                 END;
             END;

             CREATE TRIGGER ratchet_session_capacity_insert_commit_v1
             AFTER INSERT ON ratchet_sessions
             BEGIN
                 UPDATE ratchet_session_capacity_v1
                 SET row_count = row_count + 1,
                     total_session_bytes = total_session_bytes + length(NEW.session_data)
                 WHERE singleton = 1;
             END;

             CREATE TRIGGER ratchet_session_capacity_update_v1
             BEFORE UPDATE ON ratchet_sessions
             BEGIN
                 SELECT CASE
                     WHEN typeof(NEW.peer_identity_key) != 'blob'
                       OR length(NEW.peer_identity_key) != 32
                       OR typeof(NEW.session_data) != 'blob'
                       OR length(NEW.session_data) NOT BETWEEN 1 AND {max_blob_bytes}
                       OR typeof(NEW.revision) != 'integer'
                       OR NEW.revision < 0
                       OR NEW.peer_identity_key != OLD.peer_identity_key
                       OR typeof(NEW.updated_at) != 'text'
                       OR length(NEW.updated_at) NOT BETWEEN 1 AND {max_updated_at_chars}
                     THEN RAISE(ABORT, 'invalid ratchet session row')
                 END;
                 SELECT CASE
                     WHEN (SELECT COUNT(*) FROM ratchet_session_capacity_v1
                           WHERE singleton = 1) != 1
                     THEN RAISE(ABORT, 'ratchet capacity metadata is absent')
                 END;
                 SELECT CASE
                     WHEN (SELECT total_session_bytes FROM ratchet_session_capacity_v1
                           WHERE singleton = 1)
                          - length(OLD.session_data) + length(NEW.session_data)
                          NOT BETWEEN 0 AND {max_total_bytes}
                     THEN RAISE(ABORT, 'ratchet session capacity exceeded')
                 END;
             END;

             CREATE TRIGGER ratchet_session_capacity_update_commit_v1
             AFTER UPDATE ON ratchet_sessions
             BEGIN
                 UPDATE ratchet_session_capacity_v1
                 SET total_session_bytes = total_session_bytes
                     - length(OLD.session_data) + length(NEW.session_data)
                 WHERE singleton = 1;
             END;

             CREATE TRIGGER ratchet_session_capacity_delete_v1
             BEFORE DELETE ON ratchet_sessions
             BEGIN
                 SELECT CASE
                     WHEN (SELECT COUNT(*) FROM ratchet_session_capacity_v1
                           WHERE singleton = 1) != 1
                     THEN RAISE(ABORT, 'ratchet capacity metadata is absent')
                 END;
                 SELECT CASE
                     WHEN (SELECT row_count FROM ratchet_session_capacity_v1
                           WHERE singleton = 1) <= 0
                       OR (SELECT total_session_bytes FROM ratchet_session_capacity_v1
                           WHERE singleton = 1) < length(OLD.session_data)
                     THEN RAISE(ABORT, 'ratchet capacity metadata is inconsistent')
                 END;
             END;

             CREATE TRIGGER ratchet_session_capacity_delete_commit_v1
             AFTER DELETE ON ratchet_sessions
             BEGIN
                 UPDATE ratchet_session_capacity_v1
                 SET row_count = row_count - 1,
                     total_session_bytes = total_session_bytes - length(OLD.session_data)
                 WHERE singleton = 1;
             END;",
            max_rows = DIRECT_RATCHET_SESSION_MAX_ROWS_SQLITE_V1,
            max_total_bytes = DIRECT_RATCHET_SESSION_MAX_TOTAL_BYTES_SQLITE_V1,
            max_blob_bytes = DIRECT_MESSAGE_RATCHET_MAX_BYTES_SQLITE_V1,
            max_updated_at_chars = DIRECT_MESSAGE_RATCHET_UPDATED_AT_MAX_CHARS_SQLITE_V1,
        );
        tx.execute_batch(&schema)
            .map_err(|error| format!("install ratchet session capacity schema: {error}"))
    }

    /// Add encrypted device-local read state without retroactively labelling
    /// all history unread. Existing rows receive the zero-count default; newly
    /// persisted inbound messages advance it transactionally.
    fn ensure_conversation_read_state_schema(&self) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin conversation read-state schema upgrade: {e}"))?;
        for (name, definition) in [
            (
                "unread_count",
                "INTEGER NOT NULL DEFAULT 0 CHECK(unread_count BETWEEN 0 AND 2147483647)",
            ),
            ("last_read_message_id", "TEXT"),
        ] {
            let present: bool = tx
                .query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM pragma_table_info('conversations') WHERE name=?1
                     )",
                    rusqlite::params![name],
                    |row| row.get(0),
                )
                .map_err(|e| format!("inspect conversation {name} column: {e}"))?;
            if !present {
                tx.execute_batch(&format!(
                    "ALTER TABLE conversations ADD COLUMN {name} {definition};"
                ))
                .map_err(|e| format!("add conversation {name} column: {e}"))?;
            }
        }
        tx.commit()
            .map_err(|e| format!("commit conversation read-state schema upgrade: {e}"))
    }

    /// Add the nullable origin/account coordinates used by authenticated
    /// directory sync without guessing values for legacy rows. Introspection
    /// and both ALTERs share one transaction so a partial upgrade cannot be
    /// published if the second column addition fails.
    fn ensure_conversation_identity_schema(&self) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin conversation identity schema upgrade: {e}"))?;
        let has_server_origin: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('conversations')
                    WHERE name = 'server_origin'
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("inspect conversation server origin column: {e}"))?;
        if !has_server_origin {
            tx.execute_batch("ALTER TABLE conversations ADD COLUMN server_origin TEXT;")
                .map_err(|e| format!("add conversation server origin column: {e}"))?;
        }
        let has_peer_user_id: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('conversations')
                    WHERE name = 'peer_user_id'
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("inspect conversation peer user id column: {e}"))?;
        if !has_peer_user_id {
            tx.execute_batch("ALTER TABLE conversations ADD COLUMN peer_user_id TEXT;")
                .map_err(|e| format!("add conversation peer user id column: {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("commit conversation identity schema upgrade: {e}"))
    }

    fn ensure_network_profile_avatar_schema(&self) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin network profile avatar schema upgrade: {e}"))?;
        for (name, definition) in [
            ("avatar_asset_id", "TEXT"),
            (
                "avatar_digest",
                "BLOB CHECK(avatar_digest IS NULL OR length(avatar_digest) = 32)",
            ),
            (
                "avatar_content_type",
                "TEXT CHECK(avatar_content_type IS NULL OR avatar_content_type = 'image/jpeg')",
            ),
        ] {
            let present: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('network_profiles_v1') WHERE name=?1)",
                    rusqlite::params![name],
                    |row| row.get(0),
                )
                .map_err(|e| format!("inspect network profile {name} column: {e}"))?;
            if !present {
                tx.execute_batch(&format!(
                    "ALTER TABLE network_profiles_v1 ADD COLUMN {name} {definition};"
                ))
                .map_err(|e| format!("add network profile {name} column: {e}"))?;
            }
        }
        tx.commit()
            .map_err(|e| format!("commit network profile avatar schema upgrade: {e}"))
    }

    fn ensure_message_author_context_schema(&self) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin message author context schema upgrade: {e}"))?;
        let present: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('message_author_snapshots_v1')
                    WHERE name = 'author_context'
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("inspect message author context column: {e}"))?;
        if !present {
            // Existing development rows remain unknown rather than inferring
            // membership from the presentation-authority `source` column.
            tx.execute_batch(
                "ALTER TABLE message_author_snapshots_v1
                 ADD COLUMN author_context INTEGER CHECK(author_context IN (1, 2));",
            )
            .map_err(|e| format!("add message author context column: {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("commit message author context schema upgrade: {e}"))
    }

    fn ensure_identity_transparency_witness_schema(&self) -> Result<(), String> {
        let present: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('identity_transparency_heads_v1')
                    WHERE name = 'witness_policy_hash'
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("inspect transparency witness policy column: {error}"))?;
        if !present {
            self.conn
                .execute_batch(
                    "ALTER TABLE identity_transparency_heads_v1
                     ADD COLUMN witness_policy_hash BLOB NOT NULL
                     DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
                     CHECK(length(witness_policy_hash) = 32);",
                )
                .map_err(|error| format!("add transparency witness policy column: {error}"))?;
        }
        Ok(())
    }

    fn normalized_table_sql(&self, table: &str) -> Result<String, String> {
        let sql: String = self
            .conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                rusqlite::params![table],
                |row| row.get(0),
            )
            .map_err(|e| format!("inspect {table} schema: {e}"))?;
        Ok(sql
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase())
    }

    /// Historical account-authorized binding material is kept separately so
    /// databases created by the interim route schema remain readable. A
    /// replay can atomically add the missing proof without fabricating fields
    /// for already-installed generations.
    fn ensure_sender_key_historical_proof_schema(&self) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin historical Sender-Key proof schema: {e}"))?;
        tx
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sender_key_historical_device_proofs_v1 (
                    group_id TEXT NOT NULL,
                    sender_identity_key BLOB NOT NULL CHECK(length(sender_identity_key) = 32),
                    generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 4294967295),
                    sender_account_signing_key BLOB NOT NULL CHECK(length(sender_account_signing_key) = 32),
                    sender_device_capabilities BLOB NOT NULL CHECK(length(sender_device_capabilities) = 8),
                    sender_device_binding_status INTEGER NOT NULL CHECK(sender_device_binding_status BETWEEN 1 AND 3),
                    sender_account_signature BLOB NOT NULL CHECK(length(sender_account_signature) = 64),
                    target_device_identity_key BLOB CHECK(target_device_identity_key IS NULL OR length(target_device_identity_key) = 32),
                    installed_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (group_id, sender_identity_key, generation),
                    FOREIGN KEY (group_id, sender_identity_key, generation)
                        REFERENCES sender_key_incoming_routes_v1
                            (group_id, sender_identity_key, generation)
                        ON DELETE CASCADE
                );",
            )
            .map_err(|e| format!("create historical Sender-Key proof schema: {e}"))?;
        let has_target_identity: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('sender_key_historical_device_proofs_v1')
                    WHERE name = 'target_device_identity_key'
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("inspect historical Sender-Key proof schema: {e}"))?;
        if !has_target_identity {
            tx.execute_batch(
                "ALTER TABLE sender_key_historical_device_proofs_v1
                 ADD COLUMN target_device_identity_key BLOB
                 CHECK(target_device_identity_key IS NULL OR length(target_device_identity_key) = 32);",
            )
            .map_err(|e| format!("upgrade historical Sender-Key proof schema: {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("commit historical Sender-Key proof schema: {e}"))
    }

    fn ensure_sender_key_membership_context_schema(&self) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin Sender-Key membership schema upgrade: {e}"))?;
        for table in [
            "sender_key_incoming_routes_v1",
            "pending_sender_key_device_envelopes_v1",
        ] {
            let has_epoch: bool = tx
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM pragma_table_info(?1)
                        WHERE name = 'membership_epoch'
                     )",
                    rusqlite::params![table],
                    |row| row.get(0),
                )
                .map_err(|e| format!("inspect {table} membership epoch column: {e}"))?;
            let has_hash: bool = tx
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM pragma_table_info(?1)
                        WHERE name = 'membership_epoch_hash'
                     )",
                    rusqlite::params![table],
                    |row| row.get(0),
                )
                .map_err(|e| format!("inspect {table} membership hash column: {e}"))?;
            if has_epoch != has_hash {
                return Err(format!("{table} has a partial membership context schema"));
            }
            if !has_epoch {
                tx.execute_batch(&format!(
                    "ALTER TABLE {table} ADD COLUMN membership_epoch BLOB
                         CHECK(membership_epoch IS NULL OR length(membership_epoch) = 8);
                     ALTER TABLE {table} ADD COLUMN membership_epoch_hash BLOB
                         CHECK(membership_epoch_hash IS NULL OR length(membership_epoch_hash) = 32);"
                ))
                .map_err(|e| format!("upgrade {table} membership context: {e}"))?;
            }
        }
        tx.commit()
            .map_err(|e| format!("commit Sender-Key membership schema upgrade: {e}"))
    }

    /// Repair the short-lived development schema that used a route-scoped PK
    /// (allowing two randomized seals for one target/generation), a 64 KiB
    /// envelope limit, and an orphanable incoming-route table. Rebuilds are
    /// transactional and fail closed on ambiguous duplicate rows.
    fn rebuild_interim_sender_key_tables(&self) -> Result<(), String> {
        let pending_sql = self.normalized_table_sql("pending_sender_key_device_envelopes_v1")?;
        let pending_current = pending_sql
            .contains("primary key (conversation_id, generation, target_device_id)")
            && pending_sql.contains("length(sealed_envelope) between 1 and 4096");
        if !pending_current {
            let ambiguous: bool = self
                .conn
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM pending_sender_key_device_envelopes_v1
                        GROUP BY conversation_id, generation, target_device_id
                        HAVING count(*) > 1
                     )",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| format!("preflight interim sender-key cache duplicates: {e}"))?;
            let oversized: bool = self
                .conn
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM pending_sender_key_device_envelopes_v1
                        WHERE length(sealed_envelope) NOT BETWEEN 1 AND 4096
                     )",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| format!("preflight interim sender-key cache sizes: {e}"))?;
            if ambiguous || oversized {
                return Err(
                    "interim exact-device Sender-Key cache is ambiguous or exceeds protocol bounds"
                        .to_string(),
                );
            }
            let backup_exists: bool = self.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='pending_sender_key_device_envelopes_v1_interim')",
                [],
                |row| row.get(0),
            ).map_err(|e| format!("inspect interim sender-key cache backup: {e}"))?;
            if backup_exists {
                return Err("interim sender-key cache backup already exists".to_string());
            }
            let tx = self
                .conn
                .unchecked_transaction()
                .map_err(|e| format!("begin interim sender-key cache rebuild: {e}"))?;
            tx.execute_batch(
                "ALTER TABLE pending_sender_key_device_envelopes_v1
                    RENAME TO pending_sender_key_device_envelopes_v1_interim;
                 CREATE TABLE pending_sender_key_device_envelopes_v1 (
                    conversation_id TEXT NOT NULL,
                    generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 4294967295),
                    target_account_identity_key BLOB NOT NULL CHECK(length(target_account_identity_key) = 32),
                    target_device_id BLOB NOT NULL CHECK(length(target_device_id) = 16),
                    target_device_identity_key BLOB NOT NULL CHECK(length(target_device_identity_key) = 32),
                    target_binding_version BLOB NOT NULL CHECK(length(target_binding_version) = 8),
                    sender_device_id BLOB NOT NULL CHECK(length(sender_device_id) = 16),
                    sender_device_identity_key BLOB NOT NULL CHECK(length(sender_device_identity_key) = 32),
                    sender_binding_version BLOB NOT NULL CHECK(length(sender_binding_version) = 8),
                    roster_version BLOB NOT NULL CHECK(length(roster_version) = 8),
                    roster_commitment BLOB NOT NULL CHECK(length(roster_commitment) = 32),
                    envelope_commitment BLOB NOT NULL CHECK(length(envelope_commitment) = 32),
                    sealed_envelope BLOB NOT NULL CHECK(length(sealed_envelope) BETWEEN 1 AND 4096),
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (conversation_id, generation, target_device_id)
                 );
                 INSERT INTO pending_sender_key_device_envelopes_v1
                    SELECT * FROM pending_sender_key_device_envelopes_v1_interim;
                 DROP TABLE pending_sender_key_device_envelopes_v1_interim;",
            ).map_err(|e| format!("rebuild interim sender-key cache: {e}"))?;
            tx.commit()
                .map_err(|e| format!("commit interim sender-key cache rebuild: {e}"))?;
        }

        let route_sql = self.normalized_table_sql("sender_key_incoming_routes_v1")?;
        let route_current = route_sql
            .contains("foreign key (group_id, sender_identity_key, generation)")
            && route_sql.contains("on delete cascade");
        if !route_current {
            let proof_table_exists: bool = self
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master
                                   WHERE type='table' AND name='sender_key_historical_device_proofs_v1')",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| format!("inspect historical proof table before route rebuild: {e}"))?;
            if proof_table_exists {
                let proof_rows: i64 = self
                    .conn
                    .query_row(
                        "SELECT count(*) FROM sender_key_historical_device_proofs_v1",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|e| format!("count historical proofs before route rebuild: {e}"))?;
                if proof_rows != 0 {
                    return Err(
                        "cannot rebuild interim incoming routes with historical proofs present"
                            .to_string(),
                    );
                }
            }
            let backup_exists: bool = self.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sender_key_incoming_routes_v1_interim')",
                [],
                |row| row.get(0),
            ).map_err(|e| format!("inspect interim incoming-route backup: {e}"))?;
            if backup_exists {
                return Err("interim incoming Sender-Key route backup already exists".to_string());
            }
            let tx = self
                .conn
                .unchecked_transaction()
                .map_err(|e| format!("begin interim incoming-route rebuild: {e}"))?;
            if proof_table_exists {
                tx.execute_batch("DROP TABLE sender_key_historical_device_proofs_v1;")
                    .map_err(|e| {
                        format!("drop empty historical proof table for route rebuild: {e}")
                    })?;
            }
            tx.execute_batch(
                "ALTER TABLE sender_key_incoming_routes_v1
                    RENAME TO sender_key_incoming_routes_v1_interim;
                 CREATE TABLE sender_key_incoming_routes_v1 (
                    group_id TEXT NOT NULL,
                    sender_identity_key BLOB NOT NULL CHECK(length(sender_identity_key) = 32),
                    generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 4294967295),
                    sender_account_identity_key BLOB NOT NULL CHECK(length(sender_account_identity_key) = 32),
                    sender_device_id BLOB NOT NULL CHECK(length(sender_device_id) = 16),
                    sender_device_signing_key BLOB NOT NULL CHECK(length(sender_device_signing_key) = 32),
                    sender_binding_version BLOB NOT NULL CHECK(length(sender_binding_version) = 8),
                    target_device_id BLOB NOT NULL CHECK(length(target_device_id) = 16),
                    target_binding_version BLOB NOT NULL CHECK(length(target_binding_version) = 8),
                    roster_version BLOB NOT NULL CHECK(length(roster_version) = 8),
                    roster_commitment BLOB NOT NULL CHECK(length(roster_commitment) = 32),
                    envelope_commitment BLOB NOT NULL CHECK(length(envelope_commitment) = 32),
                    installed_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (group_id, sender_identity_key, generation),
                    FOREIGN KEY (group_id, sender_identity_key, generation)
                        REFERENCES sender_key_incoming_generations
                            (group_id, sender_identity_key, generation)
                        ON DELETE CASCADE
                 );
                 INSERT INTO sender_key_incoming_routes_v1
                    SELECT * FROM sender_key_incoming_routes_v1_interim;
                 DROP TABLE sender_key_incoming_routes_v1_interim;",
            ).map_err(|e| format!("rebuild interim incoming Sender-Key routes: {e}"))?;
            tx.commit()
                .map_err(|e| format!("commit interim incoming-route rebuild: {e}"))?;
            if proof_table_exists {
                self.ensure_sender_key_historical_proof_schema()?;
            }
        }
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

    /// Pin the exact self account assigned by one authenticated origin.
    ///
    /// This executes before offline sync. A server may assign the same user
    /// UUID as another self-hosted instance, but one origin may never remap
    /// the local account UUID or either long-term account key after the first
    /// successful authentication, including across process restarts.
    pub fn bind_authenticated_self(
        &self,
        canonical_server_origin: &str,
        user_id: &str,
        identity_key: &[u8; 32],
        signing_key: &[u8; 32],
    ) -> Result<(), String> {
        validate_authenticated_self_coordinates(
            canonical_server_origin,
            user_id,
            identity_key,
            signing_key,
        )?;

        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|error| format!("begin authenticated self binding: {error}"))?;
        bind_authenticated_self_in_transaction(
            &tx,
            canonical_server_origin,
            user_id,
            identity_key,
            signing_key,
        )?;
        tx.commit()
            .map_err(|error| format!("commit authenticated self binding: {error}"))
    }

    /// Atomically pin an authenticated mobile account and select its exact
    /// canonical origin for credential-free process-death reconnect.
    pub fn bind_authenticated_self_and_select_mobile_reconnect_target_v1(
        &self,
        canonical_server_origin: &str,
        user_id: &str,
        identity_key: &[u8; 32],
        signing_key: &[u8; 32],
    ) -> Result<(), String> {
        validate_authenticated_self_coordinates(
            canonical_server_origin,
            user_id,
            identity_key,
            signing_key,
        )?;
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|error| format!("begin mobile reconnect target selection: {error}"))?;
        bind_authenticated_self_in_transaction(
            &tx,
            canonical_server_origin,
            user_id,
            identity_key,
            signing_key,
        )?;
        tx.execute(
            "INSERT INTO mobile_reconnect_target_v1
                (singleton, canonical_server_origin, selected_at)
             VALUES (1, ?1, datetime('now'))
             ON CONFLICT(singleton) DO UPDATE SET
                canonical_server_origin = excluded.canonical_server_origin,
                selected_at = excluded.selected_at",
            rusqlite::params![canonical_server_origin],
        )
        .map_err(|error| format!("select mobile reconnect target: {error}"))?;
        tx.commit()
            .map_err(|error| format!("commit mobile reconnect target selection: {error}"))
    }

    /// Resolve the selected mobile origin against the immutable self binding
    /// and the account keys derived by the currently opened SQLCipher session.
    pub fn load_mobile_reconnect_target_v1(
        &self,
        current_identity_key: &[u8; 32],
        current_signing_key: &[u8; 32],
    ) -> Result<Option<MobileReconnectTargetV1>, String> {
        let canonical_server_origin = {
            let mut statement = self
                .conn
                .prepare(
                    "SELECT singleton, canonical_server_origin
                     FROM mobile_reconnect_target_v1
                     ORDER BY singleton
                     LIMIT 2",
                )
                .map_err(|error| format!("prepare mobile reconnect target load: {error}"))?;
            let mut rows = statement
                .query([])
                .map_err(|error| format!("query mobile reconnect target: {error}"))?;
            let Some(row) = rows
                .next()
                .map_err(|error| format!("read mobile reconnect target: {error}"))?
            else {
                return Ok(None);
            };
            let singleton = row
                .get::<_, i64>(0)
                .map_err(|error| format!("decode mobile reconnect target singleton: {error}"))?;
            let canonical_server_origin = row
                .get::<_, String>(1)
                .map_err(|error| format!("decode mobile reconnect target origin: {error}"))?;
            if singleton != 1 {
                return Err(
                    "persisted mobile reconnect target has an invalid singleton".to_string()
                );
            }
            if rows
                .next()
                .map_err(|error| format!("read duplicate mobile reconnect target: {error}"))?
                .is_some()
            {
                return Err("persisted mobile reconnect target is not unique".to_string());
            }
            Some(canonical_server_origin)
        };
        let Some(canonical_server_origin) = canonical_server_origin else {
            return Ok(None);
        };
        validate_canonical_server_origin(&canonical_server_origin)
            .map_err(|error| format!("persisted mobile reconnect target is invalid: {error}"))?;
        let binding = validated_self_binding_for_origin(&self.conn, &canonical_server_origin)?
            .ok_or_else(|| {
                "persisted mobile reconnect target has no authenticated self binding".to_string()
            })?;
        validate_authenticated_self_coordinates(
            &canonical_server_origin,
            &binding.user_id,
            current_identity_key,
            current_signing_key,
        )?;
        if binding.identity_key != *current_identity_key
            || binding.signing_key != *current_signing_key
        {
            return Err(
                "persisted mobile reconnect target does not match the current account keys"
                    .to_string(),
            );
        }
        Ok(Some(MobileReconnectTargetV1 {
            canonical_server_origin,
            expected_user_id: binding.user_id,
        }))
    }

    /// Merge a complete authenticated account-directory batch atomically.
    /// Any identity/signing substitution, alias, profile rollback, or
    /// equal-version equivocation rolls the whole batch back.
    pub fn upsert_identity_directory(&self, snapshots: &[AccountSnapshot]) -> Result<(), String> {
        for snapshot in snapshots {
            // Validate every untrusted presentation/scope field before using
            // it in a continuity query. The Ed25519 subgroup check deliberately
            // follows conflict classification: malformed presented key bytes
            // may be retained as incident evidence for an existing baseline,
            // but are never admitted into the directory.
            validate_account_snapshot_envelope(snapshot)?;
        }

        // A continuity conflict is security evidence, not a candidate update.
        // Persist only the alarm in its own atomic savepoint, then reject the
        // entire directory batch before any presentation or routing state can
        // change. A matching future response cannot silently clear this alarm;
        // accepting a replacement requires a separately reviewed rotation flow.
        let mut identity_changes =
            std::collections::BTreeMap::<(String, String), &AccountSnapshot>::new();
        for snapshot in snapshots {
            for alarm_user_id in account_snapshot_continuity_conflict_users(&self.conn, snapshot)? {
                identity_changes.insert(
                    (
                        snapshot.locator.canonical_server_origin.clone(),
                        alarm_user_id,
                    ),
                    snapshot,
                );
            }
        }
        if !identity_changes.is_empty() {
            run_savepoint(&self.conn, "veil_identity_change_observations", || {
                for ((_, alarm_user_id), snapshot) in &identity_changes {
                    record_identity_change_observation_for(&self.conn, alarm_user_id, snapshot)?;
                }
                Ok(())
            })?;
            return Err(
                "account identity changed; directory batch rejected and quarantined".to_string(),
            );
        }

        for snapshot in snapshots {
            validate_account_snapshot(snapshot)?;
        }

        run_savepoint(&self.conn, "veil_identity_directory_batch", || {
            let mut self_bindings =
                std::collections::HashMap::<String, Option<AuthenticatedSelfBinding>>::new();
            for snapshot in snapshots {
                let origin = &snapshot.locator.canonical_server_origin;
                if !self_bindings.contains_key(origin) {
                    self_bindings.insert(
                        origin.clone(),
                        validated_self_binding_for_origin(&self.conn, origin)?,
                    );
                }
                ensure_account_snapshot_compatible_with_self(
                    snapshot,
                    self_bindings.get(origin).and_then(Option::as_ref),
                )?;
            }
            for snapshot in snapshots {
                merge_prevalidated_account_snapshot(&self.conn, snapshot)?;
            }
            Ok(())
        })
    }

    /// Resolve one exact `(origin, user_id, identity_key)` locator.
    pub fn resolve_account_snapshot(
        &self,
        locator: &ProfileLocator,
    ) -> Result<Option<AccountSnapshot>, String> {
        validate_profile_locator(locator)?;
        load_exact_account(&self.conn, locator)
    }

    /// Resolve the single immutable account currently pinned for an exact
    /// `(origin, user_id)` namespace. This deliberately does not accept an
    /// identity-key candidate, so callers can distinguish a missing durable
    /// baseline from an exact match while preflighting continuity changes.
    pub fn resolve_account_by_origin_user(
        &self,
        canonical_server_origin: &str,
        user_id: &str,
    ) -> Result<Option<AccountSnapshot>, String> {
        validate_canonical_server_origin(canonical_server_origin)?;
        validate_canonical_uuid("account directory user id", user_id)?;
        load_account_by_origin_user(&self.conn, canonical_server_origin, user_id)
    }

    /// Compare one author tuple from an authenticated active-history row with
    /// every overlapping durable origin-scoped account/self baseline before
    /// any device proof, decryption, or process-local pin is touched. A
    /// mismatch becomes durable incident evidence owned by the baseline user,
    /// while a first observation remains service-mediated TOFU and is
    /// deliberately not promoted here.
    pub fn observe_historical_account_candidate(
        &self,
        canonical_server_origin: &str,
        user_id: &str,
        identity_key: &[u8; 32],
        signing_key: &[u8; 32],
        observed_at: &str,
    ) -> Result<HistoricalAccountContinuity, String> {
        validate_canonical_server_origin(canonical_server_origin)?;
        validate_canonical_uuid("historical account candidate user id", user_id)?;
        validate_bounded_text(
            "historical account candidate observation timestamp",
            observed_at,
            MAX_OBSERVED_AT_BYTES,
            false,
        )?;
        let candidate = AccountSnapshot {
            locator: ProfileLocator {
                canonical_server_origin: canonical_server_origin.to_string(),
                user_id: user_id.to_string(),
                identity_key: *identity_key,
            },
            signing_key: *signing_key,
            username: None,
            display_name: None,
            profile_version: None,
            profile_origin: canonical_server_origin.to_string(),
            source: AccountSnapshotSource::AuthenticatedHistory,
            observed_at: observed_at.to_string(),
        };
        let conflict_users = account_snapshot_continuity_conflict_users(&self.conn, &candidate)?;
        if !conflict_users.is_empty() {
            run_savepoint(&self.conn, "veil_historical_identity_observation", || {
                for alarm_user_id in &conflict_users {
                    record_identity_change_observation_for(&self.conn, alarm_user_id, &candidate)?;
                }
                Ok(())
            })?;
            return Ok(HistoricalAccountContinuity::IdentityChanged(
                conflict_users.into_iter().collect(),
            ));
        }

        if load_account_by_origin_user(&self.conn, canonical_server_origin, user_id)?.is_some() {
            return Ok(HistoricalAccountContinuity::Compatible);
        }
        if let Some(binding) = load_authenticated_self_binding(&self.conn, canonical_server_origin)?
        {
            if binding.user_id == user_id
                && binding.identity_key == *identity_key
                && binding.signing_key == *signing_key
            {
                return Ok(HistoricalAccountContinuity::Compatible);
            }
        }
        Ok(HistoricalAccountContinuity::NoBaseline)
    }

    /// List durable continuity alarms for one authenticated origin so the
    /// renderer signal can name the baseline account rather than an attacker-
    /// supplied alias UUID. The rows remain authoritative in SQLCipher even
    /// when event delivery is unavailable.
    pub fn identity_change_users_for_origin(
        &self,
        canonical_server_origin: &str,
    ) -> Result<Vec<String>, String> {
        validate_canonical_server_origin(canonical_server_origin)?;
        let mut statement = self
            .conn
            .prepare(
                "SELECT user_id
                 FROM identity_change_observations_v1
                 WHERE canonical_server_origin = ?1
                 ORDER BY user_id",
            )
            .map_err(|error| format!("prepare identity-change users: {error}"))?;
        let users = statement
            .query_map(rusqlite::params![canonical_server_origin], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| format!("query identity-change users: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("collect identity-change users: {error}"))?;
        for user_id in &users {
            validate_canonical_uuid("identity-change observation user id", user_id)?;
        }
        Ok(users)
    }

    /// Store one signed network profile against an exact pinned account.
    /// Rollback and equal-version equivocation fail closed.
    pub fn upsert_network_profile(&self, profile: &NetworkProfile) -> Result<(), String> {
        validate_network_profile(profile)?;
        run_savepoint(&self.conn, "veil_network_profile_upsert", || {
            if load_exact_account(&self.conn, &profile.locator)?.is_none() {
                return Err("network profile has no exact pinned account directory entry".into());
            }
            let existing = self
                .conn
                .query_row(
                    "SELECT username, display_name, about, avatar_asset_id,
                            avatar_digest, avatar_content_type, profile_version,
                            profile_updated_at
                     FROM network_profiles_v1
                     WHERE canonical_server_origin = ?1 AND user_id = ?2
                       AND identity_key = ?3",
                    rusqlite::params![
                        profile.locator.canonical_server_origin,
                        profile.locator.user_id,
                        profile.locator.identity_key.as_slice(),
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Option<Vec<u8>>>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, Vec<u8>>(6)?,
                            row.get::<_, String>(7)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| format!("load existing network profile: {error}"))?;
            if let Some((
                username,
                display_name,
                about,
                avatar_asset_id,
                avatar_digest,
                avatar_content_type,
                version,
                updated_at,
            )) = existing
            {
                let version =
                    fixed_bytes::<8>("network profile version", version).map(u64::from_be_bytes)?;
                if profile.profile_version < version {
                    return Err("network profile version rollback rejected".into());
                }
                if profile.profile_version == version
                    && (profile.username != username
                        || profile.display_name != display_name
                        || profile.about != about
                        || profile.avatar_asset_id != avatar_asset_id
                        || profile.avatar_digest.map(|value| value.to_vec()) != avatar_digest
                        || profile.avatar_content_type != avatar_content_type
                        || profile.profile_updated_at != updated_at)
                {
                    return Err("network profile changed without a version advance".into());
                }
            }

            let version = profile.profile_version.to_be_bytes();
            self.conn
                .execute(
                    "INSERT INTO network_profiles_v1
                        (canonical_server_origin, user_id, identity_key,
                         username, display_name, about, avatar_asset_id,
                         avatar_digest, avatar_content_type, profile_version,
                         profile_updated_at, observed_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                     ON CONFLICT(canonical_server_origin, user_id, identity_key)
                     DO UPDATE SET username = excluded.username,
                         display_name = excluded.display_name,
                         about = excluded.about,
                         avatar_asset_id = excluded.avatar_asset_id,
                         avatar_digest = excluded.avatar_digest,
                         avatar_content_type = excluded.avatar_content_type,
                         profile_version = excluded.profile_version,
                         profile_updated_at = excluded.profile_updated_at,
                         observed_at = excluded.observed_at",
                    rusqlite::params![
                        profile.locator.canonical_server_origin,
                        profile.locator.user_id,
                        profile.locator.identity_key.as_slice(),
                        profile.username,
                        profile.display_name,
                        profile.about,
                        profile.avatar_asset_id,
                        profile.avatar_digest.map(|value| value.to_vec()),
                        profile.avatar_content_type,
                        version.as_slice(),
                        profile.profile_updated_at,
                        profile.observed_at,
                    ],
                )
                .map_err(|error| format!("upsert network profile: {error}"))?;
            Ok(())
        })
    }

    /// Atomically merge an authenticated account snapshot and its signed
    /// network profile. This is used for the current account on a fresh
    /// device, where no conversation directory entry exists yet.
    ///
    /// The presentation fields remain non-authoritative for crypto trust: the
    /// caller must supply identity and signing keys from the already
    /// authenticated native session. Any conflict or profile rejection rolls
    /// the directory merge back with the profile write.
    pub fn upsert_authenticated_network_profile(
        &self,
        profile: &NetworkProfile,
        signing_key: [u8; 32],
    ) -> Result<(), String> {
        validate_network_profile(profile)?;
        let snapshot = AccountSnapshot {
            locator: profile.locator.clone(),
            signing_key,
            username: Some(profile.username.clone()),
            display_name: profile.display_name.clone(),
            profile_version: Some(profile.profile_version),
            profile_origin: profile.locator.canonical_server_origin.clone(),
            source: AccountSnapshotSource::AuthenticatedConversationDirectory,
            observed_at: profile.observed_at.clone(),
        };
        validate_account_snapshot(&snapshot)?;

        run_savepoint(&self.conn, "veil_authenticated_network_profile", || {
            let self_binding = validated_self_binding_for_origin(
                &self.conn,
                &profile.locator.canonical_server_origin,
            )?
            .ok_or("authenticated network profile has no pinned self binding")?;
            ensure_account_snapshot_compatible_with_self(&snapshot, Some(&self_binding))?;
            merge_prevalidated_account_snapshot(&self.conn, &snapshot)?;
            self.upsert_network_profile(profile)
        })
    }

    /// Load one exact origin/user/key-bound signed profile cache row.
    pub fn load_network_profile(
        &self,
        locator: &ProfileLocator,
    ) -> Result<Option<NetworkProfile>, String> {
        validate_profile_locator(locator)?;
        self.conn
            .query_row(
                "SELECT username, display_name, about, avatar_asset_id,
                        avatar_digest, avatar_content_type, profile_version,
                        profile_updated_at, observed_at
                 FROM network_profiles_v1
                 WHERE canonical_server_origin = ?1 AND user_id = ?2
                   AND identity_key = ?3",
                rusqlite::params![
                    locator.canonical_server_origin,
                    locator.user_id,
                    locator.identity_key.as_slice(),
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| format!("load network profile: {error}"))?
            .map(
                |(
                    username,
                    display_name,
                    about,
                    avatar_asset_id,
                    avatar_digest,
                    avatar_content_type,
                    version,
                    profile_updated_at,
                    observed_at,
                )| {
                    let profile = NetworkProfile {
                        locator: locator.clone(),
                        username,
                        display_name,
                        about,
                        avatar_asset_id,
                        avatar_digest: avatar_digest
                            .map(|value| fixed_bytes::<32>("network profile avatar digest", value))
                            .transpose()?,
                        avatar_content_type,
                        profile_version: fixed_bytes::<8>("network profile version", version)
                            .map(u64::from_be_bytes)?,
                        profile_updated_at,
                        observed_at,
                    };
                    validate_network_profile(&profile)?;
                    Ok(profile)
                },
            )
            .transpose()
    }

    /// Load a cached profile only when the currently unlocked account is
    /// durably bound to the same origin. This is the offline/restart read path;
    /// it never upgrades trust and cannot cross an origin, account or key.
    pub fn load_network_profile_for_authenticated_account(
        &self,
        canonical_server_origin: &str,
        current_user_id: &str,
        current_identity_key: &[u8; 32],
        current_signing_key: &[u8; 32],
        locator: &ProfileLocator,
    ) -> Result<Option<NetworkProfile>, String> {
        validate_canonical_server_origin(canonical_server_origin)?;
        validate_canonical_uuid("authenticated profile cache user", current_user_id)?;
        validate_profile_locator(locator)?;
        if locator.canonical_server_origin != canonical_server_origin {
            return Err("cached profile locator crosses the authenticated origin".to_string());
        }
        let binding = validated_self_binding_for_origin(&self.conn, canonical_server_origin)?
            .ok_or("cached profile origin has no authenticated self binding")?;
        if binding.user_id != current_user_id
            || binding.identity_key != *current_identity_key
            || binding.signing_key != *current_signing_key
        {
            return Err(
                "cached profile requester differs from the authenticated binding".to_string(),
            );
        }
        self.load_network_profile(locator)
    }

    /// Load device-local proof for an exact peer while offline, scoped by the
    /// currently unlocked cryptographic identity and the durable self binding
    /// for the peer's origin. No renderer-supplied account UUID is trusted.
    pub fn local_identity_verification_for_unlocked_account(
        &self,
        current_identity_key: &[u8; 32],
        current_signing_key: &[u8; 32],
        locator: &ProfileLocator,
    ) -> Result<LocalIdentityVerification, String> {
        validate_profile_locator(locator)?;
        let binding =
            validated_self_binding_for_origin(&self.conn, &locator.canonical_server_origin)?
                .ok_or("identity proof origin has no authenticated self binding")?;
        if binding.identity_key != *current_identity_key
            || binding.signing_key != *current_signing_key
        {
            return Err("identity proof requester differs from the unlocked account".to_string());
        }
        if binding.user_id == locator.user_id && binding.identity_key == locator.identity_key {
            return Err("the current account cannot verify itself".to_string());
        }
        let proof = self.local_identity_verification(locator)?;
        if proof == LocalIdentityVerification::IdentityChanged {
            return Ok(proof);
        }
        match load_account_by_origin_user(
            &self.conn,
            &locator.canonical_server_origin,
            &locator.user_id,
        )? {
            Some(pinned) if pinned.locator.identity_key != locator.identity_key => {
                return Ok(LocalIdentityVerification::IdentityChanged);
            }
            Some(_) => {}
            None => {
                return Err("identity proof target has no exact pinned account entry".to_string());
            }
        }
        Ok(proof)
    }

    /// Record an explicit account-v2 comparison of one exact identity on this
    /// device, binding both its X25519 and Ed25519 account keys.
    pub fn mark_account_verified_v2(
        &self,
        locator: &ProfileLocator,
        verified_at: &str,
    ) -> Result<(), String> {
        validate_profile_locator(locator)?;
        validate_bounded_text(
            "identity verification timestamp",
            verified_at,
            MAX_OBSERVED_AT_BYTES,
            false,
        )?;
        let account = load_exact_account(&self.conn, locator)?
            .ok_or("cannot verify an identity absent from the pinned directory")?;
        if has_identity_change_observation(
            &self.conn,
            &locator.canonical_server_origin,
            &locator.user_id,
        )? {
            return Err(
                "cannot verify an identity while a blocking identity change is pending".into(),
            );
        }
        let self_binding =
            validated_self_binding_for_origin(&self.conn, &locator.canonical_server_origin)?
                .ok_or("cannot verify an identity without an authenticated self binding")?;
        if self_binding.user_id == locator.user_id
            && self_binding.identity_key == locator.identity_key
        {
            return Err("the current account cannot verify itself".into());
        }
        self.conn
            .execute(
                "INSERT INTO local_account_verifications_v2
                    (canonical_server_origin, user_id, verified_identity_key,
                     verified_signing_key, verified_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(canonical_server_origin, user_id)
                 DO UPDATE SET verified_identity_key = excluded.verified_identity_key,
                               verified_signing_key = excluded.verified_signing_key,
                               verified_at = excluded.verified_at",
                rusqlite::params![
                    locator.canonical_server_origin,
                    locator.user_id,
                    locator.identity_key.as_slice(),
                    account.signing_key.as_slice(),
                    verified_at,
                ],
            )
            .map_err(|error| format!("store local account-v2 verification: {error}"))?;
        Ok(())
    }

    /// Compare the currently observed locator to this device's explicit pin.
    pub fn local_identity_verification(
        &self,
        locator: &ProfileLocator,
    ) -> Result<LocalIdentityVerification, String> {
        validate_profile_locator(locator)?;
        if has_identity_change_observation(
            &self.conn,
            &locator.canonical_server_origin,
            &locator.user_id,
        )? {
            return Ok(LocalIdentityVerification::IdentityChanged);
        }
        let verified_keys = self
            .conn
            .query_row(
                "SELECT verified_identity_key, verified_signing_key
                 FROM local_account_verifications_v2
                 WHERE canonical_server_origin = ?1 AND user_id = ?2",
                rusqlite::params![locator.canonical_server_origin, locator.user_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|error| format!("load local account-v2 verification: {error}"))?;
        match verified_keys {
            None => Ok(LocalIdentityVerification::NotCompared),
            Some((identity, signing)) => {
                let identity = fixed_bytes::<32>("verified identity key", identity)?;
                let signing = fixed_bytes::<32>("verified signing key", signing)?;
                if identity != locator.identity_key {
                    return Ok(LocalIdentityVerification::IdentityChanged);
                }
                let Some(current) = load_account_by_origin_user(
                    &self.conn,
                    &locator.canonical_server_origin,
                    &locator.user_id,
                )?
                else {
                    return Ok(LocalIdentityVerification::IdentityChanged);
                };
                if current.locator.identity_key != identity || current.signing_key != signing {
                    return Ok(LocalIdentityVerification::IdentityChanged);
                }
                if validated_self_binding_for_origin(&self.conn, &locator.canonical_server_origin)?
                    .is_none()
                {
                    return Ok(LocalIdentityVerification::IdentityChanged);
                }
                Ok(LocalIdentityVerification::VerifiedOnThisDevice)
            }
        }
    }

    /// Resolve a message sender within the authoritative origin already bound
    /// to its conversation. Legacy unscoped conversations return `None` rather
    /// than borrowing the currently connected origin.
    pub fn resolve_account_by_conversation_sender(
        &self,
        conversation_id: &str,
        identity_key: &[u8; 32],
    ) -> Result<Option<AccountSnapshot>, String> {
        if conversation_id.is_empty() {
            return Err("conversation id must not be empty".to_string());
        }
        let origin = self
            .conn
            .query_row(
                "SELECT server_origin FROM conversations WHERE id = ?1",
                rusqlite::params![conversation_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|e| format!("load conversation origin for account resolution: {e}"))?
            .flatten();
        match origin {
            Some(origin) => load_account_by_origin_identity(&self.conn, &origin, identity_key),
            None => Ok(None),
        }
    }

    /// Attach immutable author attribution to an already-persisted message.
    /// The directory merge and author write share a nested-safe SAVEPOINT, so
    /// this method can participate in the existing receive transaction.
    pub fn attach_message_author(
        &self,
        message_id: &str,
        snapshot: &AccountSnapshot,
    ) -> Result<(), String> {
        self.attach_message_author_with_context(
            message_id,
            snapshot,
            MessageAuthorContext::from_snapshot_source(snapshot.source),
        )
    }

    /// Attach author metadata with an explicit immutable membership context.
    /// Callers which resolve presentation fields through a stronger cached
    /// directory snapshot must still pass the context of the current
    /// authenticated observation rather than deriving membership from that
    /// merged presentation authority.
    pub fn attach_message_author_with_context(
        &self,
        message_id: &str,
        snapshot: &AccountSnapshot,
        author_context: MessageAuthorContext,
    ) -> Result<(), String> {
        if message_id.is_empty() {
            return Err("message id must not be empty".to_string());
        }
        validate_account_snapshot(snapshot)?;
        run_savepoint(&self.conn, "veil_attach_message_author", || {
            let effective = merge_account_snapshot(&self.conn, snapshot)?;
            let message_binding = self
                .conn
                .query_row(
                    "SELECT m.sender_key, c.server_origin
                     FROM messages AS m
                     JOIN conversations AS c ON c.id = m.conversation_id
                     WHERE m.id = ?1",
                    rusqlite::params![message_id],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .optional()
                .map_err(|e| format!("load message binding before author attach: {e}"))?
                .ok_or("cannot attach an author to a missing message")?;
            if message_binding.0.as_slice() != effective.locator.identity_key {
                return Err("message sender key differs from its author identity".to_string());
            }
            if message_binding.1.as_deref()
                != Some(effective.locator.canonical_server_origin.as_str())
            {
                return Err(
                    "message conversation origin differs from its author locator".to_string(),
                );
            }
            if let Some(existing) = load_message_author(&self.conn, message_id)? {
                if existing.locator != effective.locator
                    || existing.signing_key != effective.signing_key
                {
                    return Err("message author binding changed".to_string());
                }
                return Ok(());
            }

            let profile_version = effective.profile_version.map(u64::to_be_bytes);
            self.conn
                .execute(
                    "INSERT INTO message_author_snapshots_v1
                        (message_id, canonical_server_origin, user_id,
                         identity_key, signing_key, username, display_name,
                         profile_version, profile_origin, source, author_context, observed_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    rusqlite::params![
                        message_id,
                        &effective.locator.canonical_server_origin,
                        &effective.locator.user_id,
                        effective.locator.identity_key.as_slice(),
                        effective.signing_key.as_slice(),
                        effective.username.as_deref(),
                        effective.display_name.as_deref(),
                        profile_version.as_ref().map(<[u8; 8]>::as_slice),
                        &effective.profile_origin,
                        effective.source.as_u8(),
                        author_context.as_u8(),
                        &effective.observed_at,
                    ],
                )
                .map_err(|e| format!("attach message author snapshot: {e}"))?;
            Ok(())
        })
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
    #[allow(clippy::too_many_arguments)] // Persisted directory fields stay explicit at trust boundary.
    pub fn upsert_directory_conversation(
        &self,
        id: &str,
        conv_type: u8,
        canonical_server_origin: &str,
        name: Option<&str>,
        peer_user_id: Option<&str>,
        peer_identity_key: Option<&[u8]>,
        server_id: Option<&str>,
        created_at: &str,
    ) -> Result<(), String> {
        if id.is_empty() || created_at.is_empty() {
            return Err("directory conversation id and created_at must not be empty".to_string());
        }
        validate_canonical_server_origin(canonical_server_origin)?;
        validate_bounded_text(
            "directory conversation created_at",
            created_at,
            MAX_OBSERVED_AT_BYTES,
            false,
        )?;
        if let Some(name) = name {
            validate_bounded_text(
                "directory conversation name",
                name,
                MAX_ACCOUNT_PRESENTATION_BYTES,
                true,
            )?;
        }
        if let Some(server_id) = server_id {
            validate_canonical_uuid("directory conversation server id", server_id)?;
        }
        if conv_type > 2 {
            return Err("invalid directory conversation type".to_string());
        }
        if conv_type == 0 {
            let peer_user_id =
                peer_user_id.ok_or("DM directory entry must contain a peer user id")?;
            validate_canonical_uuid("DM directory peer user id", peer_user_id)?;
            if peer_identity_key.map(<[u8]>::len) != Some(32) {
                return Err(
                    "DM directory entry must contain a 32-byte peer identity key".to_string(),
                );
            }
            if peer_identity_key == Some([0u8; 32].as_slice()) {
                return Err("DM directory peer identity key must not be all zero".to_string());
            }
        } else if peer_identity_key.is_some() || peer_user_id.is_some() {
            return Err(
                "non-DM directory entry must not contain a peer account binding".to_string(),
            );
        }

        let existing = self.conn.query_row(
            "SELECT conv_type, peer_identity_key, server_id, server_origin, peer_user_id
             FROM conversations WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok((
                    row.get::<_, u8>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        );

        match existing {
            Ok((stored_type, stored_peer, stored_server, stored_origin, stored_peer_user_id)) => {
                if stored_type != conv_type {
                    return Err("authenticated directory changed the conversation type".to_string());
                }
                if stored_origin.is_none() {
                    return Err(
                        "legacy unscoped conversation requires an explicit migration; refusing to adopt the active origin"
                            .to_string(),
                    );
                }
                if conv_type != 0 && (stored_peer.is_some() || stored_peer_user_id.is_some()) {
                    return Err(
                        "persisted non-DM conversation contains a peer account binding".to_string(),
                    );
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
                if stored_origin.as_deref() != Some(canonical_server_origin) {
                    return Err(
                        "authenticated directory changed the conversation origin".to_string()
                    );
                }
                if let (Some(stored), Some(received)) =
                    (stored_peer_user_id.as_deref(), peer_user_id)
                {
                    if stored != received {
                        return Err(
                            "authenticated directory changed the pinned DM peer user".to_string()
                        );
                    }
                }

                self.conn
                    .execute(
                        "UPDATE conversations
                         SET name = ?2,
                             peer_identity_key = COALESCE(peer_identity_key, ?3),
                             server_id = COALESCE(server_id, ?4),
                             created_at = ?5,
                             server_origin = ?6,
                             peer_user_id = COALESCE(peer_user_id, ?7)
                         WHERE id = ?1",
                        rusqlite::params![
                            id,
                            name,
                            peer_identity_key,
                            server_id,
                            created_at,
                            canonical_server_origin,
                            peer_user_id,
                        ],
                    )
                    .map_err(|e| format!("update directory conversation: {e}"))?;
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                self.conn
                    .execute(
                        "INSERT INTO conversations
                           (id, conv_type, name, peer_identity_key, server_id,
                            created_at, server_origin, peer_user_id)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        rusqlite::params![
                            id,
                            conv_type,
                            name,
                            peer_identity_key,
                            server_id,
                            created_at,
                            canonical_server_origin,
                            peer_user_id,
                        ],
                    )
                    .map_err(|e| format!("insert directory conversation: {e}"))?;
            }
            Err(e) => return Err(format!("load directory conversation: {e}")),
        }
        Ok(())
    }

    /// Atomically persist every Direct conversation from one authenticated
    /// directory page. Duplicate conversation/peer bindings are rejected
    /// before the transaction so a corrupted page cannot select a winner by
    /// row order.
    pub fn upsert_directory_directs(
        &self,
        canonical_server_origin: &str,
        conversations: &[AuthenticatedDirectDirectoryEntry],
    ) -> Result<(), String> {
        validate_canonical_server_origin(canonical_server_origin)?;
        let mut conversation_ids = std::collections::HashSet::with_capacity(conversations.len());
        let mut peer_user_ids = std::collections::HashSet::with_capacity(conversations.len());
        let mut peer_identity_keys = std::collections::HashSet::with_capacity(conversations.len());
        for conversation in conversations {
            if !conversation_ids.insert(conversation.conversation_id.as_str()) {
                return Err("Direct directory batch repeats a conversation id".to_string());
            }
            if !peer_user_ids.insert(conversation.peer_user_id.as_str())
                || !peer_identity_keys.insert(conversation.peer_identity_key)
            {
                return Err("Direct directory batch repeats a peer account".to_string());
            }
        }

        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|error| format!("begin Direct directory transaction: {error}"))?;
        for conversation in conversations {
            let duplicate = self
                .conn
                .query_row(
                    "SELECT id
                     FROM conversations
                     WHERE conv_type = 0 AND id <> ?1
                       AND (
                         peer_identity_key = ?2
                         OR (server_origin = ?3 AND peer_user_id = ?4)
                       )
                     LIMIT 1",
                    rusqlite::params![
                        conversation.conversation_id,
                        conversation.peer_identity_key.as_slice(),
                        canonical_server_origin,
                        conversation.peer_user_id,
                    ],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| format!("check duplicate Direct directory route: {error}"))?;
            if let Some(existing_id) = duplicate {
                return Err(format!(
                    "Direct peer is already bound to conversation {existing_id}"
                ));
            }
            self.upsert_directory_conversation(
                &conversation.conversation_id,
                0,
                canonical_server_origin,
                Some(&conversation.name),
                Some(&conversation.peer_user_id),
                Some(&conversation.peer_identity_key),
                None,
                &conversation.created_at,
            )?;
        }
        tx.commit()
            .map_err(|error| format!("commit Direct directory transaction: {error}"))
    }

    /// Resolve one Direct history trust scope from a single SQLCipher read
    /// transaction. The authenticated self binding, conversation origin/type,
    /// immutable peer route and both directory account tuples must all agree.
    ///
    /// This helper deliberately accepts no candidate keys from the network.
    /// A caller may compare its process-local pins with the returned tuples,
    /// but it cannot use this function to establish new trust.
    pub fn resolve_authenticated_direct_history_scope_v1(
        &self,
        canonical_server_origin: &str,
        authenticated_user_id: &str,
        conversation_id: &str,
    ) -> Result<AuthenticatedDirectHistoryScopeV1, String> {
        validate_canonical_server_origin(canonical_server_origin)?;
        validate_canonical_uuid(
            "Direct history authenticated user id",
            authenticated_user_id,
        )?;
        validate_canonical_uuid("Direct history conversation id", conversation_id)?;

        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|error| format!("begin Direct history scope read: {error}"))?;
        let self_binding = load_authenticated_self_binding(&tx, canonical_server_origin)?
            .ok_or("Direct history origin has no authenticated self binding")?;
        if self_binding.user_id != authenticated_user_id {
            return Err("Direct history user differs from authenticated self".to_string());
        }

        let route = tx
            .query_row(
                "SELECT conv_type, server_origin, peer_user_id, peer_identity_key
                 FROM conversations WHERE id = ?1",
                rusqlite::params![conversation_id],
                |row| {
                    Ok((
                        row.get::<_, u8>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| format!("load Direct history conversation route: {error}"))?
            .ok_or("Direct history conversation is absent from SQLCipher")?;
        let (conversation_type, stored_origin, peer_user_id, peer_identity_key) = route;
        if conversation_type != 0 || stored_origin.as_deref() != Some(canonical_server_origin) {
            return Err("Direct history conversation has the wrong type or origin".to_string());
        }
        let peer_user_id = peer_user_id.ok_or("Direct history conversation has no peer user")?;
        validate_canonical_uuid("Direct history peer user id", &peer_user_id)?;
        if peer_user_id == authenticated_user_id {
            return Err("Direct history conversation points to authenticated self".to_string());
        }
        let peer_identity_key: [u8; 32] = peer_identity_key
            .ok_or("Direct history conversation has no peer identity")?
            .try_into()
            .map_err(|_| "Direct history peer identity has the wrong length".to_string())?;

        let self_account =
            load_account_by_origin_user(&tx, canonical_server_origin, authenticated_user_id)?
                .ok_or("Direct history authenticated account is absent from the directory")?;
        let peer_account =
            load_account_by_origin_user(&tx, canonical_server_origin, &peer_user_id)?
                .ok_or("Direct history peer account is absent from the directory")?;
        if self_account.locator.identity_key != self_binding.identity_key
            || self_account.signing_key != self_binding.signing_key
        {
            return Err("Direct history authenticated directory tuple changed".to_string());
        }
        if peer_account.locator.identity_key != peer_identity_key {
            return Err("Direct history peer route differs from its directory tuple".to_string());
        }

        tx.commit()
            .map_err(|error| format!("commit Direct history scope read: {error}"))?;
        Ok(AuthenticatedDirectHistoryScopeV1 {
            conversation_id: conversation_id.to_string(),
            self_account,
            peer_account,
        })
    }

    /// Atomically persist the text-channel conversations from one authenticated
    /// server directory page. A conflicting existing scope rolls back every
    /// row from the page so renderer state can never observe a partial trust
    /// boundary.
    pub fn upsert_directory_channels(
        &self,
        canonical_server_origin: &str,
        server_id: &str,
        channels: &[(String, String, String)],
    ) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin channel directory transaction: {e}"))?;
        for (conversation_id, name, created_at) in channels {
            self.upsert_directory_conversation(
                conversation_id,
                2,
                canonical_server_origin,
                Some(name),
                None,
                None,
                Some(server_id),
                created_at,
            )?;
        }
        tx.commit()
            .map_err(|e| format!("commit channel directory transaction: {e}"))
    }

    pub fn get_conversations(&self) -> Result<Vec<crate::models::Conversation>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, conv_type, peer_identity_key, server_id, server_origin,
                        peer_user_id, name, last_message_at, unread_count,
                        last_read_message_id, created_at
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
                    server_origin: row.get(4)?,
                    peer_user_id: row.get(5)?,
                    name: row.get(6)?,
                    last_message_at: row.get(7)?,
                    unread_count: row.get(8)?,
                    last_read_message_id: row.get(9)?,
                    created_at: row.get(10)?,
                })
            })
            .map_err(|e| format!("query: {e}"))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect: {e}"))
    }

    /// Return only authenticated channel conversations belonging to the exact
    /// server namespace. Originless legacy rows are deliberately excluded:
    /// their bare server UUID cannot authorize Sender-Key roster invalidation.
    pub fn list_origin_scoped_channel_conversation_ids(
        &self,
        canonical_server_origin: &str,
        server_id: &str,
    ) -> Result<Vec<String>, String> {
        validate_canonical_server_origin(canonical_server_origin)?;
        validate_canonical_uuid("origin-scoped channel server id", server_id)?;

        let mut stmt = self
            .conn
            .prepare(
                "SELECT id
                 FROM conversations
                 WHERE conv_type = 2 AND server_origin = ?1 AND server_id = ?2
                 ORDER BY id",
            )
            .map_err(|e| format!("prepare origin-scoped channel lookup: {e}"))?;
        let rows = stmt
            .query_map(
                rusqlite::params![canonical_server_origin, server_id],
                |row| row.get::<_, String>(0),
            )
            .map_err(|e| format!("query origin-scoped channels: {e}"))?;

        let mut conversation_ids = Vec::new();
        for row in rows {
            let conversation_id = row.map_err(|e| format!("read origin-scoped channel id: {e}"))?;
            validate_canonical_uuid(
                "persisted origin-scoped channel conversation id",
                &conversation_id,
            )?;
            conversation_ids.push(conversation_id);
        }
        Ok(conversation_ids)
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
        // This helper is used both as a standalone message write and inside
        // the client's atomic receive savepoint. A nested BEGIN transaction
        // is rejected by SQLite, while a SAVEPOINT composes in both cases and
        // still keeps the message row and unread counter all-or-nothing.
        run_savepoint(&self.conn, "veil_insert_message", || {
            let inserted = self
                .conn
                .execute(
                "INSERT OR IGNORE INTO messages (id, conversation_id, sender_key, plaintext, is_outgoing, status, server_timestamp, reply_to_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    id,
                    conversation_id,
                    sender_key,
                    plaintext,
                    is_outgoing as u8,
                    if is_outgoing { 1u8 } else { 2u8 },
                    server_timestamp,
                    reply_to_id,
                ],
            )
            .map_err(|e| format!("insert message: {e}"))?;

            if inserted == 1 {
                self.conn
                    .execute(
                        "UPDATE conversations
                     SET last_message_at = datetime('now'),
                         unread_count = CASE
                           WHEN ?2 = 0 THEN MIN(unread_count + 1, 2147483647)
                           ELSE unread_count
                         END
                     WHERE id = ?1",
                        rusqlite::params![conversation_id, is_outgoing as u8],
                    )
                    .map_err(|e| format!("update conversation message state: {e}"))?;
            }

            Ok(())
        })
    }

    /// Mark the complete currently-persisted timeline read for one exact
    /// authenticated origin. The cursor is device-local and exists only to
    /// make the zero unread count durable; no network read receipt is implied.
    pub fn mark_conversation_read(
        &self,
        conversation_id: &str,
        canonical_server_origin: &str,
    ) -> Result<Option<String>, String> {
        validate_canonical_uuid("read-state conversation id", conversation_id)?;
        validate_canonical_server_origin(canonical_server_origin)?;
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin mark conversation read: {e}"))?;
        let latest_message_id = tx
            .query_row(
                "SELECT m.id
                 FROM messages AS m
                 JOIN conversations AS c ON c.id = m.conversation_id
                 WHERE m.conversation_id = ?1 AND c.server_origin = ?2
                 ORDER BY COALESCE(
                   m.server_timestamp,
                   CAST(strftime('%s', m.created_at) AS INTEGER) * 1000
                 ) DESC, m.rowid DESC
                 LIMIT 1",
                rusqlite::params![conversation_id, canonical_server_origin],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| format!("load latest read-state message: {e}"))?;
        let changed = tx
            .execute(
                "UPDATE conversations
                 SET unread_count = 0, last_read_message_id = ?3
                 WHERE id = ?1 AND server_origin = ?2",
                rusqlite::params![conversation_id, canonical_server_origin, latest_message_id,],
            )
            .map_err(|e| format!("mark conversation read: {e}"))?;
        if changed != 1 {
            return Err(
                "read-state conversation is absent from the authenticated origin".to_string(),
            );
        }
        tx.commit()
            .map_err(|e| format!("commit mark conversation read: {e}"))?;
        Ok(latest_message_id)
    }

    /// Persist private attachment state inside the caller's current
    /// transaction/savepoint. The message row must already exist.
    pub fn insert_message_attachments(
        &self,
        message_id: &str,
        attachments: &[crate::models::MessageAttachment],
    ) -> Result<(), String> {
        if message_id.is_empty() || attachments.len() > 16 {
            return Err("invalid attachment message binding".to_string());
        }
        let mut media_ids = std::collections::HashSet::new();
        for (expected_ordinal, attachment) in attachments.iter().enumerate() {
            if usize::from(attachment.ordinal) != expected_ordinal
                || attachment.file_name.is_empty()
                || attachment.file_name.len() > 1024
                || attachment.detected_mime.is_empty()
                || attachment.detected_mime.len() > 255
                || attachment.format_version == 0
                || attachment.chunk_count == 0
                || attachment.chunk_count > 32_769
                || attachment.plaintext_size > 2 * 1024 * 1024 * 1024
                || attachment.ciphertext_size < 16
                || attachment.ciphertext_size > 2_148_007_952
                || attachment.media_id.len() != 32
                || !attachment
                    .media_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || !media_ids.insert(attachment.media_id.as_str())
            {
                return Err("invalid private attachment record".to_string());
            }
            let chunk_count = i64::try_from(attachment.chunk_count)
                .map_err(|_| "attachment chunk count exceeds SQLCipher integer".to_string())?;
            let plaintext_size = i64::try_from(attachment.plaintext_size)
                .map_err(|_| "attachment plaintext size exceeds SQLCipher integer".to_string())?;
            let ciphertext_size = i64::try_from(attachment.ciphertext_size)
                .map_err(|_| "attachment ciphertext size exceeds SQLCipher integer".to_string())?;
            self.conn
                .execute(
                    "INSERT INTO message_attachments_v1
                       (message_id, ordinal, media_id, file_name, detected_mime,
                        format_version, nonce_prefix, chunk_count, plaintext_size,
                        ciphertext_size, content_key)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    rusqlite::params![
                        message_id,
                        attachment.ordinal,
                        attachment.media_id,
                        attachment.file_name,
                        attachment.detected_mime,
                        attachment.format_version,
                        attachment.nonce_prefix.as_slice(),
                        chunk_count,
                        plaintext_size,
                        ciphertext_size,
                        attachment.content_key.as_slice(),
                    ],
                )
                .map_err(|error| format!("insert private attachment state: {error}"))?;
        }
        Ok(())
    }

    pub fn get_message_attachments(
        &self,
        message_id: &str,
    ) -> Result<Vec<crate::models::MessageAttachment>, String> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT ordinal, media_id, file_name, detected_mime, format_version,
                        nonce_prefix, chunk_count, plaintext_size, ciphertext_size,
                        content_key
                 FROM message_attachments_v1
                 WHERE message_id = ?1
                 ORDER BY ordinal",
            )
            .map_err(|error| format!("prepare private attachment query: {error}"))?;
        let rows = statement
            .query_map(rusqlite::params![message_id], |row| {
                Ok((
                    row.get::<_, u8>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, u8>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            })
            .map_err(|error| format!("query private attachments: {error}"))?;
        let mut attachments = Vec::new();
        for row in rows {
            let (
                ordinal,
                media_id,
                file_name,
                detected_mime,
                format_version,
                nonce_prefix,
                chunk_count,
                plaintext_size,
                ciphertext_size,
                content_key,
            ) = row.map_err(|error| format!("read private attachment: {error}"))?;
            attachments.push(crate::models::MessageAttachment {
                ordinal,
                media_id,
                file_name,
                detected_mime,
                format_version,
                nonce_prefix: fixed_bytes("attachment nonce prefix", nonce_prefix)?,
                chunk_count: u64::try_from(chunk_count)
                    .map_err(|_| "negative attachment chunk count".to_string())?,
                plaintext_size: u64::try_from(plaintext_size)
                    .map_err(|_| "negative attachment plaintext size".to_string())?,
                ciphertext_size: u64::try_from(ciphertext_size)
                    .map_err(|_| "negative attachment ciphertext size".to_string())?,
                content_key: fixed_bytes("attachment content key", content_key)?,
            });
        }
        // Reuse the insert-side structural validator without writing: exact
        // ordinal continuity and duplicate checks are invariants on read too.
        for (expected, attachment) in attachments.iter().enumerate() {
            if usize::from(attachment.ordinal) != expected {
                return Err("persisted attachment ordinals are not contiguous".to_string());
            }
        }
        Ok(attachments)
    }

    pub fn insert_outgoing_pending_message_with_attachments(
        &self,
        id: &str,
        conversation_id: &str,
        sender_key: &[u8; 32],
        plaintext: &str,
        reply_to_id: Option<&str>,
        attachments: &[crate::models::MessageAttachment],
    ) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|error| format!("begin attachment message transaction: {error}"))?;
        tx.execute(
            "INSERT INTO messages
               (id, conversation_id, sender_key, plaintext, is_outgoing, status, reply_to_id, msg_type)
             VALUES (?1, ?2, ?3, ?4, 1, 0, ?5, ?6)",
            rusqlite::params![
                id,
                conversation_id,
                sender_key.as_slice(),
                plaintext,
                reply_to_id,
                if attachments.is_empty() { 0u8 } else { 2u8 },
            ],
        )
        .map_err(|error| format!("insert pending attachment message: {error}"))?;
        // `unchecked_transaction` is active on the same connection; helper
        // writes participate in it and cannot publish attachment keys alone.
        self.insert_message_attachments(id, attachments)?;
        tx.execute(
            "UPDATE conversations SET last_message_at = datetime('now') WHERE id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|error| format!("update attachment conversation timestamp: {error}"))?;
        tx.commit()
            .map_err(|error| format!("commit pending attachment message: {error}"))
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

    /// Commit one advanced Direct ratchet step, optimistic local message, exact
    /// retry payload and private attachment/author state as one IMMEDIATE
    /// transaction. The ratchet CAS is intentionally performed before the
    /// other inserts: every later failure rolls it back with the whole unit.
    pub fn enqueue_direct_message_outbox_v1(
        &self,
        input: &DirectMessageOutboxEnqueueV1,
    ) -> Result<DirectMessageOutboxEnqueueResultV1, String> {
        validate_direct_message_outbox_enqueue_v1(input)?;
        let expected_revision = i64::try_from(input.expected_ratchet_revision)
            .map_err(|_| "Direct outbox expected ratchet revision exceeds SQLite integer")?;
        let next_revision = input
            .expected_ratchet_revision
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or("Direct outbox ratchet revision is exhausted")?;

        let tx = begin_immediate(&self.conn, "Direct message outbox transaction")?;
        let self_binding = require_current_direct_outbox_self_v1(&tx, &input.scope)?;
        let route = resolve_current_direct_outbox_route_v1(
            &tx,
            &input.scope,
            &self_binding,
            &input.conversation_id,
        )?;
        if let Some(snapshot) = input.author_snapshot.as_ref() {
            if snapshot.locator.canonical_server_origin != input.scope.canonical_server_origin
                || snapshot.locator.user_id != input.scope.user_id
                || snapshot.locator.identity_key != route.self_binding.identity_key
                || snapshot.signing_key != route.self_binding.signing_key
            {
                return Err(
                    "Direct outbox author snapshot differs from authenticated self".to_string(),
                );
            }
        }
        if let Some(reply_to_id) = input.reply_to_id.as_deref() {
            let valid_reply: bool = tx
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM messages
                        WHERE id = ?1 AND conversation_id = ?2
                     )",
                    rusqlite::params![reply_to_id, &input.conversation_id],
                    |row| row.get(0),
                )
                .map_err(|error| format!("validate Direct outbox reply target: {error}"))?;
            if !valid_reply {
                return Err(
                    "Direct outbox reply target is absent from its conversation".to_string()
                );
            }
        }

        let pending_count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM direct_message_outbox_v1
                 WHERE canonical_server_origin = ?1 AND user_id = ?2
                   AND device_id = ?3 AND state = 0",
                rusqlite::params![
                    &input.scope.canonical_server_origin,
                    &input.scope.user_id,
                    input.scope.device_id.as_slice(),
                ],
                |row| row.get(0),
            )
            .map_err(|error| format!("count Direct outbox capacity: {error}"))?;
        if pending_count < 0 || pending_count as usize >= DIRECT_MESSAGE_OUTBOX_MAX_PENDING_V1 {
            return Err("Direct outbox pending-row limit reached".to_string());
        }

        let changed = tx
            .execute(
                "UPDATE ratchet_sessions
                 SET session_data = ?1, revision = ?2, updated_at = datetime('now')
                 WHERE peer_identity_key = ?3 AND revision = ?4 AND session_data = ?5",
                rusqlite::params![
                    &input.advanced_ratchet_session,
                    next_revision,
                    route.peer_identity_key.as_slice(),
                    expected_revision,
                    &input.expected_ratchet_session,
                ],
            )
            .map_err(|error| format!("advance Direct outbox ratchet session: {error}"))?;
        if changed != 1 {
            return Err("Direct outbox ratchet revision changed or session is absent".to_string());
        }

        tx.execute(
            "INSERT INTO messages
               (id, conversation_id, sender_key, plaintext, is_outgoing,
                status, reply_to_id, msg_type)
             VALUES (?1, ?2, ?3, ?4, 1, 0, ?5, ?6)",
            rusqlite::params![
                &input.local_message_id,
                &input.conversation_id,
                route.self_binding.identity_key.as_slice(),
                &input.plaintext,
                input.reply_to_id.as_deref(),
                if input.attachments.is_empty() {
                    0u8
                } else {
                    2u8
                },
            ],
        )
        .map_err(|error| format!("insert Direct outbox local message: {error}"))?;
        self.insert_message_attachments(&input.local_message_id, &input.attachments)?;
        if let Some(snapshot) = input.author_snapshot.as_ref() {
            self.attach_message_author(&input.local_message_id, snapshot)?;
        }

        tx.execute(
            "INSERT INTO direct_message_outbox_v1
               (canonical_server_origin, user_id, device_id, conversation_id,
                peer_user_id, peer_identity_key, peer_signing_key,
                client_message_id, local_message_id, request_digest,
                exact_send_message_payload, ratchet_revision, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 0)",
            rusqlite::params![
                &input.scope.canonical_server_origin,
                &input.scope.user_id,
                input.scope.device_id.as_slice(),
                &input.conversation_id,
                &route.peer_user_id,
                route.peer_identity_key.as_slice(),
                route.peer_signing_key.as_slice(),
                &input.client_message_id,
                &input.local_message_id,
                input.request_digest.as_slice(),
                &input.exact_send_message_payload,
                next_revision,
            ],
        )
        .map_err(|error| format!("insert Direct exact outbox row: {error}"))?;
        let queue_order = u64::try_from(tx.last_insert_rowid())
            .ok()
            .filter(|value| *value > 0)
            .ok_or("Direct outbox queue order is invalid")?;
        tx.execute(
            "UPDATE conversations SET last_message_at = datetime('now') WHERE id = ?1",
            rusqlite::params![&input.conversation_id],
        )
        .map_err(|error| format!("update Direct outbox conversation timestamp: {error}"))?;
        tx.commit()
            .map_err(|error| format!("commit Direct message outbox transaction: {error}"))?;

        Ok(DirectMessageOutboxEnqueueResultV1 {
            queue_order,
            client_message_id: input.client_message_id.clone(),
            local_message_id: input.local_message_id.clone(),
            ratchet_revision: u64::try_from(next_revision)
                .map_err(|_| "committed Direct outbox ratchet revision is invalid")?,
        })
    }

    /// Load pending exact payloads in durable FIFO order for one authenticated
    /// origin/account/device. Every row is revalidated against current SQLCipher
    /// self, device, conversation, peer directory and ratchet state.
    pub fn load_pending_direct_message_outbox_v1(
        &self,
        scope: &DirectMessageOutboxScopeV1,
        limit: usize,
    ) -> Result<Vec<PendingDirectMessageOutboxV1>, String> {
        self.load_pending_direct_message_outbox_after_v1(scope, None, limit)
    }

    /// Continue a strict FIFO scan after the last committed queue order from
    /// the previous page. The cursor is a local SQLCipher row order, not a
    /// server-provided value.
    pub fn load_pending_direct_message_outbox_after_v1(
        &self,
        scope: &DirectMessageOutboxScopeV1,
        after_queue_order: Option<u64>,
        limit: usize,
    ) -> Result<Vec<PendingDirectMessageOutboxV1>, String> {
        validate_direct_message_outbox_scope_v1(scope)?;
        if limit == 0 || limit > DIRECT_MESSAGE_OUTBOX_MAX_LOAD_V1 {
            return Err("Direct outbox load limit is invalid".to_string());
        }
        let after_queue_order_sql = after_queue_order
            .map(|value| {
                if value == 0 {
                    return Err("Direct outbox FIFO cursor is invalid".to_string());
                }
                i64::try_from(value)
                    .map_err(|_| "Direct outbox FIFO cursor exceeds SQLite integer".to_string())
            })
            .transpose()?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)
            .map_err(|error| format!("begin Direct outbox read transaction: {error}"))?;
        let self_binding = require_current_direct_outbox_self_v1(&tx, scope)?;
        let total: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM direct_message_outbox_v1
                 WHERE canonical_server_origin = ?1 AND user_id = ?2
                   AND device_id = ?3 AND state = 0",
                rusqlite::params![
                    &scope.canonical_server_origin,
                    &scope.user_id,
                    scope.device_id.as_slice(),
                ],
                |row| row.get(0),
            )
            .map_err(|error| format!("count pending Direct outbox rows: {error}"))?;
        if total < 0 || total as usize > DIRECT_MESSAGE_OUTBOX_MAX_PENDING_V1 {
            return Err("persisted Direct outbox exceeds its pending-row bound".to_string());
        }

        let sql = format!(
            "SELECT {DIRECT_MESSAGE_OUTBOX_SELECT_V1}
             FROM direct_message_outbox_v1
             WHERE canonical_server_origin = ?1 AND user_id = ?2
               AND device_id = ?3 AND state = 0
               AND queue_order > COALESCE(?4, 0)
             ORDER BY queue_order ASC LIMIT ?5"
        );
        let mut statement = tx
            .prepare(&sql)
            .map_err(|error| format!("prepare pending Direct outbox load: {error}"))?;
        let rows = statement
            .query_map(
                rusqlite::params![
                    &scope.canonical_server_origin,
                    &scope.user_id,
                    scope.device_id.as_slice(),
                    after_queue_order_sql,
                    i64::try_from(limit).map_err(|_| "Direct outbox load limit overflow")?,
                ],
                stored_direct_message_outbox_row_v1,
            )
            .map_err(|error| format!("query pending Direct outbox rows: {error}"))?;
        let mut pending = Vec::new();
        let mut previous_queue_order = after_queue_order.unwrap_or(0);
        for row in rows {
            let row = row.map_err(|error| format!("read pending Direct outbox row: {error}"))?;
            let route = resolve_current_direct_outbox_route_v1(
                &tx,
                scope,
                &self_binding,
                &row.conversation_id,
            )?;
            let validated = validate_stored_direct_outbox_row_v1(&row, scope, Some(&route))?;
            if validated.queue_order <= previous_queue_order {
                return Err("persisted Direct outbox FIFO order is invalid".to_string());
            }
            previous_queue_order = validated.queue_order;
            let current_ratchet_revision: i64 = tx
                .query_row(
                    "SELECT revision FROM ratchet_sessions WHERE peer_identity_key = ?1",
                    rusqlite::params![validated.peer_identity_key.as_slice()],
                    |ratchet_row| ratchet_row.get(0),
                )
                .optional()
                .map_err(|error| format!("load pending Direct ratchet revision: {error}"))?
                .ok_or("pending Direct outbox ratchet session is absent")?;
            let current_ratchet_revision = u64::try_from(current_ratchet_revision)
                .map_err(|_| "pending Direct ratchet revision is invalid")?;
            if validated.ratchet_revision > current_ratchet_revision {
                return Err("pending Direct outbox is ahead of its ratchet session".to_string());
            }
            let local_binding = tx
                .query_row(
                    "SELECT conversation_id, sender_key, is_outgoing, status, plaintext
                     FROM messages WHERE id = ?1",
                    rusqlite::params![&row.local_message_id],
                    |message_row| {
                        Ok((
                            message_row.get::<_, String>(0)?,
                            message_row.get::<_, Vec<u8>>(1)?,
                            message_row.get::<_, bool>(2)?,
                            message_row.get::<_, i64>(3)?,
                            message_row.get::<_, String>(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| format!("load pending Direct local message: {error}"))?
                .ok_or("pending Direct outbox local message is absent")?;
            if local_binding.0 != row.conversation_id
                || local_binding.1.as_slice() != route.self_binding.identity_key.as_slice()
                || !local_binding.2
                || local_binding.3 != 0
                || local_binding.4.len() > DIRECT_MESSAGE_PLAINTEXT_MAX_BYTES_V1
            {
                return Err("pending Direct outbox local message binding is invalid".to_string());
            }
            pending.push(PendingDirectMessageOutboxV1 {
                queue_order: validated.queue_order,
                scope: scope.clone(),
                conversation_id: row.conversation_id.clone(),
                peer_user_id: row.peer_user_id.clone(),
                peer_identity_key: validated.peer_identity_key,
                peer_signing_key: validated.peer_signing_key,
                client_message_id: row.client_message_id.clone(),
                local_message_id: row.local_message_id.clone(),
                request_digest: validated.request_digest,
                exact_send_message_payload: row
                    .exact_send_message_payload
                    .clone()
                    .ok_or("pending Direct outbox payload disappeared")?,
                ratchet_revision: validated.ratchet_revision,
                plaintext: local_binding.4,
            });
        }
        drop(statement);
        tx.commit()
            .map_err(|error| format!("commit Direct outbox read transaction: {error}"))?;
        Ok(pending)
    }

    pub fn count_pending_direct_message_outbox_v1(
        &self,
        scope: &DirectMessageOutboxScopeV1,
    ) -> Result<usize, String> {
        validate_direct_message_outbox_scope_v1(scope)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)
            .map_err(|error| format!("begin Direct outbox count transaction: {error}"))?;
        require_current_direct_outbox_self_v1(&tx, scope)?;
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM direct_message_outbox_v1
                 WHERE canonical_server_origin = ?1 AND user_id = ?2
                   AND device_id = ?3 AND state = 0",
                rusqlite::params![
                    &scope.canonical_server_origin,
                    &scope.user_id,
                    scope.device_id.as_slice(),
                ],
                |row| row.get(0),
            )
            .map_err(|error| format!("count pending Direct outbox rows: {error}"))?;
        let count = usize::try_from(count)
            .ok()
            .filter(|value| *value <= DIRECT_MESSAGE_OUTBOX_MAX_PENDING_V1)
            .ok_or("persisted Direct outbox exceeds its pending-row bound")?;
        tx.commit()
            .map_err(|error| format!("commit Direct outbox count transaction: {error}"))?;
        Ok(count)
    }

    /// Load and fully validate one durable receipt without changing it.
    /// `Ok(None)` is an authoritative absence, while `Err` means the
    /// SQLCipher read or its persisted invariants could not be trusted.
    pub fn load_direct_message_outbox_receipt_v1(
        &self,
        scope: &DirectMessageOutboxScopeV1,
        client_message_id: &str,
    ) -> Result<Option<DirectMessageOutboxReceiptV1>, String> {
        validate_direct_message_outbox_scope_v1(scope)?;
        validate_canonical_uuid("Direct outbox receipt client message id", client_message_id)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)
            .map_err(|error| format!("begin Direct outbox receipt read: {error}"))?;
        let self_binding = require_current_direct_outbox_self_v1(&tx, scope)?;
        let sql = format!(
            "SELECT {DIRECT_MESSAGE_OUTBOX_SELECT_V1}
             FROM direct_message_outbox_v1
             WHERE client_message_id = ?1
               AND canonical_server_origin = ?2
               AND user_id = ?3 AND device_id = ?4"
        );
        let Some(row) = tx
            .query_row(
                &sql,
                rusqlite::params![
                    client_message_id,
                    &scope.canonical_server_origin,
                    &scope.user_id,
                    scope.device_id.as_slice(),
                ],
                stored_direct_message_outbox_row_v1,
            )
            .optional()
            .map_err(|error| format!("load Direct outbox receipt row: {error}"))?
        else {
            tx.commit()
                .map_err(|error| format!("commit empty Direct outbox receipt read: {error}"))?;
            return Ok(None);
        };
        let route = if row.state == 0 {
            Some(resolve_current_direct_outbox_route_v1(
                &tx,
                scope,
                &self_binding,
                &row.conversation_id,
            )?)
        } else {
            None
        };
        validate_stored_direct_outbox_row_v1(&row, scope, route.as_ref())?;
        let receipt = match row.state {
            0 => DirectMessageOutboxReceiptV1::Pending {
                local_message_id: row.local_message_id.clone(),
            },
            1 => DirectMessageOutboxReceiptV1::Acknowledged {
                local_message_id: row.local_message_id.clone(),
                server_message_id: row
                    .server_message_id
                    .clone()
                    .expect("validated acknowledged receipt has a server message id"),
                server_timestamp_ms: row
                    .server_timestamp_ms
                    .expect("validated acknowledged receipt has a server timestamp"),
            },
            2 => DirectMessageOutboxReceiptV1::Rejected {
                local_message_id: row.local_message_id.clone(),
                rejection_reason: row
                    .rejection_reason
                    .clone()
                    .expect("validated rejected receipt has a stable reason"),
            },
            _ => unreachable!("validated Direct outbox receipt state"),
        };
        tx.commit()
            .map_err(|error| format!("commit Direct outbox receipt read: {error}"))?;
        Ok(Some(receipt))
    }

    /// Commit the authoritative ACK result and erase retry bytes atomically.
    /// An acknowledged compact receipt remains immutable, making an identical
    /// repeated ACK harmless and every different result fail closed.
    pub fn acknowledge_direct_message_outbox_v1(
        &self,
        scope: &DirectMessageOutboxScopeV1,
        client_message_id: &str,
        server_message_id: &str,
        server_timestamp_ms: i64,
    ) -> Result<DirectMessageOutboxAckResultV1, String> {
        self.acknowledge_direct_message_outbox_inner_v1(
            scope,
            client_message_id,
            server_message_id,
            server_timestamp_ms,
            true,
        )
    }

    /// Validate an identical ACK only against an already-committed compact
    /// receipt. This can never transition a pending row and is therefore safe
    /// when the process has no current socket-sequence correlation.
    pub fn validate_repeated_direct_message_outbox_ack_v1(
        &self,
        scope: &DirectMessageOutboxScopeV1,
        client_message_id: &str,
        server_message_id: &str,
        server_timestamp_ms: i64,
    ) -> Result<DirectMessageOutboxAckResultV1, String> {
        self.acknowledge_direct_message_outbox_inner_v1(
            scope,
            client_message_id,
            server_message_id,
            server_timestamp_ms,
            false,
        )
    }

    fn acknowledge_direct_message_outbox_inner_v1(
        &self,
        scope: &DirectMessageOutboxScopeV1,
        client_message_id: &str,
        server_message_id: &str,
        server_timestamp_ms: i64,
        allow_pending_transition: bool,
    ) -> Result<DirectMessageOutboxAckResultV1, String> {
        validate_direct_message_outbox_scope_v1(scope)?;
        validate_canonical_uuid("Direct outbox ACK client message id", client_message_id)?;
        validate_canonical_uuid("Direct outbox ACK server message id", server_message_id)?;
        if server_timestamp_ms <= 0 {
            return Err("Direct outbox ACK timestamp is invalid".to_string());
        }
        let tx = begin_immediate(&self.conn, "Direct outbox ACK transaction")?;
        let self_binding = require_current_direct_outbox_self_v1(&tx, scope)?;
        let sql = format!(
            "SELECT {DIRECT_MESSAGE_OUTBOX_SELECT_V1}
             FROM direct_message_outbox_v1 WHERE client_message_id = ?1"
        );
        let row = tx
            .query_row(
                &sql,
                rusqlite::params![client_message_id],
                stored_direct_message_outbox_row_v1,
            )
            .optional()
            .map_err(|error| format!("load Direct outbox ACK row: {error}"))?
            .ok_or("Direct outbox ACK client message id is unknown")?;
        if row.state == 2 {
            validate_stored_direct_outbox_row_v1(&row, scope, None)?;
            return Err("rejected Direct outbox receipt cannot be acknowledged".to_string());
        }

        if row.state == 1 {
            validate_stored_direct_outbox_row_v1(&row, scope, None)?;
            if row.server_message_id.as_deref() != Some(server_message_id)
                || row.server_timestamp_ms != Some(server_timestamp_ms)
            {
                return Err(
                    "repeated Direct outbox ACK conflicts with its durable receipt".to_string(),
                );
            }
            tx.commit()
                .map_err(|error| format!("commit repeated Direct outbox ACK read: {error}"))?;
            return Ok(DirectMessageOutboxAckResultV1 {
                client_message_id: row.client_message_id.clone(),
                local_message_id: row.local_message_id.clone(),
                server_message_id: server_message_id.to_string(),
                server_timestamp_ms,
                already_acknowledged: true,
            });
        }

        let route = resolve_current_direct_outbox_route_v1(
            &tx,
            scope,
            &self_binding,
            &row.conversation_id,
        )?;
        let validated = validate_stored_direct_outbox_row_v1(&row, scope, Some(&route))?;

        if !allow_pending_transition {
            return Err(
                "pending Direct outbox ACK requires a current transport sequence correlation"
                    .to_string(),
            );
        }

        let current_ratchet_revision: i64 = tx
            .query_row(
                "SELECT revision FROM ratchet_sessions WHERE peer_identity_key = ?1",
                rusqlite::params![validated.peer_identity_key.as_slice()],
                |ratchet_row| ratchet_row.get(0),
            )
            .optional()
            .map_err(|error| format!("load Direct ACK ratchet revision: {error}"))?
            .ok_or("Direct ACK ratchet session is absent")?;
        if u64::try_from(current_ratchet_revision)
            .map_err(|_| "Direct ACK ratchet revision is invalid")?
            < validated.ratchet_revision
        {
            return Err("Direct ACK outbox is ahead of its ratchet session".to_string());
        }
        let local_message = tx
            .query_row(
                "SELECT conversation_id, sender_key, is_outgoing, status
                 FROM messages WHERE id = ?1",
                rusqlite::params![&row.local_message_id],
                |message_row| {
                    Ok((
                        message_row.get::<_, String>(0)?,
                        message_row.get::<_, Vec<u8>>(1)?,
                        message_row.get::<_, bool>(2)?,
                        message_row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| format!("load Direct ACK local message: {error}"))?
            .ok_or("Direct ACK local message is absent")?;
        if local_message.0 != row.conversation_id
            || local_message.1.as_slice() != route.self_binding.identity_key.as_slice()
            || !local_message.2
            || local_message.3 != 0
        {
            return Err("Direct ACK local message binding is invalid".to_string());
        }
        let collision: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM messages WHERE id = ?1 AND id <> ?2
                 )",
                rusqlite::params![server_message_id, &row.local_message_id],
                |message_row| message_row.get(0),
            )
            .map_err(|error| format!("check Direct ACK server id collision: {error}"))?;
        if collision {
            return Err("Direct ACK server message id already exists locally".to_string());
        }
        let changed = tx
            .execute(
                "UPDATE messages
                 SET id = ?1, server_timestamp = ?2, status = 1
                 WHERE id = ?3 AND conversation_id = ?4
                   AND is_outgoing = 1 AND status = 0",
                rusqlite::params![
                    server_message_id,
                    server_timestamp_ms,
                    &row.local_message_id,
                    &row.conversation_id,
                ],
            )
            .map_err(|error| format!("acknowledge Direct outbox message: {error}"))?;
        if changed != 1 {
            return Err("Direct ACK pending message changed during reconciliation".to_string());
        }
        if row.local_message_id != server_message_id {
            tx.execute(
                "UPDATE messages SET reply_to_id = ?1 WHERE reply_to_id = ?2",
                rusqlite::params![server_message_id, &row.local_message_id],
            )
            .map_err(|error| format!("migrate Direct ACK reply references: {error}"))?;
            tx.execute(
                "UPDATE reactions SET message_id = ?1 WHERE message_id = ?2",
                rusqlite::params![server_message_id, &row.local_message_id],
            )
            .map_err(|error| format!("migrate Direct ACK reaction references: {error}"))?;
        }
        let receipt_changed = tx
            .execute(
                "UPDATE direct_message_outbox_v1
                 SET state = 1, exact_send_message_payload = NULL,
                     server_message_id = ?1, server_timestamp_ms = ?2,
                     updated_at = datetime('now')
                 WHERE queue_order = ?3 AND state = 0",
                rusqlite::params![server_message_id, server_timestamp_ms, row.queue_order],
            )
            .map_err(|error| format!("commit Direct outbox ACK receipt: {error}"))?;
        if receipt_changed != 1 {
            return Err("Direct outbox ACK receipt changed during reconciliation".to_string());
        }
        tx.commit()
            .map_err(|error| format!("commit Direct outbox ACK transaction: {error}"))?;
        Ok(DirectMessageOutboxAckResultV1 {
            client_message_id: row.client_message_id.clone(),
            local_message_id: row.local_message_id.clone(),
            server_message_id: server_message_id.to_string(),
            server_timestamp_ms,
            already_acknowledged: false,
        })
    }

    /// Commit a correlated permanent server rejection. Callers must not use
    /// this for retryable transport loss, rate limiting or server failure.
    /// The exact payload is erased, while the UUID/digest/reason receipt stays
    /// immutable so the same ciphertext can never be assigned a new meaning.
    pub fn reject_direct_message_outbox_v1(
        &self,
        scope: &DirectMessageOutboxScopeV1,
        client_message_id: &str,
        rejection_reason: &str,
    ) -> Result<DirectMessageOutboxRejectResultV1, String> {
        self.reject_direct_message_outbox_inner_v1(scope, client_message_id, rejection_reason, true)
    }

    /// Validate an identical permanent Error only against an existing
    /// rejected receipt. It cannot turn a pending intent into Failed without
    /// a current exact sequence map.
    pub fn validate_repeated_direct_message_outbox_rejection_v1(
        &self,
        scope: &DirectMessageOutboxScopeV1,
        client_message_id: &str,
        rejection_reason: &str,
    ) -> Result<DirectMessageOutboxRejectResultV1, String> {
        self.reject_direct_message_outbox_inner_v1(
            scope,
            client_message_id,
            rejection_reason,
            false,
        )
    }

    fn reject_direct_message_outbox_inner_v1(
        &self,
        scope: &DirectMessageOutboxScopeV1,
        client_message_id: &str,
        rejection_reason: &str,
        allow_pending_transition: bool,
    ) -> Result<DirectMessageOutboxRejectResultV1, String> {
        validate_direct_message_outbox_scope_v1(scope)?;
        validate_canonical_uuid(
            "Direct outbox rejection client message id",
            client_message_id,
        )?;
        validate_direct_message_rejection_reason_v1(rejection_reason)?;

        let tx = begin_immediate(&self.conn, "Direct outbox rejection transaction")?;
        let self_binding = require_current_direct_outbox_self_v1(&tx, scope)?;
        let sql = format!(
            "SELECT {DIRECT_MESSAGE_OUTBOX_SELECT_V1}
             FROM direct_message_outbox_v1 WHERE client_message_id = ?1"
        );
        let row = tx
            .query_row(
                &sql,
                rusqlite::params![client_message_id],
                stored_direct_message_outbox_row_v1,
            )
            .optional()
            .map_err(|error| format!("load Direct outbox rejection row: {error}"))?
            .ok_or("Direct outbox rejection client message id is unknown")?;
        match row.state {
            1 => {
                validate_stored_direct_outbox_row_v1(&row, scope, None)?;
                return Err("acknowledged Direct outbox receipt cannot be rejected".to_string());
            }
            2 => {
                validate_stored_direct_outbox_row_v1(&row, scope, None)?;
                if row.rejection_reason.as_deref() != Some(rejection_reason) {
                    return Err(
                        "repeated Direct outbox rejection conflicts with its durable receipt"
                            .to_string(),
                    );
                }
                tx.commit().map_err(|error| {
                    format!("commit repeated Direct outbox rejection read: {error}")
                })?;
                return Ok(DirectMessageOutboxRejectResultV1 {
                    client_message_id: row.client_message_id.clone(),
                    local_message_id: row.local_message_id.clone(),
                    rejection_reason: rejection_reason.to_string(),
                    already_rejected: true,
                });
            }
            0 => {}
            _ => return Err("persisted Direct outbox state is invalid".to_string()),
        }

        let route = resolve_current_direct_outbox_route_v1(
            &tx,
            scope,
            &self_binding,
            &row.conversation_id,
        )?;
        let validated = validate_stored_direct_outbox_row_v1(&row, scope, Some(&route))?;

        if !allow_pending_transition {
            return Err(
                "pending Direct outbox rejection requires a current transport sequence correlation"
                    .to_string(),
            );
        }

        let current_ratchet_revision: i64 = tx
            .query_row(
                "SELECT revision FROM ratchet_sessions WHERE peer_identity_key = ?1",
                rusqlite::params![validated.peer_identity_key.as_slice()],
                |ratchet_row| ratchet_row.get(0),
            )
            .optional()
            .map_err(|error| format!("load Direct rejection ratchet revision: {error}"))?
            .ok_or("Direct rejection ratchet session is absent")?;
        if u64::try_from(current_ratchet_revision)
            .map_err(|_| "Direct rejection ratchet revision is invalid")?
            < validated.ratchet_revision
        {
            return Err("Direct rejection outbox is ahead of its ratchet session".to_string());
        }
        let failed = tx
            .execute(
                "UPDATE messages SET status = 4
                 WHERE id = ?1 AND conversation_id = ?2 AND sender_key = ?3
                   AND is_outgoing = 1 AND status = 0",
                rusqlite::params![
                    &row.local_message_id,
                    &row.conversation_id,
                    route.self_binding.identity_key.as_slice(),
                ],
            )
            .map_err(|error| format!("mark rejected Direct message Failed: {error}"))?;
        if failed != 1 {
            return Err("Direct rejection pending message binding changed".to_string());
        }
        let receipt_changed = tx
            .execute(
                "UPDATE direct_message_outbox_v1
                 SET state = 2, exact_send_message_payload = NULL,
                     rejection_reason = ?1, updated_at = datetime('now')
                 WHERE queue_order = ?2 AND state = 0",
                rusqlite::params![rejection_reason, row.queue_order],
            )
            .map_err(|error| format!("commit Direct outbox rejection receipt: {error}"))?;
        if receipt_changed != 1 {
            return Err(
                "Direct outbox rejection receipt changed during reconciliation".to_string(),
            );
        }
        tx.commit()
            .map_err(|error| format!("commit Direct outbox rejection transaction: {error}"))?;
        Ok(DirectMessageOutboxRejectResultV1 {
            client_message_id: row.client_message_id.clone(),
            local_message_id: row.local_message_id.clone(),
            rejection_reason: rejection_reason.to_string(),
            already_rejected: false,
        })
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

    /// Preserve plaintext for an asynchronously rejected send while making it
    /// impossible to confuse the row with an in-flight message after restart.
    pub fn mark_outgoing_message_failed(&self, local_message_id: &str) -> Result<(), String> {
        let changed = self
            .conn
            .execute(
                "UPDATE messages SET status = 4
                 WHERE id = ?1 AND is_outgoing = 1 AND status = 0",
                rusqlite::params![local_message_id],
            )
            .map_err(|e| format!("mark outgoing message failed: {e}"))?;
        if changed != 1 {
            return Err("pending outgoing message not found for failure".to_string());
        }
        Ok(())
    }

    /// An ACK lost to reconnect/crash is ambiguous: the server may already
    /// have stored and fanned out the ciphertext. Preserve the local plaintext
    /// without claiming either success or failure.
    pub fn mark_outgoing_message_unknown(&self, local_message_id: &str) -> Result<(), String> {
        let changed = self
            .conn
            .execute(
                "UPDATE messages SET status = 5
                 WHERE id = ?1 AND is_outgoing = 1 AND status = 0",
                rusqlite::params![local_message_id],
            )
            .map_err(|e| format!("mark outgoing message delivery unknown: {e}"))?;
        if changed != 1 {
            return Err("pending outgoing message not found for unknown delivery".to_string());
        }
        Ok(())
    }

    /// Mark a whole terminated socket epoch ambiguous atomically. If any row
    /// cannot be transitioned, none are changed; the client can then block a
    /// reconnect and retry instead of leaving a mixture of Sending/Unknown.
    pub fn mark_outgoing_messages_unknown(
        &self,
        local_message_ids: &[String],
    ) -> Result<(), String> {
        if local_message_ids.is_empty() {
            return Ok(());
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin outgoing delivery-state transaction: {e}"))?;
        for local_message_id in local_message_ids {
            let changed = tx
                .execute(
                    "UPDATE messages SET status = 5
                     WHERE id = ?1 AND is_outgoing = 1 AND status = 0",
                    rusqlite::params![local_message_id],
                )
                .map_err(|e| format!("mark outgoing message delivery unknown: {e}"))?;
            if changed != 1 {
                return Err(format!(
                    "pending outgoing message {local_message_id} not found for unknown delivery"
                ));
            }
        }
        tx.commit()
            .map_err(|e| format!("commit outgoing delivery states: {e}"))
    }

    /// Reconcile sequence-correlated sends after a clean transport loss.
    ///
    /// Legacy `Sending` rows have no durable retry correlation and therefore
    /// become `Unknown`. A `Sending` row backed by an exact pending Direct
    /// outbox remains retryable and is left untouched. Every supplied id must
    /// name exactly one of those two shapes; one invalid id rolls back all
    /// legacy transitions in the batch.
    pub fn reconcile_outgoing_transport_loss_v1(
        &self,
        local_message_ids: &[String],
    ) -> Result<usize, String> {
        if local_message_ids.is_empty() {
            return Ok(0);
        }
        let mut unique = HashSet::with_capacity(local_message_ids.len());
        for local_message_id in local_message_ids {
            validate_canonical_uuid("outgoing transport-loss local message id", local_message_id)?;
            if !unique.insert(local_message_id.as_str()) {
                return Err("outgoing transport-loss batch contains a duplicate id".to_string());
            }
        }

        let tx = begin_immediate(&self.conn, "outgoing transport-loss reconciliation")?;
        let mut transitioned = 0usize;
        for local_message_id in local_message_ids {
            let shape = tx
                .query_row(
                    "SELECT message.is_outgoing, message.status,
                            EXISTS(
                                SELECT 1 FROM direct_message_outbox_v1 AS pending
                                WHERE pending.local_message_id = message.id
                                  AND pending.state = 0
                            ),
                            EXISTS(
                                SELECT 1 FROM direct_message_outbox_v1 AS outbox
                                WHERE outbox.local_message_id = message.id
                            )
                     FROM messages AS message WHERE message.id = ?1",
                    rusqlite::params![local_message_id],
                    |row| {
                        Ok((
                            row.get::<_, bool>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, bool>(2)?,
                            row.get::<_, bool>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| format!("load outgoing transport-loss message shape: {error}"))?
                .ok_or_else(|| {
                    format!("outgoing transport-loss message {local_message_id} is absent")
                })?;
            if !shape.0 || shape.1 != 0 {
                return Err(format!(
                    "outgoing transport-loss message {local_message_id} is not Sending"
                ));
            }
            if shape.2 {
                continue;
            }
            if shape.3 {
                return Err(format!(
                    "outgoing transport-loss message {local_message_id} has no pending retry row"
                ));
            }
            let changed = tx
                .execute(
                    "UPDATE messages SET status = 5
                     WHERE id = ?1 AND is_outgoing = 1 AND status = 0
                       AND NOT EXISTS (
                           SELECT 1 FROM direct_message_outbox_v1 AS outbox
                           WHERE outbox.local_message_id = messages.id
                       )",
                    rusqlite::params![local_message_id],
                )
                .map_err(|error| format!("mark legacy outgoing transport loss Unknown: {error}"))?;
            if changed != 1 {
                return Err(format!(
                    "outgoing transport-loss message {local_message_id} changed during reconciliation"
                ));
            }
            transitioned += 1;
        }
        tx.commit()
            .map_err(|error| format!("commit outgoing transport-loss reconciliation: {error}"))?;
        Ok(transitioned)
    }

    /// Legacy process state contains the sequence-to-local-id correlation. An
    /// exact pending outbox row retains that correlation and its retry bytes,
    /// so only legacy status=0 rows become explicitly ambiguous after restart.
    pub fn recover_unacknowledged_outgoing_messages(&self) -> Result<usize, String> {
        self.conn
            .execute(
                "UPDATE messages AS message SET status = 5
                 WHERE message.is_outgoing = 1 AND message.status = 0
                   AND NOT EXISTS (
                       SELECT 1 FROM direct_message_outbox_v1 AS outbox
                       WHERE outbox.state = 0
                         AND outbox.local_message_id = message.id
                   )",
                [],
            )
            .map_err(|e| format!("recover unacknowledged outgoing messages: {e}"))
    }

    pub fn discard_failed_outgoing_message(&self, local_message_id: &str) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin discard local message transaction: {e}"))?;
        let conversation_id: String = tx
            .query_row(
                "SELECT conversation_id FROM messages
                 WHERE id = ?1 AND is_outgoing = 1 AND status IN (4, 5)",
                rusqlite::params![local_message_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("find discarded message conversation: {e}"))?
            .ok_or_else(|| "failed or unknown outgoing message not found".to_string())?;
        let changed = tx
            .execute(
                "DELETE FROM messages WHERE id = ?1 AND is_outgoing = 1 AND status IN (4, 5)",
                rusqlite::params![local_message_id],
            )
            .map_err(|e| format!("discard failed outgoing message: {e}"))?;
        if changed != 1 {
            return Err("failed or unknown outgoing message not found".to_string());
        }
        tx.execute(
            "UPDATE conversations
             SET last_message_at = (
               SELECT CASE
                 WHEN server_timestamp IS NOT NULL
                   THEN strftime('%Y-%m-%d %H:%M:%f', server_timestamp / 1000.0, 'unixepoch')
                 ELSE created_at
               END
               FROM messages
               WHERE conversation_id = ?1
               ORDER BY COALESCE(
                 server_timestamp,
                 CAST(strftime('%s', created_at) AS INTEGER) * 1000
               ) DESC, rowid DESC
               LIMIT 1
             )
             WHERE id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| format!("recalculate conversation last message: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit discarded local message: {e}"))
    }

    pub fn is_discardable_outgoing_message(&self, local_message_id: &str) -> Result<bool, String> {
        self.conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM messages
                   WHERE id = ?1 AND is_outgoing = 1 AND status IN (4, 5)
                 )",
                rusqlite::params![local_message_id],
                |row| row.get(0),
            )
            .map_err(|e| format!("check discardable outgoing message: {e}"))
    }

    pub fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
    ) -> Result<Vec<crate::models::Message>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT m.id, m.conversation_id, m.sender_key, m.plaintext,
                        m.msg_type, m.reply_to_id, m.is_outgoing, m.status,
                        m.expires_at, m.server_timestamp, m.created_at,
                        m.effective_timestamp, m.local_order,
                        a.canonical_server_origin, a.user_id, a.identity_key,
                        a.signing_key, a.username, a.display_name,
                        a.profile_version, a.profile_origin, a.source, a.observed_at,
                        a.author_context
                 FROM (
                   SELECT id, conversation_id, sender_key, plaintext, msg_type, reply_to_id,
                          is_outgoing, status, expires_at, server_timestamp, created_at,
                          COALESCE(
                            server_timestamp,
                            CAST(strftime('%s', created_at) AS INTEGER) * 1000
                          ) AS effective_timestamp,
                          rowid AS local_order
                   FROM messages
                   WHERE conversation_id = ?1
                   ORDER BY effective_timestamp DESC, local_order DESC
                   LIMIT ?2
                 ) AS m
                 LEFT JOIN message_author_snapshots_v1 AS a ON a.message_id = m.id
                 ORDER BY m.effective_timestamp ASC, m.local_order ASC",
            )
            .map_err(|e| format!("prepare: {e}"))?;

        let rows = stmt
            .query_map(rusqlite::params![conversation_id, limit], |row| {
                Ok((
                    Message {
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
                            4 => crate::models::MessageStatus::Failed,
                            5 => crate::models::MessageStatus::Unknown,
                            _ => crate::models::MessageStatus::Sending,
                        },
                        expires_at: row.get(8)?,
                        server_timestamp: row.get(9)?,
                        created_at: row.get(10)?,
                        author: None,
                        author_context: None,
                        attachments: Vec::new(),
                    },
                    raw_account_snapshot_from_row(row, 13)?,
                    row.get::<_, Option<u8>>(23)?,
                ))
            })
            .map_err(|e| format!("query: {e}"))?;

        let mut messages = Vec::new();
        for row in rows {
            let (mut message, author, author_context) =
                row.map_err(|e| format!("collect message: {e}"))?;
            message.author = author.map(RawAccountSnapshot::decode).transpose()?;
            message.author_context = author_context
                .map(|value| {
                    MessageAuthorContext::from_u8(value)
                        .ok_or_else(|| "invalid persisted message author context".to_string())
                })
                .transpose()?;
            message.attachments = self.get_message_attachments(&message.id)?;
            messages.push(message);
        }
        Ok(messages)
    }

    /// Read one newest-first page for an origin-scoped in-memory search rebuild.
    ///
    /// The cursor follows the same `(effective_timestamp, message_id)` order as
    /// the live RAM index. This keeps budget eviction and restart rebuilds on
    /// one deterministic definition of the newest continuous slice, including
    /// rows inserted out of timestamp order. Callers hold decrypted rows only
    /// in process memory and apply their own global memory/document budget.
    pub fn get_search_index_page(
        &self,
        canonical_server_origin: &str,
        before: Option<&crate::models::SearchIndexCursor>,
        limit: u32,
    ) -> Result<Vec<crate::models::SearchIndexDocument>, String> {
        validate_canonical_server_origin(canonical_server_origin)?;
        if limit == 0 || limit > 2_048 {
            return Err("search rebuild page limit must be between 1 and 2048".to_string());
        }
        if let Some(cursor) = before {
            validate_canonical_uuid("search rebuild cursor message id", &cursor.message_id)?;
        }

        let mut stmt = self
            .conn
            .prepare(
                "WITH scoped AS (
                   SELECT m.id, m.conversation_id, m.sender_key, m.plaintext,
                          COALESCE(
                            m.server_timestamp,
                            CAST(strftime('%s', m.created_at) AS INTEGER) * 1000
                          ) AS effective_timestamp
                   FROM messages AS m
                   INNER JOIN conversations AS c ON c.id = m.conversation_id
                   WHERE c.server_origin = ?1
                     AND m.plaintext <> ''
                 )
                 SELECT id, conversation_id, sender_key, plaintext,
                        effective_timestamp
                 FROM scoped
                 WHERE ?2 IS NULL
                    OR effective_timestamp < ?2
                    OR (
                      effective_timestamp = ?2
                      AND id COLLATE BINARY < ?3 COLLATE BINARY
                    )
                 ORDER BY effective_timestamp DESC, id COLLATE BINARY DESC
                 LIMIT ?4",
            )
            .map_err(|e| format!("prepare search rebuild page: {e}"))?;
        let rows = stmt
            .query_map(
                rusqlite::params![
                    canonical_server_origin,
                    before.map(|cursor| cursor.timestamp),
                    before.map(|cursor| cursor.message_id.as_str()),
                    limit
                ],
                |row| {
                    Ok(crate::models::SearchIndexDocument {
                        id: row.get(0)?,
                        conversation_id: row.get(1)?,
                        sender_key: row.get(2)?,
                        plaintext: row.get(3)?,
                        timestamp: row.get(4)?,
                    })
                },
            )
            .map_err(|e| format!("query search rebuild page: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect search rebuild page: {e}"))
    }

    /// Load one current message row for a RAM search-index hit.
    ///
    /// The index is deliberately not an identity authority. Callers must
    /// hydrate author metadata from this origin-scoped SQLCipher row and may
    /// only expose it after matching the indexed message/conversation/sender.
    pub fn get_message_for_search(
        &self,
        message_id: &str,
        conversation_id: &str,
        canonical_server_origin: &str,
    ) -> Result<Option<crate::models::Message>, String> {
        if message_id.is_empty() || conversation_id.is_empty() {
            return Err("search message and conversation ids must not be empty".to_string());
        }
        validate_canonical_server_origin(canonical_server_origin)?;
        let row = self
            .conn
            .query_row(
                "SELECT m.id, m.conversation_id, m.sender_key, m.plaintext,
                        m.msg_type, m.reply_to_id, m.is_outgoing, m.status,
                        m.expires_at, m.server_timestamp, m.created_at,
                        a.canonical_server_origin, a.user_id, a.identity_key,
                        a.signing_key, a.username, a.display_name,
                        a.profile_version, a.profile_origin, a.source, a.observed_at,
                        a.author_context
                 FROM messages AS m
                 JOIN conversations AS c ON c.id = m.conversation_id
                 LEFT JOIN message_author_snapshots_v1 AS a ON a.message_id = m.id
                 WHERE m.id = ?1 AND m.conversation_id = ?2
                   AND c.server_origin = ?3",
                rusqlite::params![message_id, conversation_id, canonical_server_origin],
                |row| {
                    Ok((
                        Message {
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
                                4 => crate::models::MessageStatus::Failed,
                                5 => crate::models::MessageStatus::Unknown,
                                _ => crate::models::MessageStatus::Sending,
                            },
                            expires_at: row.get(8)?,
                            server_timestamp: row.get(9)?,
                            created_at: row.get(10)?,
                            author: None,
                            author_context: None,
                            attachments: Vec::new(),
                        },
                        raw_account_snapshot_from_row(row, 11)?,
                        row.get::<_, Option<u8>>(21)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| format!("load message for search: {error}"))?;
        row.map(|(mut message, author, author_context)| {
            message.author = author.map(RawAccountSnapshot::decode).transpose()?;
            message.author_context = author_context
                .map(|value| {
                    MessageAuthorContext::from_u8(value)
                        .ok_or_else(|| "invalid persisted message author context".to_string())
                })
                .transpose()?;
            Ok(message)
        })
        .transpose()
    }

    /// Return a bounded chronological window centred on one current message.
    ///
    /// Both the conversation and target are re-read from SQLCipher for the
    /// caller's exact authenticated origin. Missing/deleted targets return
    /// `None`; malformed conversation, author, sender, or attachment rows fail
    /// the whole lookup rather than exposing a partially trusted context.
    pub fn get_search_result_context(
        &self,
        message_id: &str,
        conversation_id: &str,
        canonical_server_origin: &str,
    ) -> Result<Option<SearchResultContext>, String> {
        if message_id.is_empty() || conversation_id.is_empty() {
            return Err("search message and conversation ids must not be empty".to_string());
        }
        validate_canonical_server_origin(canonical_server_origin)?;

        let conversation = self
            .conn
            .query_row(
                "SELECT conv_type, server_id
                 FROM conversations
                 WHERE id = ?1 AND server_origin = ?2",
                rusqlite::params![conversation_id, canonical_server_origin],
                |row| Ok((row.get::<_, u8>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()
            .map_err(|error| format!("load search result conversation: {error}"))?;
        let Some((conversation_type, stored_server_id)) = conversation else {
            return Ok(None);
        };
        let (conversation_type, server_id) = match conversation_type {
            0 if stored_server_id.is_none() => (crate::models::ConversationType::DM, None),
            1 if stored_server_id.is_none() => (crate::models::ConversationType::Group, None),
            0 | 1 => {
                return Err("non-channel search context contains a persisted server id".to_string())
            }
            2 => {
                let server_id =
                    stored_server_id.ok_or("channel search context has no persisted server id")?;
                validate_canonical_uuid("channel search context server id", &server_id)?;
                (crate::models::ConversationType::Channel, Some(server_id))
            }
            _ => return Err("search context has an invalid conversation type".to_string()),
        };

        let mut stmt = self
            .conn
            .prepare(
                "WITH ordered AS (
                   SELECT m.id, m.conversation_id, m.sender_key, m.plaintext,
                          m.msg_type, m.reply_to_id, m.is_outgoing, m.status,
                          m.expires_at, m.server_timestamp, m.created_at,
                          COALESCE(
                            m.server_timestamp,
                            CAST(strftime('%s', m.created_at) AS INTEGER) * 1000
                          ) AS effective_timestamp,
                          m.rowid AS local_order,
                          ROW_NUMBER() OVER (
                            ORDER BY COALESCE(
                              m.server_timestamp,
                              CAST(strftime('%s', m.created_at) AS INTEGER) * 1000
                            ) ASC, m.rowid ASC
                          ) AS message_rank,
                          COUNT(*) OVER () AS total_count
                   FROM messages AS m
                   WHERE m.conversation_id = ?1
                 ),
                 target AS (
                   SELECT message_rank, total_count
                   FROM ordered
                   WHERE id = ?2
                 ),
                 bounds AS (
                   SELECT MAX(1, MIN(message_rank - 99, total_count - 199)) AS first_rank
                   FROM target
                 )
                 SELECT m.id, m.conversation_id, m.sender_key, m.plaintext,
                        m.msg_type, m.reply_to_id, m.is_outgoing, m.status,
                        m.expires_at, m.server_timestamp, m.created_at,
                        a.canonical_server_origin, a.user_id, a.identity_key,
                        a.signing_key, a.username, a.display_name,
                        a.profile_version, a.profile_origin, a.source, a.observed_at,
                        a.author_context
                 FROM ordered AS m
                 CROSS JOIN bounds AS b
                 LEFT JOIN message_author_snapshots_v1 AS a ON a.message_id = m.id
                 WHERE m.message_rank BETWEEN b.first_rank AND b.first_rank + 199
                 ORDER BY m.effective_timestamp ASC, m.local_order ASC",
            )
            .map_err(|error| format!("prepare search result context: {error}"))?;
        let rows = stmt
            .query_map(rusqlite::params![conversation_id, message_id], |row| {
                Ok((
                    Message {
                        id: row.get(0)?,
                        conversation_id: row.get(1)?,
                        sender_key: row.get(2)?,
                        plaintext: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                        msg_type: row.get(4)?,
                        reply_to_id: row.get(5)?,
                        is_outgoing: row.get::<_, u8>(6)? != 0,
                        status: match row.get::<_, u8>(7)? {
                            0 => crate::models::MessageStatus::Sending,
                            1 => crate::models::MessageStatus::Sent,
                            2 => crate::models::MessageStatus::Delivered,
                            3 => crate::models::MessageStatus::Read,
                            4 => crate::models::MessageStatus::Failed,
                            5 => crate::models::MessageStatus::Unknown,
                            value => {
                                return Err(rusqlite::Error::IntegralValueOutOfRange(
                                    7,
                                    value as i64,
                                ))
                            }
                        },
                        expires_at: row.get(8)?,
                        server_timestamp: row.get(9)?,
                        created_at: row.get(10)?,
                        author: None,
                        author_context: None,
                        attachments: Vec::new(),
                    },
                    raw_account_snapshot_from_row(row, 11)?,
                    row.get::<_, Option<u8>>(21)?,
                ))
            })
            .map_err(|error| format!("query search result context: {error}"))?;

        let mut messages = Vec::new();
        for row in rows {
            let (mut message, author, author_context) =
                row.map_err(|error| format!("collect search result context: {error}"))?;
            if message.sender_key.len() != 32 {
                return Err("search context contains an invalid sender key".to_string());
            }
            message.author = author.map(RawAccountSnapshot::decode).transpose()?;
            if message.author.as_ref().is_some_and(|author| {
                author.locator.canonical_server_origin != canonical_server_origin
                    || author.locator.identity_key.as_slice() != message.sender_key.as_slice()
            }) {
                return Err(
                    "search context contains a cross-origin or mismatched author".to_string(),
                );
            }
            message.author_context = author_context
                .map(|value| {
                    MessageAuthorContext::from_u8(value).ok_or_else(|| {
                        "invalid persisted search context author context".to_string()
                    })
                })
                .transpose()?;
            message.attachments = self.get_message_attachments(&message.id)?;
            messages.push(message);
        }
        if messages.is_empty() {
            return Ok(None);
        }
        if !messages.iter().any(|message| message.id == message_id) {
            return Err("search context window omitted its target message".to_string());
        }
        if messages.len() > 200 {
            return Err("search context exceeded its 200-message bound".to_string());
        }

        Ok(Some(SearchResultContext {
            conversation_type,
            server_id,
            messages,
        }))
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

    /// Replace exactly one established ratchet revision. A stale process or
    /// second SQLCipher handle cannot overwrite a state it did not decrypt or
    /// encrypt from.
    pub fn compare_and_swap_ratchet_session_v1(
        &self,
        peer_identity_key: &[u8; 32],
        expected_revision: u64,
        expected_session_data: &[u8],
        advanced_session_data: &[u8],
    ) -> Result<u64, String> {
        validate_ratchet_session_blob_v1(expected_session_data)?;
        validate_ratchet_session_blob_v1(advanced_session_data)?;
        let expected_revision = i64::try_from(expected_revision)
            .map_err(|_| "ratchet session revision exceeds SQLite integer".to_string())?;
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| "ratchet session revision is exhausted".to_string())?;
        let changed = self
            .conn
            .execute(
                "UPDATE ratchet_sessions
                 SET session_data = ?1, revision = ?2, updated_at = datetime('now')
                 WHERE peer_identity_key = ?3 AND revision = ?4 AND session_data = ?5",
                rusqlite::params![
                    advanced_session_data,
                    next_revision,
                    peer_identity_key.as_slice(),
                    expected_revision,
                    expected_session_data,
                ],
            )
            .map_err(|error| format!("advance ratchet session: {error}"))?;
        if changed != 1 {
            return Err("ratchet session revision changed or session is absent".to_string());
        }
        u64::try_from(next_revision)
            .map_err(|_| "advanced ratchet session revision is invalid".to_string())
    }

    /// Persist a newly initiated ratchet together with the X3DH metadata that
    /// must remain on outgoing messages until peer possession is proven.
    pub fn save_initiator_session(
        &self,
        peer_identity_key: &[u8; 32],
        session_data: &[u8],
        initial_header_data: &[u8],
    ) -> Result<(), String> {
        validate_ratchet_session_blob_v1(session_data)?;
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin initiator session transaction: {e}"))?;
        tx.execute(
            "INSERT INTO ratchet_sessions
               (peer_identity_key, session_data, revision, updated_at)
             VALUES (?1, ?2, 0, datetime('now'))",
            rusqlite::params![peer_identity_key.as_slice(), session_data],
        )
        .map_err(|e| format!("insert initiator ratchet session: {e}"))?;
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

    /// Direct v2 variant: commit the ratchet, retransmitted initial header,
    /// and sticky origin/account/device/session binding in one transaction.
    pub fn save_initiator_session_v2(
        &self,
        peer_identity_key: &[u8; 32],
        session_data: &[u8],
        initial_header_data: &[u8],
        binding: &DirectSessionBindingBlobV2,
    ) -> Result<(), String> {
        validate_ratchet_session_blob_v1(session_data)?;
        validate_direct_session_binding_blob_v2(peer_identity_key, binding)?;
        if initial_header_data.is_empty()
            || initial_header_data.len() > DIRECT_SESSION_BINDING_MAX_BYTES_V2
        {
            return Err("Direct v2 initial header record is empty or oversized".to_string());
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|error| format!("begin Direct v2 initiator transaction: {error}"))?;
        tx.execute(
            "INSERT INTO ratchet_sessions
               (peer_identity_key, session_data, revision, updated_at)
             VALUES (?1, ?2, 0, datetime('now'))",
            rusqlite::params![peer_identity_key.as_slice(), session_data],
        )
        .map_err(|error| format!("insert Direct v2 initiator ratchet: {error}"))?;
        tx.execute(
            "INSERT INTO pending_initial_headers
               (peer_identity_key, header_data, updated_at)
             VALUES (?1, ?2, datetime('now'))",
            rusqlite::params![peer_identity_key.as_slice(), initial_header_data],
        )
        .map_err(|error| format!("insert Direct v2 initial header: {error}"))?;
        insert_direct_session_binding_v2(&tx, binding)?;
        tx.commit()
            .map_err(|error| format!("commit Direct v2 initiator transaction: {error}"))
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
        if peer_identity_key.len() != 32 {
            return Err("ratchet peer identity key must be 32 bytes".to_string());
        }
        match self.conn.query_row(
            "SELECT CASE
                        WHEN length(session_data) BETWEEN 1 AND ?2 THEN session_data
                        ELSE NULL
                    END
             FROM ratchet_sessions WHERE peer_identity_key = ?1",
            rusqlite::params![
                peer_identity_key,
                DIRECT_MESSAGE_RATCHET_MAX_BYTES_SQLITE_V1
            ],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        ) {
            Ok(Some(data)) => Ok(Some(data)),
            Ok(None) => Err("persisted ratchet session is empty or oversized".to_string()),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("load ratchet session: {e}")),
        }
    }

    /// Load the exact serialized ratchet state together with the revision that
    /// a future atomic Direct enqueue must present to its CAS update.
    pub fn load_ratchet_session_with_revision_v1(
        &self,
        peer_identity_key: &[u8; 32],
    ) -> Result<Option<RatchetSessionWithRevisionV1>, String> {
        let row = self
            .conn
            .query_row(
                "SELECT CASE
                            WHEN length(session_data) BETWEEN 1 AND ?2 THEN session_data
                            ELSE NULL
                        END,
                        revision
                 FROM ratchet_sessions WHERE peer_identity_key = ?1",
                rusqlite::params![
                    peer_identity_key.as_slice(),
                    DIRECT_MESSAGE_RATCHET_MAX_BYTES_SQLITE_V1
                ],
                |row| Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|error| format!("load ratchet session revision: {error}"))?;
        let Some((session_data, revision)) = row else {
            return Ok(None);
        };
        let session_data = session_data
            .ok_or_else(|| "persisted ratchet session is empty or oversized".to_string())?;
        let revision = u64::try_from(revision)
            .map_err(|_| "persisted ratchet session revision is invalid".to_string())?;
        Ok(Some(RatchetSessionWithRevisionV1 {
            session_data,
            revision,
        }))
    }

    /// Load every encrypted-at-rest ratchet row for startup validation. The
    /// caller may publish only origin-authorized peers, but malformed orphan
    /// rows must not remain a silent future session-replacement hazard.
    pub fn load_all_ratchet_sessions_with_revision_v1(
        &self,
    ) -> Result<Vec<([u8; 32], RatchetSessionWithRevisionV1)>, String> {
        // Keep the resource preflight and row read on one SQLite snapshot so a
        // second process cannot race extra rows or bytes in after validation.
        // Aggregate length/type checks do not materialize any BLOB in Rust.
        let transaction = self
            .conn
            .unchecked_transaction()
            .map_err(|error| format!("begin ratchet session validation load: {error}"))?;
        let (row_count, total_session_bytes, invalid_rows): (i64, i64, i64) = transaction
            .query_row(
                "SELECT COUNT(*),
                        COALESCE(SUM(
                            CASE
                                WHEN typeof(session_data) = 'blob'
                                 AND length(session_data) BETWEEN 1 AND ?1
                                THEN length(session_data)
                                ELSE 0
                            END
                        ), 0),
                        COALESCE(MAX(
                            CASE
                                WHEN typeof(peer_identity_key) != 'blob'
                                  OR length(peer_identity_key) != 32
                                  OR typeof(session_data) != 'blob'
                                  OR length(session_data) NOT BETWEEN 1 AND ?1
                                  OR typeof(revision) != 'integer'
                                  OR revision < 0
                                THEN 1
                                ELSE 0
                            END
                        ), 0)
                 FROM (
                     SELECT peer_identity_key, session_data, revision
                     FROM ratchet_sessions
                     LIMIT ?2
                 )",
                rusqlite::params![
                    DIRECT_MESSAGE_RATCHET_MAX_BYTES_SQLITE_V1,
                    DIRECT_RATCHET_SESSION_MAX_ROWS_SQLITE_V1 + 1,
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| format!("preflight ratchet session validation load: {error}"))?;
        let row_capacity = validate_ratchet_session_load_preflight_v1(
            row_count,
            total_session_bytes,
            invalid_rows,
        )?;

        let mut statement = transaction
            .prepare(
                "SELECT CASE
                            WHEN typeof(peer_identity_key) = 'blob'
                             AND length(peer_identity_key) = 32
                            THEN peer_identity_key
                            ELSE NULL
                        END,
                        CASE
                            WHEN typeof(session_data) = 'blob'
                             AND length(session_data) BETWEEN 1 AND ?1
                            THEN session_data
                            ELSE NULL
                        END,
                        CASE
                            WHEN typeof(revision) = 'integer' AND revision >= 0
                            THEN revision
                            ELSE NULL
                        END
                 FROM ratchet_sessions",
            )
            .map_err(|error| format!("prepare ratchet session validation load: {error}"))?;
        let rows = statement
            .query_map(
                rusqlite::params![DIRECT_MESSAGE_RATCHET_MAX_BYTES_SQLITE_V1],
                |row| {
                    Ok((
                        row.get::<_, Option<Vec<u8>>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .map_err(|error| format!("query ratchet session validation rows: {error}"))?;
        let mut result = Vec::with_capacity(row_capacity);
        for row in rows {
            let (peer_identity_key, session_data, revision) =
                row.map_err(|error| format!("read ratchet session validation row: {error}"))?;
            let mut session_data =
                zeroize::Zeroizing::new(session_data.ok_or_else(|| {
                    "persisted ratchet session is empty or oversized".to_string()
                })?);
            let peer_identity_key: [u8; 32] = peer_identity_key
                .ok_or_else(|| "persisted ratchet peer identity key is malformed".to_string())?
                .try_into()
                .map_err(|peer_identity_key: Vec<u8>| {
                    format!(
                        "persisted ratchet peer identity key has invalid length {}",
                        peer_identity_key.len()
                    )
                })?;
            let revision = u64::try_from(
                revision
                    .ok_or_else(|| "persisted ratchet session revision is invalid".to_string())?,
            )
            .map_err(|_| "persisted ratchet session revision is invalid".to_string())?;
            result.push((
                peer_identity_key,
                RatchetSessionWithRevisionV1 {
                    session_data: std::mem::take(&mut *session_data),
                    revision,
                },
            ));
        }
        drop(statement);
        transaction
            .commit()
            .map_err(|error| format!("commit ratchet session validation load: {error}"))?;
        Ok(result)
    }

    /// Load every sticky Direct v2 binding. The caller must strictly parse the
    /// opaque record and compare all duplicated coordinates before associating
    /// it with a ratchet row.
    pub fn load_all_direct_session_bindings_v2(
        &self,
    ) -> Result<Vec<DirectSessionBindingBlobV2>, String> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT peer_identity_key, session_id, local_device_id,
                        peer_device_id, binding_data
                 FROM direct_session_bindings_v2
                 WHERE wire_version = 2
                 ORDER BY peer_identity_key",
            )
            .map_err(|error| format!("prepare Direct v2 bindings: {error}"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })
            .map_err(|error| format!("query Direct v2 bindings: {error}"))?;
        let mut bindings = Vec::new();
        for row in rows {
            let (peer, session, local_device, peer_device, binding_data) =
                row.map_err(|error| format!("read Direct v2 binding: {error}"))?;
            let binding = DirectSessionBindingBlobV2 {
                peer_identity_key: peer.try_into().map_err(|value: Vec<u8>| {
                    format!("invalid Direct v2 peer length: {}", value.len())
                })?,
                session_id: session.try_into().map_err(|value: Vec<u8>| {
                    format!("invalid Direct v2 session length: {}", value.len())
                })?,
                local_device_id: local_device.try_into().map_err(|value: Vec<u8>| {
                    format!("invalid Direct v2 local device length: {}", value.len())
                })?,
                peer_device_id: peer_device.try_into().map_err(|value: Vec<u8>| {
                    format!("invalid Direct v2 peer device length: {}", value.len())
                })?,
                binding_data,
            };
            validate_direct_session_binding_blob_v2(&binding.peer_identity_key, &binding)?;
            bindings.push(binding);
        }
        Ok(bindings)
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

    /// Load the durable device identity. A separate marker is committed in the
    /// same transaction as the key row so deletion/corruption cannot be
    /// mistaken for a legacy installation and silently generate a replacement.
    pub fn load_device_identity_v1(&self) -> Result<Option<LocalDeviceIdentityV1>, String> {
        let marker: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM client_state WHERE key = 'device_binding_v1_created'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("load device binding marker: {e}"))?;

        type DeviceRow = (
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            i64,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
        );
        let row: Option<DeviceRow> = self
            .conn
            .query_row(
                "SELECT device_id, version, x25519_secret, ed25519_secret,
                        device_identity_key, device_signing_key, capabilities,
                        status, account_identity_key, account_signing_key,
                        account_signature
                   FROM device_identity_v1 WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| format!("load device identity: {e}"))?;

        match (marker, row) {
            (None, None) => Ok(None),
            (Some(_), None) => Err(
                "device binding marker exists but private device identity is missing".to_string(),
            ),
            (None, Some(_)) => {
                Err("private device identity exists without its binding marker".to_string())
            }
            (Some(marker), Some(row)) => {
                let device_id = fixed_bytes::<16>("device id", row.0)?;
                let marker = fixed_bytes::<16>("device binding marker", marker)?;
                if marker != device_id {
                    return Err("device binding marker does not match device identity".to_string());
                }
                let version = u64::from_be_bytes(fixed_bytes::<8>("device version", row.1)?);
                let capabilities =
                    u64::from_be_bytes(fixed_bytes::<8>("device capabilities", row.6)?);
                let status = u8::try_from(row.7)
                    .map_err(|_| "persisted device status is out of range".to_string())?;
                if !(1..=3).contains(&status) {
                    return Err("persisted device status is invalid".to_string());
                }
                Ok(Some(LocalDeviceIdentityV1 {
                    device_id,
                    version,
                    x25519_secret: fixed_bytes::<32>("device X25519 secret", row.2)?,
                    ed25519_secret: fixed_bytes::<32>("device Ed25519 secret", row.3)?,
                    device_identity_key: fixed_bytes::<32>("device identity key", row.4)?,
                    device_signing_key: fixed_bytes::<32>("device signing key", row.5)?,
                    capabilities,
                    status,
                    account_identity_key: fixed_bytes::<32>("account identity key", row.8)?,
                    account_signing_key: fixed_bytes::<32>("account signing key", row.9)?,
                    account_signature: fixed_bytes::<64>("device account signature", row.10)?,
                }))
            }
        }
    }

    /// Commit the first device identity and its non-deletable-without-detection
    /// marker atomically. Existing bindings are immutable through this API.
    pub fn create_device_identity_v1(
        &self,
        identity: &LocalDeviceIdentityV1,
    ) -> Result<(), String> {
        if identity.device_id == [0u8; 16] || identity.version == 0 {
            return Err("refusing an invalid device identity".to_string());
        }
        let persisted_device_id = self.get_or_create_device_id(identity.device_id)?;
        if persisted_device_id != identity.device_id {
            return Err("device identity does not match the stable installation id".to_string());
        }
        if self.load_device_identity_v1()?.is_some() {
            return Err("device identity already exists and is immutable".to_string());
        }

        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin device identity transaction: {e}"))?;
        tx.execute(
            "INSERT INTO device_identity_v1
               (singleton, device_id, version, x25519_secret, ed25519_secret,
                device_identity_key, device_signing_key, capabilities, status,
                account_identity_key, account_signing_key, account_signature)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                identity.device_id.as_slice(),
                identity.version.to_be_bytes().as_slice(),
                identity.x25519_secret.as_slice(),
                identity.ed25519_secret.as_slice(),
                identity.device_identity_key.as_slice(),
                identity.device_signing_key.as_slice(),
                identity.capabilities.to_be_bytes().as_slice(),
                identity.status,
                identity.account_identity_key.as_slice(),
                identity.account_signing_key.as_slice(),
                identity.account_signature.as_slice(),
            ],
        )
        .map_err(|e| format!("store device identity: {e}"))?;
        tx.execute(
            "INSERT INTO client_state (key, value)
             VALUES ('device_binding_v1_created', ?1)",
            rusqlite::params![identity.device_id.as_slice()],
        )
        .map_err(|e| format!("store device binding marker: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit device identity: {e}"))?;
        Ok(())
    }

    /// Advance only the account-signed public binding metadata while keeping
    /// the per-install private keys byte-identical. The server accepts the
    /// same contiguous candidate idempotently during WS v3 auth, so a crash
    /// on either side can safely retry before publishing the new local head.
    pub fn advance_device_identity_binding_v1(
        &self,
        candidate: &LocalDeviceIdentityV1,
    ) -> Result<(), String> {
        let current = self
            .load_device_identity_v1()?
            .ok_or("device identity is missing during binding advance")?;
        let expected_version = current
            .version
            .checked_add(1)
            .ok_or("device binding version is exhausted")?;
        if candidate.device_id != current.device_id
            || candidate.version != expected_version
            || candidate.x25519_secret != current.x25519_secret
            || candidate.ed25519_secret != current.ed25519_secret
            || candidate.device_identity_key != current.device_identity_key
            || candidate.device_signing_key != current.device_signing_key
            || candidate.capabilities | current.capabilities != candidate.capabilities
            || candidate.capabilities == current.capabilities
            || candidate.status != current.status
            || candidate.account_identity_key != current.account_identity_key
            || candidate.account_signing_key != current.account_signing_key
            || candidate.account_signature == current.account_signature
        {
            return Err("device binding advance changed immutable identity state".to_string());
        }
        let updated = self
            .conn
            .execute(
                "UPDATE device_identity_v1
                 SET version = ?1, capabilities = ?2, account_signature = ?3
                 WHERE singleton = 1 AND version = ?4 AND capabilities = ?5
                   AND account_signature = ?6",
                rusqlite::params![
                    candidate.version.to_be_bytes().as_slice(),
                    candidate.capabilities.to_be_bytes().as_slice(),
                    candidate.account_signature.as_slice(),
                    current.version.to_be_bytes().as_slice(),
                    current.capabilities.to_be_bytes().as_slice(),
                    current.account_signature.as_slice(),
                ],
            )
            .map_err(|e| format!("advance local device binding: {e}"))?;
        if updated != 1 {
            return Err("local device binding changed concurrently".to_string());
        }
        Ok(())
    }

    /// Commit an independently validated roster proof and every observed
    /// account-authorized device binding as one rollback-resistant snapshot.
    pub fn commit_device_roster_snapshot_v1(
        &self,
        snapshot: &DeviceRosterSnapshotV1<'_>,
    ) -> Result<(), String> {
        if snapshot.conversation_id.is_empty()
            || snapshot.roster_version == 0
            || snapshot.roster_version > i64::MAX as u64
            || snapshot.required_capabilities == 0
            || snapshot.required_capabilities > i64::MAX as u64
            || snapshot.canonical_snapshot.is_empty()
            || snapshot.canonical_snapshot.len() > 1_048_576
        {
            return Err("invalid device roster snapshot scope".to_string());
        }
        let mut unique_devices = std::collections::HashSet::new();
        for binding in snapshot.bindings {
            if binding.device_id == [0u8; 16]
                || !unique_devices.insert(binding.device_id)
                || binding.binding_version == 0
                || binding.binding_version > i64::MAX as u64
                || binding.capabilities > i64::MAX as u64
                || !(1..=3).contains(&binding.status)
                || std::collections::HashSet::from([
                    binding.account_identity_key,
                    binding.account_signing_key,
                    binding.device_identity_key,
                    binding.device_signing_key,
                ])
                .len()
                    != 4
            {
                return Err("invalid device binding pin in roster snapshot".to_string());
            }
        }

        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin device roster snapshot transaction: {e}"))?;
        let existing_roster = tx
            .query_row(
                "SELECT roster_version, roster_commitment, required_capabilities,
                        canonical_snapshot
                 FROM conversation_device_roster_snapshots_v1
                 WHERE conversation_id = ?1",
                rusqlite::params![snapshot.conversation_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| format!("load pinned device roster head: {e}"))?;
        if let Some((version, commitment, capabilities, canonical)) = existing_roster {
            let version = u64::from_be_bytes(fixed_bytes("roster version", version)?);
            if snapshot.roster_version < version {
                return Err("device roster version rollback rejected".to_string());
            }
            if snapshot.roster_version == version
                && (commitment.as_slice() != snapshot.roster_commitment
                    || u64::from_be_bytes(fixed_bytes::<8>(
                        "roster required capabilities",
                        capabilities,
                    )?) != snapshot.required_capabilities
                    || canonical.as_slice() != snapshot.canonical_snapshot)
            {
                return Err("same device roster version changed committed state".to_string());
            }
        }

        for binding in snapshot.bindings {
            type PinRow = (
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                i64,
                Vec<u8>,
            );
            let existing: Option<PinRow> = tx
                .query_row(
                    "SELECT account_identity_key, account_signing_key,
                            device_identity_key, device_signing_key,
                            binding_version, capabilities, status,
                            account_signature
                     FROM device_binding_pins_v1 WHERE device_id = ?1",
                    rusqlite::params![binding.device_id.as_slice()],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                            row.get(7)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| format!("load device binding pin: {e}"))?;
            if let Some(existing) = existing {
                let old_version =
                    u64::from_be_bytes(fixed_bytes("pinned binding version", existing.4)?);
                let old_capabilities =
                    u64::from_be_bytes(fixed_bytes("pinned binding capabilities", existing.5)?);
                let old_status = u8::try_from(existing.6)
                    .map_err(|_| "pinned device binding status is invalid".to_string())?;
                if existing.0.as_slice() != binding.account_identity_key
                    || existing.1.as_slice() != binding.account_signing_key
                    || existing.2.as_slice() != binding.device_identity_key
                    || existing.3.as_slice() != binding.device_signing_key
                {
                    return Err("pinned device/account key replacement rejected".to_string());
                }
                if binding.binding_version < old_version {
                    return Err("device binding version rollback rejected".to_string());
                }
                if old_status == 3 && binding.status != 3 {
                    return Err("revoked device binding cannot become active again".to_string());
                }
                if binding.binding_version == old_version
                    && (binding.capabilities != old_capabilities
                        || binding.status != old_status
                        || existing.7.as_slice() != binding.account_signature)
                {
                    return Err("same device binding version changed signed state".to_string());
                }
            }

            tx.execute(
                "INSERT INTO device_binding_pins_v1
                    (device_id, account_identity_key, account_signing_key,
                     device_identity_key, device_signing_key, binding_version,
                     capabilities, status, account_signature, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, datetime('now'))
                 ON CONFLICT(device_id) DO UPDATE SET
                    binding_version = excluded.binding_version,
                    capabilities = excluded.capabilities,
                    status = excluded.status,
                    account_signature = excluded.account_signature,
                    updated_at = datetime('now')",
                rusqlite::params![
                    binding.device_id.as_slice(),
                    binding.account_identity_key.as_slice(),
                    binding.account_signing_key.as_slice(),
                    binding.device_identity_key.as_slice(),
                    binding.device_signing_key.as_slice(),
                    binding.binding_version.to_be_bytes().as_slice(),
                    binding.capabilities.to_be_bytes().as_slice(),
                    binding.status,
                    binding.account_signature.as_slice(),
                ],
            )
            .map_err(|e| format!("pin device binding: {e}"))?;
        }

        tx.execute(
            "INSERT INTO conversation_device_roster_snapshots_v1
                (conversation_id, roster_version, roster_commitment,
                 required_capabilities, canonical_snapshot, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))
             ON CONFLICT(conversation_id) DO UPDATE SET
                roster_version = excluded.roster_version,
                roster_commitment = excluded.roster_commitment,
                required_capabilities = excluded.required_capabilities,
                canonical_snapshot = excluded.canonical_snapshot,
                updated_at = datetime('now')",
            rusqlite::params![
                snapshot.conversation_id,
                snapshot.roster_version.to_be_bytes().as_slice(),
                snapshot.roster_commitment.as_slice(),
                snapshot.required_capabilities.to_be_bytes().as_slice(),
                snapshot.canonical_snapshot,
            ],
        )
        .map_err(|e| format!("persist device roster snapshot: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit device roster snapshot: {e}"))
    }

    pub fn load_device_roster_head_v1(
        &self,
        conversation_id: &str,
    ) -> Result<Option<(u64, [u8; 32], u64)>, String> {
        let row = self
            .conn
            .query_row(
                "SELECT roster_version, roster_commitment, required_capabilities
                 FROM conversation_device_roster_snapshots_v1
                 WHERE conversation_id = ?1",
                rusqlite::params![conversation_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| format!("load device roster head: {e}"))?;
        row.map(|(version, commitment, capabilities)| {
            Ok((
                u64::from_be_bytes(fixed_bytes("roster version", version)?),
                fixed_bytes("roster commitment", commitment)?,
                u64::from_be_bytes(fixed_bytes("roster capabilities", capabilities)?),
            ))
        })
        .transpose()
    }

    pub fn load_membership_epoch_head_v1(
        &self,
        conversation_id: &str,
    ) -> Result<Option<MembershipEpochPinnedHeadV1>, String> {
        let row = self
            .conn
            .query_row(
                "SELECT epoch, epoch_hash, roster_version, roster_commitment
                 FROM conversation_membership_epoch_heads_v1
                 WHERE conversation_id = ?1",
                rusqlite::params![conversation_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| format!("load membership epoch head: {e}"))?;
        row.map(|(epoch, hash, roster_version, roster_commitment)| {
            let epoch = u64::from_be_bytes(fixed_bytes("membership epoch", epoch)?);
            let roster_version =
                u64::from_be_bytes(fixed_bytes("membership roster version", roster_version)?);
            if epoch == 0 || roster_version == 0 {
                return Err("persisted membership epoch head is invalid".to_string());
            }
            Ok(MembershipEpochPinnedHeadV1 {
                epoch,
                epoch_hash: fixed_bytes("membership epoch hash", hash)?,
                roster_version,
                roster_commitment: fixed_bytes("membership roster commitment", roster_commitment)?,
            })
        })
        .transpose()
    }

    pub fn membership_epoch_matches_pin_v1(
        &self,
        conversation_id: &str,
        epoch: u64,
        epoch_hash: &[u8; 32],
    ) -> Result<bool, String> {
        if conversation_id.is_empty()
            || epoch == 0
            || epoch > i64::MAX as u64
            || epoch_hash == &[0u8; 32]
        {
            return Ok(false);
        }
        let stored = self
            .conn
            .query_row(
                "SELECT epoch_hash
                 FROM conversation_membership_epoch_history_v1
                 WHERE conversation_id = ?1 AND epoch = ?2",
                rusqlite::params![conversation_id, epoch.to_be_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|e| format!("load membership epoch history pin: {e}"))?;
        match stored {
            Some(stored) => {
                Ok(fixed_bytes::<32>("membership epoch history hash", stored)? == *epoch_hash)
            }
            None => Ok(false),
        }
    }

    /// Commit a completely verified predecessor-linked chain. Existing rows
    /// must be byte-identical and new rows must extend the durable head by one;
    /// restoring an older SQLCipher file therefore cannot silently roll back
    /// a head that remains present in this database.
    pub fn commit_membership_epoch_chain_v1(
        &self,
        records: &[MembershipEpochPinV1],
    ) -> Result<MembershipEpochPinnedHeadV1, String> {
        if records.is_empty() || records.len() > 100_000 {
            return Err("invalid membership epoch chain length".to_string());
        }
        let conversation_id = records[0].conversation_id.as_str();
        if conversation_id.is_empty() {
            return Err("invalid membership epoch conversation".to_string());
        }
        for (index, record) in records.iter().enumerate() {
            let expected_epoch = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or("membership epoch number overflow")?;
            if record.conversation_id != conversation_id
                || record.epoch != expected_epoch
                || record.epoch > i64::MAX as u64
                || record.epoch_hash == [0u8; 32]
                || (record.epoch == 1) != (record.predecessor_hash == [0u8; 32])
                || record.roster_version == 0
                || record.roster_version > i64::MAX as u64
                || record.roster_commitment == [0u8; 32]
                || record.canonical_unsigned.is_empty()
                || record.canonical_unsigned.len() > 65_536
                || (record.epoch == 1)
                    != (record.bootstrap_owner_id.is_some()
                        && record.bootstrap_owner_signing_key.is_some())
                || (index > 0 && record.predecessor_hash != records[index - 1].epoch_hash)
            {
                return Err("invalid membership epoch pin".to_string());
            }
        }

        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin membership epoch pin transaction: {e}"))?;
        let existing_head = tx
            .query_row(
                "SELECT epoch, epoch_hash FROM conversation_membership_epoch_heads_v1
                 WHERE conversation_id = ?1",
                rusqlite::params![conversation_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|e| format!("load membership epoch pin head: {e}"))?;
        if let Some((encoded_epoch, encoded_hash)) = existing_head {
            let epoch = u64::from_be_bytes(fixed_bytes("membership epoch", encoded_epoch)?);
            let head = records
                .get(usize::try_from(epoch.saturating_sub(1)).unwrap_or(usize::MAX))
                .ok_or("membership epoch rollback rejected")?;
            if head.epoch_hash.as_slice() != encoded_hash {
                return Err("membership epoch equivocation rejected".to_string());
            }
        }

        for record in records {
            let existing = tx
                .query_row(
                    "SELECT epoch_hash, predecessor_hash, roster_version,
                            roster_commitment, canonical_unsigned,
                            bootstrap_owner_id, bootstrap_owner_signing_key
                     FROM conversation_membership_epoch_history_v1
                     WHERE conversation_id = ?1 AND epoch = ?2",
                    rusqlite::params![conversation_id, record.epoch.to_be_bytes().as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, Option<Vec<u8>>>(5)?,
                            row.get::<_, Option<Vec<u8>>>(6)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| format!("load membership epoch pin: {e}"))?;
            if let Some(existing) = existing {
                if existing.0.as_slice() != record.epoch_hash
                    || existing.1.as_slice() != record.predecessor_hash
                    || existing.2.as_slice() != record.roster_version.to_be_bytes()
                    || existing.3.as_slice() != record.roster_commitment
                    || existing.4.as_slice() != record.canonical_unsigned
                    || existing.5.as_deref()
                        != record
                            .bootstrap_owner_id
                            .as_ref()
                            .map(|value| value.as_slice())
                    || existing.6.as_deref()
                        != record
                            .bootstrap_owner_signing_key
                            .as_ref()
                            .map(|value| value.as_slice())
                {
                    return Err("membership epoch history equivocation rejected".to_string());
                }
                continue;
            }
            tx.execute(
                "INSERT INTO conversation_membership_epoch_history_v1
                    (conversation_id, epoch, epoch_hash, predecessor_hash,
                     roster_version, roster_commitment, canonical_unsigned,
                     bootstrap_owner_id, bootstrap_owner_signing_key)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    conversation_id,
                    record.epoch.to_be_bytes().as_slice(),
                    record.epoch_hash.as_slice(),
                    record.predecessor_hash.as_slice(),
                    record.roster_version.to_be_bytes().as_slice(),
                    record.roster_commitment.as_slice(),
                    record.canonical_unsigned.as_slice(),
                    record
                        .bootstrap_owner_id
                        .as_ref()
                        .map(|value| value.as_slice()),
                    record
                        .bootstrap_owner_signing_key
                        .as_ref()
                        .map(|value| value.as_slice()),
                ],
            )
            .map_err(|e| format!("pin membership epoch: {e}"))?;
        }
        let head = records.last().ok_or("membership epoch head is absent")?;
        tx.execute(
            "INSERT INTO conversation_membership_epoch_heads_v1
                (conversation_id, epoch, epoch_hash, roster_version,
                 roster_commitment, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))
             ON CONFLICT(conversation_id) DO UPDATE SET
                epoch = excluded.epoch,
                epoch_hash = excluded.epoch_hash,
                roster_version = excluded.roster_version,
                roster_commitment = excluded.roster_commitment,
                updated_at = datetime('now')",
            rusqlite::params![
                conversation_id,
                head.epoch.to_be_bytes().as_slice(),
                head.epoch_hash.as_slice(),
                head.roster_version.to_be_bytes().as_slice(),
                head.roster_commitment.as_slice(),
            ],
        )
        .map_err(|e| format!("advance membership epoch head: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit membership epoch pins: {e}"))?;
        Ok(MembershipEpochPinnedHeadV1 {
            epoch: head.epoch,
            epoch_hash: head.epoch_hash,
            roster_version: head.roster_version,
            roster_commitment: head.roster_commitment,
        })
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
    /// are protected by SQLCipher and zeroized by `LocalPreKey` on drop. A
    /// protocol id is immutable for the lifetime of the installation: a stale
    /// client must fail instead of replacing or resurrecting key material.
    pub fn save_local_prekeys(&self, keys: &[LocalPreKey]) -> Result<(), String> {
        let tx = begin_immediate(&self.conn, "local prekey transaction")?;
        for key in keys {
            let signature = key.signature.as_ref().map(|value| value.as_slice());
            tx.execute(
                "INSERT INTO local_prekeys
                   (key_type, protocol_key_id, secret_key, public_key, signature, consumed)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
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

    /// Initialize or advance the persisted allocator to at least one greater
    /// than every existing protocol id. The immediate transaction also makes
    /// opening an older database safe before its first reservation.
    pub fn synchronize_local_prekey_allocator(&self) -> Result<(u32, u32), String> {
        let tx = begin_immediate(&self.conn, "local prekey allocator synchronization")?;
        let next = synchronize_local_prekey_allocator_on(&tx)?;
        tx.commit()
            .map_err(|error| format!("commit local prekey allocator synchronization: {error}"))?;
        Ok(next)
    }

    /// Atomically reserve one SPK id and twenty contiguous OPK ids.
    ///
    /// The reservation is intentionally committed before generation and key
    /// persistence. Gaps after crashes or failed writes are safe; reuse is not.
    pub fn reserve_local_prekey_batch_ids(&self) -> Result<LocalPreKeyIdReservationV1, String> {
        let tx = begin_immediate(&self.conn, "local prekey id reservation")?;
        let (signed_prekey_id, one_time_prekey_start_id) =
            synchronize_local_prekey_allocator_on(&tx)?;
        let next_signed_prekey_id = signed_prekey_id
            .checked_add(1)
            .ok_or_else(|| "signed prekey id exhausted".to_string())?;
        let next_one_time_prekey_id = one_time_prekey_start_id
            .checked_add(LOCAL_PREKEY_PUBLICATION_BATCH_SIZE as u32)
            .ok_or_else(|| "one-time prekey id exhausted".to_string())?;
        let changed = tx
            .execute(
                "UPDATE local_prekey_allocator_v1
                 SET next_signed_prekey_id = ?1,
                     next_one_time_prekey_id = ?2,
                     updated_at = datetime('now')
                 WHERE singleton = 1
                   AND next_signed_prekey_id = ?3
                   AND next_one_time_prekey_id = ?4",
                rusqlite::params![
                    i64::from(next_signed_prekey_id),
                    i64::from(next_one_time_prekey_id),
                    i64::from(signed_prekey_id),
                    i64::from(one_time_prekey_start_id),
                ],
            )
            .map_err(|error| format!("reserve local prekey ids: {error}"))?;
        if changed != 1 {
            return Err("local prekey allocator changed during reservation".to_string());
        }
        tx.commit()
            .map_err(|error| format!("commit local prekey id reservation: {error}"))?;
        Ok(LocalPreKeyIdReservationV1 {
            signed_prekey_id,
            one_time_prekey_start_id,
            next_signed_prekey_id,
            next_one_time_prekey_id,
        })
    }

    /// Atomically reserve twenty contiguous OPK ids without advancing the SPK
    /// allocator. This is used only to refill an acknowledged publication
    /// whose exact current signed prekey is retained.
    pub fn reserve_local_one_time_prekey_batch_ids(
        &self,
    ) -> Result<LocalOneTimePreKeyIdReservationV1, String> {
        let tx = begin_immediate(&self.conn, "local one-time prekey id reservation")?;
        let (signed_prekey_id, one_time_prekey_start_id) =
            synchronize_local_prekey_allocator_on(&tx)?;
        let next_one_time_prekey_id = one_time_prekey_start_id
            .checked_add(LOCAL_PREKEY_PUBLICATION_BATCH_SIZE as u32)
            .ok_or_else(|| "one-time prekey id exhausted".to_string())?;
        let changed = tx
            .execute(
                "UPDATE local_prekey_allocator_v1
                 SET next_one_time_prekey_id = ?1,
                     updated_at = datetime('now')
                 WHERE singleton = 1
                   AND next_signed_prekey_id = ?2
                   AND next_one_time_prekey_id = ?3",
                rusqlite::params![
                    i64::from(next_one_time_prekey_id),
                    i64::from(signed_prekey_id),
                    i64::from(one_time_prekey_start_id),
                ],
            )
            .map_err(|error| format!("reserve local one-time prekey ids: {error}"))?;
        if changed != 1 {
            return Err("local prekey allocator changed during OPK reservation".to_string());
        }
        tx.commit()
            .map_err(|error| format!("commit local one-time prekey id reservation: {error}"))?;
        Ok(LocalOneTimePreKeyIdReservationV1 {
            one_time_prekey_start_id,
            next_one_time_prekey_id,
        })
    }

    /// Atomically persist a newly generated SPK/OPK batch and its exact-byte
    /// origin-scoped publication outbox. Existing protocol ids are never
    /// overwritten: one id must identify one key for the lifetime of an
    /// installation, including after a failed or ambiguous network attempt.
    pub fn save_local_prekeys_with_publication(
        &self,
        keys: &[LocalPreKey],
        publication: &LocalPreKeyPublicationV1,
    ) -> Result<(), String> {
        validate_local_prekey_publication_input(keys, publication)?;

        let tx = begin_immediate(&self.conn, "local prekey publication transaction")?;
        validate_local_prekey_publication_scope_on(&tx, publication)?;

        for key in keys {
            let signature = key.signature.as_ref().map(|value| value.as_slice());
            tx.execute(
                "INSERT INTO local_prekeys
                   (key_type, protocol_key_id, secret_key, public_key, signature, consumed)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                rusqlite::params![
                    key.key_type,
                    i64::from(key.protocol_key_id),
                    key.secret_key.as_slice(),
                    key.public_key.as_slice(),
                    signature,
                ],
            )
            .map_err(|e| {
                format!(
                    "save immutable local publication prekey {}: {e}",
                    key.protocol_key_id
                )
            })?;
        }

        save_local_prekey_publication_outbox_on(&tx, publication)?;

        tx.commit()
            .map_err(|e| format!("commit local prekey publication: {e}"))
    }

    /// Persist an OPK-only refill and replace the exact-byte publication
    /// outbox in one transaction. The supplied SPK must already exist as the
    /// exact live immutable row; it is checked but never reinserted.
    pub fn save_local_prekey_refill_with_publication(
        &self,
        signed_prekey: &LocalPreKey,
        one_time_prekeys: &[LocalPreKey],
        publication: &LocalPreKeyPublicationV1,
    ) -> Result<(), String> {
        validate_local_prekey_refill_input(signed_prekey, one_time_prekeys, publication)?;

        let tx = begin_immediate(&self.conn, "local prekey refill transaction")?;
        validate_local_prekey_publication_scope_on(&tx, publication)?;

        let persisted: Option<PersistedLocalSignedPreKeyRow> = tx
            .query_row(
                "SELECT secret_key, public_key, signature, consumed
                 FROM local_prekeys
                 WHERE key_type = 0 AND protocol_key_id = ?1",
                rusqlite::params![i64::from(signed_prekey.protocol_key_id)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|e| format!("load retained local signed prekey: {e}"))?;
        let Some((secret_key, public_key, signature, consumed)) = persisted else {
            return Err("retained local signed prekey is unavailable".to_string());
        };
        if consumed != 0
            || secret_key.as_slice() != signed_prekey.secret_key.as_slice()
            || public_key.as_slice() != signed_prekey.public_key.as_slice()
            || signature.as_deref()
                != signed_prekey
                    .signature
                    .as_ref()
                    .map(|value| value.as_slice())
        {
            return Err("retained local signed prekey differs from immutable storage".to_string());
        }

        for key in one_time_prekeys {
            tx.execute(
                "INSERT INTO local_prekeys
                   (key_type, protocol_key_id, secret_key, public_key, signature, consumed)
                 VALUES (1, ?1, ?2, ?3, NULL, 0)",
                rusqlite::params![
                    i64::from(key.protocol_key_id),
                    key.secret_key.as_slice(),
                    key.public_key.as_slice(),
                ],
            )
            .map_err(|e| {
                format!(
                    "save immutable local refill OPK {}: {e}",
                    key.protocol_key_id
                )
            })?;
        }
        save_local_prekey_publication_outbox_on(&tx, publication)?;
        tx.commit()
            .map_err(|e| format!("commit local prekey refill: {e}"))
    }

    /// Load one exact live signed prekey for publication refill. No other
    /// private prekey material is exposed to the caller.
    pub fn load_local_signed_prekey(
        &self,
        protocol_key_id: u32,
    ) -> Result<Option<LocalPreKey>, String> {
        if protocol_key_id == 0 {
            return Err("local signed prekey id is invalid".to_string());
        }
        let raw = self
            .conn
            .query_row(
                "SELECT secret_key, public_key, signature
                 FROM local_prekeys
                 WHERE key_type = 0 AND protocol_key_id = ?1 AND consumed = 0",
                rusqlite::params![i64::from(protocol_key_id)],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| format!("load exact local signed prekey: {e}"))?;
        raw.map(|(secret, public, signature)| {
            let secret = Zeroizing::new(secret);
            let secret_key: [u8; 32] = secret.as_slice().try_into().map_err(|_| {
                format!(
                    "invalid local signed prekey secret length for {protocol_key_id}: {}",
                    secret.len()
                )
            })?;
            Ok(LocalPreKey {
                key_type: 0,
                protocol_key_id,
                secret_key,
                public_key: fixed_bytes::<32>("local signed prekey public key", public)?,
                signature: Some(fixed_bytes::<64>(
                    "local signed prekey signature",
                    signature.ok_or("local signed prekey signature is missing")?,
                )?),
            })
        })
        .transpose()
    }

    pub fn load_local_prekey_publication(
        &self,
        canonical_server_origin: &str,
        user_id: &str,
        device_id: &[u8; 16],
    ) -> Result<Option<LocalPreKeyPublicationV1>, String> {
        validate_canonical_server_origin(canonical_server_origin)?;
        validate_canonical_uuid("local prekey publication user id", user_id)?;
        if *device_id == [0u8; 16] {
            return Err("local prekey publication device is invalid".to_string());
        }

        let raw = self
            .conn
            .query_row(
                "SELECT signed_prekey_id, one_time_prekey_count, request_body,
                        body_sha256, acknowledged
                 FROM local_prekey_publications_v1
                 WHERE canonical_server_origin = ?1 AND user_id = ?2 AND device_id = ?3",
                rusqlite::params![canonical_server_origin, user_id, device_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, u8>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| format!("load local prekey publication: {e}"))?;

        raw.map(
            |(signed_prekey_id, one_time_prekey_count, request_body, digest, acknowledged)| {
                let signed_prekey_id = u32::try_from(signed_prekey_id)
                    .map_err(|_| "persisted publication SPK id is invalid".to_string())?;
                let one_time_prekey_count = u32::try_from(one_time_prekey_count)
                    .map_err(|_| "persisted publication OPK count is invalid".to_string())?;
                let body_sha256 = fixed_bytes::<32>("local prekey publication digest", digest)?;
                let publication = LocalPreKeyPublicationV1 {
                    canonical_server_origin: canonical_server_origin.to_string(),
                    user_id: user_id.to_string(),
                    device_id: *device_id,
                    signed_prekey_id,
                    one_time_prekey_count,
                    request_body,
                    body_sha256,
                    acknowledged: match acknowledged {
                        0 => false,
                        1 => true,
                        _ => {
                            return Err(
                                "persisted publication acknowledgement is invalid".to_string()
                            )
                        }
                    },
                };
                validate_local_prekey_publication_record(&publication)?;
                Ok(publication)
            },
        )
        .transpose()
    }

    /// Mark only the exact current outbox row acknowledged. Wrong scope,
    /// digest, or SPK id leaves it pending and returns an error.
    pub fn acknowledge_local_prekey_publication(
        &self,
        canonical_server_origin: &str,
        user_id: &str,
        device_id: &[u8; 16],
        signed_prekey_id: u32,
        body_sha256: &[u8; 32],
    ) -> Result<(), String> {
        validate_canonical_server_origin(canonical_server_origin)?;
        validate_canonical_uuid("local prekey publication user id", user_id)?;
        if *device_id == [0u8; 16] || signed_prekey_id == 0 || *body_sha256 == [0u8; 32] {
            return Err("local prekey publication acknowledgement is invalid".to_string());
        }
        let tx = begin_immediate(&self.conn, "local prekey publication acknowledgement")?;
        // Match and acknowledge in one write-serialized statement. Updating an
        // already acknowledged exact row is deliberately idempotent, while a
        // rotation to another SPK/body can never pass this predicate.
        let changed = tx
            .execute(
                "UPDATE local_prekey_publications_v1
                 SET acknowledged = 1,
                     acknowledged_at = COALESCE(acknowledged_at, datetime('now')),
                     updated_at = CASE
                         WHEN acknowledged = 0 THEN datetime('now')
                         ELSE updated_at
                     END
                 WHERE canonical_server_origin = ?1 AND user_id = ?2 AND device_id = ?3
                   AND signed_prekey_id = ?4 AND body_sha256 = ?5",
                rusqlite::params![
                    canonical_server_origin,
                    user_id,
                    device_id.as_slice(),
                    i64::from(signed_prekey_id),
                    body_sha256.as_slice(),
                ],
            )
            .map_err(|e| format!("acknowledge local prekey publication: {e}"))?;
        if changed != 1 {
            return Err(
                "local prekey publication acknowledgement does not match the outbox".to_string(),
            );
        }
        tx.commit()
            .map_err(|error| format!("commit local prekey publication acknowledgement: {error}"))
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
        max_local_prekey_id_on(&self.conn, key_type)
    }

    /// Atomically persist the authenticated first ratchet state and destroy the
    /// claimed one-time private key. Either both changes commit or neither does.
    pub fn commit_initial_ratchet_session(
        &self,
        peer_identity_key: &[u8; 32],
        session_data: &[u8],
        one_time_prekey_id: Option<u32>,
    ) -> Result<(), String> {
        validate_ratchet_session_blob_v1(session_data)?;
        // SAVEPOINT composes with the outer atomic receive savepoint while
        // still providing standalone all-or-nothing semantics in direct use.
        self.conn
            .execute_batch("SAVEPOINT veil_initial_ratchet")
            .map_err(|e| format!("begin initial ratchet savepoint: {e}"))?;
        let operation = (|| {
            self.conn
                .execute(
                    "INSERT INTO ratchet_sessions
                       (peer_identity_key, session_data, revision, updated_at)
                     VALUES (?1, ?2, 0, datetime('now'))",
                    rusqlite::params![peer_identity_key.as_slice(), session_data],
                )
                .map_err(|e| format!("insert initial ratchet session: {e}"))?;
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

    /// Direct v2 responder commit. The ratchet, sticky session binding and OPK
    /// destruction share one savepoint, so no crash can publish a v2 floor
    /// without the matching state or reuse a consumed private key.
    pub fn commit_initial_ratchet_session_v2(
        &self,
        peer_identity_key: &[u8; 32],
        session_data: &[u8],
        one_time_prekey_id: Option<u32>,
        binding: &DirectSessionBindingBlobV2,
    ) -> Result<(), String> {
        validate_ratchet_session_blob_v1(session_data)?;
        validate_direct_session_binding_blob_v2(peer_identity_key, binding)?;
        self.conn
            .execute_batch("SAVEPOINT veil_initial_ratchet_v2")
            .map_err(|error| format!("begin Direct v2 initial ratchet savepoint: {error}"))?;
        let operation = (|| {
            self.conn
                .execute(
                    "INSERT INTO ratchet_sessions
                       (peer_identity_key, session_data, revision, updated_at)
                     VALUES (?1, ?2, 0, datetime('now'))",
                    rusqlite::params![peer_identity_key.as_slice(), session_data],
                )
                .map_err(|error| format!("insert Direct v2 initial ratchet: {error}"))?;
            insert_direct_session_binding_v2(&self.conn, binding)?;
            if let Some(id) = one_time_prekey_id {
                let changed = self
                    .conn
                    .execute(
                        "UPDATE local_prekeys
                         SET secret_key = NULL, consumed = 1
                         WHERE key_type = 1 AND protocol_key_id = ?1 AND consumed = 0",
                        rusqlite::params![i64::from(id)],
                    )
                    .map_err(|error| format!("consume Direct v2 one-time prekey: {error}"))?;
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
                "ROLLBACK TO SAVEPOINT veil_initial_ratchet_v2;
                 RELEASE SAVEPOINT veil_initial_ratchet_v2;",
            );
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback_error) => {
                    format!("{error}; Direct v2 initial ratchet rollback failed: {rollback_error}")
                }
            });
        }
        self.conn
            .execute_batch("RELEASE SAVEPOINT veil_initial_ratchet_v2")
            .map_err(|error| format!("commit Direct v2 initial ratchet: {error}"))
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

    #[allow(clippy::too_many_arguments)]
    pub fn save_incoming_sender_key_generation(
        &self,
        group_id: &str,
        sender_identity_key: &[u8; 32],
        generation: u32,
        iteration: u32,
        state_revision: u64,
        distribution_commitment: &[u8; 32],
        key_data: &[u8],
    ) -> Result<(), String> {
        self.conn
            .execute_batch("SAVEPOINT veil_incoming_sender_key")
            .map_err(|e| format!("begin incoming sender-key savepoint: {e}"))?;
        let operation = upsert_incoming_sender_key_generation(
            &self.conn,
            group_id,
            sender_identity_key,
            generation,
            iteration,
            state_revision,
            distribution_commitment,
            key_data,
        );
        if let Err(error) = operation {
            let rollback = self.conn.execute_batch(
                "ROLLBACK TO SAVEPOINT veil_incoming_sender_key;
                 RELEASE SAVEPOINT veil_incoming_sender_key;",
            );
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback_error) => {
                    format!("{error}; incoming sender-key rollback failed: {rollback_error}")
                }
            });
        }
        self.conn
            .execute_batch("RELEASE SAVEPOINT veil_incoming_sender_key")
            .map_err(|e| format!("commit incoming sender-key savepoint: {e}"))
    }

    /// Atomically install an incoming generation and its immutable historical
    /// route proof. The same generation can be replayed only with byte-for-byte
    /// identical device/binding/roster metadata.
    pub fn begin_retained_sender_key_conversation_v1(&self) -> Result<(), String> {
        self.conn
            .execute_batch("SAVEPOINT veil_retained_sender_key_conversation")
            .map_err(|e| format!("begin retained Sender-Key conversation savepoint: {e}"))
    }

    pub fn commit_retained_sender_key_conversation_v1(&self) -> Result<(), String> {
        self.conn
            .execute_batch("RELEASE SAVEPOINT veil_retained_sender_key_conversation")
            .map_err(|e| format!("commit retained Sender-Key conversation savepoint: {e}"))
    }

    pub fn rollback_retained_sender_key_conversation_v1(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "ROLLBACK TO SAVEPOINT veil_retained_sender_key_conversation;
                 RELEASE SAVEPOINT veil_retained_sender_key_conversation;",
            )
            .map_err(|e| format!("rollback retained Sender-Key conversation savepoint: {e}"))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn save_incoming_sender_key_generation_with_route_v1(
        &self,
        group_id: &str,
        sender_identity_key: &[u8; 32],
        generation: u32,
        iteration: u32,
        state_revision: u64,
        distribution_commitment: &[u8; 32],
        key_data: &[u8],
        route: &IncomingSenderKeyRouteV1,
    ) -> Result<(), String> {
        let historical = route
            .historical_sender_binding
            .as_ref()
            .ok_or("incoming sender-key route has no historical device proof")?;
        if route.sender_device_identity_key != *sender_identity_key
            || route.sender_device_id == [0u8; 16]
            || route.target_device_id == [0u8; 16]
            || route.sender_binding_version == 0
            || route.sender_binding_version > i64::MAX as u64
            || route.target_binding_version == 0
            || route.target_binding_version > i64::MAX as u64
            || route.roster_version == 0
            || route.roster_version > i64::MAX as u64
            || !valid_membership_coordinate_v1(route.membership_epoch, &route.membership_epoch_hash)
            || historical.sender_account_signing_key == [0u8; 32]
            || historical.sender_device_capabilities > i64::MAX as u64
            || !(1..=3).contains(&historical.sender_device_binding_status)
            || historical.target_device_identity_key == Some([0u8; 32])
            || historical.target_device_identity_key.is_none()
            || std::collections::HashSet::from([
                route.sender_account_identity_key,
                historical.sender_account_signing_key,
                route.sender_device_identity_key,
                route.sender_device_signing_key,
            ])
            .len()
                != 4
        {
            return Err("invalid incoming sender-key route proof".to_string());
        }
        self.conn
            .execute_batch("SAVEPOINT veil_incoming_sender_key_route")
            .map_err(|e| format!("begin incoming sender-key route savepoint: {e}"))?;
        let operation = (|| {
            let trusted_signing: Option<Vec<u8>> = self
                .conn
                .query_row(
                    "SELECT signing_key FROM trusted_identity_keys WHERE identity_key = ?1",
                    rusqlite::params![route.sender_account_identity_key.as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| format!("load historical trusted signing pin: {e}"))?;
            if trusted_signing
                .as_ref()
                .is_some_and(|stored| stored.as_slice() != historical.sender_account_signing_key)
            {
                return Err("trusted signing key changed for pinned identity".to_string());
            }
            if trusted_signing.is_none() {
                self.conn
                    .execute(
                        "INSERT INTO trusted_identity_keys (identity_key, signing_key)
                         VALUES (?1, ?2)",
                        rusqlite::params![
                            route.sender_account_identity_key.as_slice(),
                            historical.sender_account_signing_key.as_slice(),
                        ],
                    )
                    .map_err(|e| format!("pin historical trusted signing key: {e}"))?;
            }

            type ExistingDevicePin = (
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                i64,
                Vec<u8>,
            );
            let existing_pin: Option<ExistingDevicePin> = self
                .conn
                .query_row(
                    "SELECT account_identity_key, account_signing_key,
                            device_identity_key, device_signing_key,
                            binding_version, capabilities, status,
                            account_signature
                     FROM device_binding_pins_v1 WHERE device_id = ?1",
                    rusqlite::params![route.sender_device_id.as_slice()],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                            row.get(7)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| format!("load historical device binding pin: {e}"))?;
            let mut advance_pin = true;
            if let Some(existing) = existing_pin {
                let old_version =
                    u64::from_be_bytes(fixed_bytes("pinned binding version", existing.4)?);
                let old_capabilities =
                    u64::from_be_bytes(fixed_bytes("pinned binding capabilities", existing.5)?);
                let old_status = u8::try_from(existing.6)
                    .map_err(|_| "pinned device binding status is invalid".to_string())?;
                if existing.0.as_slice() != route.sender_account_identity_key
                    || existing.1.as_slice() != historical.sender_account_signing_key
                    || existing.2.as_slice() != route.sender_device_identity_key
                    || existing.3.as_slice() != route.sender_device_signing_key
                {
                    return Err("pinned device/account key replacement rejected".to_string());
                }
                if route.sender_binding_version < old_version {
                    // Historical decrypt proof is accepted, but must never
                    // lower or reactivate the current binding head.
                    advance_pin = false;
                } else if route.sender_binding_version == old_version {
                    if old_capabilities != historical.sender_device_capabilities
                        || old_status != historical.sender_device_binding_status
                        || existing.7.as_slice() != historical.sender_account_signature
                    {
                        return Err("same device binding version changed signed state".to_string());
                    }
                    advance_pin = false;
                } else if old_status == 3 && historical.sender_device_binding_status != 3 {
                    return Err("revoked device binding cannot become active again".to_string());
                }
            }
            if advance_pin {
                self.conn
                    .execute(
                        "INSERT INTO device_binding_pins_v1
                            (device_id, account_identity_key, account_signing_key,
                             device_identity_key, device_signing_key, binding_version,
                             capabilities, status, account_signature, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, datetime('now'))
                         ON CONFLICT(device_id) DO UPDATE SET
                            binding_version = excluded.binding_version,
                            capabilities = excluded.capabilities,
                            status = excluded.status,
                            account_signature = excluded.account_signature,
                            updated_at = datetime('now')",
                        rusqlite::params![
                            route.sender_device_id.as_slice(),
                            route.sender_account_identity_key.as_slice(),
                            historical.sender_account_signing_key.as_slice(),
                            route.sender_device_identity_key.as_slice(),
                            route.sender_device_signing_key.as_slice(),
                            route.sender_binding_version.to_be_bytes().as_slice(),
                            historical
                                .sender_device_capabilities
                                .to_be_bytes()
                                .as_slice(),
                            historical.sender_device_binding_status,
                            historical.sender_account_signature.as_slice(),
                        ],
                    )
                    .map_err(|e| format!("pin historical device binding: {e}"))?;
            }

            upsert_incoming_sender_key_generation(
                &self.conn,
                group_id,
                sender_identity_key,
                generation,
                iteration,
                state_revision,
                distribution_commitment,
                key_data,
            )?;
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO sender_key_incoming_routes_v1
                        (group_id, sender_identity_key, generation,
                         sender_account_identity_key, sender_device_id,
                         sender_device_signing_key, sender_binding_version,
                         target_device_id, target_binding_version, roster_version,
                         roster_commitment, membership_epoch,
                         membership_epoch_hash, envelope_commitment)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    rusqlite::params![
                        group_id,
                        sender_identity_key.as_slice(),
                        i64::from(generation),
                        route.sender_account_identity_key.as_slice(),
                        route.sender_device_id.as_slice(),
                        route.sender_device_signing_key.as_slice(),
                        route.sender_binding_version.to_be_bytes().as_slice(),
                        route.target_device_id.as_slice(),
                        route.target_binding_version.to_be_bytes().as_slice(),
                        route.roster_version.to_be_bytes().as_slice(),
                        route.roster_commitment.as_slice(),
                        (route.membership_epoch != 0).then(|| route.membership_epoch.to_be_bytes()),
                        (route.membership_epoch != 0)
                            .then_some(route.membership_epoch_hash.as_slice()),
                        route.envelope_commitment.as_slice(),
                    ],
                )
                .map_err(|e| format!("save incoming sender-key route proof: {e}"))?;
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO sender_key_historical_device_proofs_v1
                        (group_id, sender_identity_key, generation,
                         sender_account_signing_key, sender_device_capabilities,
                         sender_device_binding_status, sender_account_signature,
                         target_device_identity_key)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(group_id, sender_identity_key, generation) DO UPDATE SET
                        target_device_identity_key = excluded.target_device_identity_key
                     WHERE sender_key_historical_device_proofs_v1.target_device_identity_key IS NULL",
                    rusqlite::params![
                        group_id,
                        sender_identity_key.as_slice(),
                        i64::from(generation),
                        historical.sender_account_signing_key.as_slice(),
                        historical
                            .sender_device_capabilities
                            .to_be_bytes()
                            .as_slice(),
                        historical.sender_device_binding_status,
                        historical.sender_account_signature.as_slice(),
                        historical
                            .target_device_identity_key
                            .as_ref()
                            .map(|key| key.as_slice()),
                    ],
                )
                .map_err(|e| format!("save historical sender device proof: {e}"))?;
            let stored = self
                .load_incoming_sender_key_route_v1(group_id, sender_identity_key, generation)?
                .ok_or("incoming sender-key route proof disappeared after save")?;
            if stored != *route {
                return Err("incoming sender-key route proof changed for generation".to_string());
            }
            Ok(())
        })();
        if let Err(error) = operation {
            let rollback = self.conn.execute_batch(
                "ROLLBACK TO SAVEPOINT veil_incoming_sender_key_route;
                 RELEASE SAVEPOINT veil_incoming_sender_key_route;",
            );
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback_error) => {
                    format!("{error}; incoming sender-key route rollback failed: {rollback_error}")
                }
            });
        }
        self.conn
            .execute_batch("RELEASE SAVEPOINT veil_incoming_sender_key_route")
            .map_err(|e| format!("commit incoming sender-key route savepoint: {e}"))
    }

    pub fn load_incoming_sender_key_route_v1(
        &self,
        group_id: &str,
        sender_identity_key: &[u8; 32],
        generation: u32,
    ) -> Result<Option<IncomingSenderKeyRouteV1>, String> {
        let row = self
            .conn
            .query_row(
                "SELECT r.sender_account_identity_key, r.sender_device_id,
                    r.sender_device_signing_key, r.sender_binding_version,
                    r.target_device_id, r.target_binding_version, r.roster_version,
                    r.roster_commitment, r.membership_epoch,
                    r.membership_epoch_hash, r.envelope_commitment,
                    p.sender_account_signing_key, p.sender_device_capabilities,
                    p.sender_device_binding_status, p.sender_account_signature,
                    p.target_device_identity_key
             FROM sender_key_incoming_routes_v1 r
             LEFT JOIN sender_key_historical_device_proofs_v1 p
               ON p.group_id = r.group_id
              AND p.sender_identity_key = r.sender_identity_key
              AND p.generation = r.generation
             WHERE r.group_id = ?1 AND r.sender_identity_key = ?2 AND r.generation = ?3",
                rusqlite::params![
                    group_id,
                    sender_identity_key.as_slice(),
                    i64::from(generation)
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Option<Vec<u8>>>(8)?,
                        row.get::<_, Option<Vec<u8>>>(9)?,
                        row.get::<_, Vec<u8>>(10)?,
                        row.get::<_, Option<Vec<u8>>>(11)?,
                        row.get::<_, Option<Vec<u8>>>(12)?,
                        row.get::<_, Option<i64>>(13)?,
                        row.get::<_, Option<Vec<u8>>>(14)?,
                        row.get::<_, Option<Vec<u8>>>(15)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| format!("load incoming sender-key route proof: {e}"))?;
        row.map(|row| {
            let route = IncomingSenderKeyRouteV1 {
                sender_account_identity_key: fixed_bytes("route sender account identity", row.0)?,
                sender_device_id: fixed_bytes("route sender device id", row.1)?,
                sender_device_identity_key: *sender_identity_key,
                sender_device_signing_key: fixed_bytes("route sender device signing key", row.2)?,
                sender_binding_version: u64::from_be_bytes(fixed_bytes(
                    "route sender binding version",
                    row.3,
                )?),
                target_device_id: fixed_bytes("route target device id", row.4)?,
                target_binding_version: u64::from_be_bytes(fixed_bytes(
                    "route target binding version",
                    row.5,
                )?),
                roster_version: u64::from_be_bytes(fixed_bytes("route roster version", row.6)?),
                roster_commitment: fixed_bytes("route roster commitment", row.7)?,
                membership_epoch: match row.8 {
                    Some(encoded) => {
                        u64::from_be_bytes(fixed_bytes("route membership epoch", encoded)?)
                    }
                    None => 0,
                },
                membership_epoch_hash: row
                    .9
                    .map(|encoded| fixed_bytes("route membership epoch hash", encoded))
                    .transpose()?
                    .unwrap_or([0u8; 32]),
                envelope_commitment: fixed_bytes("route envelope commitment", row.10)?,
                historical_sender_binding: match (row.11, row.12, row.13, row.14, row.15) {
                    (None, None, None, None, None) => None,
                    (Some(signing), Some(capabilities), Some(status), Some(signature), target) => {
                        Some(HistoricalDeviceBindingProofV1 {
                            sender_account_signing_key: fixed_bytes(
                                "route sender account signing key",
                                signing,
                            )?,
                            sender_device_capabilities: u64::from_be_bytes(fixed_bytes(
                                "route sender device capabilities",
                                capabilities,
                            )?),
                            sender_device_binding_status: u8::try_from(status).map_err(|_| {
                                "route sender device binding status is invalid".to_string()
                            })?,
                            sender_account_signature: fixed_bytes(
                                "route sender account signature",
                                signature,
                            )?,
                            target_device_identity_key: target
                                .map(|key| fixed_bytes("route target device identity key", key))
                                .transpose()?,
                        })
                    }
                    _ => {
                        return Err(
                            "persisted historical sender device proof is partial".to_string()
                        )
                    }
                },
            };
            if !valid_membership_coordinate_v1(route.membership_epoch, &route.membership_epoch_hash)
            {
                return Err("persisted sender-key membership coordinate is partial".to_string());
            }
            Ok(route)
        })
        .transpose()
    }

    /// Promote one legacy single-row incoming state into the generation-keyed
    /// table. Insert/verification and legacy deletion are atomic, so a crash
    /// leaves either the old readable row or the complete new row.
    #[allow(clippy::too_many_arguments)]
    pub fn migrate_legacy_incoming_sender_key_generation(
        &self,
        group_id: &str,
        sender_identity_key: &[u8; 32],
        generation: u32,
        iteration: u32,
        state_revision: u64,
        distribution_commitment: &[u8; 32],
        key_data: &[u8],
    ) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin legacy sender-key migration: {e}"))?;
        upsert_incoming_sender_key_generation(
            &tx,
            group_id,
            sender_identity_key,
            generation,
            iteration,
            state_revision,
            distribution_commitment,
            key_data,
        )?;
        let deleted = tx
            .execute(
                "DELETE FROM sender_keys_local
                 WHERE group_id = ?1 AND sender_identity_key = ?2 AND is_outgoing = 0",
                rusqlite::params![group_id, sender_identity_key.as_slice()],
            )
            .map_err(|e| format!("delete migrated legacy sender key: {e}"))?;
        if deleted > 1 {
            return Err("legacy sender-key migration deleted multiple rows".to_string());
        }
        tx.commit()
            .map_err(|e| format!("commit legacy sender-key migration: {e}"))
    }

    pub fn load_incoming_sender_key_generations_for_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<StoredIncomingSenderKeyGeneration>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sender_identity_key, generation, iteration,
                        state_revision, distribution_commitment, key_data
                 FROM sender_key_incoming_generations
                 WHERE group_id = ?1
                 ORDER BY sender_identity_key ASC, generation ASC",
            )
            .map_err(|e| format!("prepare load incoming sender-key generations: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![group_id], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    Zeroizing::new(row.get::<_, Vec<u8>>(5)?),
                ))
            })
            .map_err(|e| format!("query incoming sender-key generations: {e}"))?;

        let mut result = Vec::new();
        let mut current_sender = None;
        let mut current_sender_generations = 0usize;
        for row in rows {
            let (sender, generation, iteration, revision, commitment, key_data) =
                row.map_err(|e| format!("read incoming sender-key generation: {e}"))?;
            let sender_identity_key = fixed_bytes("incoming sender identity", sender)?;
            if current_sender == Some(sender_identity_key) {
                current_sender_generations += 1;
            } else {
                current_sender = Some(sender_identity_key);
                current_sender_generations = 1;
            }
            if current_sender_generations > MAX_RETAINED_SENDER_KEY_GENERATIONS_PER_SENDER {
                return Err(
                    "persisted incoming sender-key generation retention limit exceeded".to_string(),
                );
            }
            result.push(StoredIncomingSenderKeyGeneration {
                sender_identity_key,
                generation: u32::try_from(generation)
                    .map_err(|_| "incoming sender-key generation exceeds u32".to_string())?,
                iteration: u32::try_from(iteration)
                    .map_err(|_| "incoming sender-key iteration exceeds u32".to_string())?,
                state_revision: u64::from_be_bytes(fixed_bytes(
                    "incoming sender-key revision",
                    revision,
                )?),
                distribution_commitment: fixed_bytes(
                    "incoming sender-key distribution commitment",
                    commitment,
                )?,
                key_data,
            });
        }
        Ok(result)
    }

    pub fn load_legacy_incoming_sender_keys_for_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<StoredSenderKeyMaterial>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sender_identity_key, key_data
                 FROM sender_keys_local
                 WHERE group_id = ?1 AND is_outgoing = 0
                 ORDER BY sender_identity_key ASC",
            )
            .map_err(|e| format!("prepare load legacy incoming sender keys: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![group_id], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    Zeroizing::new(row.get::<_, Vec<u8>>(1)?),
                ))
            })
            .map_err(|e| format!("query legacy incoming sender keys: {e}"))?;
        let mut result = Vec::new();
        for row in rows {
            let (sender, key_data) =
                row.map_err(|e| format!("read legacy incoming sender key: {e}"))?;
            result.push((
                fixed_bytes("legacy incoming sender identity", sender)?,
                key_data,
            ));
        }
        Ok(result)
    }

    /// Commit a fresh outgoing generation and invalidate every cached sealed
    /// envelope from the previous generation as one durable transition.
    ///
    /// Splitting these writes can leave a crash-recovered client with the old
    /// generation but without its immutable retry envelopes (or vice versa).
    /// The runtime prepares the new state off to the side and only publishes it
    /// in memory after this transaction succeeds.
    pub fn commit_sender_key_rotation(
        &self,
        group_id: &str,
        sender_identity_key: &[u8; 32],
        key_data: &[u8],
    ) -> Result<(), String> {
        if group_id.is_empty() {
            return Err("sender-key rotation group id must not be empty".to_string());
        }
        if key_data.is_empty() || key_data.len() > 4096 {
            return Err("invalid rotated sender-key state size".to_string());
        }

        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin sender-key rotation transaction: {e}"))?;
        tx.execute(
            "DELETE FROM sender_keys_local
             WHERE group_id = ?1 AND is_outgoing = 1 AND sender_identity_key <> ?2",
            rusqlite::params![group_id, sender_identity_key.as_slice()],
        )
        .map_err(|e| format!("remove superseded sender-key owner state: {e}"))?;
        tx.execute(
            "INSERT OR REPLACE INTO sender_keys_local
                (group_id, sender_identity_key, key_data, is_outgoing, updated_at)
             VALUES (?1, ?2, ?3, 1, datetime('now'))",
            rusqlite::params![group_id, sender_identity_key.as_slice(), key_data],
        )
        .map_err(|e| format!("persist rotated sender key: {e}"))?;
        tx.execute(
            "DELETE FROM pending_sender_key_envelopes WHERE conversation_id = ?1",
            rusqlite::params![group_id],
        )
        .map_err(|e| format!("invalidate rotated sender-key envelopes: {e}"))?;
        tx.execute(
            "DELETE FROM pending_sender_key_device_envelopes_v1 WHERE conversation_id = ?1",
            rusqlite::params![group_id],
        )
        .map_err(|e| format!("invalidate rotated exact-device sender-key envelopes: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit sender-key rotation: {e}"))
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
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin delete sender keys: {e}"))?;
        tx.execute(
            "DELETE FROM sender_keys_local WHERE group_id = ?1",
            rusqlite::params![group_id],
        )
        .map_err(|e| format!("delete legacy/outgoing sender keys: {e}"))?;
        tx.execute(
            "DELETE FROM sender_key_incoming_generations WHERE group_id = ?1",
            rusqlite::params![group_id],
        )
        .map_err(|e| format!("delete incoming sender-key generations: {e}"))?;
        tx.execute(
            "DELETE FROM sender_key_incoming_routes_v1 WHERE group_id = ?1",
            rusqlite::params![group_id],
        )
        .map_err(|e| format!("delete incoming sender-key route proofs: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit delete sender keys: {e}"))
    }

    pub fn load_outgoing_sender_keys_for_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<StoredSenderKeyMaterial>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sender_identity_key, key_data
                 FROM sender_keys_local
                 WHERE group_id = ?1 AND is_outgoing = 1
                 ORDER BY sender_identity_key ASC",
            )
            .map_err(|e| format!("prepare load outgoing sender keys: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![group_id], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    Zeroizing::new(row.get::<_, Vec<u8>>(1)?),
                ))
            })
            .map_err(|e| format!("query outgoing sender keys: {e}"))?;
        let mut result = Vec::new();
        for row in rows {
            let (sender, key_data) = row.map_err(|e| format!("read outgoing sender key: {e}"))?;
            result.push((fixed_bytes("outgoing sender identity", sender)?, key_data));
        }
        Ok(result)
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

    /// Persist the first sealed SKDM accepted locally for one exact
    /// conversation/generation/recipient tuple. A retry may reuse the row only
    /// when both the sender binding and the bytes are identical.
    pub fn save_pending_sender_key_envelope(
        &self,
        conversation_id: &str,
        generation: u32,
        target_identity_key: &[u8; 32],
        sender_identity_key: &[u8; 32],
        sealed_envelope: &[u8],
    ) -> Result<Vec<u8>, String> {
        if conversation_id.is_empty() || generation == 0 {
            return Err("invalid pending sender-key envelope scope".to_string());
        }
        if sealed_envelope.is_empty() || sealed_envelope.len() > 4096 {
            return Err("invalid pending sender-key envelope size".to_string());
        }
        self.conn
            .execute(
                "INSERT OR IGNORE INTO pending_sender_key_envelopes
                   (conversation_id, generation, target_identity_key,
                    sender_identity_key, sealed_envelope)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    conversation_id,
                    i64::from(generation),
                    target_identity_key.as_slice(),
                    sender_identity_key.as_slice(),
                    sealed_envelope,
                ],
            )
            .map_err(|e| format!("save pending sender-key envelope: {e}"))?;

        let (stored_sender, stored_envelope): (Vec<u8>, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT sender_identity_key, sealed_envelope
                 FROM pending_sender_key_envelopes
                 WHERE conversation_id = ?1 AND generation = ?2
                   AND target_identity_key = ?3",
                rusqlite::params![
                    conversation_id,
                    i64::from(generation),
                    target_identity_key.as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| format!("verify pending sender-key envelope: {e}"))?;
        if stored_sender.as_slice() != sender_identity_key.as_slice()
            || stored_envelope.as_slice() != sealed_envelope
        {
            return Err(
                "pending sender-key generation is already committed to different bytes".to_string(),
            );
        }
        Ok(stored_envelope)
    }

    pub fn load_pending_sender_key_envelope(
        &self,
        conversation_id: &str,
        generation: u32,
        target_identity_key: &[u8; 32],
        expected_sender_identity_key: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, String> {
        let row = self
            .conn
            .query_row(
                "SELECT sender_identity_key, sealed_envelope
                 FROM pending_sender_key_envelopes
                 WHERE conversation_id = ?1 AND generation = ?2
                   AND target_identity_key = ?3",
                rusqlite::params![
                    conversation_id,
                    i64::from(generation),
                    target_identity_key.as_slice(),
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|e| format!("load pending sender-key envelope: {e}"))?;
        let Some((sender_identity_key, sealed_envelope)) = row else {
            return Ok(None);
        };
        if sender_identity_key.as_slice() != expected_sender_identity_key.as_slice() {
            return Err("pending sender-key envelope belongs to another sender".to_string());
        }
        if sealed_envelope.is_empty() || sealed_envelope.len() > 4096 {
            return Err("persisted sender-key envelope has an invalid size".to_string());
        }
        Ok(Some(sealed_envelope))
    }

    pub fn save_pending_sender_key_device_envelope_v1(
        &self,
        envelope: &PendingSenderKeyDeviceEnvelopeV1,
    ) -> Result<Vec<u8>, String> {
        if envelope.conversation_id.is_empty()
            || envelope.generation == 0
            || envelope.target_device_id == [0u8; 16]
            || envelope.sender_device_id == [0u8; 16]
            || envelope.target_binding_version == 0
            || envelope.target_binding_version > i64::MAX as u64
            || envelope.sender_binding_version == 0
            || envelope.sender_binding_version > i64::MAX as u64
            || envelope.roster_version == 0
            || envelope.roster_version > i64::MAX as u64
            || !valid_membership_coordinate_v1(
                envelope.membership_epoch,
                &envelope.membership_epoch_hash,
            )
            || envelope.sealed_envelope.is_empty()
            || envelope.sealed_envelope.len() > 4_096
        {
            return Err("invalid exact-device sender-key envelope".to_string());
        }
        self.conn
            .execute(
                "INSERT OR IGNORE INTO pending_sender_key_device_envelopes_v1
                (conversation_id, generation, target_account_identity_key,
                 target_device_id, target_device_identity_key,
                 target_binding_version, sender_device_id,
                 sender_device_identity_key, sender_binding_version,
                 roster_version, roster_commitment, membership_epoch,
                 membership_epoch_hash, envelope_commitment, sealed_envelope)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                rusqlite::params![
                    envelope.conversation_id,
                    i64::from(envelope.generation),
                    envelope.target_account_identity_key.as_slice(),
                    envelope.target_device_id.as_slice(),
                    envelope.target_device_identity_key.as_slice(),
                    envelope.target_binding_version.to_be_bytes().as_slice(),
                    envelope.sender_device_id.as_slice(),
                    envelope.sender_device_identity_key.as_slice(),
                    envelope.sender_binding_version.to_be_bytes().as_slice(),
                    envelope.roster_version.to_be_bytes().as_slice(),
                    envelope.roster_commitment.as_slice(),
                    (envelope.membership_epoch != 0)
                        .then(|| envelope.membership_epoch.to_be_bytes()),
                    (envelope.membership_epoch != 0)
                        .then_some(envelope.membership_epoch_hash.as_slice()),
                    envelope.envelope_commitment.as_slice(),
                    envelope.sealed_envelope,
                ],
            )
            .map_err(|e| format!("save exact-device sender-key envelope: {e}"))?;
        let stored = self
            .load_pending_sender_key_device_envelope_v1(
                &envelope.conversation_id,
                envelope.generation,
                &envelope.target_device_id,
                envelope.target_binding_version,
                envelope.roster_version,
            )?
            .ok_or("exact-device sender-key envelope disappeared after save")?;
        if stored != *envelope {
            return Err("exact-device sender-key envelope tuple changed".to_string());
        }
        Ok(stored.sealed_envelope)
    }

    pub fn load_pending_sender_key_device_envelope_v1(
        &self,
        conversation_id: &str,
        generation: u32,
        target_device_id: &[u8; 16],
        target_binding_version: u64,
        roster_version: u64,
    ) -> Result<Option<PendingSenderKeyDeviceEnvelopeV1>, String> {
        type Row = (
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
        );
        let row: Option<Row> = self
            .conn
            .query_row(
                "SELECT target_account_identity_key, target_device_identity_key,
                    sender_device_id, sender_device_identity_key,
                    sender_binding_version, roster_commitment,
                    membership_epoch, membership_epoch_hash,
                    envelope_commitment, sealed_envelope, target_binding_version,
                    roster_version
             FROM pending_sender_key_device_envelopes_v1
             WHERE conversation_id = ?1 AND generation = ?2
               AND target_device_id = ?3",
                rusqlite::params![
                    conversation_id,
                    i64::from(generation),
                    target_device_id.as_slice(),
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| format!("load exact-device sender-key envelope: {e}"))?;
        row.map(|row| {
            let stored_target_version =
                u64::from_be_bytes(fixed_bytes("cached target binding version", row.10)?);
            if stored_target_version != target_binding_version {
                return Err("cached target binding version mismatch".to_string());
            }
            let stored_roster_version =
                u64::from_be_bytes(fixed_bytes("cached roster version", row.11)?);
            if stored_roster_version != roster_version {
                return Err("cached roster version mismatch".to_string());
            }
            let membership_epoch = match row.6 {
                Some(encoded) => {
                    u64::from_be_bytes(fixed_bytes("cached membership epoch", encoded)?)
                }
                None => 0,
            };
            let membership_epoch_hash = row
                .7
                .map(|encoded| fixed_bytes("cached membership epoch hash", encoded))
                .transpose()?
                .unwrap_or([0u8; 32]);
            if !valid_membership_coordinate_v1(membership_epoch, &membership_epoch_hash) {
                return Err("cached membership coordinate is partial".to_string());
            }
            Ok(PendingSenderKeyDeviceEnvelopeV1 {
                conversation_id: conversation_id.to_string(),
                generation,
                target_account_identity_key: fixed_bytes("cached target account identity", row.0)?,
                target_device_id: *target_device_id,
                target_device_identity_key: fixed_bytes("cached target device identity", row.1)?,
                target_binding_version,
                sender_device_id: fixed_bytes("cached sender device id", row.2)?,
                sender_device_identity_key: fixed_bytes("cached sender device identity", row.3)?,
                sender_binding_version: u64::from_be_bytes(fixed_bytes(
                    "cached sender binding version",
                    row.4,
                )?),
                roster_version,
                roster_commitment: fixed_bytes("cached roster commitment", row.5)?,
                membership_epoch,
                membership_epoch_hash,
                envelope_commitment: fixed_bytes("cached envelope commitment", row.8)?,
                sealed_envelope: row.9,
            })
        })
        .transpose()
    }

    pub fn delete_pending_sender_key_device_generation_v1(
        &self,
        conversation_id: &str,
        generation: u32,
        roster_version: u64,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM pending_sender_key_device_envelopes_v1
             WHERE conversation_id = ?1 AND generation = ?2 AND roster_version = ?3",
                rusqlite::params![
                    conversation_id,
                    i64::from(generation),
                    roster_version.to_be_bytes().as_slice()
                ],
            )
            .map(|_| ())
            .map_err(|e| format!("delete exact-device sender-key envelopes: {e}"))
    }

    /// Remove a completed generation only after all corresponding gateway
    /// durable-storage ACKs have been observed by the client.
    pub fn delete_pending_sender_key_envelope_generation(
        &self,
        conversation_id: &str,
        generation: u32,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM pending_sender_key_envelopes
                 WHERE conversation_id = ?1 AND generation = ?2",
                rusqlite::params![conversation_id, i64::from(generation)],
            )
            .map(|_| ())
            .map_err(|e| format!("delete acknowledged sender-key envelopes: {e}"))
    }

    /// Rotation is a protocol boundary: cached envelopes from every older
    /// roster/generation must be invalidated before the new key is created.
    pub fn delete_pending_sender_key_envelopes_for_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("begin sender-key cache invalidation: {e}"))?;
        tx.execute(
            "DELETE FROM pending_sender_key_envelopes WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| format!("invalidate pending sender-key envelopes: {e}"))?;
        tx.execute(
            "DELETE FROM pending_sender_key_device_envelopes_v1 WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| format!("invalidate pending exact-device sender-key envelopes: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit sender-key cache invalidation: {e}"))
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

    /// Resolve a cached server/channel from its backing conversation without
    /// loading or replacing any renderer channel lists. Search results can
    /// reference channels that have not been opened in the current session.
    pub fn find_channel_context_by_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<Option<(String, String)>, String> {
        self.conn
            .query_row(
                "SELECT server_id, id
                 FROM server_channels_cache
                 WHERE conversation_id = ?1
                 LIMIT 1",
                rusqlite::params![conversation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| format!("resolve channel conversation: {e}"))
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

    pub fn identity_transparency_pinned_head_v1(
        &self,
        canonical_server_origin: &str,
    ) -> Result<Option<IdentityTransparencyPinnedHeadV1>, String> {
        validate_canonical_server_origin(canonical_server_origin)?;
        load_identity_transparency_head_on(&self.conn, canonical_server_origin)
    }

    /// Verify and atomically pin one exact transparency proof. A signed split
    /// view or rollback is committed to immutable local alarm history before
    /// this method returns an error, so callers cannot accidentally erase the
    /// evidence by rolling back the head update.
    pub fn verify_and_pin_identity_transparency_proof_v1(
        &self,
        proof: &IdentityTransparencyProofV1,
    ) -> Result<IdentityTransparencyAcceptanceV1, String> {
        self.verify_and_pin_identity_transparency_proof_with_anchor_v1(proof, None)
    }

    /// As `verify_and_pin_identity_transparency_proof_v1`, with an additional
    /// independently persisted OS-secure minimum head. This lets a restored
    /// older SQLCipher snapshot recover forward but never move below, replace,
    /// or fork from the stronger anchor.
    pub fn verify_and_pin_identity_transparency_proof_with_anchor_v1(
        &self,
        proof: &IdentityTransparencyProofV1,
        rollback_anchor: Option<&IdentityTransparencyPinnedHeadV1>,
    ) -> Result<IdentityTransparencyAcceptanceV1, String> {
        use veil_crypto::transparency::{
            log_id_v1, verify_consistency_v1, verify_inclusion_v1, TransparencyTreeHeadV1,
            MAX_TRANSPARENCY_TREE_SIZE_V1,
        };

        validate_canonical_server_origin(&proof.canonical_server_origin)?;
        if proof.tree_size == 0
            || proof.tree_size > MAX_TRANSPARENCY_TREE_SIZE_V1
            || proof.issued_at_ms == 0
            || proof.issued_at_ms > i64::MAX as u64
            || proof.leaf_index >= proof.tree_size
            || proof.consistency_from > MAX_TRANSPARENCY_TREE_SIZE_V1
            || proof.witness_quorum > 32
            || (proof.witness_policy_hash == [0u8; 32]) != (proof.witness_quorum == 0)
        {
            return Err("identity transparency proof coordinates are invalid".to_string());
        }
        if log_id_v1(&proof.canonical_server_origin, &proof.node_signing_key)? != proof.log_id {
            return Err("identity transparency log id is not origin/key bound".to_string());
        }
        let observed_head = TransparencyTreeHeadV1 {
            log_id: proof.log_id,
            tree_size: proof.tree_size,
            root_hash: proof.root_hash,
            issued_at_ms: proof.issued_at_ms,
        };
        if !observed_head.verify_node_signature(
            &proof.canonical_server_origin,
            &proof.node_signing_key,
            &proof.tree_head_signature,
        ) {
            return Err("identity transparency tree-head signature is invalid".to_string());
        }
        if !verify_inclusion_v1(
            &proof.canonical_event,
            proof.leaf_index,
            proof.tree_size,
            &proof.inclusion_proof,
            &proof.root_hash,
        ) {
            return Err("identity transparency inclusion proof is invalid".to_string());
        }
        if let Some(anchor) = rollback_anchor {
            validate_identity_transparency_anchor_v1(&proof.canonical_server_origin, anchor)?;
        }

        let tx = begin_immediate(&self.conn, "identity transparency pin transaction")?;
        let pinned = load_identity_transparency_head_on(&tx, &proof.canonical_server_origin)?;
        if let (Some(sqlcipher), Some(anchor)) = (pinned.as_ref(), rollback_anchor) {
            let conflict = sqlcipher.log_id != anchor.log_id
                || sqlcipher.node_signing_key != anchor.node_signing_key
                || sqlcipher.tree_size == anchor.tree_size
                    && (sqlcipher.root_hash != anchor.root_hash
                        || sqlcipher.witness_policy_hash != [0u8; 32]
                            && anchor.witness_policy_hash != [0u8; 32]
                            && sqlcipher.witness_policy_hash != anchor.witness_policy_hash);
            if conflict {
                let alarm_kind = if sqlcipher.log_id != anchor.log_id
                    || sqlcipher.node_signing_key != anchor.node_signing_key
                {
                    1
                } else {
                    3
                };
                record_identity_transparency_alarm_on(&tx, alarm_kind, anchor, proof)?;
                tx.commit().map_err(|error| {
                    format!("commit identity transparency local-anchor alarm: {error}")
                })?;
                return Err(
                    "identity transparency SQLCipher pin conflicts with the OS rollback anchor"
                        .to_string(),
                );
            }
        }

        let required_witness_policy = rollback_anchor
            .filter(|anchor| anchor.witness_policy_hash != [0u8; 32])
            .or_else(|| {
                pinned
                    .as_ref()
                    .filter(|head| head.witness_policy_hash != [0u8; 32])
            });
        if let Some(required) = required_witness_policy {
            if proof.witness_policy_hash != required.witness_policy_hash
                || proof.witness_quorum == 0
            {
                record_identity_transparency_alarm_on(&tx, 4, required, proof)?;
                tx.commit().map_err(|error| {
                    format!("commit identity transparency witness-downgrade alarm: {error}")
                })?;
                return Err(
                    "identity transparency witness policy downgrade or replacement detected"
                        .to_string(),
                );
            }
        }

        let rollback_anchor_ahead = rollback_anchor.filter(|anchor| {
            pinned.as_ref().is_none_or(|sqlcipher| {
                anchor.tree_size > sqlcipher.tree_size
                    || anchor.tree_size == sqlcipher.tree_size
                        && anchor.root_hash == sqlcipher.root_hash
                        && sqlcipher.witness_policy_hash == [0u8; 32]
                        && anchor.witness_policy_hash != [0u8; 32]
            })
        });
        if let Some(anchor) = rollback_anchor_ahead {
            let alarm = if proof.log_id != anchor.log_id
                || proof.node_signing_key != anchor.node_signing_key
            {
                Some((1, "identity transparency log replacement detected"))
            } else if proof.tree_size < anchor.tree_size {
                Some((
                    2,
                    "identity transparency rollback below the OS anchor detected",
                ))
            } else if proof.tree_size == anchor.tree_size && proof.root_hash != anchor.root_hash {
                Some((
                    3,
                    "identity transparency split view against the OS anchor detected",
                ))
            } else {
                None
            };
            if let Some((kind, message)) = alarm {
                record_identity_transparency_alarm_on(&tx, kind, anchor, proof)?;
                tx.commit().map_err(|error| {
                    format!("commit identity transparency rollback-anchor alarm: {error}")
                })?;
                return Err(message.to_string());
            }
            if proof.consistency_from != anchor.tree_size
                || !verify_consistency_v1(
                    anchor.tree_size,
                    proof.tree_size,
                    &anchor.root_hash,
                    &proof.root_hash,
                    &proof.consistency_proof,
                )
            {
                record_identity_transparency_alarm_on(&tx, 4, anchor, proof)?;
                tx.commit().map_err(|error| {
                    format!(
                        "commit identity transparency rollback-anchor consistency alarm: {error}"
                    )
                })?;
                return Err(
                    "identity transparency proof does not extend the OS rollback anchor"
                        .to_string(),
                );
            }
            let exact_anchor_quorum = if proof.tree_size == anchor.tree_size
                && proof.root_hash == anchor.root_hash
                && proof.witness_policy_hash == anchor.witness_policy_hash
            {
                proof.witness_quorum.max(anchor.witness_quorum)
            } else {
                proof.witness_quorum
            };
            match pinned.as_ref() {
                Some(sqlcipher) => {
                    let updated = tx
                        .execute(
                            "UPDATE identity_transparency_heads_v1
                             SET log_id = ?2, node_signing_key = ?3, tree_size = ?4,
                                 root_hash = ?5, issued_at_ms = ?6,
                                 tree_head_signature = ?7, witness_policy_hash = ?8,
                                 witness_quorum = ?9,
                                 updated_at = datetime('now')
                             WHERE canonical_server_origin = ?1
                               AND log_id = ?10 AND node_signing_key = ?11
                               AND tree_size = ?12 AND root_hash = ?13",
                            rusqlite::params![
                                proof.canonical_server_origin,
                                proof.log_id.as_slice(),
                                proof.node_signing_key.as_slice(),
                                i64::try_from(proof.tree_size).map_err(|_| {
                                    "identity transparency tree size is invalid".to_string()
                                })?,
                                proof.root_hash.as_slice(),
                                i64::try_from(proof.issued_at_ms).map_err(|_| {
                                    "identity transparency issue time is invalid".to_string()
                                })?,
                                proof.tree_head_signature.as_slice(),
                                proof.witness_policy_hash.as_slice(),
                                i64::from(exact_anchor_quorum),
                                sqlcipher.log_id.as_slice(),
                                sqlcipher.node_signing_key.as_slice(),
                                i64::try_from(sqlcipher.tree_size).map_err(|_| {
                                    "pinned identity transparency size is invalid".to_string()
                                })?,
                                sqlcipher.root_hash.as_slice(),
                            ],
                        )
                        .map_err(|error| {
                            format!("recover identity transparency head from OS anchor: {error}")
                        })?;
                    if updated != 1 {
                        return Err(format!(
                            "identity transparency rollback recovery affected {updated} rows instead of one"
                        ));
                    }
                }
                None => {
                    tx.execute(
                        "INSERT INTO identity_transparency_heads_v1
                           (canonical_server_origin, log_id, node_signing_key, tree_size,
                            root_hash, issued_at_ms, tree_head_signature,
                            witness_policy_hash, witness_quorum)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        rusqlite::params![
                            proof.canonical_server_origin,
                            proof.log_id.as_slice(),
                            proof.node_signing_key.as_slice(),
                            i64::try_from(proof.tree_size).map_err(|_| {
                                "identity transparency tree size is invalid".to_string()
                            })?,
                            proof.root_hash.as_slice(),
                            i64::try_from(proof.issued_at_ms).map_err(|_| {
                                "identity transparency issue time is invalid".to_string()
                            })?,
                            proof.tree_head_signature.as_slice(),
                            proof.witness_policy_hash.as_slice(),
                            i64::from(exact_anchor_quorum),
                        ],
                    )
                    .map_err(|error| {
                        format!("restore identity transparency head from OS anchor: {error}")
                    })?;
                }
            }
            tx.commit().map_err(|error| {
                format!("commit identity transparency rollback-anchor recovery: {error}")
            })?;
            return Ok(IdentityTransparencyAcceptanceV1::RollbackAnchorRecovered);
        }
        let Some(pinned) = pinned else {
            if proof.consistency_from != 0 || !proof.consistency_proof.is_empty() {
                return Err("first-contact transparency proof invented a prior anchor".to_string());
            }
            tx.execute(
                "INSERT INTO identity_transparency_heads_v1
                   (canonical_server_origin, log_id, node_signing_key, tree_size,
                    root_hash, issued_at_ms, tree_head_signature,
                    witness_policy_hash, witness_quorum)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    proof.canonical_server_origin,
                    proof.log_id.as_slice(),
                    proof.node_signing_key.as_slice(),
                    i64::try_from(proof.tree_size)
                        .map_err(|_| "identity transparency tree size is invalid".to_string())?,
                    proof.root_hash.as_slice(),
                    i64::try_from(proof.issued_at_ms)
                        .map_err(|_| "identity transparency issue time is invalid".to_string())?,
                    proof.tree_head_signature.as_slice(),
                    proof.witness_policy_hash.as_slice(),
                    i64::from(proof.witness_quorum),
                ],
            )
            .map_err(|error| format!("pin first identity transparency head: {error}"))?;
            tx.commit()
                .map_err(|error| format!("commit first identity transparency head: {error}"))?;
            return Ok(IdentityTransparencyAcceptanceV1::FirstContactPinned);
        };

        let alarm =
            if proof.log_id != pinned.log_id || proof.node_signing_key != pinned.node_signing_key {
                Some((1, "identity transparency log replacement detected"))
            } else if proof.tree_size < pinned.tree_size {
                Some((2, "identity transparency rollback detected"))
            } else if proof.tree_size == pinned.tree_size && proof.root_hash != pinned.root_hash {
                Some((3, "identity transparency same-size split view detected"))
            } else {
                None
            };
        if let Some((kind, message)) = alarm {
            record_identity_transparency_alarm_on(&tx, kind, &pinned, proof)?;
            tx.commit()
                .map_err(|error| format!("commit identity transparency alarm: {error}"))?;
            return Err(message.to_string());
        }
        if proof.tree_size == pinned.tree_size {
            let witness_upgrade =
                pinned.witness_policy_hash == [0u8; 32] && proof.witness_policy_hash != [0u8; 32];
            let stronger_quorum = proof.witness_policy_hash == pinned.witness_policy_hash
                && proof.witness_quorum > pinned.witness_quorum;
            if proof.issued_at_ms > pinned.issued_at_ms || witness_upgrade || stronger_quorum {
                tx.execute(
                    "UPDATE identity_transparency_heads_v1
                     SET issued_at_ms = ?2, tree_head_signature = ?3,
                         witness_policy_hash = ?4, witness_quorum = ?5,
                         updated_at = datetime('now')
                     WHERE canonical_server_origin = ?1",
                    rusqlite::params![
                        proof.canonical_server_origin,
                        i64::try_from(proof.issued_at_ms).map_err(|_| {
                            "identity transparency issue time is invalid".to_string()
                        })?,
                        proof.tree_head_signature.as_slice(),
                        proof.witness_policy_hash.as_slice(),
                        i64::from(proof.witness_quorum.max(pinned.witness_quorum)),
                    ],
                )
                .map_err(|error| format!("refresh identity transparency head: {error}"))?;
            }
            tx.commit()
                .map_err(|error| format!("commit current identity transparency head: {error}"))?;
            return Ok(IdentityTransparencyAcceptanceV1::CurrentHeadConfirmed);
        }

        if proof.consistency_from != pinned.tree_size {
            return Err(
                "identity transparency proof does not extend the current SQLCipher pin".to_string(),
            );
        }

        if !verify_consistency_v1(
            pinned.tree_size,
            proof.tree_size,
            &pinned.root_hash,
            &proof.root_hash,
            &proof.consistency_proof,
        ) {
            record_identity_transparency_alarm_on(&tx, 4, &pinned, proof)?;
            tx.commit().map_err(|error| {
                format!("commit non-append-only identity transparency alarm: {error}")
            })?;
            return Err("identity transparency non-append-only advance detected".to_string());
        }
        let advanced_rows = tx
            .execute(
                "UPDATE identity_transparency_heads_v1
             SET tree_size = ?2, root_hash = ?3, issued_at_ms = ?4,
                  tree_head_signature = ?5, witness_policy_hash = ?6,
                  witness_quorum = ?7, updated_at = datetime('now')
             WHERE canonical_server_origin = ?1
               AND log_id = ?8 AND node_signing_key = ?9
               AND tree_size = ?10 AND root_hash = ?11",
                rusqlite::params![
                    proof.canonical_server_origin,
                    i64::try_from(proof.tree_size)
                        .map_err(|_| "identity transparency tree size is invalid".to_string())?,
                    proof.root_hash.as_slice(),
                    i64::try_from(proof.issued_at_ms)
                        .map_err(|_| "identity transparency issue time is invalid".to_string())?,
                    proof.tree_head_signature.as_slice(),
                    proof.witness_policy_hash.as_slice(),
                    i64::from(proof.witness_quorum),
                    pinned.log_id.as_slice(),
                    pinned.node_signing_key.as_slice(),
                    i64::try_from(pinned.tree_size)
                        .map_err(|_| "pinned identity transparency size is invalid".to_string())?,
                    pinned.root_hash.as_slice(),
                ],
            )
            .map_err(|error| format!("advance identity transparency head: {error}"))?;
        if advanced_rows != 1 {
            return Err(format!(
                "identity transparency head advance affected {advanced_rows} rows instead of one"
            ));
        }
        tx.commit()
            .map_err(|error| format!("commit identity transparency head advance: {error}"))?;
        Ok(IdentityTransparencyAcceptanceV1::AppendOnlyAdvancePinned)
    }

    pub fn identity_transparency_alarm_count_v1(
        &self,
        canonical_server_origin: &str,
    ) -> Result<u64, String> {
        validate_canonical_server_origin(canonical_server_origin)?;
        let count: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM identity_transparency_alarms_v1
                 WHERE canonical_server_origin = ?1",
                rusqlite::params![canonical_server_origin],
                |row| row.get(0),
            )
            .map_err(|error| format!("count identity transparency alarms: {error}"))?;
        u64::try_from(count).map_err(|_| "identity transparency alarm count is invalid".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const ORIGIN_A: &str = "https://alpha.example:443";
    const ORIGIN_B: &str = "https://beta.example:443";
    const USER_A: &str = "00000000-0000-0000-0000-0000000000a1";
    const USER_B: &str = "00000000-0000-0000-0000-0000000000b2";

    fn test_signing_key(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    fn sample_account(
        canonical_server_origin: &str,
        user_id: &str,
        seed: u8,
        source: AccountSnapshotSource,
        profile_version: Option<u64>,
    ) -> AccountSnapshot {
        AccountSnapshot {
            locator: ProfileLocator {
                canonical_server_origin: canonical_server_origin.to_string(),
                user_id: user_id.to_string(),
                identity_key: [seed; 32],
            },
            signing_key: test_signing_key(seed.wrapping_add(1)),
            username: Some(format!("user-{seed}")),
            display_name: Some(format!("User {seed}")),
            profile_version,
            profile_origin: canonical_server_origin.to_string(),
            source,
            observed_at: "2026-07-12T12:00:00Z".to_string(),
        }
    }

    fn sample_network_profile(account: &AccountSnapshot, version: u64) -> NetworkProfile {
        NetworkProfile {
            locator: account.locator.clone(),
            username: account.username.clone().unwrap(),
            display_name: account.display_name.clone(),
            about: "A signed origin-scoped profile.".to_string(),
            avatar_asset_id: None,
            avatar_digest: None,
            avatar_content_type: None,
            profile_version: version,
            profile_updated_at: "2026-07-13T02:00:00Z".to_string(),
            observed_at: "2026-07-13T02:00:01Z".to_string(),
        }
    }

    fn sample_device_identity(device_id: [u8; 16]) -> LocalDeviceIdentityV1 {
        LocalDeviceIdentityV1 {
            device_id,
            version: 1,
            x25519_secret: [0x11; 32],
            ed25519_secret: [0x22; 32],
            device_identity_key: [0x33; 32],
            device_signing_key: [0x44; 32],
            capabilities: 3,
            status: 1,
            account_identity_key: [0x55; 32],
            account_signing_key: [0x66; 32],
            account_signature: [0x77; 64],
        }
    }

    fn sample_prekey_batch(spk_id: u32, first_opk_id: u32) -> Vec<LocalPreKey> {
        let mut keys = Vec::with_capacity(LOCAL_PREKEY_PUBLICATION_BATCH_SIZE + 1);
        keys.push(LocalPreKey {
            key_type: 0,
            protocol_key_id: spk_id,
            secret_key: [0x31; 32],
            public_key: [0x32; 32],
            signature: Some([0x33; 64]),
        });
        for offset in 0..LOCAL_PREKEY_PUBLICATION_BATCH_SIZE as u32 {
            let id = first_opk_id + offset;
            let marker = u8::try_from((id % 250) + 1).unwrap();
            keys.push(LocalPreKey {
                key_type: 1,
                protocol_key_id: id,
                secret_key: [marker; 32],
                public_key: [marker.wrapping_add(1); 32],
                signature: None,
            });
        }
        keys
    }

    fn sample_prekey_publication(
        origin: &str,
        user_id: &str,
        device_id: [u8; 16],
        spk_id: u32,
        body: &[u8],
    ) -> LocalPreKeyPublicationV1 {
        LocalPreKeyPublicationV1 {
            canonical_server_origin: origin.to_string(),
            user_id: user_id.to_string(),
            device_id,
            signed_prekey_id: spk_id,
            one_time_prekey_count: LOCAL_PREKEY_PUBLICATION_BATCH_SIZE as u32,
            request_body: body.to_vec(),
            body_sha256: Sha256::digest(body).into(),
            acknowledged: false,
        }
    }

    fn sample_binding_pin(seed: u8, version: u64, status: u8) -> DeviceBindingPinV1 {
        DeviceBindingPinV1 {
            device_id: [seed; 16],
            account_identity_key: [seed.wrapping_add(1); 32],
            account_signing_key: [seed.wrapping_add(2); 32],
            device_identity_key: [seed.wrapping_add(3); 32],
            device_signing_key: [seed.wrapping_add(4); 32],
            binding_version: version,
            capabilities: 3,
            status,
            account_signature: [seed.wrapping_add(5); 64],
        }
    }

    fn sample_incoming_route(
        binding: &DeviceBindingPinV1,
        target_device_id: [u8; 16],
        target_device_identity_key: [u8; 32],
    ) -> IncomingSenderKeyRouteV1 {
        IncomingSenderKeyRouteV1 {
            sender_account_identity_key: binding.account_identity_key,
            sender_device_id: binding.device_id,
            sender_device_identity_key: binding.device_identity_key,
            sender_device_signing_key: binding.device_signing_key,
            sender_binding_version: binding.binding_version,
            target_device_id,
            target_binding_version: 1,
            roster_version: 1,
            roster_commitment: [0x91; 32],
            membership_epoch: 0,
            membership_epoch_hash: [0u8; 32],
            envelope_commitment: [0x92; 32],
            historical_sender_binding: Some(HistoricalDeviceBindingProofV1 {
                sender_account_signing_key: binding.account_signing_key,
                sender_device_capabilities: binding.capabilities,
                sender_device_binding_status: binding.status,
                sender_account_signature: binding.account_signature,
                target_device_identity_key: Some(target_device_identity_key),
            }),
        }
    }

    fn sample_membership_pin(
        conversation_id: &str,
        epoch: u64,
        epoch_hash: [u8; 32],
        predecessor_hash: [u8; 32],
    ) -> MembershipEpochPinV1 {
        MembershipEpochPinV1 {
            conversation_id: conversation_id.to_string(),
            epoch,
            epoch_hash,
            predecessor_hash,
            roster_version: epoch,
            roster_commitment: [0x90u8.wrapping_add(epoch as u8); 32],
            canonical_unsigned: vec![0xA0u8.wrapping_add(epoch as u8); 64],
            bootstrap_owner_id: (epoch == 1).then_some([0xB1; 16]),
            bootstrap_owner_signing_key: (epoch == 1).then_some([0xB2; 32]),
        }
    }

    const DIRECT_CONVERSATION_ID: &str = "10000000-0000-4000-8000-000000000001";
    const DIRECT_CLIENT_ID_1: &str = "20000000-0000-4000-8000-000000000001";
    const DIRECT_CLIENT_ID_2: &str = "20000000-0000-4000-8000-000000000002";
    const DIRECT_CLIENT_ID_3: &str = "20000000-0000-4000-8000-000000000003";
    const DIRECT_SERVER_ID_1: &str = "30000000-0000-4000-8000-000000000001";
    const DIRECT_SERVER_ID_2: &str = "30000000-0000-4000-8000-000000000002";
    const DIRECT_LEGACY_ID_1: &str = "40000000-0000-4000-8000-000000000001";
    const DIRECT_LEGACY_ID_2: &str = "40000000-0000-4000-8000-000000000002";
    const DIRECT_LEGACY_ID_3: &str = "40000000-0000-4000-8000-000000000003";

    #[derive(Clone)]
    struct DirectOutboxFixture {
        scope: DirectMessageOutboxScopeV1,
        self_account: AccountSnapshot,
        peer_account: AccountSnapshot,
    }

    #[derive(serde::Deserialize)]
    struct DirectV1StoreVector {
        expected: DirectV1StoreExpected,
    }

    #[derive(serde::Deserialize)]
    struct DirectV1StoreExpected {
        identities: DirectV1StoreIdentities,
        sessions: DirectV1StoreSessions,
        headers: DirectV1StoreHeaders,
    }

    #[derive(serde::Deserialize)]
    struct DirectV1StoreIdentities {
        bob: DirectV1StoreBobIdentity,
    }

    #[derive(serde::Deserialize)]
    struct DirectV1StoreBobIdentity {
        x25519_public_b64: String,
        ed25519_public_b64: String,
    }

    #[derive(serde::Deserialize)]
    struct DirectV1StoreSessions {
        initiator_before_message_json_b64: String,
        initiator_after_message_json_b64: String,
    }

    #[derive(serde::Deserialize)]
    struct DirectV1StoreHeaders {
        pending_initial_json_b64: String,
    }

    fn decode_direct_v1_vector_b64(label: &str, value: &str) -> Vec<u8> {
        fn sextet(label: &str, index: usize, value: u8) -> u8 {
            match value {
                b'A'..=b'Z' => value - b'A',
                b'a'..=b'z' => value - b'a' + 26,
                b'0'..=b'9' => value - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => panic!("Direct-v1 {label} has invalid Base64 byte at {index}"),
            }
        }

        let input = value.as_bytes();
        assert!(
            input.len().is_multiple_of(4),
            "Direct-v1 {label} Base64 length is not divisible by four"
        );
        let mut decoded = Vec::with_capacity(input.len() / 4 * 3);
        let chunk_count = input.len() / 4;
        for (chunk_index, chunk) in input.chunks_exact(4).enumerate() {
            assert!(
                chunk[0] != b'=' && chunk[1] != b'=',
                "Direct-v1 {label} has early Base64 padding"
            );
            let padding = match (chunk[2] == b'=', chunk[3] == b'=') {
                (true, true) => 2,
                (false, true) => 1,
                (false, false) => 0,
                (true, false) => panic!("Direct-v1 {label} has invalid Base64 padding"),
            };
            assert!(
                padding == 0 || chunk_index + 1 == chunk_count,
                "Direct-v1 {label} has non-terminal Base64 padding"
            );

            let offset = chunk_index * 4;
            let a = sextet(label, offset, chunk[0]);
            let b = sextet(label, offset + 1, chunk[1]);
            let c = if padding == 2 {
                0
            } else {
                sextet(label, offset + 2, chunk[2])
            };
            let d = if padding == 0 {
                sextet(label, offset + 3, chunk[3])
            } else {
                0
            };
            if padding == 2 {
                assert_eq!(
                    b & 0x0f,
                    0,
                    "Direct-v1 {label} has non-canonical Base64 padding bits"
                );
            } else if padding == 1 {
                assert_eq!(
                    c & 0x03,
                    0,
                    "Direct-v1 {label} has non-canonical Base64 padding bits"
                );
            }

            decoded.push((a << 2) | (b >> 4));
            if padding < 2 {
                decoded.push((b << 4) | (c >> 2));
            }
            if padding == 0 {
                decoded.push((c << 6) | d);
            }
        }
        decoded
    }

    fn remove_sqlcipher_test_files(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    fn install_direct_outbox_fixture(db: &VeilDb) -> DirectOutboxFixture {
        install_direct_outbox_fixture_with_ratchet(
            db,
            [0x73; 32],
            test_signing_key(0x74),
            b"ratchet-session-v0",
            b"initial-header-v1",
        )
    }

    fn install_direct_outbox_fixture_with_ratchet(
        db: &VeilDb,
        peer_identity_key: [u8; 32],
        peer_signing_key: [u8; 32],
        session_data: &[u8],
        initial_header_data: &[u8],
    ) -> DirectOutboxFixture {
        let self_account = sample_account(
            ORIGIN_A,
            USER_A,
            0x71,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            Some(1),
        );
        let mut peer_account = sample_account(
            ORIGIN_A,
            USER_B,
            0x73,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            Some(1),
        );
        peer_account.locator.identity_key = peer_identity_key;
        peer_account.signing_key = peer_signing_key;
        db.bind_authenticated_self(
            ORIGIN_A,
            USER_A,
            &self_account.locator.identity_key,
            &self_account.signing_key,
        )
        .unwrap();
        db.upsert_identity_directory(&[self_account.clone(), peer_account.clone()])
            .unwrap();

        let device_id = [0x75; 16];
        let mut device = sample_device_identity(device_id);
        device.account_identity_key = self_account.locator.identity_key;
        device.account_signing_key = self_account.signing_key;
        db.create_device_identity_v1(&device).unwrap();
        db.upsert_directory_directs(
            ORIGIN_A,
            &[AuthenticatedDirectDirectoryEntry {
                conversation_id: DIRECT_CONVERSATION_ID.to_string(),
                name: "Durable Direct".to_string(),
                peer_user_id: USER_B.to_string(),
                peer_identity_key: peer_account.locator.identity_key,
                created_at: "2026-07-19T00:00:00Z".to_string(),
            }],
        )
        .unwrap();
        db.save_initiator_session(
            &peer_account.locator.identity_key,
            session_data,
            initial_header_data,
        )
        .unwrap();

        DirectOutboxFixture {
            scope: DirectMessageOutboxScopeV1 {
                canonical_server_origin: ORIGIN_A.to_string(),
                user_id: USER_A.to_string(),
                device_id,
            },
            self_account,
            peer_account,
        }
    }

    fn install_direct_outbox_self_without_directory(db: &VeilDb) -> DirectMessageOutboxScopeV1 {
        let self_account = sample_account(
            ORIGIN_A,
            USER_A,
            0x77,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        db.bind_authenticated_self(
            ORIGIN_A,
            USER_A,
            &self_account.locator.identity_key,
            &self_account.signing_key,
        )
        .unwrap();

        let device_id = [0x78; 16];
        let mut device = sample_device_identity(device_id);
        device.account_identity_key = self_account.locator.identity_key;
        device.account_signing_key = self_account.signing_key;
        db.create_device_identity_v1(&device).unwrap();

        DirectMessageOutboxScopeV1 {
            canonical_server_origin: ORIGIN_A.to_string(),
            user_id: USER_A.to_string(),
            device_id,
        }
    }

    fn sample_direct_attachment() -> crate::models::MessageAttachment {
        crate::models::MessageAttachment {
            ordinal: 0,
            media_id: "ab".repeat(16),
            file_name: "ciphertext.bin".to_string(),
            detected_mime: "application/octet-stream".to_string(),
            format_version: 1,
            nonce_prefix: [0x81; 16],
            chunk_count: 1,
            plaintext_size: 5,
            ciphertext_size: 21,
            content_key: [0x82; 32],
        }
    }

    fn direct_outbox_input(
        fixture: &DirectOutboxFixture,
        client_message_id: &str,
        payload: &[u8],
        expected_ratchet_revision: u64,
    ) -> DirectMessageOutboxEnqueueV1 {
        DirectMessageOutboxEnqueueV1 {
            scope: fixture.scope.clone(),
            conversation_id: DIRECT_CONVERSATION_ID.to_string(),
            client_message_id: client_message_id.to_string(),
            local_message_id: client_message_id.to_string(),
            request_digest: direct_message_request_digest_v1(payload),
            exact_send_message_payload: payload.to_vec(),
            expected_ratchet_revision,
            expected_ratchet_session: format!("ratchet-session-v{expected_ratchet_revision}")
                .into_bytes(),
            advanced_ratchet_session: format!("ratchet-session-v{}", expected_ratchet_revision + 1)
                .into_bytes(),
            plaintext: format!("plaintext for {client_message_id}"),
            reply_to_id: None,
            attachments: vec![sample_direct_attachment()],
            author_snapshot: Some(fixture.self_account.clone()),
        }
    }

    fn message_status(db: &VeilDb, message_id: &str) -> Option<i64> {
        db.conn
            .query_row(
                "SELECT status FROM messages WHERE id = ?1",
                rusqlite::params![message_id],
                |row| row.get(0),
            )
            .optional()
            .unwrap()
    }

    fn table_count(db: &VeilDb, table: &str) -> i64 {
        db.conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn ratchet_capacity(db: &VeilDb) -> (i64, i64) {
        db.conn
            .query_row(
                "SELECT row_count, total_session_bytes
                 FROM ratchet_session_capacity_v1 WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    fn ratchet_table_without_rowid(db: &VeilDb) -> bool {
        db.conn
            .query_row(
                "SELECT wr FROM pragma_table_list
                 WHERE schema = 'main' AND name = 'ratchet_sessions' AND type = 'table'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
            == 1
    }

    fn assert_ratchet_rowid_sql_is_unavailable(db: &VeilDb, existing_peer: &[u8; 32]) {
        let rejected_peer = [0xFEu8; 32];
        let capacity_before = ratchet_capacity(db);
        assert!(db
            .conn
            .prepare("SELECT rowid FROM ratchet_sessions")
            .is_err());
        assert!(db
            .conn
            .execute(
                "INSERT INTO ratchet_sessions
                     (rowid, peer_identity_key, session_data, revision, updated_at)
                 VALUES (-1, ?1, x'63', 0, datetime('now'))",
                rusqlite::params![rejected_peer.as_slice()],
            )
            .is_err());
        assert!(db
            .conn
            .execute(
                "UPDATE ratchet_sessions SET rowid = -1
                 WHERE peer_identity_key = ?1",
                rusqlite::params![existing_peer.as_slice()],
            )
            .is_err());
        assert!(db
            .conn
            .execute(
                "INSERT OR REPLACE INTO ratchet_sessions
                     (rowid, peer_identity_key, session_data, revision, updated_at)
                 VALUES (-1, ?1, x'64', 0, datetime('now'))",
                rusqlite::params![rejected_peer.as_slice()],
            )
            .is_err());
        assert_eq!(ratchet_capacity(db), capacity_before);
    }

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
        assert!(ratchet_table_without_rowid(&db));
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
    fn unread_state_is_transactional_duplicate_safe_and_origin_scoped() {
        const CONVERSATION: &str = "550e8400-e29b-41d4-a716-446655440101";
        const INCOMING_ONE: &str = "550e8400-e29b-41d4-a716-446655440102";
        const OUTGOING: &str = "550e8400-e29b-41d4-a716-446655440103";
        const INCOMING_TWO: &str = "550e8400-e29b-41d4-a716-446655440104";
        let db = VeilDb::open_memory(&[0x2a; 32]).unwrap();
        db.upsert_directory_conversation(
            CONVERSATION,
            1,
            ORIGIN_A,
            Some("Unread Circle"),
            None,
            None,
            None,
            "2026-07-12T12:00:00Z",
        )
        .unwrap();

        db.insert_message(
            INCOMING_ONE,
            CONVERSATION,
            &[0x11; 32],
            "first",
            false,
            Some(10),
            None,
        )
        .unwrap();
        // A replay/duplicate cannot inflate the durable badge.
        db.insert_message(
            INCOMING_ONE,
            CONVERSATION,
            &[0x11; 32],
            "first",
            false,
            Some(10),
            None,
        )
        .unwrap();
        db.insert_message(
            OUTGOING,
            CONVERSATION,
            &[0x22; 32],
            "mine",
            true,
            Some(20),
            None,
        )
        .unwrap();
        assert_eq!(db.get_conversations().unwrap()[0].unread_count, 1);

        assert!(db.mark_conversation_read(CONVERSATION, ORIGIN_B).is_err());
        assert_eq!(db.get_conversations().unwrap()[0].unread_count, 1);
        assert_eq!(
            db.mark_conversation_read(CONVERSATION, ORIGIN_A).unwrap(),
            Some(OUTGOING.to_string())
        );
        let read = db.get_conversations().unwrap().remove(0);
        assert_eq!(read.unread_count, 0);
        assert_eq!(read.last_read_message_id.as_deref(), Some(OUTGOING));

        // Atomic inbound receive owns an outer savepoint. Message persistence
        // must nest beneath it without publishing either the row or unread
        // increment when the enclosing cryptographic operation rolls back.
        db.begin_receive_savepoint().unwrap();
        db.insert_message(
            INCOMING_TWO,
            CONVERSATION,
            &[0x11; 32],
            "second",
            false,
            Some(30),
            None,
        )
        .unwrap();
        assert!(db.message_exists(INCOMING_TWO).unwrap());
        assert_eq!(db.get_conversations().unwrap()[0].unread_count, 1);
        db.rollback_receive_savepoint().unwrap();
        assert!(!db.message_exists(INCOMING_TWO).unwrap());
        assert_eq!(db.get_conversations().unwrap()[0].unread_count, 0);

        db.insert_message(
            INCOMING_TWO,
            CONVERSATION,
            &[0x11; 32],
            "second",
            false,
            Some(30),
            None,
        )
        .unwrap();
        assert_eq!(db.get_conversations().unwrap()[0].unread_count, 1);
    }

    #[test]
    fn search_rebuild_page_is_origin_scoped_and_keyset_paginated() {
        let db = VeilDb::open_memory(&[42u8; 32]).unwrap();
        const A_1: &str = "550e8400-e29b-41d4-a716-446655440010";
        const A_2: &str = "550e8400-e29b-41d4-a716-446655440020";
        const A_3: &str = "550e8400-e29b-41d4-a716-446655440030";
        const A_TIE: &str = "550e8400-e29b-41d4-a716-446655440031";
        const A_EMPTY: &str = "550e8400-e29b-41d4-a716-446655440040";
        const B_1: &str = "550e8400-e29b-41d4-a716-446655440050";
        db.upsert_directory_conversation(
            "search-a",
            1,
            ORIGIN_A,
            Some("Alpha"),
            None,
            None,
            None,
            "2026-07-14T00:00:00Z",
        )
        .unwrap();
        db.upsert_directory_conversation(
            "search-b",
            1,
            ORIGIN_B,
            Some("Beta"),
            None,
            None,
            None,
            "2026-07-14T00:00:00Z",
        )
        .unwrap();

        db.insert_message(
            A_3,
            "search-a",
            &[1u8; 32],
            "newest lower tie",
            false,
            Some(5),
            None,
        )
        .unwrap();
        db.insert_message(
            B_1,
            "search-b",
            &[2u8; 32],
            "other origin",
            false,
            Some(99),
            None,
        )
        .unwrap();
        db.insert_message(A_1, "search-a", &[1u8; 32], "oldest", false, Some(1), None)
            .unwrap();
        db.insert_message(A_EMPTY, "search-a", &[1u8; 32], "", false, Some(100), None)
            .unwrap();
        db.insert_message(
            A_TIE,
            "search-a",
            &[1u8; 32],
            "newest higher tie",
            false,
            Some(5),
            None,
        )
        .unwrap();
        db.insert_message(
            A_2,
            "search-a",
            &[1u8; 32],
            "middle inserted last",
            false,
            Some(3),
            None,
        )
        .unwrap();

        let first = db.get_search_index_page(ORIGIN_A, None, 2).unwrap();
        assert_eq!(
            first.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
            vec![A_TIE, A_3]
        );
        assert!(first.iter().all(|row| row.conversation_id == "search-a"));
        let cursor = crate::models::SearchIndexCursor {
            timestamp: first[1].timestamp,
            message_id: first[1].id.clone(),
        };
        let second = db
            .get_search_index_page(ORIGIN_A, Some(&cursor), 2)
            .unwrap();
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].id, A_2);
        assert_eq!(second[1].id, A_1);
        assert_eq!(second[1].timestamp, 1);
    }

    #[test]
    fn search_result_context_is_origin_scoped_bounded_and_centred_on_target() {
        let db = VeilDb::open_memory(&[43u8; 32]).unwrap();
        db.upsert_directory_conversation(
            "context-a",
            1,
            ORIGIN_A,
            Some("Alpha"),
            None,
            None,
            None,
            "2026-07-14T00:00:00Z",
        )
        .unwrap();
        for index in 0..250 {
            db.insert_message(
                &format!("context-{index}"),
                "context-a",
                &[1u8; 32],
                &format!("message {index}"),
                false,
                Some(index + 1),
                None,
            )
            .unwrap();
        }

        let middle = db
            .get_search_result_context("context-125", "context-a", ORIGIN_A)
            .unwrap()
            .unwrap();
        assert_eq!(
            middle.conversation_type,
            crate::models::ConversationType::Group
        );
        assert_eq!(middle.server_id, None);
        assert_eq!(middle.messages.len(), 200);
        assert_eq!(middle.messages.first().unwrap().id, "context-26");
        assert_eq!(middle.messages.last().unwrap().id, "context-225");
        assert!(middle
            .messages
            .iter()
            .any(|message| message.id == "context-125"));

        let first = db
            .get_search_result_context("context-0", "context-a", ORIGIN_A)
            .unwrap()
            .unwrap();
        assert_eq!(first.messages.first().unwrap().id, "context-0");
        assert_eq!(first.messages.last().unwrap().id, "context-199");

        let last = db
            .get_search_result_context("context-249", "context-a", ORIGIN_A)
            .unwrap()
            .unwrap();
        assert_eq!(last.messages.first().unwrap().id, "context-50");
        assert_eq!(last.messages.last().unwrap().id, "context-249");

        assert!(db
            .get_search_result_context("context-125", "context-a", ORIGIN_B)
            .unwrap()
            .is_none());
        assert!(db
            .get_search_result_context("deleted", "context-a", ORIGIN_A)
            .unwrap()
            .is_none());
    }

    #[test]
    fn search_result_context_fails_closed_for_corrupt_message_or_channel_rows() {
        let db = VeilDb::open_memory(&[44u8; 32]).unwrap();
        db.upsert_directory_conversation(
            "context-corrupt",
            1,
            ORIGIN_A,
            Some("Corrupt"),
            None,
            None,
            None,
            "2026-07-14T00:00:00Z",
        )
        .unwrap();
        db.insert_message(
            "corrupt-message",
            "context-corrupt",
            &[2u8; 32],
            "body",
            false,
            Some(1),
            None,
        )
        .unwrap();
        db.conn
            .execute(
                "UPDATE messages SET sender_key = X'01' WHERE id = 'corrupt-message'",
                [],
            )
            .unwrap();
        assert!(db
            .get_search_result_context("corrupt-message", "context-corrupt", ORIGIN_A)
            .unwrap_err()
            .contains("invalid sender key"));

        db.conn
            .execute(
                "INSERT INTO conversations
                   (id, conv_type, server_origin, name, created_at)
                 VALUES ('channel-without-server', 2, ?1, 'general', '2026-07-14T00:00:00Z')",
                rusqlite::params![ORIGIN_A],
            )
            .unwrap();
        assert!(db
            .get_search_result_context("missing", "channel-without-server", ORIGIN_A)
            .unwrap_err()
            .contains("no persisted server id"));

        db.conn
            .execute(
                "UPDATE conversations SET server_id = ?1 WHERE id = 'context-corrupt'",
                rusqlite::params!["550e8400-e29b-41d4-a716-446655440099"],
            )
            .unwrap();
        assert!(db
            .get_search_result_context("corrupt-message", "context-corrupt", ORIGIN_A)
            .unwrap_err()
            .contains("non-channel search context"));
    }

    #[test]
    fn search_result_context_publishes_server_id_only_for_channels() {
        let db = VeilDb::open_memory(&[45u8; 32]).unwrap();
        let server_id = "550e8400-e29b-41d4-a716-446655440045";
        db.upsert_directory_conversation(
            "channel-context",
            2,
            ORIGIN_A,
            Some("general"),
            None,
            None,
            Some(server_id),
            "2026-07-14T00:00:00Z",
        )
        .unwrap();
        db.insert_message(
            "channel-message",
            "channel-context",
            &[3u8; 32],
            "channel body",
            false,
            Some(1),
            None,
        )
        .unwrap();

        let context = db
            .get_search_result_context("channel-message", "channel-context", ORIGIN_A)
            .unwrap()
            .unwrap();
        assert_eq!(
            context.conversation_type,
            crate::models::ConversationType::Channel
        );
        assert_eq!(context.server_id.as_deref(), Some(server_id));
    }

    #[test]
    fn search_result_context_rehydrates_persisted_author_context_and_attachments() {
        let db = VeilDb::open_memory(&[46u8; 32]).unwrap();
        let conversation_id = "550e8400-e29b-41d4-a716-446655440046";
        let message_id = "550e8400-e29b-41d4-a716-446655440047";
        let author = sample_account(
            ORIGIN_A,
            USER_A,
            0x46,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            Some(7),
        );
        db.upsert_directory_conversation(
            conversation_id,
            1,
            ORIGIN_A,
            Some("Composition"),
            None,
            None,
            None,
            "2026-07-14T00:00:00Z",
        )
        .unwrap();
        let attachment = crate::models::MessageAttachment {
            ordinal: 0,
            media_id: "0123456789abcdef0123456789abcdef".to_string(),
            file_name: "evidence.txt".to_string(),
            detected_mime: "text/plain".to_string(),
            format_version: 2,
            nonce_prefix: [0x47; 16],
            chunk_count: 1,
            plaintext_size: 8,
            ciphertext_size: 24,
            content_key: [0x48; 32],
        };
        db.insert_outgoing_pending_message_with_attachments(
            message_id,
            conversation_id,
            &author.locator.identity_key,
            "search composition",
            None,
            std::slice::from_ref(&attachment),
        )
        .unwrap();
        db.attach_message_author_with_context(
            message_id,
            &author,
            MessageAuthorContext::DirectoryMemberAtObservation,
        )
        .unwrap();

        let context = db
            .get_search_result_context(message_id, conversation_id, ORIGIN_A)
            .unwrap()
            .unwrap();
        assert_eq!(context.messages.len(), 1);
        let hydrated = &context.messages[0];
        assert_eq!(hydrated.author.as_ref(), Some(&author));
        assert_eq!(
            hydrated.author_context,
            Some(MessageAuthorContext::DirectoryMemberAtObservation)
        );
        assert_eq!(hydrated.attachments.len(), 1);
        assert_eq!(hydrated.attachments[0].file_name, attachment.file_name);
        assert_eq!(hydrated.attachments[0].media_id, attachment.media_id);
        assert_eq!(hydrated.attachments[0].content_key, attachment.content_key);

        db.conn
            .execute(
                "UPDATE messages SET sender_key = ?1 WHERE id = ?2",
                rusqlite::params![[0x49u8; 32].as_slice(), message_id],
            )
            .unwrap();
        assert!(db
            .get_search_result_context(message_id, conversation_id, ORIGIN_A)
            .unwrap_err()
            .contains("mismatched author"));
    }

    #[test]
    fn resolves_cached_channel_context_without_loading_channel_lists() {
        let mut db = VeilDb::open_memory(&[42u8; 32]).unwrap();
        db.replace_servers(&[crate::models::CachedServer {
            id: "server-1".into(),
            name: "Server".into(),
            description: None,
            icon_url: None,
            owner_id: "owner".into(),
            position: 0,
            created_at: "2026-01-01T00:00:00Z".into(),
        }])
        .unwrap();
        db.upsert_channel(&crate::models::CachedChannel {
            id: "channel-1".into(),
            server_id: "server-1".into(),
            conversation_id: Some("conversation-1".into()),
            name: "general".into(),
            channel_type: 0,
            category_id: None,
            position: 0,
            topic: None,
            nsfw: false,
            slowmode_secs: 0,
        })
        .unwrap();

        assert_eq!(
            db.find_channel_context_by_conversation("conversation-1")
                .unwrap(),
            Some(("server-1".into(), "channel-1".into()))
        );
        assert!(db
            .find_channel_context_by_conversation("missing")
            .unwrap()
            .is_none());
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
    fn device_identity_is_created_only_explicitly_and_is_immutable() {
        let db = VeilDb::open_memory(&[0x81u8; 32]).unwrap();
        assert!(db.load_device_identity_v1().unwrap().is_none());

        let identity = sample_device_identity([0x10; 16]);
        db.create_device_identity_v1(&identity).unwrap();
        let loaded = db.load_device_identity_v1().unwrap().unwrap();
        assert_eq!(loaded.device_id, identity.device_id);
        assert_eq!(loaded.version, identity.version);
        assert_eq!(loaded.x25519_secret, identity.x25519_secret);
        assert_eq!(loaded.ed25519_secret, identity.ed25519_secret);
        assert_eq!(loaded.device_identity_key, identity.device_identity_key);
        assert_eq!(loaded.device_signing_key, identity.device_signing_key);
        assert_eq!(loaded.capabilities, identity.capabilities);
        assert_eq!(loaded.status, identity.status);
        assert_eq!(loaded.account_signature, identity.account_signature);
        assert!(db.create_device_identity_v1(&identity).is_err());
    }

    #[test]
    fn device_binding_capability_advance_is_contiguous_and_compare_and_swap() {
        let db = VeilDb::open_memory(&[0x84u8; 32]).unwrap();
        let identity = sample_device_identity([0x11; 16]);
        db.create_device_identity_v1(&identity).unwrap();

        let mut candidate = db.load_device_identity_v1().unwrap().unwrap();
        candidate.version += 1;
        candidate.capabilities |= 4;
        candidate.account_signature[0] ^= 1;
        db.advance_device_identity_binding_v1(&candidate).unwrap();

        let advanced = db.load_device_identity_v1().unwrap().unwrap();
        assert_eq!(advanced.version, 2);
        assert_eq!(advanced.capabilities, 7);
        assert_eq!(advanced.x25519_secret, identity.x25519_secret);
        assert_eq!(advanced.ed25519_secret, identity.ed25519_secret);
        assert_eq!(advanced.device_identity_key, identity.device_identity_key);
        assert_eq!(advanced.device_signing_key, identity.device_signing_key);
        assert_eq!(advanced.account_signature, candidate.account_signature);

        assert!(db.advance_device_identity_binding_v1(&candidate).is_err());
        let mut substitution = db.load_device_identity_v1().unwrap().unwrap();
        substitution.version += 1;
        substitution.capabilities |= 8;
        substitution.account_signature[0] ^= 1;
        substitution.device_identity_key[0] ^= 1;
        assert!(db
            .advance_device_identity_binding_v1(&substitution)
            .unwrap_err()
            .contains("immutable identity state"));
        assert_eq!(db.load_device_identity_v1().unwrap().unwrap().version, 2);
    }

    #[test]
    fn device_binding_marker_makes_missing_or_mismatched_material_fail_closed() {
        let db = VeilDb::open_memory(&[0x82u8; 32]).unwrap();
        let identity = sample_device_identity([0x20; 16]);
        db.create_device_identity_v1(&identity).unwrap();
        db.conn
            .execute("DELETE FROM device_identity_v1 WHERE singleton = 1", [])
            .unwrap();
        assert!(db
            .load_device_identity_v1()
            .err()
            .unwrap()
            .contains("private device identity is missing"));

        db.conn
            .execute(
                "UPDATE client_state SET value = ?1
                 WHERE key = 'device_binding_v1_created'",
                rusqlite::params![[0x21u8; 16].as_slice()],
            )
            .unwrap();
        // Reinsert structurally valid material without changing the marker.
        db.conn
            .execute(
                "INSERT INTO device_identity_v1
                   (singleton, device_id, version, x25519_secret, ed25519_secret,
                    device_identity_key, device_signing_key, capabilities, status,
                    account_identity_key, account_signing_key, account_signature)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                rusqlite::params![
                    identity.device_id.as_slice(),
                    identity.version.to_be_bytes().as_slice(),
                    identity.x25519_secret.as_slice(),
                    identity.ed25519_secret.as_slice(),
                    identity.device_identity_key.as_slice(),
                    identity.device_signing_key.as_slice(),
                    identity.capabilities.to_be_bytes().as_slice(),
                    identity.status,
                    identity.account_identity_key.as_slice(),
                    identity.account_signing_key.as_slice(),
                    identity.account_signature.as_slice(),
                ],
            )
            .unwrap();
        assert!(db
            .load_device_identity_v1()
            .err()
            .unwrap()
            .contains("marker does not match"));
    }

    #[test]
    fn device_identity_survives_sqlcipher_restart() {
        let path =
            std::env::temp_dir().join(format!("veil-device-identity-{}.db", uuid::Uuid::new_v4()));
        let db_key = [0x83u8; 32];
        let identity = sample_device_identity([0x30; 16]);
        {
            let db = VeilDb::open(&path, &db_key).unwrap();
            db.create_device_identity_v1(&identity).unwrap();
            let mut candidate = db.load_device_identity_v1().unwrap().unwrap();
            candidate.version += 1;
            candidate.capabilities |= 4;
            candidate.account_signature[0] ^= 1;
            db.advance_device_identity_binding_v1(&candidate).unwrap();
        }
        {
            let reopened = VeilDb::open(&path, &db_key).unwrap();
            let loaded = reopened.load_device_identity_v1().unwrap().unwrap();
            assert_eq!(loaded.device_id, identity.device_id);
            assert_eq!(loaded.version, identity.version + 1);
            assert_eq!(loaded.capabilities, identity.capabilities | 4);
            assert_eq!(loaded.x25519_secret, identity.x25519_secret);
            assert_eq!(loaded.ed25519_secret, identity.ed25519_secret);
            assert_eq!(loaded.account_signature, identity.account_signature);
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
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
    fn pending_sender_key_envelope_is_first_write_immutable_and_scoped() {
        let db = VeilDb::open_memory(&[0x91u8; 32]).unwrap();
        let sender = [1u8; 32];
        let target_a = [2u8; 32];
        let target_b = [3u8; 32];
        let first = b"sealed-generation-one";

        assert_eq!(
            db.save_pending_sender_key_envelope("group-cache", 7, &target_a, &sender, first)
                .unwrap(),
            first
        );
        assert_eq!(
            db.save_pending_sender_key_envelope("group-cache", 7, &target_a, &sender, first)
                .unwrap(),
            first
        );
        assert!(db
            .save_pending_sender_key_envelope(
                "group-cache",
                7,
                &target_a,
                &sender,
                b"different-randomized-seal",
            )
            .is_err());
        assert_eq!(
            db.load_pending_sender_key_envelope("group-cache", 7, &target_a, &sender)
                .unwrap()
                .unwrap(),
            first
        );

        db.save_pending_sender_key_envelope("group-cache", 7, &target_b, &sender, b"target-b")
            .unwrap();
        db.save_pending_sender_key_envelope(
            "group-cache",
            8,
            &target_a,
            &sender,
            b"generation-eight",
        )
        .unwrap();
        db.delete_pending_sender_key_envelope_generation("group-cache", 7)
            .unwrap();
        assert!(db
            .load_pending_sender_key_envelope("group-cache", 7, &target_a, &sender)
            .unwrap()
            .is_none());
        assert!(db
            .load_pending_sender_key_envelope("group-cache", 7, &target_b, &sender)
            .unwrap()
            .is_none());
        assert!(db
            .load_pending_sender_key_envelope("group-cache", 8, &target_a, &sender)
            .unwrap()
            .is_some());
        db.delete_pending_sender_key_envelopes_for_conversation("group-cache")
            .unwrap();
        assert!(db
            .load_pending_sender_key_envelope("group-cache", 8, &target_a, &sender)
            .unwrap()
            .is_none());
    }

    #[test]
    fn exact_device_sender_key_cache_persists_complete_v6_membership_coordinate() {
        let db = VeilDb::open_memory(&[0x92u8; 32]).unwrap();
        let envelope = PendingSenderKeyDeviceEnvelopeV1 {
            conversation_id: "00000000-0000-0000-0000-000000000106".to_string(),
            generation: 9,
            target_account_identity_key: [0x10; 32],
            target_device_id: [0x11; 16],
            target_device_identity_key: [0x12; 32],
            target_binding_version: 2,
            sender_device_id: [0x13; 16],
            sender_device_identity_key: [0x14; 32],
            sender_binding_version: 3,
            roster_version: 4,
            roster_commitment: [0x15; 32],
            membership_epoch: 5,
            membership_epoch_hash: [0x16; 32],
            envelope_commitment: [0x17; 32],
            sealed_envelope: b"sealed-v6-envelope".to_vec(),
        };
        assert_eq!(
            db.save_pending_sender_key_device_envelope_v1(&envelope)
                .unwrap(),
            envelope.sealed_envelope
        );
        assert_eq!(
            db.load_pending_sender_key_device_envelope_v1(
                &envelope.conversation_id,
                envelope.generation,
                &envelope.target_device_id,
                envelope.target_binding_version,
                envelope.roster_version,
            )
            .unwrap(),
            Some(envelope.clone())
        );

        let mut partial = envelope;
        partial.generation += 1;
        partial.membership_epoch_hash = [0u8; 32];
        assert!(db
            .save_pending_sender_key_device_envelope_v1(&partial)
            .unwrap_err()
            .contains("invalid exact-device"));
    }

    #[test]
    fn sender_key_rotation_rolls_back_state_when_cache_invalidation_fails() {
        let db = VeilDb::open_memory(&[0x95u8; 32]).unwrap();
        let sender = [0x11u8; 32];
        let target = [0x22u8; 32];
        let old_state = b"old-outgoing-state";
        db.save_sender_key("group-atomic-rotation", &sender, old_state, true)
            .unwrap();
        db.save_pending_sender_key_envelope(
            "group-atomic-rotation",
            7,
            &target,
            &sender,
            b"immutable-old-envelope",
        )
        .unwrap();
        db.conn
            .execute_batch(
                "CREATE TRIGGER abort_sender_key_cache_delete
                 BEFORE DELETE ON pending_sender_key_envelopes
                 BEGIN
                   SELECT RAISE(ABORT, 'injected cache delete failure');
                 END;",
            )
            .unwrap();

        let error = db
            .commit_sender_key_rotation("group-atomic-rotation", &sender, b"new-outgoing-state")
            .unwrap_err();
        assert!(error.contains("injected cache delete failure"));
        assert_eq!(
            db.load_sender_key("group-atomic-rotation", &sender)
                .unwrap()
                .unwrap(),
            old_state
        );
        assert_eq!(
            db.load_pending_sender_key_envelope("group-atomic-rotation", 7, &target, &sender,)
                .unwrap()
                .unwrap(),
            b"immutable-old-envelope"
        );
    }

    #[test]
    fn pending_sender_key_envelope_survives_sqlcipher_restart() {
        let path =
            std::env::temp_dir().join(format!("veil-pending-skdm-{}.db", uuid::Uuid::new_v4()));
        let db_key = [0x92u8; 32];
        let sender = [4u8; 32];
        let target = [5u8; 32];
        let sealed = b"exact-sealed-envelope-survives-restart";
        {
            let db = VeilDb::open(&path, &db_key).unwrap();
            db.save_pending_sender_key_envelope("group-restart", 19, &target, &sender, sealed)
                .unwrap();
        }
        {
            let reopened = VeilDb::open(&path, &db_key).unwrap();
            assert_eq!(
                reopened
                    .load_pending_sender_key_envelope("group-restart", 19, &target, &sender,)
                    .unwrap()
                    .unwrap(),
                sealed
            );
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn incoming_sender_key_generations_persist_ordered_and_reject_state_rollback() {
        let path = std::env::temp_dir().join(format!(
            "veil-incoming-generations-{}.db",
            uuid::Uuid::new_v4()
        ));
        let key = [0xA1; 32];
        let sender = [0x31; 32];
        {
            let db = VeilDb::open(&path, &key).unwrap();
            db.save_incoming_sender_key_generation(
                "group-generations",
                &sender,
                2,
                0,
                1,
                &[0x22; 32],
                b"generation-two-revision-one",
            )
            .unwrap();
            db.save_incoming_sender_key_generation(
                "group-generations",
                &sender,
                1,
                0,
                1,
                &[0x11; 32],
                b"generation-one-revision-one",
            )
            .unwrap();
            db.save_incoming_sender_key_generation(
                "group-generations",
                &sender,
                1,
                1,
                2,
                &[0x11; 32],
                b"generation-one-revision-two",
            )
            .unwrap();
            assert!(db
                .save_incoming_sender_key_generation(
                    "group-generations",
                    &sender,
                    1,
                    0,
                    1,
                    &[0x11; 32],
                    b"generation-one-revision-one",
                )
                .unwrap_err()
                .contains("rollback"));
            assert!(db
                .save_incoming_sender_key_generation(
                    "group-generations",
                    &sender,
                    1,
                    1,
                    2,
                    &[0x11; 32],
                    b"changed-without-revision",
                )
                .unwrap_err()
                .contains("without a revision"));
        }
        {
            let db = VeilDb::open(&path, &key).unwrap();
            let rows = db
                .load_incoming_sender_key_generations_for_group("group-generations")
                .unwrap();
            assert_eq!(rows.len(), 2);
            assert_eq!(
                (
                    rows[0].generation,
                    rows[0].iteration,
                    rows[0].state_revision
                ),
                (1, 1, 2)
            );
            assert_eq!(rows[0].key_data.as_slice(), b"generation-one-revision-two");
            assert_eq!(rows[1].generation, 2);
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn incoming_sender_key_generation_retention_cap_is_fail_closed_and_scoped() {
        let db = VeilDb::open_memory(&[0xA7; 32]).unwrap();
        let sender = [0xA8; 32];
        for generation in 1..=MAX_RETAINED_SENDER_KEY_GENERATIONS_PER_SENDER as u32 {
            db.save_incoming_sender_key_generation(
                "bounded-conversation",
                &sender,
                generation,
                0,
                1,
                &[generation as u8; 32],
                &[generation as u8],
            )
            .unwrap();
        }
        let error = db
            .save_incoming_sender_key_generation(
                "bounded-conversation",
                &sender,
                MAX_RETAINED_SENDER_KEY_GENERATIONS_PER_SENDER as u32 + 1,
                0,
                1,
                &[0xFF; 32],
                b"must-not-persist",
            )
            .unwrap_err();
        assert!(error.contains("retention limit"));
        assert_eq!(
            db.load_incoming_sender_key_generations_for_group("bounded-conversation")
                .unwrap()
                .len(),
            MAX_RETAINED_SENDER_KEY_GENERATIONS_PER_SENDER,
        );
        db.save_incoming_sender_key_generation(
            "independent-conversation",
            &sender,
            1,
            0,
            1,
            &[0xF1; 32],
            b"independent",
        )
        .unwrap();
        assert_eq!(
            db.load_incoming_sender_key_generations_for_group("independent-conversation")
                .unwrap()
                .len(),
            1,
        );
    }

    #[test]
    fn injected_legacy_sender_key_migration_failure_rolls_back_new_generation() {
        let db = VeilDb::open_memory(&[0xA2; 32]).unwrap();
        let sender = [0x41; 32];
        db.save_sender_key("group-legacy-rollback", &sender, b"legacy-state", false)
            .unwrap();
        db.conn
            .execute_batch(
                "CREATE TRIGGER abort_legacy_sender_key_delete
                 BEFORE DELETE ON sender_keys_local
                 BEGIN SELECT RAISE(ABORT, 'injected legacy migration failure'); END;",
            )
            .unwrap();
        let error = db
            .migrate_legacy_incoming_sender_key_generation(
                "group-legacy-rollback",
                &sender,
                7,
                0,
                0,
                &[0u8; 32],
                b"legacy-state",
            )
            .unwrap_err();
        assert!(error.contains("injected legacy migration failure"));
        assert_eq!(
            db.load_sender_key("group-legacy-rollback", &sender)
                .unwrap()
                .unwrap(),
            b"legacy-state"
        );
        assert!(db
            .load_incoming_sender_key_generations_for_group("group-legacy-rollback")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn device_roster_pins_survive_restart_and_reject_rollback_or_equivocation() {
        let path =
            std::env::temp_dir().join(format!("veil-roster-pins-{}.db", uuid::Uuid::new_v4()));
        let key = [0xA3; 32];
        let binding = sample_binding_pin(0x20, 1, 1);
        {
            let db = VeilDb::open(&path, &key).unwrap();
            db.commit_device_roster_snapshot_v1(&DeviceRosterSnapshotV1 {
                conversation_id: "00000000-0000-0000-0000-000000000101",
                roster_version: 5,
                roster_commitment: [0x51; 32],
                required_capabilities: 3,
                canonical_snapshot: b"canonical-roster-five",
                bindings: std::slice::from_ref(&binding),
            })
            .unwrap();
        }
        {
            let db = VeilDb::open(&path, &key).unwrap();
            assert_eq!(
                db.load_device_roster_head_v1("00000000-0000-0000-0000-000000000101")
                    .unwrap(),
                Some((5, [0x51; 32], 3))
            );
            assert!(db
                .commit_device_roster_snapshot_v1(&DeviceRosterSnapshotV1 {
                    conversation_id: "00000000-0000-0000-0000-000000000101",
                    roster_version: 4,
                    roster_commitment: [0x41; 32],
                    required_capabilities: 3,
                    canonical_snapshot: b"rollback",
                    bindings: std::slice::from_ref(&binding),
                })
                .unwrap_err()
                .contains("rollback"));
            assert!(db
                .commit_device_roster_snapshot_v1(&DeviceRosterSnapshotV1 {
                    conversation_id: "00000000-0000-0000-0000-000000000101",
                    roster_version: 5,
                    roster_commitment: [0x52; 32],
                    required_capabilities: 3,
                    canonical_snapshot: b"same-version-equivocation",
                    bindings: std::slice::from_ref(&binding),
                })
                .unwrap_err()
                .contains("same device roster version"));
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn membership_epoch_chain_is_idempotent_append_only_and_pins_history() {
        const CONVERSATION: &str = "00000000-0000-0000-0000-000000000102";
        let db = VeilDb::open_memory(&[0xA6; 32]).unwrap();
        let epoch_one_hash = [0x11; 32];
        let epoch_two_hash = [0x22; 32];

        let first = vec![sample_membership_pin(
            CONVERSATION,
            1,
            epoch_one_hash,
            [0u8; 32],
        )];
        let head = db.commit_membership_epoch_chain_v1(&first).unwrap();
        assert_eq!(head.epoch, 1);
        assert_eq!(head.epoch_hash, epoch_one_hash);
        assert_eq!(db.commit_membership_epoch_chain_v1(&first).unwrap(), head);
        assert!(db
            .membership_epoch_matches_pin_v1(CONVERSATION, 1, &epoch_one_hash)
            .unwrap());

        let full = vec![
            sample_membership_pin(CONVERSATION, 1, epoch_one_hash, [0u8; 32]),
            sample_membership_pin(CONVERSATION, 2, epoch_two_hash, epoch_one_hash),
        ];
        let head = db.commit_membership_epoch_chain_v1(&full).unwrap();
        assert_eq!(head.epoch, 2);
        assert_eq!(head.epoch_hash, epoch_two_hash);
        assert!(db
            .membership_epoch_matches_pin_v1(CONVERSATION, 1, &epoch_one_hash)
            .unwrap());
        assert!(db
            .membership_epoch_matches_pin_v1(CONVERSATION, 2, &epoch_two_hash)
            .unwrap());
        assert!(!db
            .membership_epoch_matches_pin_v1(CONVERSATION, 2, &[0x23; 32])
            .unwrap());

        assert!(db
            .commit_membership_epoch_chain_v1(&first)
            .unwrap_err()
            .contains("rollback"));
        let equivocation = vec![
            sample_membership_pin(CONVERSATION, 1, [0x12; 32], [0u8; 32]),
            sample_membership_pin(CONVERSATION, 2, epoch_two_hash, [0x12; 32]),
        ];
        assert!(db
            .commit_membership_epoch_chain_v1(&equivocation)
            .unwrap_err()
            .contains("equivocation"));
        assert_eq!(
            db.load_membership_epoch_head_v1(CONVERSATION)
                .unwrap()
                .unwrap()
                .epoch_hash,
            epoch_two_hash
        );
    }

    #[test]
    fn device_binding_pin_rejects_key_replacement_rollback_and_revoked_resurrection_atomically() {
        let db = VeilDb::open_memory(&[0xA4; 32]).unwrap();
        let original = sample_binding_pin(0x30, 2, 1);
        db.commit_device_roster_snapshot_v1(&DeviceRosterSnapshotV1 {
            conversation_id: "00000000-0000-0000-0000-000000000201",
            roster_version: 1,
            roster_commitment: [0x61; 32],
            required_capabilities: 3,
            canonical_snapshot: b"initial",
            bindings: std::slice::from_ref(&original),
        })
        .unwrap();

        let mut replacement = original.clone();
        replacement.binding_version = 3;
        replacement.device_identity_key[0] ^= 1;
        assert!(db
            .commit_device_roster_snapshot_v1(&DeviceRosterSnapshotV1 {
                conversation_id: "00000000-0000-0000-0000-000000000202",
                roster_version: 1,
                roster_commitment: [0x62; 32],
                required_capabilities: 3,
                canonical_snapshot: b"replacement",
                bindings: std::slice::from_ref(&replacement),
            })
            .unwrap_err()
            .contains("replacement"));

        let mut rollback = original.clone();
        rollback.binding_version = 1;
        assert!(db
            .commit_device_roster_snapshot_v1(&DeviceRosterSnapshotV1 {
                conversation_id: "00000000-0000-0000-0000-000000000203",
                roster_version: 1,
                roster_commitment: [0x63; 32],
                required_capabilities: 3,
                canonical_snapshot: b"binding-rollback",
                bindings: std::slice::from_ref(&rollback),
            })
            .unwrap_err()
            .contains("binding version rollback"));

        let mut revoked = original.clone();
        revoked.binding_version = 3;
        revoked.status = 3;
        revoked.account_signature[0] ^= 1;
        db.commit_device_roster_snapshot_v1(&DeviceRosterSnapshotV1 {
            conversation_id: "00000000-0000-0000-0000-000000000204",
            roster_version: 1,
            roster_commitment: [0x64; 32],
            required_capabilities: 3,
            canonical_snapshot: b"revoked",
            bindings: std::slice::from_ref(&revoked),
        })
        .unwrap();
        let mut resurrected = revoked.clone();
        resurrected.binding_version = 4;
        resurrected.status = 1;
        assert!(db
            .commit_device_roster_snapshot_v1(&DeviceRosterSnapshotV1 {
                conversation_id: "00000000-0000-0000-0000-000000000205",
                roster_version: 1,
                roster_commitment: [0x65; 32],
                required_capabilities: 3,
                canonical_snapshot: b"resurrected",
                bindings: std::slice::from_ref(&resurrected),
            })
            .unwrap_err()
            .contains("cannot become active"));

        let fresh = sample_binding_pin(0x40, 1, 1);
        let mut conflict = revoked.clone();
        conflict.binding_version = 4;
        conflict.device_signing_key[0] ^= 1;
        assert!(db
            .commit_device_roster_snapshot_v1(&DeviceRosterSnapshotV1 {
                conversation_id: "00000000-0000-0000-0000-000000000206",
                roster_version: 1,
                roster_commitment: [0x66; 32],
                required_capabilities: 3,
                canonical_snapshot: b"atomic-failure",
                bindings: &[fresh.clone(), conflict],
            })
            .is_err());
        let count: i64 = db
            .conn
            .query_row(
                "SELECT count(*) FROM device_binding_pins_v1 WHERE device_id = ?1",
                rusqlite::params![fresh.device_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "failed roster transaction leaked its first pin");
        assert!(db
            .load_device_roster_head_v1("00000000-0000-0000-0000-000000000206")
            .unwrap()
            .is_none());
    }

    #[test]
    fn historical_sender_proof_first_seen_tofu_pins_atomically_and_conflicts_roll_back() {
        let db = VeilDb::open_memory(&[0xB1; 32]).unwrap();
        let binding = sample_binding_pin(0x51, 1, 1);
        let mut route = sample_incoming_route(&binding, [0x61; 16], [0x62; 32]);
        route.membership_epoch = 7;
        route.membership_epoch_hash = [0x67; 32];
        db.save_incoming_sender_key_generation_with_route_v1(
            "historical-tofu",
            &binding.device_identity_key,
            1,
            0,
            1,
            &[0x63; 32],
            b"incoming-state",
            &route,
        )
        .unwrap();
        assert_eq!(
            db.load_incoming_sender_key_route_v1(
                "historical-tofu",
                &binding.device_identity_key,
                1,
            )
            .unwrap(),
            Some(route)
        );
        let mut partial = sample_incoming_route(&binding, [0x68; 16], [0x69; 32]);
        partial.membership_epoch = 8;
        assert!(db
            .save_incoming_sender_key_generation_with_route_v1(
                "historical-partial-membership",
                &binding.device_identity_key,
                2,
                0,
                1,
                &[0x6A; 32],
                b"must-not-persist",
                &partial,
            )
            .unwrap_err()
            .contains("invalid incoming sender-key route proof"));
        assert!(db
            .load_incoming_sender_key_generations_for_group("historical-partial-membership")
            .unwrap()
            .is_empty());
        assert!(db
            .load_trusted_signing_keys()
            .unwrap()
            .contains(&(binding.account_identity_key, binding.account_signing_key,)));

        let conflict_db = VeilDb::open_memory(&[0xB2; 32]).unwrap();
        conflict_db
            .pin_trusted_signing_key(&binding.account_identity_key, &[0xEE; 32])
            .unwrap();
        let error = conflict_db
            .save_incoming_sender_key_generation_with_route_v1(
                "historical-conflict",
                &binding.device_identity_key,
                1,
                0,
                1,
                &[0x64; 32],
                b"must-rollback",
                &sample_incoming_route(&binding, [0x65; 16], [0x66; 32]),
            )
            .unwrap_err();
        assert!(error.contains("trusted signing key changed"));
        assert!(conflict_db
            .load_incoming_sender_key_generations_for_group("historical-conflict")
            .unwrap()
            .is_empty());
        let leaked_device_pin: i64 = conflict_db
            .conn
            .query_row(
                "SELECT count(*) FROM device_binding_pins_v1 WHERE device_id = ?1",
                rusqlite::params![binding.device_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(leaked_device_pin, 0);
    }

    #[test]
    fn historical_binding_below_current_head_never_downgrades_or_reactivates_it() {
        let db = VeilDb::open_memory(&[0xB3; 32]).unwrap();
        let historical = sample_binding_pin(0x71, 1, 1);
        let mut current = historical.clone();
        current.binding_version = 2;
        current.account_signature = [0x81; 64];
        db.commit_device_roster_snapshot_v1(&DeviceRosterSnapshotV1 {
            conversation_id: "00000000-0000-0000-0000-000000000701",
            roster_version: 1,
            roster_commitment: [0x82; 32],
            required_capabilities: 3,
            canonical_snapshot: b"current-active",
            bindings: std::slice::from_ref(&current),
        })
        .unwrap();
        let route = sample_incoming_route(&historical, [0x83; 16], [0x84; 32]);
        db.save_incoming_sender_key_generation_with_route_v1(
            "historical-below-active",
            &historical.device_identity_key,
            1,
            0,
            1,
            &[0x85; 32],
            b"historical-active",
            &route,
        )
        .unwrap();

        let mut revoked = current.clone();
        revoked.binding_version = 3;
        revoked.status = 3;
        revoked.account_signature = [0x86; 64];
        db.commit_device_roster_snapshot_v1(&DeviceRosterSnapshotV1 {
            conversation_id: "00000000-0000-0000-0000-000000000702",
            roster_version: 1,
            roster_commitment: [0x87; 32],
            required_capabilities: 3,
            canonical_snapshot: b"current-revoked",
            bindings: std::slice::from_ref(&revoked),
        })
        .unwrap();
        let mut second_route = route.clone();
        second_route.roster_version = 2;
        second_route.roster_commitment = [0x88; 32];
        second_route.envelope_commitment = [0x89; 32];
        db.save_incoming_sender_key_generation_with_route_v1(
            "historical-below-revoked",
            &historical.device_identity_key,
            2,
            0,
            1,
            &[0x8A; 32],
            b"historical-revoked",
            &second_route,
        )
        .unwrap();
        let (version, status): (Vec<u8>, i64) = db
            .conn
            .query_row(
                "SELECT binding_version, status FROM device_binding_pins_v1 WHERE device_id = ?1",
                rusqlite::params![historical.device_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            u64::from_be_bytes(fixed_bytes("test version", version).unwrap()),
            3
        );
        assert_eq!(status, 3);

        let mut equivocation = second_route;
        equivocation.sender_device_identity_key = [0xFE; 32];
        let error = db
            .save_incoming_sender_key_generation_with_route_v1(
                "historical-equivocation",
                &[0xFE; 32],
                3,
                0,
                1,
                &[0x8B; 32],
                b"must-not-persist",
                &equivocation,
            )
            .unwrap_err();
        assert!(error.contains("replacement"));
        assert!(db
            .load_incoming_sender_key_generations_for_group("historical-equivocation")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn interim_exact_device_tables_rebuild_idempotently_and_fail_closed_on_ambiguity() {
        let db = VeilDb::open_memory(&[0xA5; 32]).unwrap();
        db.conn
            .execute_batch(
                "DROP TABLE sender_key_incoming_routes_v1;
                 DROP TABLE pending_sender_key_device_envelopes_v1;
                 CREATE TABLE pending_sender_key_device_envelopes_v1 (
                    conversation_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    target_account_identity_key BLOB NOT NULL,
                    target_device_id BLOB NOT NULL,
                    target_device_identity_key BLOB NOT NULL,
                    target_binding_version BLOB NOT NULL,
                    sender_device_id BLOB NOT NULL,
                    sender_device_identity_key BLOB NOT NULL,
                    sender_binding_version BLOB NOT NULL,
                    roster_version BLOB NOT NULL,
                    roster_commitment BLOB NOT NULL,
                    envelope_commitment BLOB NOT NULL,
                    sealed_envelope BLOB NOT NULL CHECK(length(sealed_envelope) BETWEEN 1 AND 65536),
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (conversation_id, generation, target_device_id,
                                 target_binding_version, roster_version)
                 );
                 CREATE TABLE sender_key_incoming_routes_v1 (
                    group_id TEXT NOT NULL,
                    sender_identity_key BLOB NOT NULL,
                    generation INTEGER NOT NULL,
                    sender_account_identity_key BLOB NOT NULL,
                    sender_device_id BLOB NOT NULL,
                    sender_device_signing_key BLOB NOT NULL,
                    sender_binding_version BLOB NOT NULL,
                    target_device_id BLOB NOT NULL,
                    target_binding_version BLOB NOT NULL,
                    roster_version BLOB NOT NULL,
                    roster_commitment BLOB NOT NULL,
                    envelope_commitment BLOB NOT NULL,
                    installed_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (group_id, sender_identity_key, generation)
                 );",
            )
            .unwrap();
        db.save_incoming_sender_key_generation(
            "group-interim",
            &[0x11; 32],
            1,
            0,
            1,
            &[0x12; 32],
            b"state",
        )
        .unwrap();
        db.conn
            .execute(
                "INSERT INTO sender_key_incoming_routes_v1 VALUES
                (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, datetime('now'))",
                rusqlite::params![
                    "group-interim",
                    [0x11u8; 32].as_slice(),
                    [0x13u8; 32].as_slice(),
                    [0x14u8; 16].as_slice(),
                    [0x15u8; 32].as_slice(),
                    1u64.to_be_bytes().as_slice(),
                    [0x16u8; 16].as_slice(),
                    1u64.to_be_bytes().as_slice(),
                    1u64.to_be_bytes().as_slice(),
                    [0x17u8; 32].as_slice(),
                    [0x18u8; 32].as_slice(),
                ],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO pending_sender_key_device_envelopes_v1 VALUES
                (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, datetime('now'))",
                rusqlite::params![
                    "group-interim",
                    [0x21u8; 32].as_slice(),
                    [0x22u8; 16].as_slice(),
                    [0x23u8; 32].as_slice(),
                    1u64.to_be_bytes().as_slice(),
                    [0x24u8; 16].as_slice(),
                    [0x25u8; 32].as_slice(),
                    1u64.to_be_bytes().as_slice(),
                    1u64.to_be_bytes().as_slice(),
                    [0x26u8; 32].as_slice(),
                    [0x27u8; 32].as_slice(),
                    b"sealed",
                ],
            )
            .unwrap();
        db.rebuild_interim_sender_key_tables().unwrap();
        db.rebuild_interim_sender_key_tables().unwrap();
        assert!(db
            .normalized_table_sql("pending_sender_key_device_envelopes_v1")
            .unwrap()
            .contains("primary key (conversation_id, generation, target_device_id)"));
        assert!(db
            .normalized_table_sql("sender_key_incoming_routes_v1")
            .unwrap()
            .contains("on delete cascade"));
        db.conn
            .execute_batch(
                "DROP TABLE sender_key_historical_device_proofs_v1;
                 CREATE TABLE sender_key_historical_device_proofs_v1 (
                    group_id TEXT NOT NULL, sender_identity_key BLOB NOT NULL,
                    generation INTEGER NOT NULL, sender_account_signing_key BLOB NOT NULL,
                    sender_device_capabilities BLOB NOT NULL,
                    sender_device_binding_status INTEGER NOT NULL,
                    sender_account_signature BLOB NOT NULL,
                    PRIMARY KEY (group_id, sender_identity_key, generation),
                    FOREIGN KEY (group_id, sender_identity_key, generation)
                      REFERENCES sender_key_incoming_routes_v1
                        (group_id, sender_identity_key, generation) ON DELETE CASCADE
                 );",
            )
            .unwrap();
        db.ensure_sender_key_historical_proof_schema().unwrap();
        db.ensure_sender_key_historical_proof_schema().unwrap();
        let target_column_present: bool = db
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('sender_key_historical_device_proofs_v1')
                    WHERE name = 'target_device_identity_key'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(target_column_present);

        db.conn
            .execute_batch(
                "DROP TABLE pending_sender_key_device_envelopes_v1;
                 CREATE TABLE pending_sender_key_device_envelopes_v1 (
                    conversation_id TEXT NOT NULL, generation INTEGER NOT NULL,
                    target_account_identity_key BLOB NOT NULL, target_device_id BLOB NOT NULL,
                    target_device_identity_key BLOB NOT NULL, target_binding_version BLOB NOT NULL,
                    sender_device_id BLOB NOT NULL, sender_device_identity_key BLOB NOT NULL,
                    sender_binding_version BLOB NOT NULL, roster_version BLOB NOT NULL,
                    roster_commitment BLOB NOT NULL, envelope_commitment BLOB NOT NULL,
                    sealed_envelope BLOB NOT NULL CHECK(length(sealed_envelope) BETWEEN 1 AND 65536),
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (conversation_id, generation, target_device_id,
                                 target_binding_version, roster_version)
                 );",
            )
            .unwrap();
        for version in [1u64, 2] {
            db.conn
                .execute(
                    "INSERT INTO pending_sender_key_device_envelopes_v1 VALUES
                    (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, datetime('now'))",
                    rusqlite::params![
                        "group-ambiguous",
                        [0x31u8; 32].as_slice(),
                        [0x32u8; 16].as_slice(),
                        [0x33u8; 32].as_slice(),
                        version.to_be_bytes().as_slice(),
                        [0x34u8; 16].as_slice(),
                        [0x35u8; 32].as_slice(),
                        1u64.to_be_bytes().as_slice(),
                        version.to_be_bytes().as_slice(),
                        [0x36u8; 32].as_slice(),
                        [0x37u8; 32].as_slice(),
                        b"sealed",
                    ],
                )
                .unwrap();
        }
        assert!(db
            .rebuild_interim_sender_key_tables()
            .unwrap_err()
            .contains("ambiguous"));
        let rows: i64 = db
            .conn
            .query_row(
                "SELECT count(*) FROM pending_sender_key_device_envelopes_v1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2);
        assert!(db
            .normalized_table_sql("pending_sender_key_device_envelopes_v1")
            .unwrap()
            .contains("target_binding_version, roster_version"));
    }

    #[test]
    fn interim_route_rebuild_rolls_back_when_an_orphan_cannot_gain_its_foreign_key() {
        let db = VeilDb::open_memory(&[0xA6; 32]).unwrap();
        db.conn.execute_batch(
            "DROP TABLE sender_key_incoming_routes_v1;
             CREATE TABLE sender_key_incoming_routes_v1 (
                group_id TEXT NOT NULL, sender_identity_key BLOB NOT NULL, generation INTEGER NOT NULL,
                sender_account_identity_key BLOB NOT NULL, sender_device_id BLOB NOT NULL,
                sender_device_signing_key BLOB NOT NULL, sender_binding_version BLOB NOT NULL,
                target_device_id BLOB NOT NULL, target_binding_version BLOB NOT NULL,
                roster_version BLOB NOT NULL, roster_commitment BLOB NOT NULL,
                envelope_commitment BLOB NOT NULL, installed_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (group_id, sender_identity_key, generation)
             );"
        ).unwrap();
        db.conn
            .execute(
                "INSERT INTO sender_key_incoming_routes_v1 VALUES
                ('orphan', ?1, 9, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, datetime('now'))",
                rusqlite::params![
                    [0x41u8; 32].as_slice(),
                    [0x42u8; 32].as_slice(),
                    [0x43u8; 16].as_slice(),
                    [0x44u8; 32].as_slice(),
                    1u64.to_be_bytes().as_slice(),
                    [0x45u8; 16].as_slice(),
                    1u64.to_be_bytes().as_slice(),
                    1u64.to_be_bytes().as_slice(),
                    [0x46u8; 32].as_slice(),
                    [0x47u8; 32].as_slice(),
                ],
            )
            .unwrap();
        assert!(db.rebuild_interim_sender_key_tables().is_err());
        assert!(!db
            .normalized_table_sql("sender_key_incoming_routes_v1")
            .unwrap()
            .contains("foreign key"));
        let rows: i64 = db
            .conn
            .query_row(
                "SELECT count(*) FROM sender_key_incoming_routes_v1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 1);
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
    fn attachment_secrets_follow_ack_and_delete_atomically() {
        let db = VeilDb::open_memory(&[0x71u8; 32]).unwrap();
        db.insert_conversation("attachment-conversation", 1, Some("Circle"), None, None)
            .unwrap();
        let attachment = crate::models::MessageAttachment {
            ordinal: 0,
            media_id: "0123456789abcdef0123456789abcdef".to_string(),
            file_name: "safe.txt".to_string(),
            detected_mime: "text/plain".to_string(),
            format_version: 2,
            nonce_prefix: [3u8; 16],
            chunk_count: 1,
            plaintext_size: 5,
            ciphertext_size: 21,
            content_key: [4u8; 32],
        };
        db.insert_outgoing_pending_message_with_attachments(
            "local-attachment",
            "attachment-conversation",
            &[5u8; 32],
            "caption",
            None,
            &[attachment],
        )
        .unwrap();
        assert_eq!(
            db.get_messages("attachment-conversation", 10).unwrap()[0].attachments[0].content_key,
            [4u8; 32]
        );

        db.acknowledge_outgoing_message("local-attachment", "server-attachment", 1234)
            .unwrap();
        assert!(db
            .get_message_attachments("local-attachment")
            .unwrap()
            .is_empty());
        assert_eq!(
            db.get_message_attachments("server-attachment").unwrap()[0].file_name,
            "safe.txt"
        );

        db.delete_message_scoped("server-attachment", "attachment-conversation")
            .unwrap();
        assert!(db
            .get_message_attachments("server-attachment")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn rejected_outgoing_message_remains_failed_until_explicitly_discarded() {
        let db = VeilDb::open_memory(&[0x62u8; 32]).unwrap();
        db.insert_conversation("conv-failed", 1, Some("Group"), None, None)
            .unwrap();
        db.insert_outgoing_pending_message(
            "local-failed",
            "conv-failed",
            &[5u8; 32],
            "keep this draft",
            None,
        )
        .unwrap();

        db.mark_outgoing_message_failed("local-failed").unwrap();
        let failed = db.get_messages("conv-failed", 10).unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].status, crate::models::MessageStatus::Failed);
        assert_eq!(failed[0].plaintext, "keep this draft");

        db.discard_failed_outgoing_message("local-failed").unwrap();
        assert!(db.get_messages("conv-failed", 10).unwrap().is_empty());
        assert!(db
            .get_conversations()
            .unwrap()
            .into_iter()
            .find(|conversation| conversation.id == "conv-failed")
            .unwrap()
            .last_message_at
            .is_none());
    }

    #[test]
    fn crash_recovery_marks_sending_rows_unknown_and_keeps_latest_window() {
        let db = VeilDb::open_memory(&[0x63u8; 32]).unwrap();
        db.insert_conversation("conv-unknown", 1, Some("Group"), None, None)
            .unwrap();
        for (id, text) in [
            ("local-1", "first"),
            ("local-2", "second"),
            ("local-3", "possibly delivered"),
        ] {
            db.insert_outgoing_pending_message(id, "conv-unknown", &[6u8; 32], text, None)
                .unwrap();
        }

        assert_eq!(db.recover_unacknowledged_outgoing_messages().unwrap(), 3);
        let latest = db.get_messages("conv-unknown", 2).unwrap();
        assert_eq!(
            latest
                .iter()
                .map(|message| message.id.as_str())
                .collect::<Vec<_>>(),
            vec!["local-2", "local-3"]
        );
        assert!(latest
            .iter()
            .all(|message| message.status == crate::models::MessageStatus::Unknown));
        assert_eq!(latest[1].plaintext, "possibly delivered");
    }

    #[test]
    fn directory_upsert_fills_but_never_replaces_crypto_bindings() {
        let db = VeilDb::open_memory(&[11u8; 32]).unwrap();
        let peer = [4u8; 32];
        db.upsert_directory_conversation(
            "dm-directory",
            0,
            ORIGIN_A,
            Some("Alice"),
            Some(USER_A),
            Some(&peer),
            None,
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        db.upsert_directory_conversation(
            "dm-directory",
            0,
            ORIGIN_A,
            Some("Alice renamed"),
            Some(USER_A),
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
                ORIGIN_A,
                Some("Mallory"),
                Some(USER_A),
                Some(&[5u8; 32]),
                None,
                "2026-01-01T00:00:00Z",
            )
            .is_err());
        assert!(db
            .upsert_directory_conversation(
                "dm-directory",
                1,
                ORIGIN_A,
                Some("type swap"),
                None,
                None,
                None,
                "2026-01-01T00:00:00Z",
            )
            .is_err());
    }

    #[test]
    fn authenticated_channel_page_is_atomic_and_origin_scoped() {
        let db = VeilDb::open_memory(&[0xBA; 32]).unwrap();
        let server_id = "00000000-0000-0000-0000-0000000000d3";
        let first = "00000000-0000-0000-0000-0000000000c4";
        let conflicting = "00000000-0000-0000-0000-0000000000c5";
        db.upsert_directory_conversation(
            conflicting,
            2,
            ORIGIN_B,
            Some("Existing beta channel"),
            None,
            None,
            Some(server_id),
            "2026-07-12T12:00:00Z",
        )
        .unwrap();

        assert!(db
            .upsert_directory_channels(
                ORIGIN_A,
                server_id,
                &[
                    (
                        first.to_string(),
                        "Alpha general".to_string(),
                        "2026-07-12T12:01:00Z".to_string(),
                    ),
                    (
                        conflicting.to_string(),
                        "Substituted channel".to_string(),
                        "2026-07-12T12:02:00Z".to_string(),
                    ),
                ],
            )
            .is_err());
        let conversations = db.get_conversations().unwrap();
        assert!(!conversations
            .iter()
            .any(|conversation| conversation.id == first));
        let retained = conversations
            .iter()
            .find(|conversation| conversation.id == conflicting)
            .unwrap();
        assert_eq!(retained.server_origin.as_deref(), Some(ORIGIN_B));
        assert_eq!(retained.name.as_deref(), Some("Existing beta channel"));

        db.upsert_directory_channels(
            ORIGIN_A,
            server_id,
            &[(
                first.to_string(),
                "Alpha general".to_string(),
                "2026-07-12T12:01:00Z".to_string(),
            )],
        )
        .unwrap();
        assert_eq!(
            db.list_origin_scoped_channel_conversation_ids(ORIGIN_A, server_id)
                .unwrap(),
            vec![first.to_string()]
        );
    }

    #[test]
    fn origin_scoped_channel_lookup_isolates_same_server_uuid_and_excludes_originless_rows() {
        let db = VeilDb::open_memory(&[0xB8; 32]).unwrap();
        let server_id = "00000000-0000-0000-0000-0000000000d1";
        let channel_a = "00000000-0000-0000-0000-0000000000c1";
        let channel_b = "00000000-0000-0000-0000-0000000000c2";
        let originless_channel = "00000000-0000-0000-0000-0000000000c3";

        for (conversation_id, origin, name) in [
            (channel_a, ORIGIN_A, "Alpha channel"),
            (channel_b, ORIGIN_B, "Beta channel"),
        ] {
            db.upsert_directory_conversation(
                conversation_id,
                2,
                origin,
                Some(name),
                None,
                None,
                Some(server_id),
                "2026-07-12T12:00:00Z",
            )
            .unwrap();
        }
        db.insert_conversation(
            originless_channel,
            2,
            Some("Originless legacy channel"),
            None,
            Some(server_id),
        )
        .unwrap();

        assert_eq!(
            db.list_origin_scoped_channel_conversation_ids(ORIGIN_A, server_id)
                .unwrap(),
            vec![channel_a.to_string()]
        );
        assert_eq!(
            db.list_origin_scoped_channel_conversation_ids(ORIGIN_B, server_id)
                .unwrap(),
            vec![channel_b.to_string()]
        );
        assert!(!db
            .list_origin_scoped_channel_conversation_ids(ORIGIN_A, server_id)
            .unwrap()
            .iter()
            .any(|conversation_id| conversation_id == originless_channel));
    }

    #[test]
    fn origin_scoped_channel_lookup_validates_inputs_and_persisted_ids() {
        let db = VeilDb::open_memory(&[0xB9; 32]).unwrap();
        let server_id = "00000000-0000-0000-0000-0000000000d2";

        assert!(db
            .list_origin_scoped_channel_conversation_ids("https://Alpha.example:443", server_id)
            .is_err());
        assert!(db
            .list_origin_scoped_channel_conversation_ids(
                ORIGIN_A,
                "00000000-0000-0000-0000-000000000000",
            )
            .is_err());

        db.conn
            .execute(
                "INSERT INTO conversations
                    (id, conv_type, server_id, server_origin, name)
                 VALUES ('not-a-canonical-uuid', 2, ?1, ?2, 'Corrupt channel')",
                rusqlite::params![server_id, ORIGIN_A],
            )
            .unwrap();
        assert!(db
            .list_origin_scoped_channel_conversation_ids(ORIGIN_A, server_id)
            .is_err());
    }

    #[test]
    fn identity_directory_scopes_the_same_user_uuid_by_origin() {
        let db = VeilDb::open_memory(&[0xB1; 32]).unwrap();
        let alpha = sample_account(
            ORIGIN_A,
            USER_A,
            0x11,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        let beta = sample_account(
            ORIGIN_B,
            USER_A,
            0x22,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        db.upsert_identity_directory(&[alpha.clone(), beta.clone()])
            .unwrap();

        assert_eq!(
            db.resolve_account_snapshot(&alpha.locator).unwrap(),
            Some(alpha)
        );
        assert_eq!(
            db.resolve_account_snapshot(&beta.locator).unwrap(),
            Some(beta)
        );
    }

    #[test]
    fn authenticated_self_binding_is_origin_scoped_and_immutable() {
        let db = VeilDb::open_memory(&[0xA1; 32]).unwrap();
        let identity_key = [0x11; 32];
        let signing_key = test_signing_key(0x12);

        db.bind_authenticated_self(ORIGIN_A, USER_A, &identity_key, &signing_key)
            .unwrap();
        db.bind_authenticated_self(ORIGIN_A, USER_A, &identity_key, &signing_key)
            .unwrap();
        db.bind_authenticated_self(ORIGIN_B, USER_B, &identity_key, &signing_key)
            .unwrap();

        assert!(db
            .bind_authenticated_self(ORIGIN_A, USER_B, &identity_key, &signing_key)
            .is_err());
        assert!(db
            .bind_authenticated_self(ORIGIN_A, USER_A, &[0x13; 32], &signing_key)
            .is_err());
        assert!(db
            .bind_authenticated_self(ORIGIN_A, USER_A, &identity_key, &[0x14; 32])
            .is_err());
        assert!(db
            .bind_authenticated_self(ORIGIN_A, USER_A, &[0u8; 32], &signing_key)
            .is_err());
        assert!(db
            .bind_authenticated_self(ORIGIN_A, USER_A, &identity_key, &identity_key)
            .is_err());
    }

    #[test]
    fn authenticated_self_binding_survives_file_restart() {
        let path = std::env::temp_dir().join(format!(
            "veil-authenticated-self-binding-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db_key = [0xA2; 32];
        let identity_key = [0x21; 32];
        let signing_key = test_signing_key(0x22);
        {
            let db = VeilDb::open(&path, &db_key).unwrap();
            db.bind_authenticated_self(ORIGIN_A, USER_A, &identity_key, &signing_key)
                .unwrap();
        }
        {
            let reopened = VeilDb::open(&path, &db_key).unwrap();
            reopened
                .bind_authenticated_self(ORIGIN_A, USER_A, &identity_key, &signing_key)
                .unwrap();
            assert!(reopened
                .bind_authenticated_self(ORIGIN_A, USER_B, &identity_key, &signing_key)
                .is_err());
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn mobile_reconnect_target_requires_explicit_atomic_mobile_selection() {
        let db = VeilDb::open_memory(&[0xA6; 32]).unwrap();
        let identity_key = [0x23; 32];
        let signing_key = test_signing_key(0x24);

        db.bind_authenticated_self(ORIGIN_A, USER_A, &identity_key, &signing_key)
            .unwrap();
        assert_eq!(
            db.load_mobile_reconnect_target_v1(&identity_key, &signing_key)
                .unwrap(),
            None
        );

        db.bind_authenticated_self_and_select_mobile_reconnect_target_v1(
            ORIGIN_A,
            USER_A,
            &identity_key,
            &signing_key,
        )
        .unwrap();
        assert_eq!(
            db.load_mobile_reconnect_target_v1(&identity_key, &signing_key)
                .unwrap(),
            Some(MobileReconnectTargetV1 {
                canonical_server_origin: ORIGIN_A.to_string(),
                expected_user_id: USER_A.to_string(),
            })
        );
        assert!(db
            .load_mobile_reconnect_target_v1(&[0x25; 32], &signing_key)
            .is_err());

        db.bind_authenticated_self_and_select_mobile_reconnect_target_v1(
            ORIGIN_B,
            USER_B,
            &identity_key,
            &signing_key,
        )
        .unwrap();
        assert_eq!(
            db.load_mobile_reconnect_target_v1(&identity_key, &signing_key)
                .unwrap(),
            Some(MobileReconnectTargetV1 {
                canonical_server_origin: ORIGIN_B.to_string(),
                expected_user_id: USER_B.to_string(),
            })
        );
    }

    #[test]
    fn mobile_reconnect_target_migration_never_guesses_from_legacy_self_bindings() {
        let path = std::env::temp_dir().join(format!(
            "veil-mobile-reconnect-legacy-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db_key = [0xAC; 32];
        let identity_key = [0x2E; 32];
        let signing_key = test_signing_key(0x2F);
        {
            let db = VeilDb::open(&path, &db_key).unwrap();
            db.bind_authenticated_self(ORIGIN_A, USER_A, &identity_key, &signing_key)
                .unwrap();
            db.conn
                .execute_batch("DROP TABLE mobile_reconnect_target_v1;")
                .unwrap();
        }
        {
            let migrated = VeilDb::open(&path, &db_key).unwrap();
            assert_eq!(
                migrated
                    .load_mobile_reconnect_target_v1(&identity_key, &signing_key)
                    .unwrap(),
                None
            );
            let retained_bindings: i64 = migrated
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM authenticated_self_bindings_v1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(retained_bindings, 1);
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn mobile_reconnect_target_selection_rolls_back_on_account_remap() {
        let db = VeilDb::open_memory(&[0xA7; 32]).unwrap();
        let identity_key = [0x26; 32];
        let signing_key = test_signing_key(0x27);
        db.bind_authenticated_self(ORIGIN_A, USER_A, &identity_key, &signing_key)
            .unwrap();
        db.bind_authenticated_self_and_select_mobile_reconnect_target_v1(
            ORIGIN_B,
            USER_B,
            &identity_key,
            &signing_key,
        )
        .unwrap();

        assert!(db
            .bind_authenticated_self_and_select_mobile_reconnect_target_v1(
                ORIGIN_A,
                USER_B,
                &identity_key,
                &signing_key,
            )
            .is_err());
        assert_eq!(
            db.load_mobile_reconnect_target_v1(&identity_key, &signing_key)
                .unwrap(),
            Some(MobileReconnectTargetV1 {
                canonical_server_origin: ORIGIN_B.to_string(),
                expected_user_id: USER_B.to_string(),
            })
        );
    }

    #[test]
    fn mobile_reconnect_target_write_failures_roll_back_self_binding_and_selection() {
        let identity_key = [0x2C; 32];
        let signing_key = test_signing_key(0x2D);
        let insert_failure = VeilDb::open_memory(&[0xAA; 32]).unwrap();
        insert_failure
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_mobile_target_insert
                 BEFORE INSERT ON mobile_reconnect_target_v1
                 BEGIN
                    SELECT RAISE(ABORT, 'injected target insert failure');
                 END;",
            )
            .unwrap();
        assert!(insert_failure
            .bind_authenticated_self_and_select_mobile_reconnect_target_v1(
                ORIGIN_A,
                USER_A,
                &identity_key,
                &signing_key,
            )
            .is_err());
        let inserted_bindings: i64 = insert_failure
            .conn
            .query_row(
                "SELECT COUNT(*) FROM authenticated_self_bindings_v1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(inserted_bindings, 0);

        let update_failure = VeilDb::open_memory(&[0xAB; 32]).unwrap();
        update_failure
            .bind_authenticated_self_and_select_mobile_reconnect_target_v1(
                ORIGIN_A,
                USER_A,
                &identity_key,
                &signing_key,
            )
            .unwrap();
        update_failure
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_mobile_target_update
                 BEFORE UPDATE ON mobile_reconnect_target_v1
                 BEGIN
                    SELECT RAISE(ABORT, 'injected target update failure');
                 END;",
            )
            .unwrap();
        assert!(update_failure
            .bind_authenticated_self_and_select_mobile_reconnect_target_v1(
                ORIGIN_B,
                USER_B,
                &identity_key,
                &signing_key,
            )
            .is_err());
        assert!(
            load_authenticated_self_binding(&update_failure.conn, ORIGIN_B)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            update_failure
                .load_mobile_reconnect_target_v1(&identity_key, &signing_key)
                .unwrap(),
            Some(MobileReconnectTargetV1 {
                canonical_server_origin: ORIGIN_A.to_string(),
                expected_user_id: USER_A.to_string(),
            })
        );
    }

    #[test]
    fn mobile_reconnect_target_survives_repeated_file_restarts() {
        let path = std::env::temp_dir().join(format!(
            "veil-mobile-reconnect-target-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db_key = [0xA8; 32];
        let identity_key = [0x28; 32];
        let signing_key = test_signing_key(0x29);
        {
            let db = VeilDb::open(&path, &db_key).unwrap();
            db.bind_authenticated_self_and_select_mobile_reconnect_target_v1(
                ORIGIN_A,
                USER_A,
                &identity_key,
                &signing_key,
            )
            .unwrap();
        }
        {
            let reopened = VeilDb::open(&path, &db_key).unwrap();
            assert_eq!(
                reopened
                    .load_mobile_reconnect_target_v1(&identity_key, &signing_key)
                    .unwrap(),
                Some(MobileReconnectTargetV1 {
                    canonical_server_origin: ORIGIN_A.to_string(),
                    expected_user_id: USER_A.to_string(),
                })
            );
        }
        {
            let reopened = VeilDb::open(&path, &db_key).unwrap();
            assert_eq!(
                reopened
                    .load_mobile_reconnect_target_v1(&identity_key, &signing_key)
                    .unwrap(),
                Some(MobileReconnectTargetV1 {
                    canonical_server_origin: ORIGIN_A.to_string(),
                    expected_user_id: USER_A.to_string(),
                })
            );
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn mobile_reconnect_target_fails_closed_when_its_self_binding_is_missing() {
        let db = VeilDb::open_memory(&[0xA9; 32]).unwrap();
        let identity_key = [0x2A; 32];
        let signing_key = test_signing_key(0x2B);
        db.bind_authenticated_self_and_select_mobile_reconnect_target_v1(
            ORIGIN_A,
            USER_A,
            &identity_key,
            &signing_key,
        )
        .unwrap();
        db.conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        db.conn
            .execute(
                "DELETE FROM authenticated_self_bindings_v1
                 WHERE canonical_server_origin = ?1",
                rusqlite::params![ORIGIN_A],
            )
            .unwrap();
        db.conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();

        assert!(db
            .load_mobile_reconnect_target_v1(&identity_key, &signing_key)
            .is_err());
    }

    #[test]
    fn mobile_reconnect_target_fails_closed_on_an_invalid_singleton_row() {
        let db = VeilDb::open_memory(&[0xAD; 32]).unwrap();
        let identity_key = [0x30; 32];
        let signing_key = test_signing_key(0x31);
        db.bind_authenticated_self(ORIGIN_A, USER_A, &identity_key, &signing_key)
            .unwrap();
        db.conn
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO mobile_reconnect_target_v1
                    (singleton, canonical_server_origin)
                 VALUES (2, ?1)",
                rusqlite::params![ORIGIN_A],
            )
            .unwrap();
        db.conn
            .execute_batch("PRAGMA ignore_check_constraints = OFF;")
            .unwrap();

        assert!(db
            .load_mobile_reconnect_target_v1(&identity_key, &signing_key)
            .is_err());
    }

    #[test]
    fn authenticated_self_binding_rejects_upgrade_poisoning_before_insert() {
        let db = VeilDb::open_memory(&[0xA3; 32]).unwrap();
        let persisted_self = sample_account(
            ORIGIN_A,
            USER_A,
            0x31,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        db.upsert_identity_directory(std::slice::from_ref(&persisted_self))
            .unwrap();

        assert!(db
            .bind_authenticated_self(
                ORIGIN_A,
                USER_B,
                &persisted_self.locator.identity_key,
                &persisted_self.signing_key,
            )
            .is_err());
        db.bind_authenticated_self(
            ORIGIN_A,
            USER_A,
            &persisted_self.locator.identity_key,
            &persisted_self.signing_key,
        )
        .unwrap();

        let stored_user: String = db
            .conn
            .query_row(
                "SELECT user_id FROM authenticated_self_bindings_v1
                 WHERE canonical_server_origin = ?1",
                rusqlite::params![ORIGIN_A],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_user, USER_A);
    }

    #[test]
    fn authenticated_self_binding_rejects_later_directory_poisoning_atomically() {
        let db = VeilDb::open_memory(&[0xA4; 32]).unwrap();
        let self_account = sample_account(
            ORIGIN_A,
            USER_A,
            0x36,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        db.bind_authenticated_self(
            ORIGIN_A,
            USER_A,
            &self_account.locator.identity_key,
            &self_account.signing_key,
        )
        .unwrap();

        let unrelated = sample_account(
            ORIGIN_A,
            USER_B,
            0x37,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        let mut substituted_self = self_account.clone();
        substituted_self.locator.identity_key = [0x38; 32];
        substituted_self.signing_key = test_signing_key(0x39);
        assert!(db
            .upsert_identity_directory(&[unrelated.clone(), substituted_self])
            .is_err());
        assert!(db
            .resolve_account_snapshot(&unrelated.locator)
            .unwrap()
            .is_none());

        let mut identity_alias = sample_account(
            ORIGIN_A,
            USER_B,
            0x3A,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        identity_alias.locator.identity_key = self_account.locator.identity_key;
        assert!(db.upsert_identity_directory(&[identity_alias]).is_err());

        let mut signing_alias = sample_account(
            ORIGIN_A,
            USER_B,
            0x3B,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        signing_alias.signing_key = self_account.signing_key;
        assert!(db.upsert_identity_directory(&[signing_alias]).is_err());
        assert_eq!(
            db.identity_change_users_for_origin(ORIGIN_A).unwrap(),
            vec![USER_A.to_string()]
        );
        assert!(db
            .resolve_account_by_origin_user(ORIGIN_A, USER_B)
            .unwrap()
            .is_none());

        db.upsert_identity_directory(&[unrelated.clone(), self_account.clone()])
            .unwrap();
        assert_eq!(
            db.resolve_account_snapshot(&self_account.locator).unwrap(),
            Some(self_account)
        );
        assert_eq!(
            db.resolve_account_snapshot(&unrelated.locator).unwrap(),
            Some(unrelated)
        );

        let other_origin = sample_account(
            ORIGIN_B,
            USER_A,
            0x3C,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        db.upsert_identity_directory(std::slice::from_ref(&other_origin))
            .unwrap();
        assert_eq!(
            db.resolve_account_snapshot(&other_origin.locator).unwrap(),
            Some(other_origin)
        );
    }

    #[test]
    fn authenticated_self_reconnect_revalidates_the_persisted_directory() {
        let db = VeilDb::open_memory(&[0xA5; 32]).unwrap();
        let identity_key = [0x41; 32];
        let signing_key = test_signing_key(0x42);
        db.bind_authenticated_self(ORIGIN_A, USER_A, &identity_key, &signing_key)
            .unwrap();
        let poisoned_identity_key = [0x43u8; 32];
        let poisoned_signing_key = test_signing_key(0x44);

        db.conn
            .execute(
                "INSERT INTO identity_directory_v1
                    (canonical_server_origin, user_id, identity_key, signing_key,
                     username, display_name, profile_version, profile_origin,
                     source, observed_at)
                 VALUES (?1, ?2, ?3, ?4, 'poisoned', NULL, NULL, ?1, 2,
                         '2026-07-12T12:00:00Z')",
                rusqlite::params![
                    ORIGIN_A,
                    USER_A,
                    poisoned_identity_key.as_slice(),
                    poisoned_signing_key.as_slice()
                ],
            )
            .unwrap();

        assert!(db
            .bind_authenticated_self(ORIGIN_A, USER_A, &identity_key, &signing_key)
            .is_err());
    }

    #[test]
    fn identity_directory_substitution_or_alias_rolls_back_the_whole_batch() {
        let db = VeilDb::open_memory(&[0xB2; 32]).unwrap();
        let original = sample_account(
            ORIGIN_A,
            USER_A,
            0x31,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        db.upsert_identity_directory(std::slice::from_ref(&original))
            .unwrap();

        let unrelated = sample_account(
            ORIGIN_A,
            USER_B,
            0x32,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        let mut substituted = original.clone();
        substituted.locator.identity_key = [0x33; 32];
        substituted.signing_key = test_signing_key(0x34);
        assert!(db
            .upsert_identity_directory(&[unrelated.clone(), substituted])
            .is_err());
        assert!(db
            .resolve_account_snapshot(&unrelated.locator)
            .unwrap()
            .is_none());
        assert_eq!(
            db.resolve_account_snapshot(&original.locator).unwrap(),
            Some(original.clone())
        );
        assert_eq!(
            db.local_identity_verification(&original.locator).unwrap(),
            LocalIdentityVerification::IdentityChanged
        );

        let mut signing_substitution = original.clone();
        signing_substitution.signing_key = test_signing_key(0x35);
        assert!(db
            .upsert_identity_directory(&[signing_substitution])
            .is_err());

        let mut aliased = original.clone();
        aliased.locator.user_id = USER_B.to_string();
        assert!(db.upsert_identity_directory(&[aliased]).is_err());
        assert_eq!(
            db.resolve_account_snapshot(&original.locator).unwrap(),
            Some(original)
        );
    }

    #[test]
    fn identity_directory_signing_key_is_unique_per_origin_and_batch_atomic() {
        let db = VeilDb::open_memory(&[0xB8; 32]).unwrap();
        let original = sample_account(
            ORIGIN_A,
            USER_A,
            0x3D,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        let mut signing_alias = sample_account(
            ORIGIN_A,
            USER_B,
            0x3E,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        signing_alias.signing_key = original.signing_key;

        assert!(db
            .upsert_identity_directory(&[original.clone(), signing_alias.clone()])
            .is_err());
        assert!(db
            .resolve_account_snapshot(&original.locator)
            .unwrap()
            .is_none());
        assert!(db
            .resolve_account_snapshot(&signing_alias.locator)
            .unwrap()
            .is_none());
        assert!(db
            .identity_change_users_for_origin(ORIGIN_A)
            .unwrap()
            .is_empty());

        db.upsert_identity_directory(std::slice::from_ref(&original))
            .unwrap();
        db.upsert_identity_directory(std::slice::from_ref(&original))
            .unwrap();
        assert!(db
            .upsert_identity_directory(std::slice::from_ref(&signing_alias))
            .is_err());
        assert_eq!(
            db.identity_change_users_for_origin(ORIGIN_A).unwrap(),
            vec![USER_A.to_string()]
        );

        let mut cross_origin = signing_alias;
        cross_origin.locator.canonical_server_origin = ORIGIN_B.to_string();
        cross_origin.profile_origin = ORIGIN_B.to_string();
        db.upsert_identity_directory(std::slice::from_ref(&cross_origin))
            .unwrap();
        assert_eq!(
            db.resolve_account_snapshot(&cross_origin.locator).unwrap(),
            Some(cross_origin)
        );
    }

    #[test]
    fn identity_directory_signing_alias_is_rejected_after_restart() {
        let path = std::env::temp_dir().join(format!(
            "veil-identity-signing-alias-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db_key = [0xB9; 32];
        let original = sample_account(
            ORIGIN_A,
            USER_A,
            0x3F,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        {
            let db = VeilDb::open(&path, &db_key).unwrap();
            db.upsert_identity_directory(std::slice::from_ref(&original))
                .unwrap();
        }
        {
            let reopened = VeilDb::open(&path, &db_key).unwrap();
            let mut signing_alias = sample_account(
                ORIGIN_A,
                USER_B,
                0x40,
                AccountSnapshotSource::AuthenticatedConversationDirectory,
                None,
            );
            signing_alias.signing_key = original.signing_key;
            assert!(reopened
                .upsert_identity_directory(std::slice::from_ref(&signing_alias))
                .is_err());
            assert_eq!(
                reopened
                    .resolve_account_snapshot(&original.locator)
                    .unwrap(),
                Some(original.clone())
            );
        }
        {
            let reopened = VeilDb::open(&path, &db_key).unwrap();
            assert_eq!(
                reopened.identity_change_users_for_origin(ORIGIN_A).unwrap(),
                vec![USER_A.to_string()]
            );
            assert_eq!(
                reopened
                    .local_identity_verification(&original.locator)
                    .unwrap(),
                LocalIdentityVerification::IdentityChanged
            );
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn historical_account_candidate_alarm_is_durable_and_never_promotes_the_candidate() {
        let path = std::env::temp_dir().join(format!(
            "veil-historical-account-candidate-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db_key = [0xBA; 32];
        let original = sample_account(
            ORIGIN_A,
            USER_A,
            0x45,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        {
            let db = VeilDb::open(&path, &db_key).unwrap();
            db.upsert_identity_directory(std::slice::from_ref(&original))
                .unwrap();
            assert_eq!(
                db.observe_historical_account_candidate(
                    ORIGIN_A,
                    USER_A,
                    &original.locator.identity_key,
                    &original.signing_key,
                    "2026-07-13T12:10:00Z",
                )
                .unwrap(),
                HistoricalAccountContinuity::Compatible
            );
            let mut unpinned_weak_signing = [0u8; 32];
            unpinned_weak_signing[0] = 1;
            assert_eq!(
                db.observe_historical_account_candidate(
                    ORIGIN_A,
                    USER_B,
                    &[0x46; 32],
                    &unpinned_weak_signing,
                    "2026-07-13T12:11:00Z",
                )
                .unwrap(),
                HistoricalAccountContinuity::NoBaseline
            );
            assert!(db
                .identity_change_users_for_origin(ORIGIN_A)
                .unwrap()
                .is_empty());

            let mut weak_changed_signing = [0u8; 32];
            weak_changed_signing[0] = 1;
            assert_eq!(
                db.observe_historical_account_candidate(
                    ORIGIN_A,
                    USER_A,
                    &original.locator.identity_key,
                    &weak_changed_signing,
                    "2026-07-13T12:12:00Z",
                )
                .unwrap(),
                HistoricalAccountContinuity::IdentityChanged(vec![USER_A.to_string()])
            );
            assert_eq!(
                db.resolve_account_snapshot(&original.locator).unwrap(),
                Some(original.clone())
            );
            assert_eq!(
                db.local_identity_verification(&original.locator).unwrap(),
                LocalIdentityVerification::IdentityChanged
            );
        }
        {
            let reopened = VeilDb::open(&path, &db_key).unwrap();
            assert_eq!(
                reopened
                    .local_identity_verification(&original.locator)
                    .unwrap(),
                LocalIdentityVerification::IdentityChanged
            );
            assert_eq!(
                reopened
                    .resolve_account_snapshot(&original.locator)
                    .unwrap(),
                Some(original)
            );
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn historical_account_candidate_alarms_cross_user_and_self_alias_owners() {
        let original = sample_account(
            ORIGIN_A,
            USER_A,
            0x47,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );

        let identity_alias_db = VeilDb::open_memory(&[0xBB; 32]).unwrap();
        identity_alias_db
            .upsert_identity_directory(std::slice::from_ref(&original))
            .unwrap();
        assert_eq!(
            identity_alias_db
                .observe_historical_account_candidate(
                    ORIGIN_A,
                    USER_B,
                    &original.locator.identity_key,
                    &original.signing_key,
                    "2026-07-13T12:13:00Z",
                )
                .unwrap(),
            HistoricalAccountContinuity::IdentityChanged(vec![USER_A.to_string()])
        );
        assert!(identity_alias_db
            .resolve_account_by_origin_user(ORIGIN_A, USER_B)
            .unwrap()
            .is_none());
        assert_eq!(
            identity_alias_db
                .identity_change_users_for_origin(ORIGIN_A)
                .unwrap(),
            vec![USER_A.to_string()]
        );

        let signing_alias_db = VeilDb::open_memory(&[0xBC; 32]).unwrap();
        signing_alias_db
            .upsert_identity_directory(std::slice::from_ref(&original))
            .unwrap();
        let signing_alias_identity = [0x49; 32];
        assert_eq!(
            signing_alias_db
                .observe_historical_account_candidate(
                    ORIGIN_A,
                    USER_B,
                    &signing_alias_identity,
                    &original.signing_key,
                    "2026-07-13T12:14:00Z",
                )
                .unwrap(),
            HistoricalAccountContinuity::IdentityChanged(vec![USER_A.to_string()])
        );
        assert!(signing_alias_db
            .resolve_account_by_origin_user(ORIGIN_A, USER_B)
            .unwrap()
            .is_none());

        let self_alias_db = VeilDb::open_memory(&[0xBD; 32]).unwrap();
        self_alias_db
            .bind_authenticated_self(
                ORIGIN_A,
                USER_A,
                &original.locator.identity_key,
                &original.signing_key,
            )
            .unwrap();
        assert_eq!(
            self_alias_db
                .observe_historical_account_candidate(
                    ORIGIN_A,
                    USER_A,
                    &original.locator.identity_key,
                    &original.signing_key,
                    "2026-07-13T12:15:00Z",
                )
                .unwrap(),
            HistoricalAccountContinuity::Compatible
        );
        assert_eq!(
            self_alias_db
                .observe_historical_account_candidate(
                    ORIGIN_A,
                    USER_B,
                    &original.locator.identity_key,
                    &original.signing_key,
                    "2026-07-13T12:16:00Z",
                )
                .unwrap(),
            HistoricalAccountContinuity::IdentityChanged(vec![USER_A.to_string()])
        );
        assert!(self_alias_db
            .resolve_account_by_origin_user(ORIGIN_A, USER_B)
            .unwrap()
            .is_none());
        assert_eq!(
            self_alias_db
                .identity_change_users_for_origin(ORIGIN_A)
                .unwrap(),
            vec![USER_A.to_string()]
        );
    }

    #[test]
    fn identity_directory_source_and_profile_versions_merge_fail_closed() {
        let db = VeilDb::open_memory(&[0xB3; 32]).unwrap();
        let mut historical = sample_account(
            ORIGIN_A,
            USER_A,
            0x41,
            AccountSnapshotSource::AuthenticatedHistory,
            None,
        );
        historical.display_name = Some("Historical".to_string());
        db.upsert_identity_directory(&[historical.clone()]).unwrap();

        let mut directory = historical.clone();
        directory.source = AccountSnapshotSource::AuthenticatedConversationDirectory;
        directory.display_name = Some("Directory".to_string());
        directory.observed_at = "2026-07-12T12:01:00Z".to_string();
        db.upsert_identity_directory(&[directory.clone()]).unwrap();

        let mut stale_history = historical;
        stale_history.display_name = Some("Stale history".to_string());
        stale_history.observed_at = "2026-07-12T12:02:00Z".to_string();
        db.upsert_identity_directory(&[stale_history]).unwrap();
        assert_eq!(
            db.resolve_account_snapshot(&directory.locator)
                .unwrap()
                .unwrap()
                .display_name
                .as_deref(),
            Some("Directory")
        );

        directory.profile_version = Some(2);
        directory.display_name = Some("Version two".to_string());
        db.upsert_identity_directory(&[directory.clone()]).unwrap();

        let mut rollback = directory.clone();
        rollback.profile_version = Some(1);
        assert!(db.upsert_identity_directory(&[rollback]).is_err());

        let mut equivocation = directory.clone();
        equivocation.display_name = Some("Different version two".to_string());
        assert!(db.upsert_identity_directory(&[equivocation]).is_err());

        let mut unversioned = directory.clone();
        unversioned.profile_version = None;
        unversioned.display_name = Some("Unversioned replacement".to_string());
        db.upsert_identity_directory(&[unversioned]).unwrap();
        assert_eq!(
            db.resolve_account_snapshot(&directory.locator)
                .unwrap()
                .unwrap()
                .display_name
                .as_deref(),
            Some("Version two")
        );

        let mut version_three = directory.clone();
        version_three.profile_version = Some(3);
        version_three.display_name = Some("Version three".to_string());
        db.upsert_identity_directory(&[version_three.clone()])
            .unwrap();
        assert_eq!(
            db.resolve_account_snapshot(&directory.locator)
                .unwrap()
                .unwrap(),
            version_three
        );
    }

    #[test]
    fn network_profile_requires_an_exact_directory_and_is_origin_scoped() {
        let db = VeilDb::open_memory(&[0xC1; 32]).unwrap();
        let alpha = sample_account(
            ORIGIN_A,
            USER_A,
            0x51,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            Some(1),
        );
        let beta = sample_account(
            ORIGIN_B,
            USER_A,
            0x52,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            Some(1),
        );
        let alpha_profile = sample_network_profile(&alpha, 1);
        assert!(db.upsert_network_profile(&alpha_profile).is_err());

        db.upsert_identity_directory(&[alpha.clone(), beta.clone()])
            .unwrap();
        let mut beta_profile = sample_network_profile(&beta, 1);
        beta_profile.display_name = Some("Beta account".to_string());
        db.upsert_network_profile(&alpha_profile).unwrap();
        db.upsert_network_profile(&beta_profile).unwrap();

        assert_eq!(
            db.load_network_profile(&alpha.locator).unwrap(),
            Some(alpha_profile)
        );
        assert_eq!(
            db.load_network_profile(&beta.locator).unwrap(),
            Some(beta_profile)
        );
    }

    #[test]
    fn network_profile_rejects_rollback_equivocation_and_unsafe_text() {
        let db = VeilDb::open_memory(&[0xC2; 32]).unwrap();
        let account = sample_account(
            ORIGIN_A,
            USER_A,
            0x53,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            Some(3),
        );
        db.upsert_identity_directory(std::slice::from_ref(&account))
            .unwrap();
        let mut current = sample_network_profile(&account, 3);
        current.about = "first line\nsecond line".to_string();
        current.avatar_asset_id = Some("550e8400-e29b-41d4-a716-446655440000".to_string());
        current.avatar_digest = Some([0xA5; 32]);
        current.avatar_content_type = Some("image/jpeg".to_string());
        db.upsert_network_profile(&current).unwrap();

        let mut rollback = current.clone();
        rollback.profile_version = 2;
        assert!(db.upsert_network_profile(&rollback).is_err());

        let mut equivocation = current.clone();
        equivocation.about = "changed at the same revision".to_string();
        assert!(db.upsert_network_profile(&equivocation).is_err());

        let mut avatar_equivocation = current.clone();
        avatar_equivocation.avatar_digest = Some([0xA6; 32]);
        assert!(db.upsert_network_profile(&avatar_equivocation).is_err());

        let mut incomplete_avatar = current.clone();
        incomplete_avatar.profile_version = 4;
        incomplete_avatar.avatar_digest = None;
        assert!(db.upsert_network_profile(&incomplete_avatar).is_err());

        let mut bidi = current.clone();
        bidi.profile_version = 4;
        bidi.about = "safe\u{202e}evil".to_string();
        assert!(db.upsert_network_profile(&bidi).is_err());
        for unsafe_character in [
            '\u{00ad}', '\u{034f}', '\u{180e}', '\u{200b}', '\u{2028}', '\u{2029}', '\u{2060}',
            '\u{feff}',
        ] {
            let mut spoofing = current.clone();
            spoofing.profile_version = 4;
            spoofing.display_name = Some(format!("safe{unsafe_character}hidden"));
            assert!(db.upsert_network_profile(&spoofing).is_err());
        }
        assert_eq!(
            db.load_network_profile(&account.locator).unwrap(),
            Some(current)
        );
    }

    #[test]
    fn authenticated_network_profile_bootstraps_fresh_self_atomically() {
        let db = VeilDb::open_memory(&[0xC5; 32]).unwrap();
        let account = sample_account(
            ORIGIN_A,
            USER_A,
            0x57,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            Some(1),
        );
        let profile = sample_network_profile(&account, 1);
        assert!(db
            .upsert_authenticated_network_profile(&profile, account.signing_key)
            .is_err());
        assert!(db
            .resolve_account_snapshot(&account.locator)
            .unwrap()
            .is_none());
        db.bind_authenticated_self(
            ORIGIN_A,
            USER_A,
            &account.locator.identity_key,
            &account.signing_key,
        )
        .unwrap();

        db.upsert_authenticated_network_profile(&profile, account.signing_key)
            .unwrap();
        assert_eq!(
            db.load_network_profile(&account.locator).unwrap(),
            Some(profile.clone())
        );
        assert_eq!(
            db.resolve_account_snapshot(&account.locator)
                .unwrap()
                .unwrap()
                .signing_key,
            account.signing_key
        );

        let conflicting_signing_key = test_signing_key(0x59);
        let mut advanced = profile.clone();
        advanced.profile_version = 2;
        advanced.display_name = Some("Must roll back".to_string());
        assert!(db
            .upsert_authenticated_network_profile(&advanced, conflicting_signing_key)
            .is_err());
        assert_eq!(
            db.load_network_profile(&account.locator).unwrap(),
            Some(profile)
        );
    }

    #[test]
    fn authenticated_profile_cache_survives_restart_and_rejects_cross_origin_reads() {
        let path = std::env::temp_dir().join(format!(
            "veil-network-profile-cache-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db_key = [0xC7; 32];
        let account = sample_account(
            ORIGIN_A,
            USER_A,
            0x61,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            Some(2),
        );
        let mut profile = sample_network_profile(&account, 2);
        profile.display_name = Some("Restart cache".to_string());
        {
            let db = VeilDb::open(&path, &db_key).unwrap();
            db.bind_authenticated_self(
                ORIGIN_A,
                USER_A,
                &account.locator.identity_key,
                &account.signing_key,
            )
            .unwrap();
            db.upsert_authenticated_network_profile(&profile, account.signing_key)
                .unwrap();
        }
        {
            let db = VeilDb::open(&path, &db_key).unwrap();
            assert_eq!(
                db.load_network_profile_for_authenticated_account(
                    ORIGIN_A,
                    USER_A,
                    &account.locator.identity_key,
                    &account.signing_key,
                    &account.locator,
                )
                .unwrap(),
                Some(profile.clone())
            );
            assert!(db
                .load_network_profile_for_authenticated_account(
                    ORIGIN_B,
                    USER_A,
                    &account.locator.identity_key,
                    &account.signing_key,
                    &account.locator,
                )
                .is_err());
            assert!(db
                .load_network_profile_for_authenticated_account(
                    ORIGIN_A,
                    USER_A,
                    &[0x62; 32],
                    &account.signing_key,
                    &account.locator,
                )
                .is_err());
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn local_verification_v2_detects_signing_change_after_restart() {
        let path = std::env::temp_dir().join(format!(
            "veil-local-identity-verification-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db_key = [0xC3; 32];
        let self_account = sample_account(
            ORIGIN_A,
            USER_B,
            0x53,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        let account = sample_account(
            ORIGIN_A,
            USER_A,
            0x54,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        let mut changed_account = account.clone();
        changed_account.signing_key = test_signing_key(0x56);
        changed_account.source = AccountSnapshotSource::AuthenticatedHistory;
        changed_account.observed_at = "2026-07-13T02:11:00Z".to_string();
        {
            let db = VeilDb::open(&path, &db_key).unwrap();
            db.bind_authenticated_self(
                ORIGIN_A,
                USER_B,
                &self_account.locator.identity_key,
                &self_account.signing_key,
            )
            .unwrap();
            db.upsert_identity_directory(&[self_account.clone(), account.clone()])
                .unwrap();
            assert_eq!(
                db.local_identity_verification(&account.locator).unwrap(),
                LocalIdentityVerification::NotCompared
            );
            db.mark_account_verified_v2(&account.locator, "2026-07-13T02:10:00Z")
                .unwrap();
            assert_eq!(
                db.local_identity_verification(&account.locator).unwrap(),
                LocalIdentityVerification::VerifiedOnThisDevice
            );
            assert!(db
                .upsert_identity_directory(std::slice::from_ref(&changed_account))
                .is_err());
        }
        {
            let db = VeilDb::open(&path, &db_key).unwrap();
            assert_eq!(
                db.local_identity_verification(&account.locator).unwrap(),
                LocalIdentityVerification::IdentityChanged
            );
            assert_eq!(
                db.local_identity_verification_for_unlocked_account(
                    &self_account.locator.identity_key,
                    &self_account.signing_key,
                    &account.locator,
                )
                .unwrap(),
                LocalIdentityVerification::IdentityChanged
            );
            assert_eq!(
                db.local_identity_verification(&changed_account.locator)
                    .unwrap(),
                LocalIdentityVerification::IdentityChanged
            );
            assert_eq!(
                db.resolve_account_snapshot(&account.locator).unwrap(),
                Some(account.clone())
            );
            assert_eq!(
                db.resolve_account_snapshot(&changed_account.locator)
                    .unwrap(),
                Some(account.clone())
            );
            assert!(db
                .mark_account_verified_v2(&account.locator, "2026-07-13T02:12:00Z")
                .is_err());
            let other_origin = ProfileLocator {
                canonical_server_origin: ORIGIN_B.to_string(),
                ..changed_account.locator.clone()
            };
            assert_eq!(
                db.local_identity_verification(&other_origin).unwrap(),
                LocalIdentityVerification::NotCompared
            );
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn offline_proof_reports_durable_origin_user_key_mismatch_without_seeding_it() {
        let db = VeilDb::open_memory(&[0xC4; 32]).unwrap();
        let self_a = sample_account(
            ORIGIN_A,
            USER_B,
            0x63,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        let mut self_b = self_a.clone();
        self_b.locator.canonical_server_origin = ORIGIN_B.to_string();
        self_b.profile_origin = ORIGIN_B.to_string();
        let peer_a = sample_account(
            ORIGIN_A,
            USER_A,
            0x64,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        db.bind_authenticated_self(
            ORIGIN_A,
            USER_B,
            &self_a.locator.identity_key,
            &self_a.signing_key,
        )
        .unwrap();
        db.bind_authenticated_self(
            ORIGIN_B,
            USER_B,
            &self_b.locator.identity_key,
            &self_b.signing_key,
        )
        .unwrap();
        db.upsert_identity_directory(&[self_a.clone(), self_b, peer_a.clone()])
            .unwrap();

        assert_eq!(
            db.local_identity_verification_for_unlocked_account(
                &self_a.locator.identity_key,
                &self_a.signing_key,
                &peer_a.locator,
            )
            .unwrap(),
            LocalIdentityVerification::NotCompared
        );
        let changed_a = ProfileLocator {
            identity_key: [0x65; 32],
            ..peer_a.locator.clone()
        };
        assert_eq!(
            db.local_identity_verification_for_unlocked_account(
                &self_a.locator.identity_key,
                &self_a.signing_key,
                &changed_a,
            )
            .unwrap(),
            LocalIdentityVerification::IdentityChanged
        );
        assert!(db.resolve_account_snapshot(&changed_a).unwrap().is_none());

        let unknown = ProfileLocator {
            user_id: "550e8400-e29b-41d4-a716-446655440099".to_string(),
            identity_key: [0x66; 32],
            ..peer_a.locator.clone()
        };
        assert!(db
            .local_identity_verification_for_unlocked_account(
                &self_a.locator.identity_key,
                &self_a.signing_key,
                &unknown,
            )
            .is_err());

        let cross_origin = ProfileLocator {
            canonical_server_origin: ORIGIN_B.to_string(),
            ..changed_a
        };
        assert!(db
            .local_identity_verification_for_unlocked_account(
                &self_a.locator.identity_key,
                &self_a.signing_key,
                &cross_origin,
            )
            .is_err());
    }

    #[test]
    fn local_verification_rejects_the_authenticated_self_identity() {
        let db = VeilDb::open_memory(&[0xC4; 32]).unwrap();
        let account = sample_account(
            ORIGIN_A,
            USER_A,
            0x56,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        db.bind_authenticated_self(
            ORIGIN_A,
            USER_A,
            &account.locator.identity_key,
            &account.signing_key,
        )
        .unwrap();
        db.upsert_identity_directory(std::slice::from_ref(&account))
            .unwrap();
        assert!(db
            .mark_account_verified_v2(&account.locator, "2026-07-13T02:20:00Z")
            .is_err());
        assert_eq!(
            db.local_identity_verification(&account.locator).unwrap(),
            LocalIdentityVerification::NotCompared
        );
    }

    #[test]
    fn account_v2_verification_binds_signing_key_and_never_upgrades_v1() {
        let db = VeilDb::open_memory(&[0xC5; 32]).unwrap();
        let self_account = sample_account(
            ORIGIN_A,
            USER_B,
            0x73,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        let peer = sample_account(
            ORIGIN_A,
            USER_A,
            0x74,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        db.bind_authenticated_self(
            ORIGIN_A,
            USER_B,
            &self_account.locator.identity_key,
            &self_account.signing_key,
        )
        .unwrap();
        db.upsert_identity_directory(&[self_account, peer.clone()])
            .unwrap();

        db.conn
            .execute_batch(
                "CREATE TABLE local_identity_verifications_v1 (
                    canonical_server_origin TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    verified_identity_key BLOB NOT NULL,
                    verified_at TEXT NOT NULL,
                    PRIMARY KEY (canonical_server_origin, user_id)
                 );",
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO local_identity_verifications_v1
                    (canonical_server_origin, user_id, verified_identity_key, verified_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    ORIGIN_A,
                    USER_A,
                    peer.locator.identity_key.as_slice(),
                    "2026-07-13T02:30:00Z",
                ],
            )
            .unwrap();
        assert_eq!(
            db.local_identity_verification(&peer.locator).unwrap(),
            LocalIdentityVerification::NotCompared
        );

        db.mark_account_verified_v2(&peer.locator, "2026-07-13T02:31:00Z")
            .unwrap();
        assert_eq!(
            db.local_identity_verification(&peer.locator).unwrap(),
            LocalIdentityVerification::VerifiedOnThisDevice
        );
        let mut presentation_only = peer.clone();
        presentation_only.display_name = Some("Renamed presentation".to_string());
        presentation_only.observed_at = "2026-07-13T02:32:00Z".to_string();
        db.upsert_identity_directory(std::slice::from_ref(&presentation_only))
            .unwrap();
        assert_eq!(
            db.local_identity_verification(&peer.locator).unwrap(),
            LocalIdentityVerification::VerifiedOnThisDevice
        );

        let mut signing_change = peer.clone();
        signing_change.signing_key = test_signing_key(0x76);
        signing_change.observed_at = "2026-07-13T02:33:00Z".to_string();
        assert!(db
            .upsert_identity_directory(std::slice::from_ref(&signing_change))
            .is_err());
        assert_eq!(
            db.local_identity_verification(&peer.locator).unwrap(),
            LocalIdentityVerification::IdentityChanged
        );
        assert!(db
            .mark_account_verified_v2(&peer.locator, "2026-07-13T02:34:00Z")
            .is_err());
    }

    #[test]
    fn authoritative_conversation_keeps_conversation_and_peer_ids_distinct() {
        let db = VeilDb::open_memory(&[0xB4; 32]).unwrap();
        let conversation_id = "00000000-0000-0000-0000-0000000000c3";
        let peer_key = [0x51; 32];
        db.upsert_directory_conversation(
            conversation_id,
            0,
            ORIGIN_A,
            Some("Peer"),
            Some(USER_A),
            Some(&peer_key),
            None,
            "2026-07-12T12:00:00Z",
        )
        .unwrap();

        let stored = db.get_conversations().unwrap().remove(0);
        assert_eq!(stored.id, conversation_id);
        assert_eq!(stored.peer_user_id.as_deref(), Some(USER_A));
        assert_ne!(stored.id, stored.peer_user_id.unwrap());
        assert_eq!(stored.server_origin.as_deref(), Some(ORIGIN_A));

        assert!(db
            .upsert_directory_conversation(
                conversation_id,
                0,
                ORIGIN_B,
                Some("Cross-origin"),
                Some(USER_A),
                Some(&peer_key),
                None,
                "2026-07-12T12:00:00Z",
            )
            .is_err());
        assert!(db
            .upsert_directory_conversation(
                conversation_id,
                0,
                ORIGIN_A,
                Some("Different peer"),
                Some(USER_B),
                Some(&peer_key),
                None,
                "2026-07-12T12:00:00Z",
            )
            .is_err());
    }

    #[test]
    fn account_snapshot_validation_rejects_zero_keys_and_cross_origin_profiles() {
        let db = VeilDb::open_memory(&[0xB5; 32]).unwrap();
        let mut zero_identity = sample_account(
            ORIGIN_A,
            USER_A,
            0x61,
            AccountSnapshotSource::AuthenticatedHistory,
            None,
        );
        zero_identity.locator.identity_key = [0; 32];
        assert!(db.upsert_identity_directory(&[zero_identity]).is_err());

        let mut zero_signing = sample_account(
            ORIGIN_A,
            USER_A,
            0x62,
            AccountSnapshotSource::AuthenticatedHistory,
            None,
        );
        zero_signing.signing_key = [0; 32];
        assert!(db.upsert_identity_directory(&[zero_signing]).is_err());

        let mut low_order_signing = sample_account(
            ORIGIN_A,
            USER_A,
            0x64,
            AccountSnapshotSource::AuthenticatedHistory,
            None,
        );
        low_order_signing.signing_key = [0; 32];
        low_order_signing.signing_key[0] = 1;
        assert!(db
            .upsert_identity_directory(std::slice::from_ref(&low_order_signing))
            .is_err());
        assert!(db
            .bind_authenticated_self(
                ORIGIN_A,
                USER_A,
                &low_order_signing.locator.identity_key,
                &low_order_signing.signing_key,
            )
            .is_err());

        let mut cross_origin = sample_account(
            ORIGIN_A,
            USER_A,
            0x63,
            AccountSnapshotSource::AuthenticatedHistory,
            None,
        );
        cross_origin.profile_origin = ORIGIN_B.to_string();
        assert!(db.upsert_identity_directory(&[cross_origin]).is_err());
    }

    #[test]
    fn author_attach_requires_exact_sender_and_scoped_conversation() {
        let db = VeilDb::open_memory(&[0xB6; 32]).unwrap();
        let author = sample_account(
            ORIGIN_A,
            USER_A,
            0x71,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        db.insert_conversation(
            "legacy-author",
            0,
            None,
            Some(&author.locator.identity_key),
            None,
        )
        .unwrap();
        db.insert_message(
            "legacy-message",
            "legacy-author",
            &author.locator.identity_key,
            "legacy",
            false,
            Some(1),
            None,
        )
        .unwrap();
        assert!(db.attach_message_author("legacy-message", &author).is_err());
        assert!(db
            .resolve_account_snapshot(&author.locator)
            .unwrap()
            .is_none());
        assert!(db.get_messages("legacy-author", 10).unwrap()[0]
            .author
            .is_none());

        db.upsert_directory_conversation(
            "scoped-author",
            0,
            ORIGIN_A,
            Some("Peer"),
            Some(USER_A),
            Some(&author.locator.identity_key),
            None,
            "2026-07-12T12:00:00Z",
        )
        .unwrap();
        db.insert_message(
            "wrong-sender-message",
            "scoped-author",
            &[0x72; 32],
            "wrong sender",
            false,
            Some(2),
            None,
        )
        .unwrap();
        assert!(db
            .attach_message_author("wrong-sender-message", &author)
            .is_err());
        assert!(db
            .resolve_account_snapshot(&author.locator)
            .unwrap()
            .is_none());
    }

    #[test]
    fn message_author_context_is_separate_from_authority_and_immutable_per_message() {
        let db = VeilDb::open_memory(&[0xBC; 32]).unwrap();
        let directory_author = sample_account(
            ORIGIN_A,
            USER_A,
            0x75,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            Some(4),
        );
        db.upsert_identity_directory(std::slice::from_ref(&directory_author))
            .unwrap();
        db.upsert_directory_conversation(
            "author-context-conversation",
            1,
            ORIGIN_A,
            Some("Context group"),
            None,
            None,
            None,
            "2026-07-13T13:00:00Z",
        )
        .unwrap();

        db.insert_message(
            "former-author-message",
            "author-context-conversation",
            &directory_author.locator.identity_key,
            "restored history",
            false,
            Some(1),
            None,
        )
        .unwrap();
        db.attach_message_author_with_context(
            "former-author-message",
            &directory_author,
            MessageAuthorContext::FormerMemberAtObservation,
        )
        .unwrap();

        let former = db
            .get_messages("author-context-conversation", 10)
            .unwrap()
            .remove(0);
        assert_eq!(
            former.author.as_ref().map(|author| author.source),
            Some(AccountSnapshotSource::AuthenticatedConversationDirectory),
            "presentation authority must not be downgraded by history",
        );
        assert_eq!(
            former.author_context,
            Some(MessageAuthorContext::FormerMemberAtObservation),
        );

        // A later directory replay cannot rewrite the immutable provenance of
        // an already-committed historical message.
        db.attach_message_author_with_context(
            "former-author-message",
            &directory_author,
            MessageAuthorContext::DirectoryMemberAtObservation,
        )
        .unwrap();
        assert_eq!(
            db.get_messages("author-context-conversation", 10).unwrap()[0].author_context,
            Some(MessageAuthorContext::FormerMemberAtObservation),
        );

        // A new message observed after the account is present again receives
        // the current-directory context without rewriting the older message.
        db.insert_message(
            "rejoined-author-message",
            "author-context-conversation",
            &directory_author.locator.identity_key,
            "after rejoin",
            false,
            Some(2),
            None,
        )
        .unwrap();
        db.attach_message_author("rejoined-author-message", &directory_author)
            .unwrap();
        let messages = db.get_messages("author-context-conversation", 10).unwrap();
        assert_eq!(
            messages[0].author_context,
            Some(MessageAuthorContext::FormerMemberAtObservation)
        );
        assert_eq!(
            messages[1].author_context,
            Some(MessageAuthorContext::DirectoryMemberAtObservation)
        );
    }

    #[test]
    fn author_snapshot_survives_a_file_backed_sqlcipher_restart() {
        let path =
            std::env::temp_dir().join(format!("veil-author-snapshot-{}.db", uuid::Uuid::new_v4()));
        let db_key = [0xB7; 32];
        let author = sample_account(
            ORIGIN_A,
            USER_A,
            0x81,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            Some(7),
        );
        {
            let db = VeilDb::open(&path, &db_key).unwrap();
            db.upsert_directory_conversation(
                "restart-author-conversation",
                0,
                ORIGIN_A,
                Some("Peer"),
                Some(USER_A),
                Some(&author.locator.identity_key),
                None,
                "2026-07-12T12:00:00Z",
            )
            .unwrap();
            db.insert_message(
                "restart-author-message",
                "restart-author-conversation",
                &author.locator.identity_key,
                "persisted author",
                false,
                Some(10),
                None,
            )
            .unwrap();
            db.attach_message_author("restart-author-message", &author)
                .unwrap();
            db.attach_message_author("restart-author-message", &author)
                .unwrap();
        }
        {
            let reopened = VeilDb::open(&path, &db_key).unwrap();
            let message = reopened
                .get_messages("restart-author-conversation", 10)
                .unwrap()
                .remove(0);
            assert_eq!(message.author, Some(author));
            assert_eq!(
                message.author_context,
                Some(MessageAuthorContext::DirectoryMemberAtObservation)
            );
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn search_hydration_is_exact_message_conversation_and_origin_scoped() {
        let db = VeilDb::open_memory(&[0xBA; 32]).unwrap();
        let author = sample_account(
            ORIGIN_A,
            USER_A,
            0x83,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            Some(9),
        );
        db.upsert_directory_conversation(
            "search-author-conversation",
            1,
            ORIGIN_A,
            Some("Search group"),
            None,
            None,
            None,
            "2026-07-13T12:00:00Z",
        )
        .unwrap();
        db.insert_message(
            "search-author-message",
            "search-author-conversation",
            &author.locator.identity_key,
            "origin scoped search",
            false,
            Some(42),
            None,
        )
        .unwrap();
        db.attach_message_author("search-author-message", &author)
            .unwrap();

        let loaded = db
            .get_message_for_search(
                "search-author-message",
                "search-author-conversation",
                ORIGIN_A,
            )
            .unwrap()
            .expect("exact search row must resolve");
        assert_eq!(loaded.author, Some(author));
        assert_eq!(
            loaded.author_context,
            Some(MessageAuthorContext::DirectoryMemberAtObservation)
        );
        assert!(db
            .get_message_for_search("search-author-message", "different-conversation", ORIGIN_A,)
            .unwrap()
            .is_none());
        assert!(db
            .get_message_for_search(
                "search-author-message",
                "search-author-conversation",
                ORIGIN_B,
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn outgoing_ack_cascades_the_author_snapshot_to_the_server_uuid() {
        let db = VeilDb::open_memory(&[0xB8; 32]).unwrap();
        let author = sample_account(
            ORIGIN_A,
            USER_A,
            0x91,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );
        db.upsert_directory_conversation(
            "author-ack-conversation",
            1,
            ORIGIN_A,
            Some("Group"),
            None,
            None,
            None,
            "2026-07-12T12:00:00Z",
        )
        .unwrap();
        db.insert_outgoing_pending_message(
            "local-author-id",
            "author-ack-conversation",
            &author.locator.identity_key,
            "pending",
            None,
        )
        .unwrap();
        db.attach_message_author("local-author-id", &author)
            .unwrap();
        db.acknowledge_outgoing_message("local-author-id", "server-author-id", 123)
            .unwrap();

        assert!(load_message_author(&db.conn, "local-author-id")
            .unwrap()
            .is_none());
        assert_eq!(
            load_message_author(&db.conn, "server-author-id").unwrap(),
            Some(author.clone())
        );
        assert_eq!(
            db.get_messages("author-ack-conversation", 10).unwrap()[0].author,
            Some(author)
        );
        assert_eq!(
            db.get_messages("author-ack-conversation", 10).unwrap()[0].author_context,
            Some(MessageAuthorContext::DirectoryMemberAtObservation)
        );
    }

    #[test]
    fn conversation_identity_schema_upgrade_is_idempotent_and_does_not_guess_legacy_scope() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE conversations (
                id TEXT PRIMARY KEY,
                conv_type INTEGER NOT NULL,
                peer_identity_key BLOB,
                server_id TEXT,
                name TEXT,
                last_message_at TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO conversations (id, conv_type, name)
             VALUES ('legacy-unscoped', 1, 'Legacy');",
        )
        .unwrap();
        let db = VeilDb { conn };
        db.run_migrations().unwrap();
        db.run_migrations().unwrap();

        let columns: (bool, bool, bool, bool) = db
            .conn
            .query_row(
                "SELECT
                    EXISTS(SELECT 1 FROM pragma_table_info('conversations') WHERE name='server_origin'),
                    EXISTS(SELECT 1 FROM pragma_table_info('conversations') WHERE name='peer_user_id'),
                    EXISTS(SELECT 1 FROM pragma_table_info('conversations') WHERE name='unread_count'),
                    EXISTS(SELECT 1 FROM pragma_table_info('conversations') WHERE name='last_read_message_id')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(columns, (true, true, true, true));
        let legacy = db.get_conversations().unwrap().remove(0);
        assert!(legacy.server_origin.is_none());
        assert!(legacy.peer_user_id.is_none());

        db.insert_message(
            "legacy-history-message",
            "legacy-unscoped",
            &[0xA1; 32],
            "legacy history must keep its unknown origin",
            false,
            Some(1),
            None,
        )
        .unwrap();
        assert!(db
            .upsert_directory_conversation(
                "legacy-unscoped",
                1,
                ORIGIN_B,
                Some("Attempted adoption"),
                None,
                None,
                None,
                "2026-07-12T12:00:00Z",
            )
            .is_err());
        let legacy_after = db.get_conversations().unwrap().remove(0);
        assert!(legacy_after.server_origin.is_none());
        assert_eq!(db.get_messages("legacy-unscoped", 10).unwrap().len(), 1);
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
        assert_eq!(
            db.get_messages("sync-conv", 10).unwrap()[0].status,
            crate::models::MessageStatus::Delivered
        );

        // Opening a pre-fix database normalizes legacy incoming status=0.
        db.conn
            .execute(
                "UPDATE messages SET status = 0 WHERE id = 'server-message'",
                [],
            )
            .unwrap();
        db.run_migrations().unwrap();
        assert_eq!(
            db.get_messages("sync-conv", 10).unwrap()[0].status,
            crate::models::MessageStatus::Delivered
        );
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
    fn prekey_publication_outbox_survives_restart_and_is_origin_scoped() {
        let path = std::env::temp_dir().join(format!(
            "veil-prekey-publication-{}.db",
            uuid::Uuid::new_v4()
        ));
        let key = [0x91u8; 32];
        let device_id = [0x41u8; 16];
        let body_a = br#"{"device_id":"41414141414141414141414141414141","batch":"alpha"}"#;
        let body_b = br#"{"device_id":"41414141414141414141414141414141","batch":"beta"}"#;

        {
            let db = VeilDb::open(&path, &key).unwrap();
            let mut device = sample_device_identity(device_id);
            device.account_signing_key = test_signing_key(0x68);
            db.create_device_identity_v1(&device).unwrap();
            db.bind_authenticated_self(
                ORIGIN_A,
                USER_A,
                &device.account_identity_key,
                &device.account_signing_key,
            )
            .unwrap();
            db.bind_authenticated_self(
                ORIGIN_B,
                USER_B,
                &device.account_identity_key,
                &device.account_signing_key,
            )
            .unwrap();

            let publication_a = sample_prekey_publication(ORIGIN_A, USER_A, device_id, 1, body_a);
            db.save_local_prekeys_with_publication(&sample_prekey_batch(1, 1), &publication_a)
                .unwrap();
            assert!(db
                .load_local_prekey_publication(ORIGIN_B, USER_B, &device_id)
                .unwrap()
                .is_none());
        }

        {
            let db = VeilDb::open(&path, &key).unwrap();
            let loaded = db
                .load_local_prekey_publication(ORIGIN_A, USER_A, &device_id)
                .unwrap()
                .unwrap();
            assert_eq!(loaded.request_body, body_a);
            let expected_body_sha256: [u8; 32] = Sha256::digest(body_a).into();
            assert_eq!(loaded.body_sha256, expected_body_sha256);
            assert!(!loaded.acknowledged);
            let mut wrong_digest = loaded.body_sha256;
            wrong_digest[0] ^= 1;
            assert!(db
                .acknowledge_local_prekey_publication(
                    ORIGIN_A,
                    USER_A,
                    &device_id,
                    loaded.signed_prekey_id,
                    &wrong_digest,
                )
                .is_err());
            db.acknowledge_local_prekey_publication(
                ORIGIN_A,
                USER_A,
                &device_id,
                loaded.signed_prekey_id,
                &loaded.body_sha256,
            )
            .unwrap();
            assert!(
                db.load_local_prekey_publication(ORIGIN_A, USER_A, &device_id)
                    .unwrap()
                    .unwrap()
                    .acknowledged
            );

            let publication_b = sample_prekey_publication(ORIGIN_B, USER_B, device_id, 2, body_b);
            db.save_local_prekeys_with_publication(&sample_prekey_batch(2, 21), &publication_b)
                .unwrap();
            assert_eq!(
                db.load_local_prekey_publication(ORIGIN_B, USER_B, &device_id)
                    .unwrap()
                    .unwrap()
                    .request_body,
                body_b,
            );
            assert_eq!(
                db.load_local_prekey_publication(ORIGIN_A, USER_A, &device_id)
                    .unwrap()
                    .unwrap()
                    .request_body,
                body_a,
            );
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn prekey_publication_key_conflict_rolls_back_the_entire_outbox_transaction() {
        let db = VeilDb::open_memory(&[0x92u8; 32]).unwrap();
        let device_id = [0x42u8; 16];
        let mut device = sample_device_identity(device_id);
        device.account_signing_key = test_signing_key(0x69);
        db.create_device_identity_v1(&device).unwrap();
        db.bind_authenticated_self(
            ORIGIN_A,
            USER_A,
            &device.account_identity_key,
            &device.account_signing_key,
        )
        .unwrap();
        db.save_local_prekeys(&[LocalPreKey {
            key_type: 1,
            protocol_key_id: 7,
            secret_key: [0x51; 32],
            public_key: [0x52; 32],
            signature: None,
        }])
        .unwrap();

        let publication = sample_prekey_publication(
            ORIGIN_A,
            USER_A,
            device_id,
            1,
            br#"{"device_id":"42424242424242424242424242424242","batch":"conflict"}"#,
        );
        assert!(db
            .save_local_prekeys_with_publication(&sample_prekey_batch(1, 1), &publication)
            .is_err());
        assert!(db
            .load_local_prekey_publication(ORIGIN_A, USER_A, &device_id)
            .unwrap()
            .is_none());
        assert_eq!(db.load_local_prekeys().unwrap().len(), 1);
        assert_eq!(db.max_local_prekey_id(0).unwrap(), 0);
        assert_eq!(db.max_local_prekey_id(1).unwrap(), 7);
    }

    #[test]
    fn persisted_prekey_allocator_serializes_preopened_database_handles() {
        let path =
            std::env::temp_dir().join(format!("veil-prekey-allocator-{}.db", uuid::Uuid::new_v4()));
        let key = [0x93u8; 32];
        let first = VeilDb::open(&path, &key).unwrap();
        let second = VeilDb::open(&path, &key).unwrap();

        // Simulate an older database whose key rows predate the allocator.
        first
            .save_local_prekeys(&[
                LocalPreKey {
                    key_type: 0,
                    protocol_key_id: 7,
                    secret_key: [0x11; 32],
                    public_key: [0x12; 32],
                    signature: Some([0x13; 64]),
                },
                LocalPreKey {
                    key_type: 1,
                    protocol_key_id: 41,
                    secret_key: [0x21; 32],
                    public_key: [0x22; 32],
                    signature: None,
                },
            ])
            .unwrap();

        let from_second = second.reserve_local_prekey_batch_ids().unwrap();
        assert_eq!(from_second.signed_prekey_id, 8);
        assert_eq!(from_second.one_time_prekey_start_id, 42);
        assert_eq!(from_second.next_signed_prekey_id, 9);
        assert_eq!(from_second.next_one_time_prekey_id, 62);

        let from_first = first.reserve_local_prekey_batch_ids().unwrap();
        assert_eq!(from_first.signed_prekey_id, 9);
        assert_eq!(from_first.one_time_prekey_start_id, 62);
        assert_eq!(from_first.next_signed_prekey_id, 10);
        assert_eq!(from_first.next_one_time_prekey_id, 82);

        drop(second);
        drop(first);
        let reopened = VeilDb::open(&path, &key).unwrap();
        assert_eq!(
            reopened.synchronize_local_prekey_allocator().unwrap(),
            (10, 82)
        );
        drop(reopened);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn opk_only_reservation_never_advances_the_signed_prekey_namespace() {
        let db = VeilDb::open_memory(&[0xA3u8; 32]).unwrap();
        let initial = db.reserve_local_prekey_batch_ids().unwrap();
        assert_eq!(initial.signed_prekey_id, 1);
        assert_eq!(initial.one_time_prekey_start_id, 1);

        let refill = db.reserve_local_one_time_prekey_batch_ids().unwrap();
        assert_eq!(refill.one_time_prekey_start_id, 21);
        assert_eq!(refill.next_one_time_prekey_id, 41);
        assert_eq!(db.synchronize_local_prekey_allocator().unwrap(), (2, 41));

        let next_full = db.reserve_local_prekey_batch_ids().unwrap();
        assert_eq!(next_full.signed_prekey_id, 2);
        assert_eq!(next_full.one_time_prekey_start_id, 41);
    }

    #[test]
    fn prekey_refill_reuses_only_the_exact_immutable_signed_prekey() {
        let db = VeilDb::open_memory(&[0xA4u8; 32]).unwrap();
        let device_id = [0x4Au8; 16];
        let mut device = sample_device_identity(device_id);
        device.account_signing_key = test_signing_key(0x6B);
        db.create_device_identity_v1(&device).unwrap();
        db.bind_authenticated_self(
            ORIGIN_A,
            USER_A,
            &device.account_identity_key,
            &device.account_signing_key,
        )
        .unwrap();

        let first_keys = sample_prekey_batch(1, 1);
        let first = sample_prekey_publication(
            ORIGIN_A,
            USER_A,
            device_id,
            1,
            br#"{"device_id":"4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a","batch":"first"}"#,
        );
        db.save_local_prekeys_with_publication(&first_keys, &first)
            .unwrap();
        db.acknowledge_local_prekey_publication(
            ORIGIN_A,
            USER_A,
            &device_id,
            first.signed_prekey_id,
            &first.body_sha256,
        )
        .unwrap();

        let signed_prekey = db.load_local_signed_prekey(1).unwrap().unwrap();
        assert_eq!(signed_prekey.secret_key, first_keys[0].secret_key);
        assert_eq!(signed_prekey.public_key, first_keys[0].public_key);
        assert_eq!(signed_prekey.signature, first_keys[0].signature);

        let refill_batch = sample_prekey_batch(1, 21);
        let refill = sample_prekey_publication(
            ORIGIN_A,
            USER_A,
            device_id,
            1,
            br#"{"device_id":"4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a","batch":"refill"}"#,
        );
        let mut tampered_signed = signed_prekey.clone();
        tampered_signed.public_key[0] ^= 1;
        assert!(db
            .save_local_prekey_refill_with_publication(
                &tampered_signed,
                &refill_batch[1..],
                &refill,
            )
            .is_err());
        assert!(
            db.load_local_prekey_publication(ORIGIN_A, USER_A, &device_id)
                .unwrap()
                .unwrap()
                .acknowledged
        );
        assert_eq!(db.load_local_prekeys().unwrap().len(), 21);

        db.save_local_prekey_refill_with_publication(&signed_prekey, &refill_batch[1..], &refill)
            .unwrap();
        let stored = db.load_local_prekeys().unwrap();
        assert_eq!(stored.iter().filter(|key| key.key_type == 0).count(), 1);
        assert_eq!(stored.iter().filter(|key| key.key_type == 1).count(), 40);
        assert!(
            !db.load_local_prekey_publication(ORIGIN_A, USER_A, &device_id)
                .unwrap()
                .unwrap()
                .acknowledged
        );
    }

    #[test]
    fn immutable_prekey_insert_cannot_resurrect_a_consumed_opk() {
        let db = VeilDb::open_memory(&[0x94u8; 32]).unwrap();
        let original_public = [0x32u8; 32];
        db.save_local_prekeys(&[LocalPreKey {
            key_type: 1,
            protocol_key_id: 7,
            secret_key: [0x31; 32],
            public_key: original_public,
            signature: None,
        }])
        .unwrap();
        db.commit_initial_ratchet_session(&[0x33; 32], b"session", Some(7))
            .unwrap();

        assert!(db
            .save_local_prekeys(&[LocalPreKey {
                key_type: 1,
                protocol_key_id: 7,
                secret_key: [0x41; 32],
                public_key: [0x42; 32],
                signature: None,
            }])
            .is_err());
        let (secret, public, consumed): (Option<Vec<u8>>, Vec<u8>, u8) = db
            .conn
            .query_row(
                "SELECT secret_key, public_key, consumed FROM local_prekeys
                 WHERE key_type = 1 AND protocol_key_id = 7",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(secret.is_none());
        assert_eq!(public, original_public);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn prekey_publication_ack_is_exact_idempotent_and_cannot_cross_rotation() {
        let db = VeilDb::open_memory(&[0x95u8; 32]).unwrap();
        let device_id = [0x43u8; 16];
        let mut device = sample_device_identity(device_id);
        device.account_signing_key = test_signing_key(0x6A);
        db.create_device_identity_v1(&device).unwrap();
        db.bind_authenticated_self(
            ORIGIN_A,
            USER_A,
            &device.account_identity_key,
            &device.account_signing_key,
        )
        .unwrap();

        let first = sample_prekey_publication(
            ORIGIN_A,
            USER_A,
            device_id,
            1,
            br#"{"device_id":"43434343434343434343434343434343","batch":"first"}"#,
        );
        db.save_local_prekeys_with_publication(&sample_prekey_batch(1, 1), &first)
            .unwrap();
        db.acknowledge_local_prekey_publication(
            ORIGIN_A,
            USER_A,
            &device_id,
            first.signed_prekey_id,
            &first.body_sha256,
        )
        .unwrap();
        // Reinstalling the exact ACK is harmless and does not require a
        // read-before-write race window.
        db.acknowledge_local_prekey_publication(
            ORIGIN_A,
            USER_A,
            &device_id,
            first.signed_prekey_id,
            &first.body_sha256,
        )
        .unwrap();

        let second = sample_prekey_publication(
            ORIGIN_A,
            USER_A,
            device_id,
            2,
            br#"{"device_id":"43434343434343434343434343434343","batch":"second"}"#,
        );
        db.save_local_prekeys_with_publication(&sample_prekey_batch(2, 21), &second)
            .unwrap();
        assert!(db
            .acknowledge_local_prekey_publication(
                ORIGIN_A,
                USER_A,
                &device_id,
                first.signed_prekey_id,
                &first.body_sha256,
            )
            .is_err());
        assert!(
            !db.load_local_prekey_publication(ORIGIN_A, USER_A, &device_id)
                .unwrap()
                .unwrap()
                .acknowledged
        );
        db.acknowledge_local_prekey_publication(
            ORIGIN_A,
            USER_A,
            &device_id,
            second.signed_prekey_id,
            &second.body_sha256,
        )
        .unwrap();
        db.acknowledge_local_prekey_publication(
            ORIGIN_A,
            USER_A,
            &device_id,
            second.signed_prekey_id,
            &second.body_sha256,
        )
        .unwrap();
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

        // Reusing the OTK for a different peer reaches the late consume check,
        // then rolls back both the successful INSERT and its AFTER capacity
        // counter update.
        let capacity_before_reuse = ratchet_capacity(&db);
        let reuse_peer = [31u8; 32];
        assert!(db
            .commit_initial_ratchet_session(&reuse_peer, b"ratchet-two-grown", Some(9))
            .is_err());
        assert!(db.load_ratchet_session(&reuse_peer).unwrap().is_none());
        assert_eq!(ratchet_capacity(&db), capacity_before_reuse);
        assert_eq!(
            db.load_ratchet_session(&peer).unwrap().unwrap(),
            b"ratchet-one"
        );
    }

    #[test]
    fn direct_v2_binding_is_atomic_sticky_and_cascades_with_its_ratchet() {
        fn binding(peer: [u8; 32], marker: u8) -> DirectSessionBindingBlobV2 {
            DirectSessionBindingBlobV2 {
                peer_identity_key: peer,
                session_id: [marker; 32],
                local_device_id: [marker.wrapping_add(1); 16],
                peer_device_id: [marker.wrapping_add(2); 16],
                binding_data: vec![marker, marker.wrapping_add(3)],
            }
        }

        let db = VeilDb::open_memory(&[0x81; 32]).unwrap();
        let peer = [0x51; 32];
        let valid = binding(peer, 0x61);
        let mut malformed = valid.clone();
        malformed.session_id = [0u8; 32];
        assert!(db
            .save_initiator_session_v2(&peer, b"ratchet", b"initial", &malformed)
            .is_err());
        assert!(db.load_ratchet_session(&peer).unwrap().is_none());
        assert!(db.load_pending_initial_headers().unwrap().is_empty());
        assert!(db.load_all_direct_session_bindings_v2().unwrap().is_empty());

        db.save_initiator_session_v2(&peer, b"ratchet", b"initial", &valid)
            .unwrap();
        assert_eq!(db.load_ratchet_session(&peer).unwrap().unwrap(), b"ratchet");
        assert_eq!(db.load_pending_initial_headers().unwrap().len(), 1);
        let loaded = db.load_all_direct_session_bindings_v2().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].peer_identity_key, peer);
        assert_eq!(loaded[0].session_id, valid.session_id);
        assert_eq!(loaded[0].binding_data, valid.binding_data);

        db.conn
            .execute(
                "DELETE FROM ratchet_sessions WHERE peer_identity_key = ?1",
                rusqlite::params![peer.as_slice()],
            )
            .unwrap();
        assert!(db.load_all_direct_session_bindings_v2().unwrap().is_empty());

        let responder = VeilDb::open_memory(&[0x82; 32]).unwrap();
        responder
            .save_local_prekeys(&[LocalPreKey {
                key_type: 1,
                protocol_key_id: 19,
                secret_key: [0x71; 32],
                public_key: [0x72; 32],
                signature: None,
            }])
            .unwrap();
        let responder_peer = [0x52; 32];
        let responder_binding = binding(responder_peer, 0x62);
        responder
            .commit_initial_ratchet_session_v2(
                &responder_peer,
                b"responder-ratchet",
                Some(19),
                &responder_binding,
            )
            .unwrap();
        assert_eq!(responder.load_local_prekeys().unwrap().len(), 0);
        assert_eq!(
            responder
                .load_all_direct_session_bindings_v2()
                .unwrap()
                .len(),
            1
        );

        let reuse_peer = [0x53; 32];
        let reuse_binding = binding(reuse_peer, 0x63);
        assert!(responder
            .commit_initial_ratchet_session_v2(
                &reuse_peer,
                b"must-rollback",
                Some(19),
                &reuse_binding,
            )
            .is_err());
        assert!(responder
            .load_ratchet_session(&reuse_peer)
            .unwrap()
            .is_none());
        assert_eq!(
            responder
                .load_all_direct_session_bindings_v2()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn ratchet_cas_requires_exact_revision_and_expected_bytes() {
        let db = VeilDb::open_memory(&[0xC1; 32]).unwrap();
        let peer = [0x31; 32];
        db.commit_initial_ratchet_session(&peer, b"state-zero", None)
            .unwrap();

        assert_eq!(
            db.compare_and_swap_ratchet_session_v1(&peer, 0, b"state-zero", b"state-one",)
                .unwrap(),
            1
        );
        assert!(db
            .compare_and_swap_ratchet_session_v1(&peer, 0, b"state-zero", b"stale-state",)
            .is_err());
        assert!(db
            .compare_and_swap_ratchet_session_v1(
                &peer,
                1,
                b"same-revision-equivocation",
                b"must-not-commit",
            )
            .is_err());

        let stored = db
            .load_ratchet_session_with_revision_v1(&peer)
            .unwrap()
            .unwrap();
        assert_eq!(stored.session_data, b"state-one");
        assert_eq!(stored.revision, 1);
    }

    #[test]
    fn file_backed_stale_ratchet_handle_cannot_overwrite_newer_state() {
        let path = std::env::temp_dir().join(format!(
            "veil-ratchet-stale-cas-{}.db",
            uuid::Uuid::new_v4()
        ));
        let key = [0xC2; 32];
        let peer = [0x32; 32];
        let first = VeilDb::open(&path, &key).unwrap();
        first
            .commit_initial_ratchet_session(&peer, b"state-zero", None)
            .unwrap();
        let stale = VeilDb::open(&path, &key).unwrap();
        let stale_snapshot = stale
            .load_ratchet_session_with_revision_v1(&peer)
            .unwrap()
            .unwrap();

        first
            .compare_and_swap_ratchet_session_v1(&peer, 0, b"state-zero", b"state-one")
            .unwrap();
        assert!(stale
            .compare_and_swap_ratchet_session_v1(
                &peer,
                stale_snapshot.revision,
                &stale_snapshot.session_data,
                b"stale-branch",
            )
            .is_err());
        let durable = stale
            .load_ratchet_session_with_revision_v1(&peer)
            .unwrap()
            .unwrap();
        assert_eq!(durable.session_data, b"state-one");
        assert_eq!(durable.revision, 1);

        drop(durable);
        drop(stale_snapshot);
        drop(stale);
        drop(first);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ratchet_storage_bounds_and_initial_inserts_fail_closed() {
        let db = VeilDb::open_memory(&[0xC3; 32]).unwrap();
        let peer = [0x33; 32];
        db.commit_initial_ratchet_session(&peer, b"original", None)
            .unwrap();
        assert!(db
            .save_initiator_session(&peer, b"replacement", b"pending")
            .is_err());
        let stored = db
            .load_ratchet_session_with_revision_v1(&peer)
            .unwrap()
            .unwrap();
        assert_eq!(stored.session_data, b"original");
        assert_eq!(stored.revision, 0);
        assert!(db.load_pending_initial_headers().unwrap().is_empty());
        assert!(db
            .commit_initial_ratchet_session(&[0x34; 32], b"", None)
            .is_err());
        assert!(db
            .commit_initial_ratchet_session(
                &[0x35; 32],
                &vec![0u8; DIRECT_MESSAGE_RATCHET_MAX_BYTES_V1 + 1],
                None,
            )
            .is_err());

        db.conn
            .execute_batch(
                "DROP TRIGGER ratchet_session_capacity_insert_v1;
                 DROP TRIGGER ratchet_session_capacity_insert_commit_v1;
                 DROP TRIGGER ratchet_session_capacity_update_v1;
                 DROP TRIGGER ratchet_session_capacity_update_commit_v1;
                 DROP TRIGGER ratchet_session_capacity_delete_v1;
                 DROP TRIGGER ratchet_session_capacity_delete_commit_v1;
                 PRAGMA ignore_check_constraints = ON;",
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO ratchet_sessions
                   (peer_identity_key, session_data, revision, updated_at)
                 VALUES (?1, zeroblob(?2), 0, datetime('now'))",
                rusqlite::params![
                    [0x36u8; 32].as_slice(),
                    DIRECT_MESSAGE_RATCHET_MAX_BYTES_SQLITE_V1 + 1,
                ],
            )
            .unwrap();
        assert!(db.load_all_ratchet_sessions_with_revision_v1().is_err());
        db.conn.execute("DELETE FROM ratchet_sessions", []).unwrap();
        db.conn
            .execute(
                "INSERT INTO ratchet_sessions
                   (peer_identity_key, session_data, revision, updated_at)
                 VALUES (zeroblob(?1), x'01', 0, datetime('now'))",
                rusqlite::params![DIRECT_MESSAGE_RATCHET_MAX_BYTES_SQLITE_V1 + 1],
            )
            .unwrap();
        assert!(db.load_all_ratchet_sessions_with_revision_v1().is_err());

        assert_eq!(
            validate_ratchet_session_load_preflight_v1(
                DIRECT_RATCHET_SESSION_MAX_ROWS_SQLITE_V1,
                DIRECT_RATCHET_SESSION_MAX_TOTAL_BYTES_SQLITE_V1,
                0,
            )
            .unwrap(),
            DIRECT_RATCHET_SESSION_MAX_ROWS_V1
        );
        assert!(validate_ratchet_session_load_preflight_v1(
            DIRECT_RATCHET_SESSION_MAX_ROWS_SQLITE_V1 + 1,
            1,
            0,
        )
        .is_err());
        assert!(validate_ratchet_session_load_preflight_v1(
            1,
            DIRECT_RATCHET_SESSION_MAX_TOTAL_BYTES_SQLITE_V1 + 1,
            0,
        )
        .is_err());
        assert!(validate_ratchet_session_load_preflight_v1(1, 1, 1).is_err());
    }

    #[test]
    fn ratchet_fresh_schema_is_without_rowid_and_rejects_rowid_sql() {
        let db = VeilDb::open_memory(&[0xC4; 32]).unwrap();
        let peer = [0x40; 32];
        db.commit_initial_ratchet_session(&peer, b"fresh-state", None)
            .unwrap();

        assert!(ratchet_table_without_rowid(&db));
        assert_ratchet_rowid_sql_is_unavailable(&db, &peer);
        let durable = db
            .load_ratchet_session_with_revision_v1(&peer)
            .unwrap()
            .unwrap();
        assert_eq!(durable.session_data, b"fresh-state");
        assert_eq!(durable.revision, 0);
    }

    #[test]
    fn ratchet_legacy_rowid_table_migrates_losslessly_and_reopens_idempotently() {
        let path = std::env::temp_dir().join(format!(
            "veil-ratchet-without-rowid-migration-{}.db",
            uuid::Uuid::new_v4()
        ));
        let key = [0xC5; 32];
        let first_peer = [0x81; 32];
        let second_peer = [0x82; 32];
        let first_session = [0x00, 0xFF, 0x10, 0x00, 0x7F];
        let second_session = [0x80, 0x00, 0x01, 0xFE, 0xFD, 0xFC];
        let first_updated_at = "2026-07-19T01:02:03.456789Z";
        let second_updated_at = "2026-07-19 04:05:06.000001+05:00";

        let legacy = VeilDb::open(&path, &key).unwrap();
        legacy
            .conn
            .execute_batch(
                "DROP TRIGGER ratchet_session_capacity_insert_v1;
                 DROP TRIGGER ratchet_session_capacity_insert_commit_v1;
                 DROP TRIGGER ratchet_session_capacity_update_v1;
                 DROP TRIGGER ratchet_session_capacity_update_commit_v1;
                 DROP TRIGGER ratchet_session_capacity_delete_v1;
                 DROP TRIGGER ratchet_session_capacity_delete_commit_v1;
                 DROP TABLE ratchet_session_capacity_v1;
                 DROP TABLE ratchet_sessions;
                 CREATE TABLE ratchet_sessions (
                     peer_identity_key BLOB PRIMARY KEY,
                     session_data BLOB NOT NULL,
                     revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
                     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );",
            )
            .unwrap();
        legacy
            .conn
            .execute(
                "INSERT INTO ratchet_sessions
                     (rowid, peer_identity_key, session_data, revision, updated_at)
                 VALUES (-1, ?1, ?2, ?3, ?4)",
                rusqlite::params![
                    first_peer.as_slice(),
                    first_session.as_slice(),
                    7_i64,
                    first_updated_at,
                ],
            )
            .unwrap();
        legacy
            .conn
            .execute(
                "INSERT INTO ratchet_sessions
                     (rowid, peer_identity_key, session_data, revision, updated_at)
                 VALUES (42, ?1, ?2, ?3, ?4)",
                rusqlite::params![
                    second_peer.as_slice(),
                    second_session.as_slice(),
                    19_i64,
                    second_updated_at,
                ],
            )
            .unwrap();
        assert!(!ratchet_table_without_rowid(&legacy));
        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT rowid FROM ratchet_sessions WHERE peer_identity_key = ?1",
                    rusqlite::params![first_peer.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            -1
        );
        drop(legacy);

        let assert_preserved = |db: &VeilDb| {
            assert!(ratchet_table_without_rowid(db));
            assert_eq!(table_count(db, "ratchet_sessions"), 2);
            let first: (Vec<u8>, i64, Vec<u8>) = db
                .conn
                .query_row(
                    "SELECT session_data, revision, CAST(updated_at AS BLOB)
                     FROM ratchet_sessions WHERE peer_identity_key = ?1",
                    rusqlite::params![first_peer.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            let second: (Vec<u8>, i64, Vec<u8>) = db
                .conn
                .query_row(
                    "SELECT session_data, revision, CAST(updated_at AS BLOB)
                     FROM ratchet_sessions WHERE peer_identity_key = ?1",
                    rusqlite::params![second_peer.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(
                first,
                (
                    first_session.to_vec(),
                    7,
                    first_updated_at.as_bytes().to_vec(),
                )
            );
            assert_eq!(
                second,
                (
                    second_session.to_vec(),
                    19,
                    second_updated_at.as_bytes().to_vec(),
                )
            );
            assert_eq!(
                ratchet_capacity(db),
                (
                    2,
                    i64::try_from(first_session.len() + second_session.len()).unwrap(),
                )
            );
        };

        let migrated = VeilDb::open(&path, &key).unwrap();
        assert_preserved(&migrated);
        assert_ratchet_rowid_sql_is_unavailable(&migrated, &first_peer);
        migrated.run_migrations().unwrap();
        assert_preserved(&migrated);
        drop(migrated);

        let reopened = VeilDb::open(&path, &key).unwrap();
        assert_preserved(&reopened);
        assert_ratchet_rowid_sql_is_unavailable(&reopened, &second_peer);
        drop(reopened);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ratchet_legacy_future_column_fails_closed_without_rebuild() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE ratchet_sessions (
                     peer_identity_key BLOB PRIMARY KEY,
                     session_data BLOB NOT NULL,
                     updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                     future_state BLOB NOT NULL
                 );
                 INSERT INTO ratchet_sessions
                     (rowid, peer_identity_key, session_data, updated_at, future_state)
                 VALUES (
                     -1,
                     x'9191919191919191919191919191919191919191919191919191919191919191',
                     x'0001ff',
                     '2026-07-19T11:12:13.123456Z',
                     x'deadbeef'
                 );",
            )
            .unwrap();
        let legacy = VeilDb { conn: connection };

        assert!(legacy.run_migrations().is_err());
        assert!(!ratchet_table_without_rowid(&legacy));
        let preserved: (i64, Vec<u8>, Vec<u8>, Vec<u8>) = legacy
            .conn
            .query_row(
                "SELECT rowid, session_data, CAST(updated_at AS BLOB), future_state
                 FROM ratchet_sessions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            preserved,
            (
                -1,
                vec![0, 1, 0xFF],
                b"2026-07-19T11:12:13.123456Z".to_vec(),
                vec![0xDE, 0xAD, 0xBE, 0xEF],
            )
        );
        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('ratchet_sessions')
                     WHERE name = 'revision'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE name IN (
                         'ratchet_sessions_rowid_legacy_v1',
                         'ratchet_session_capacity_v1'
                     )",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn ratchet_legacy_unique_autoindex_fails_closed_without_mutation() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE ratchet_sessions (
                     peer_identity_key BLOB PRIMARY KEY,
                     session_data BLOB NOT NULL UNIQUE,
                     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );
                 INSERT INTO ratchet_sessions
                     (rowid, peer_identity_key, session_data, updated_at)
                 VALUES (
                     -1,
                     x'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
                     x'0001ff',
                     '2026-07-19T12:13:14.123456Z'
                 );",
            )
            .unwrap();
        let legacy = VeilDb { conn: connection };
        let schema_before: String = legacy
            .conn
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'table' AND name = 'ratchet_sessions'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let indexes_before: Vec<(String, String)> = {
            let mut statement = legacy
                .conn
                .prepare(
                    "SELECT name, origin FROM pragma_index_list('ratchet_sessions')
                     ORDER BY seq",
                )
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(indexes_before.len(), 2);
        assert!(indexes_before.iter().any(|(_, origin)| origin == "u"));

        assert!(legacy
            .ensure_ratchet_sessions_without_rowid_schema()
            .is_err());

        let schema_after: String = legacy
            .conn
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'table' AND name = 'ratchet_sessions'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(schema_after, schema_before);
        let indexes_after: Vec<(String, String)> = {
            let mut statement = legacy
                .conn
                .prepare(
                    "SELECT name, origin FROM pragma_index_list('ratchet_sessions')
                     ORDER BY seq",
                )
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(indexes_after, indexes_before);
        assert!(legacy
            .conn
            .execute(
                "INSERT INTO ratchet_sessions
                     (peer_identity_key, session_data, updated_at)
                 VALUES (?1, x'0001ff', '2026-07-19T12:13:15Z')",
                rusqlite::params![[0xA2u8; 32].as_slice()],
            )
            .is_err());
        let preserved: (i64, Vec<u8>, Vec<u8>) = legacy
            .conn
            .query_row(
                "SELECT rowid, session_data, CAST(updated_at AS BLOB)
                 FROM ratchet_sessions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            preserved,
            (
                -1,
                vec![0, 1, 0xFF],
                b"2026-07-19T12:13:14.123456Z".to_vec(),
            )
        );
    }

    #[test]
    fn ratchet_legacy_check_and_strict_shapes_fail_closed_without_mutation() {
        for (suffix, expected_strict) in [
            (
                ", CHECK(length(session_data) > 0)\n                 )",
                0_i64,
            ),
            (") STRICT", 1_i64),
        ] {
            let connection = Connection::open_in_memory().unwrap();
            connection
                .execute_batch(&format!(
                    "CREATE TABLE ratchet_sessions (
                         peer_identity_key BLOB PRIMARY KEY,
                         session_data BLOB NOT NULL,
                         updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                         {suffix};
                     INSERT INTO ratchet_sessions
                         (rowid, peer_identity_key, session_data, updated_at)
                     VALUES (
                         -1,
                         x'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3',
                         x'010203',
                         '2026-07-19T13:14:15.123456Z'
                     );"
                ))
                .unwrap();
            let legacy = VeilDb { conn: connection };
            let schema_before: String = legacy
                .conn
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE name = 'ratchet_sessions'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();

            assert!(legacy
                .ensure_ratchet_sessions_without_rowid_schema()
                .is_err());

            assert_eq!(
                legacy
                    .conn
                    .query_row(
                        "SELECT sql FROM sqlite_schema WHERE name = 'ratchet_sessions'",
                        [],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                schema_before
            );
            assert_eq!(
                legacy
                    .conn
                    .query_row(
                        "SELECT strict FROM pragma_table_list
                         WHERE schema = 'main' AND name = 'ratchet_sessions'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                expected_strict
            );
            assert_eq!(
                legacy
                    .conn
                    .query_row("SELECT rowid FROM ratchet_sessions", [], |row| row
                        .get::<_, i64>(0),)
                    .unwrap(),
                -1
            );
            assert_eq!(
                legacy
                    .conn
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema
                         WHERE name = 'ratchet_session_capacity_v1'
                            OR name = 'ratchet_sessions_rowid_legacy_v1'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }

        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE ratchet_sessions (
                     peer_identity_key BLOB PRIMARY KEY,
                     session_data BLOBNOT NULL,
                     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );
                 INSERT INTO ratchet_sessions
                     (rowid, peer_identity_key, session_data, updated_at)
                 VALUES (
                     -1,
                     x'a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8',
                     x'010203',
                     '2026-07-19T13:14:16.123456Z'
                 );",
            )
            .unwrap();
        let legacy = VeilDb { conn: connection };
        let schema_before: String = legacy
            .conn
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name = 'ratchet_sessions'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(legacy
            .ensure_ratchet_sessions_without_rowid_schema()
            .is_err());
        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE name = 'ratchet_sessions'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            schema_before
        );
        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT type, \"notnull\" FROM pragma_table_info('ratchet_sessions')
                     WHERE name = 'session_data'",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap(),
            ("BLOBNOT".to_string(), 0)
        );
    }

    #[test]
    fn ratchet_legacy_altered_revision_migrates_losslessly_and_idempotently() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE ratchet_sessions (
                     peer_identity_key BLOB PRIMARY KEY,
                     session_data BLOB NOT NULL,
                     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );
                 ALTER TABLE ratchet_sessions
                     ADD COLUMN revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0);
                 INSERT INTO ratchet_sessions
                     (rowid, peer_identity_key, session_data, updated_at, revision)
                 VALUES (
                     -1,
                     x'a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9',
                     x'ff0001',
                     '2026-07-19T17:18:19.123456Z',
                     37
                 );",
            )
            .unwrap();
        let legacy = VeilDb { conn: connection };

        legacy
            .ensure_ratchet_sessions_without_rowid_schema()
            .unwrap();
        legacy
            .ensure_ratchet_sessions_without_rowid_schema()
            .unwrap();

        assert!(ratchet_table_without_rowid(&legacy));
        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT session_data, revision, CAST(updated_at AS BLOB)
                     FROM ratchet_sessions",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )
                .unwrap(),
            (
                vec![0xFF, 0, 1],
                37,
                b"2026-07-19T17:18:19.123456Z".to_vec(),
            )
        );
        assert_eq!(ratchet_capacity(&legacy), (1, 3));
        assert_ratchet_rowid_sql_is_unavailable(&legacy, &[0xA9; 32]);
    }

    #[test]
    fn ratchet_legacy_external_rowid_trigger_fails_closed_without_mutation() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE ratchet_sessions (
                     peer_identity_key BLOB PRIMARY KEY,
                     session_data BLOB NOT NULL,
                     revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
                     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );
                 INSERT INTO ratchet_sessions
                     (rowid, peer_identity_key, session_data, revision, updated_at)
                 VALUES (
                     -1,
                     x'a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4',
                     x'040506',
                     29,
                     '2026-07-19T14:15:16.123456Z'
                 );
                 CREATE TABLE external_probe (probe INTEGER NOT NULL);
                 CREATE TABLE external_result (ratchet_rowid INTEGER NOT NULL);
                 CREATE TRIGGER external_ratchet_rowid_probe
                 AFTER INSERT ON external_probe
                 BEGIN
                     INSERT INTO external_result (ratchet_rowid)
                     SELECT rowid FROM ratchet_sessions LIMIT 1;
                 END;",
            )
            .unwrap();
        let legacy = VeilDb { conn: connection };
        let trigger_before: String = legacy
            .conn
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'trigger' AND name = 'external_ratchet_rowid_probe'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(legacy
            .ensure_ratchet_sessions_without_rowid_schema()
            .is_err());

        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT sql FROM sqlite_schema
                     WHERE type = 'trigger' AND name = 'external_ratchet_rowid_probe'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            trigger_before
        );
        legacy
            .conn
            .execute("INSERT INTO external_probe (probe) VALUES (1)", [])
            .unwrap();
        assert_eq!(
            legacy
                .conn
                .query_row("SELECT ratchet_rowid FROM external_result", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            -1
        );
        let preserved: (Vec<u8>, i64, Vec<u8>) = legacy
            .conn
            .query_row(
                "SELECT session_data, revision, CAST(updated_at AS BLOB)
                 FROM ratchet_sessions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            preserved,
            (vec![4, 5, 6], 29, b"2026-07-19T14:15:16.123456Z".to_vec(),)
        );
    }

    #[test]
    fn ratchet_legacy_external_rowid_view_fails_closed_without_mutation() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE ratchet_sessions (
                     peer_identity_key BLOB PRIMARY KEY,
                     session_data BLOB NOT NULL,
                     updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                     revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0)
                 );
                 INSERT INTO ratchet_sessions
                     (rowid, peer_identity_key, session_data, revision, updated_at)
                 VALUES (
                     -1,
                     x'a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5',
                     x'070809',
                     31,
                     '2026-07-19T15:16:17.123456Z'
                 );
                 CREATE VIEW external_ratchet_rowid_view AS
                 SELECT rowid AS ratchet_rowid FROM ratchet_sessions;",
            )
            .unwrap();
        let legacy = VeilDb { conn: connection };
        let view_before: String = legacy
            .conn
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'view' AND name = 'external_ratchet_rowid_view'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(legacy
            .ensure_ratchet_sessions_without_rowid_schema()
            .is_err());

        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT sql FROM sqlite_schema
                     WHERE type = 'view' AND name = 'external_ratchet_rowid_view'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            view_before
        );
        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT ratchet_rowid FROM external_ratchet_rowid_view",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            -1
        );
        assert!(!ratchet_table_without_rowid(&legacy));
    }

    #[test]
    fn ratchet_reserved_capacity_schema_fails_closed_without_mutation() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE ratchet_sessions (
                     peer_identity_key BLOB PRIMARY KEY,
                     session_data BLOB NOT NULL,
                     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );
                 INSERT INTO ratchet_sessions
                     (rowid, peer_identity_key, session_data, updated_at)
                 VALUES (
                     -1,
                     x'a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6',
                     x'0a0b0c',
                     '2026-07-19T16:17:18.123456Z'
                 );
                 CREATE TABLE RATCHET_SESSION_CAPACITY_V1 (
                     future_owner TEXT NOT NULL
                 );
                 INSERT INTO RATCHET_SESSION_CAPACITY_V1 (future_owner)
                 VALUES ('preserve-me');",
            )
            .unwrap();
        let legacy = VeilDb { conn: connection };
        let reserved_before: String = legacy
            .conn
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'table'
                   AND lower(name) = 'ratchet_session_capacity_v1'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(legacy
            .ensure_ratchet_sessions_without_rowid_schema()
            .is_err());

        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT sql FROM sqlite_schema
                     WHERE type = 'table'
                       AND lower(name) = 'ratchet_session_capacity_v1'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            reserved_before
        );
        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT future_owner FROM ratchet_session_capacity_v1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "preserve-me"
        );
        assert_eq!(
            legacy
                .conn
                .query_row("SELECT rowid FROM ratchet_sessions", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            -1
        );
    }

    #[test]
    fn ratchet_mixed_case_reserved_capacity_trigger_fails_closed_without_mutation() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE ratchet_sessions (
                     peer_identity_key BLOB PRIMARY KEY,
                     session_data BLOB NOT NULL,
                     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );
                 INSERT INTO ratchet_sessions
                     (rowid, peer_identity_key, session_data, updated_at)
                 VALUES (
                     -1,
                     x'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     x'0d0e0f',
                     '2026-07-19T18:19:20.123456Z'
                 );
                 CREATE TABLE external_capacity_probe (probe INTEGER NOT NULL);
                 CREATE TRIGGER RATCHET_SESSION_CAPACITY_INSERT_V1
                 AFTER INSERT ON external_capacity_probe
                 BEGIN
                     SELECT 1;
                 END;",
            )
            .unwrap();
        let legacy = VeilDb { conn: connection };
        let trigger_before: String = legacy
            .conn
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'trigger'
                   AND lower(name) = 'ratchet_session_capacity_insert_v1'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(legacy
            .ensure_ratchet_sessions_without_rowid_schema()
            .is_err());

        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT sql FROM sqlite_schema
                     WHERE type = 'trigger'
                       AND lower(name) = 'ratchet_session_capacity_insert_v1'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            trigger_before
        );
        legacy
            .conn
            .execute("INSERT INTO external_capacity_probe (probe) VALUES (1)", [])
            .unwrap();
        assert_eq!(
            legacy
                .conn
                .query_row("SELECT rowid FROM ratchet_sessions", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            -1
        );
    }

    #[test]
    fn ratchet_temp_dependencies_fail_closed_without_mutation() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE ratchet_sessions (
                     peer_identity_key BLOB PRIMARY KEY,
                     session_data BLOB NOT NULL,
                     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );
                 INSERT INTO ratchet_sessions
                     (rowid, peer_identity_key, session_data, updated_at)
                 VALUES (
                     -1,
                     x'abababababababababababababababababababababababababababababababab',
                     x'101112',
                     '2026-07-19T19:20:21.123456Z'
                 );
                 CREATE TEMP VIEW external_temp_ratchet_rowid_view AS
                 SELECT rowid AS ratchet_rowid FROM main.ratchet_sessions;",
            )
            .unwrap();
        let legacy = VeilDb { conn: connection };
        let temp_view_before: String = legacy
            .conn
            .query_row(
                "SELECT sql FROM sqlite_temp_schema
                 WHERE type = 'view' AND name = 'external_temp_ratchet_rowid_view'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(legacy
            .ensure_ratchet_sessions_without_rowid_schema()
            .is_err());

        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT sql FROM sqlite_temp_schema
                     WHERE type = 'view' AND name = 'external_temp_ratchet_rowid_view'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            temp_view_before
        );
        assert_eq!(
            legacy
                .conn
                .query_row(
                    "SELECT ratchet_rowid FROM external_temp_ratchet_rowid_view",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            -1
        );
        assert!(!ratchet_table_without_rowid(&legacy));

        let db = VeilDb::open_memory(&[0xC3; 32]).unwrap();
        db.conn
            .execute_batch(
                "CREATE TEMP VIEW external_temp_ratchet_capacity_view AS
                 SELECT row_count, total_session_bytes
                 FROM main.ratchet_session_capacity_v1;",
            )
            .unwrap();
        assert!(db.ensure_ratchet_sessions_without_rowid_schema().is_err());
        assert_eq!(
            db.conn
                .query_row(
                    "SELECT row_count, total_session_bytes
                     FROM external_temp_ratchet_capacity_view",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap(),
            (0, 0)
        );
        assert_eq!(
            db.conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'trigger'
                       AND name LIKE 'ratchet_session_capacity_%_v1'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            6
        );
    }

    #[test]
    fn ratchet_capacity_external_dependency_fails_closed_without_mutation() {
        let db = VeilDb::open_memory(&[0xC4; 32]).unwrap();
        let peer = [0xA7; 32];
        db.commit_initial_ratchet_session(&peer, b"capacity", None)
            .unwrap();
        db.conn
            .execute_batch(
                "CREATE VIEW external_ratchet_capacity_view AS
                 SELECT row_count, total_session_bytes
                 FROM ratchet_session_capacity_v1;",
            )
            .unwrap();
        let view_before: String = db
            .conn
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'view' AND name = 'external_ratchet_capacity_view'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(db.ensure_ratchet_sessions_without_rowid_schema().is_err());

        assert_eq!(
            db.conn
                .query_row(
                    "SELECT sql FROM sqlite_schema
                     WHERE type = 'view' AND name = 'external_ratchet_capacity_view'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            view_before
        );
        assert_eq!(ratchet_capacity(&db), (1, 8));
        assert_eq!(
            db.load_ratchet_session_with_revision_v1(&peer)
                .unwrap()
                .unwrap()
                .session_data,
            b"capacity"
        );
        assert_eq!(
            db.conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'trigger'
                       AND name LIKE 'ratchet_session_capacity_%_v1'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            6
        );
    }

    #[test]
    fn ratchet_capacity_triggers_gate_insert_and_update_atomically() {
        let db = VeilDb::open_memory(&[0xC6; 32]).unwrap();
        let peer = [0x41; 32];
        let second_peer = [0x42; 32];
        db.commit_initial_ratchet_session(&peer, b"a", None)
            .unwrap();
        assert_eq!(ratchet_capacity(&db), (1, 1));
        assert_eq!(
            db.compare_and_swap_ratchet_session_v1(&peer, 0, b"a", b"aaaa")
                .unwrap(),
            1
        );
        assert_eq!(ratchet_capacity(&db), (1, 4));
        assert_eq!(
            db.compare_and_swap_ratchet_session_v1(&peer, 1, b"aaaa", b"aa")
                .unwrap(),
            2
        );
        assert_eq!(ratchet_capacity(&db), (1, 2));

        db.commit_initial_ratchet_session(&second_peer, b"b", None)
            .unwrap();
        assert_eq!(ratchet_capacity(&db), (2, 3));
        for sql in [
            "INSERT OR IGNORE INTO ratchet_sessions
                 (peer_identity_key, session_data, revision, updated_at)
             VALUES (?1, x'63', 0, datetime('now'))",
            "INSERT INTO ratchet_sessions
                 (peer_identity_key, session_data, revision, updated_at)
             VALUES (?1, x'63', 0, datetime('now'))
             ON CONFLICT(peer_identity_key) DO UPDATE SET session_data = excluded.session_data",
            "INSERT OR REPLACE INTO ratchet_sessions
                 (peer_identity_key, session_data, revision, updated_at)
             VALUES (?1, x'63', 0, datetime('now'))",
        ] {
            assert!(db
                .conn
                .execute(sql, rusqlite::params![peer.as_slice()])
                .is_err());
            assert_eq!(ratchet_capacity(&db), (2, 3));
            let durable = db
                .load_ratchet_session_with_revision_v1(&peer)
                .unwrap()
                .unwrap();
            assert_eq!(durable.session_data, b"aa");
            assert_eq!(durable.revision, 2);
        }
        assert_ratchet_rowid_sql_is_unavailable(&db, &peer);
        assert_eq!(ratchet_capacity(&db), (2, 3));
        assert_eq!(
            db.load_ratchet_session_with_revision_v1(&peer)
                .unwrap()
                .unwrap()
                .session_data,
            b"aa"
        );
        assert_eq!(
            db.load_ratchet_session_with_revision_v1(&second_peer)
                .unwrap()
                .unwrap()
                .session_data,
            b"b"
        );
        assert_eq!(
            db.conn
                .execute(
                    "DELETE FROM ratchet_sessions WHERE peer_identity_key = ?1",
                    rusqlite::params![second_peer.as_slice()],
                )
                .unwrap(),
            1
        );
        assert_eq!(ratchet_capacity(&db), (1, 2));

        db.conn
            .execute(
                "UPDATE ratchet_session_capacity_v1 SET row_count = ?1
                 WHERE singleton = 1",
                rusqlite::params![DIRECT_RATCHET_SESSION_MAX_ROWS_SQLITE_V1],
            )
            .unwrap();
        assert!(db
            .commit_initial_ratchet_session(&second_peer, b"b", None)
            .is_err());
        assert!(db
            .load_ratchet_session_with_revision_v1(&second_peer)
            .unwrap()
            .is_none());
        assert_eq!(
            ratchet_capacity(&db),
            (DIRECT_RATCHET_SESSION_MAX_ROWS_SQLITE_V1, 2)
        );

        db.conn
            .execute(
                "UPDATE ratchet_session_capacity_v1
                 SET row_count = 1, total_session_bytes = ?1
                 WHERE singleton = 1",
                rusqlite::params![DIRECT_RATCHET_SESSION_MAX_TOTAL_BYTES_SQLITE_V1],
            )
            .unwrap();
        assert!(db
            .compare_and_swap_ratchet_session_v1(&peer, 2, b"aa", b"aaa")
            .is_err());
        let durable = db
            .load_ratchet_session_with_revision_v1(&peer)
            .unwrap()
            .unwrap();
        assert_eq!(durable.session_data, b"aa");
        assert_eq!(durable.revision, 2);
        assert_eq!(
            ratchet_capacity(&db),
            (1, DIRECT_RATCHET_SESSION_MAX_TOTAL_BYTES_SQLITE_V1)
        );
    }

    #[test]
    fn ratchet_capacity_last_slot_is_visible_across_file_handles() {
        let path = std::env::temp_dir().join(format!(
            "veil-ratchet-capacity-last-slot-{}.db",
            uuid::Uuid::new_v4()
        ));
        let key = [0xC5; 32];
        let first = VeilDb::open(&path, &key).unwrap();
        let second = VeilDb::open(&path, &key).unwrap();
        first
            .conn
            .execute(
                "UPDATE ratchet_session_capacity_v1 SET row_count = ?1
                 WHERE singleton = 1",
                rusqlite::params![DIRECT_RATCHET_SESSION_MAX_ROWS_SQLITE_V1 - 1],
            )
            .unwrap();

        let accepted_peer = [0x51; 32];
        let rejected_peer = [0x52; 32];
        first
            .commit_initial_ratchet_session(&accepted_peer, b"a", None)
            .unwrap();
        assert!(second
            .commit_initial_ratchet_session(&rejected_peer, b"b", None)
            .is_err());
        assert_eq!(
            ratchet_capacity(&first),
            (DIRECT_RATCHET_SESSION_MAX_ROWS_SQLITE_V1, 1)
        );
        assert!(second
            .load_ratchet_session_with_revision_v1(&rejected_peer)
            .unwrap()
            .is_none());
        drop(second);
        drop(first);

        let reopened = VeilDb::open(&path, &key).unwrap();
        assert_eq!(ratchet_capacity(&reopened), (1, 1));
        assert_eq!(
            reopened
                .load_ratchet_session_with_revision_v1(&accepted_peer)
                .unwrap()
                .unwrap()
                .session_data,
            b"a"
        );
        drop(reopened);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn direct_outbox_schema_and_ratchet_revision_upgrade_are_idempotent() {
        let db = VeilDb::open_memory(&[0xD0; 32]).unwrap();
        db.run_migrations().unwrap();
        db.run_migrations().unwrap();

        let revision_columns: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('ratchet_sessions')
                 WHERE name = 'revision' AND \"notnull\" = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revision_columns, 1);
        let capacity_peer = [0xD1; 32];
        db.commit_initial_ratchet_session(&capacity_peer, b"state", None)
            .unwrap();
        db.conn
            .execute(
                "UPDATE ratchet_session_capacity_v1
                 SET row_count = ?1, total_session_bytes = ?2
                 WHERE singleton = 1",
                rusqlite::params![
                    DIRECT_RATCHET_SESSION_MAX_ROWS_SQLITE_V1,
                    DIRECT_RATCHET_SESSION_MAX_TOTAL_BYTES_SQLITE_V1,
                ],
            )
            .unwrap();
        db.run_migrations().unwrap();
        assert_eq!(ratchet_capacity(&db), (1, 5));
        let capacity_triggers: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'trigger' AND name LIKE 'ratchet_session_capacity_%_v1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(capacity_triggers, 6);
        let schema = db.normalized_table_sql("direct_message_outbox_v1").unwrap();
        assert!(schema.contains("queue_order integer primary key autoincrement"));
        assert!(schema.contains("client_message_id text not null unique"));
        assert!(schema.contains("check(client_message_id = local_message_id)"));
        assert!(schema.contains("state in (0, 1, 2)"));
        let outbox_foreign_keys: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_list('direct_message_outbox_v1')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(outbox_foreign_keys, 0);

        let payload = b"opaque-protobuf-payload";
        let mut expected = Sha256::new();
        expected.update(b"veil.message.send.v1\x00");
        expected.update(payload);
        assert_eq!(
            direct_message_request_digest_v1(payload),
            <[u8; 32]>::from(expected.finalize())
        );
        assert_ne!(
            direct_message_request_digest_v1(payload),
            <[u8; 32]>::from(Sha256::digest(payload))
        );

        let legacy = Connection::open_in_memory().unwrap();
        legacy
            .execute_batch(
                "CREATE TABLE ratchet_sessions (
                    peer_identity_key BLOB PRIMARY KEY,
                    session_data BLOB NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );
                 INSERT INTO ratchet_sessions (peer_identity_key, session_data)
                 VALUES (x'0101010101010101010101010101010101010101010101010101010101010101',
                         x'0203');",
            )
            .unwrap();
        let legacy = VeilDb { conn: legacy };
        legacy
            .ensure_ratchet_sessions_without_rowid_schema()
            .unwrap();
        legacy
            .ensure_ratchet_sessions_without_rowid_schema()
            .unwrap();
        let preserved: (Vec<u8>, i64) = legacy
            .conn
            .query_row(
                "SELECT session_data, revision FROM ratchet_sessions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(preserved, (vec![2, 3], 0));
        assert!(ratchet_table_without_rowid(&legacy));
        assert_eq!(ratchet_capacity(&legacy), (1, 2));
        assert_ratchet_rowid_sql_is_unavailable(&legacy, &[1u8; 32]);
    }

    #[test]
    fn direct_outbox_empty_account_does_not_require_a_self_presentation_row() {
        let db = VeilDb::open_memory(&[0xCF; 32]).unwrap();
        let scope = install_direct_outbox_self_without_directory(&db);

        assert_eq!(table_count(&db, "identity_directory_v1"), 0);
        assert_eq!(table_count(&db, "direct_message_outbox_v1"), 0);
        assert_eq!(
            db.count_pending_direct_message_outbox_v1(&scope).unwrap(),
            0
        );
        assert!(db
            .load_pending_direct_message_outbox_v1(&scope, 1)
            .unwrap()
            .is_empty());
        assert_eq!(table_count(&db, "identity_directory_v1"), 0);
    }

    #[test]
    fn direct_outbox_empty_account_still_rejects_a_conflicting_directory_row() {
        let db = VeilDb::open_memory(&[0xCE; 32]).unwrap();
        let scope = install_direct_outbox_self_without_directory(&db);
        let conflicting_identity_key = [0x79u8; 32];
        let conflicting_signing_key = test_signing_key(0x7A);

        db.conn
            .execute(
                "INSERT INTO identity_directory_v1
                    (canonical_server_origin, user_id, identity_key, signing_key,
                     username, display_name, profile_version, profile_origin,
                     source, observed_at)
                 VALUES (?1, ?2, ?3, ?4, 'conflict', NULL, NULL, ?1, 2,
                         '2026-07-19T00:00:00Z')",
                rusqlite::params![
                    ORIGIN_A,
                    USER_A,
                    conflicting_identity_key.as_slice(),
                    conflicting_signing_key.as_slice(),
                ],
            )
            .unwrap();

        let error = db
            .count_pending_direct_message_outbox_v1(&scope)
            .unwrap_err();
        assert!(error.contains("conflicts with the authenticated self binding"));
        assert_eq!(table_count(&db, "direct_message_outbox_v1"), 0);
    }

    #[test]
    fn direct_outbox_self_presentation_is_an_optional_corroborating_cache() {
        let db = VeilDb::open_memory(&[0xCD; 32]).unwrap();
        let scope = install_direct_outbox_self_without_directory(&db);
        let self_account = sample_account(
            ORIGIN_A,
            USER_A,
            0x77,
            AccountSnapshotSource::AuthenticatedConversationDirectory,
            None,
        );

        db.upsert_identity_directory(std::slice::from_ref(&self_account))
            .unwrap();
        assert_eq!(table_count(&db, "identity_directory_v1"), 1);
        assert_eq!(
            db.count_pending_direct_message_outbox_v1(&scope).unwrap(),
            0
        );

        db.conn
            .execute(
                "DELETE FROM identity_directory_v1
                 WHERE canonical_server_origin = ?1 AND user_id = ?2",
                rusqlite::params![ORIGIN_A, USER_A],
            )
            .unwrap();

        assert_eq!(table_count(&db, "identity_directory_v1"), 0);
        assert_eq!(
            db.count_pending_direct_message_outbox_v1(&scope).unwrap(),
            0
        );
    }

    #[test]
    fn direct_outbox_empty_account_keeps_exact_origin_user_and_device_guards() {
        let db = VeilDb::open_memory(&[0xCC; 32]).unwrap();
        let scope = install_direct_outbox_self_without_directory(&db);

        let mut wrong_origin = scope.clone();
        wrong_origin.canonical_server_origin = ORIGIN_B.to_string();
        assert!(db
            .count_pending_direct_message_outbox_v1(&wrong_origin)
            .is_err());

        let mut wrong_user = scope.clone();
        wrong_user.user_id = USER_B.to_string();
        assert!(db
            .count_pending_direct_message_outbox_v1(&wrong_user)
            .is_err());

        let mut wrong_device = scope.clone();
        wrong_device.device_id = [0x7B; 16];
        assert!(db
            .count_pending_direct_message_outbox_v1(&wrong_device)
            .is_err());

        db.conn
            .execute(
                "UPDATE device_identity_v1 SET status = 2 WHERE singleton = 1",
                [],
            )
            .unwrap();
        assert!(db.count_pending_direct_message_outbox_v1(&scope).is_err());
        assert_eq!(table_count(&db, "direct_message_outbox_v1"), 0);
    }

    #[test]
    fn direct_outbox_enqueue_faults_roll_back_ratchet_and_every_private_row() {
        for (table, operation) in [
            ("ratchet_sessions", "UPDATE"),
            ("messages", "INSERT"),
            ("direct_message_outbox_v1", "INSERT"),
            ("message_author_snapshots_v1", "INSERT"),
        ] {
            let db = VeilDb::open_memory(&[0xD1; 32]).unwrap();
            let fixture = install_direct_outbox_fixture(&db);
            let capacity_before = ratchet_capacity(&db);
            db.conn
                .execute_batch(&format!(
                    "CREATE TRIGGER fail_direct_enqueue
                     BEFORE {operation} ON {table}
                     BEGIN SELECT RAISE(ABORT, 'injected direct enqueue failure'); END;"
                ))
                .unwrap();

            let mut input =
                direct_outbox_input(&fixture, DIRECT_CLIENT_ID_1, b"exact-send-payload-fault", 0);
            input
                .advanced_ratchet_session
                .extend_from_slice(b"-grown-before-late-fault");
            assert!(db.enqueue_direct_message_outbox_v1(&input).is_err());
            let ratchet = db
                .load_ratchet_session_with_revision_v1(&fixture.peer_account.locator.identity_key)
                .unwrap()
                .unwrap();
            assert_eq!(ratchet.session_data, b"ratchet-session-v0");
            assert_eq!(ratchet.revision, 0, "fault target: {table}");
            assert_eq!(
                ratchet_capacity(&db),
                capacity_before,
                "fault target: {table}"
            );
            assert_eq!(table_count(&db, "messages"), 0, "fault target: {table}");
            assert_eq!(
                table_count(&db, "message_attachments_v1"),
                0,
                "fault target: {table}"
            );
            assert_eq!(
                table_count(&db, "message_author_snapshots_v1"),
                0,
                "fault target: {table}"
            );
            assert_eq!(
                table_count(&db, "direct_message_outbox_v1"),
                0,
                "fault target: {table}"
            );
            let last_message_at: Option<String> = db
                .conn
                .query_row(
                    "SELECT last_message_at FROM conversations WHERE id = ?1",
                    rusqlite::params![DIRECT_CONVERSATION_ID],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(last_message_at.is_none(), "fault target: {table}");
        }
    }

    #[test]
    fn direct_outbox_reopens_exact_bytes_pages_fifo_and_cas_blocks_second_handle() {
        let path =
            std::env::temp_dir().join(format!("veil-direct-outbox-{}.db", uuid::Uuid::new_v4()));
        let key = [0xD2; 32];
        let first_payload = b"first exact serialized SendMessage".to_vec();
        let second_payload = b"second exact serialized SendMessage".to_vec();
        let fixture;
        {
            let first = VeilDb::open(&path, &key).unwrap();
            fixture = install_direct_outbox_fixture(&first);
            let second_handle = VeilDb::open(&path, &key).unwrap();
            let first_input = direct_outbox_input(&fixture, DIRECT_CLIENT_ID_1, &first_payload, 0);
            let committed = first
                .enqueue_direct_message_outbox_v1(&first_input)
                .unwrap();
            assert_eq!(committed.ratchet_revision, 1);

            let mut wrong_expected_bytes = direct_outbox_input(
                &fixture,
                DIRECT_CLIENT_ID_2,
                b"same revision, wrong expected ratchet bytes",
                1,
            );
            wrong_expected_bytes.expected_ratchet_session = b"wrong-state-at-revision-one".to_vec();
            assert!(second_handle
                .enqueue_direct_message_outbox_v1(&wrong_expected_bytes)
                .is_err());
            assert_eq!(message_status(&second_handle, DIRECT_CLIENT_ID_2), None);
            assert_eq!(table_count(&second_handle, "messages"), 1);
            assert_eq!(table_count(&second_handle, "message_attachments_v1"), 1);
            assert_eq!(table_count(&second_handle, "direct_message_outbox_v1"), 1);
            let durable_after_wrong_bytes = second_handle
                .load_ratchet_session_with_revision_v1(&fixture.peer_account.locator.identity_key)
                .unwrap()
                .unwrap();
            assert_eq!(
                durable_after_wrong_bytes.session_data,
                b"ratchet-session-v1"
            );
            assert_eq!(durable_after_wrong_bytes.revision, 1);

            let stale = direct_outbox_input(
                &fixture,
                DIRECT_CLIENT_ID_2,
                b"stale competing ciphertext",
                0,
            );
            assert!(second_handle
                .enqueue_direct_message_outbox_v1(&stale)
                .is_err());
            assert_eq!(message_status(&second_handle, DIRECT_CLIENT_ID_2), None);
            assert_eq!(
                second_handle
                    .load_ratchet_session_with_revision_v1(
                        &fixture.peer_account.locator.identity_key,
                    )
                    .unwrap()
                    .unwrap()
                    .revision,
                1
            );
        }
        {
            let reopened = VeilDb::open(&path, &key).unwrap();
            let first_page = reopened
                .load_pending_direct_message_outbox_v1(&fixture.scope, 1)
                .unwrap();
            assert_eq!(first_page.len(), 1);
            let first_row = &first_page[0];
            assert_eq!(first_row.client_message_id, DIRECT_CLIENT_ID_1);
            assert_eq!(first_row.local_message_id, DIRECT_CLIENT_ID_1);
            assert_eq!(first_row.exact_send_message_payload, first_payload);
            assert_eq!(
                first_row.request_digest,
                direct_message_request_digest_v1(&first_payload)
            );
            assert_eq!(first_row.peer_user_id, USER_B);
            assert_eq!(
                first_row.peer_identity_key,
                fixture.peer_account.locator.identity_key
            );
            assert_eq!(first_row.peer_signing_key, fixture.peer_account.signing_key);
            assert_eq!(first_row.ratchet_revision, 1);

            let second_input =
                direct_outbox_input(&fixture, DIRECT_CLIENT_ID_2, &second_payload, 1);
            let second_result = reopened
                .enqueue_direct_message_outbox_v1(&second_input)
                .unwrap();
            assert!(second_result.queue_order > first_row.queue_order);
            assert_eq!(
                reopened
                    .count_pending_direct_message_outbox_v1(&fixture.scope)
                    .unwrap(),
                2
            );
            let second_page = reopened
                .load_pending_direct_message_outbox_after_v1(
                    &fixture.scope,
                    Some(first_row.queue_order),
                    1,
                )
                .unwrap();
            assert_eq!(second_page.len(), 1);
            assert_eq!(second_page[0].client_message_id, DIRECT_CLIENT_ID_2);
            assert_eq!(second_page[0].exact_send_message_payload, second_payload);
            assert!(reopened
                .load_pending_direct_message_outbox_after_v1(
                    &fixture.scope,
                    Some(second_page[0].queue_order),
                    1,
                )
                .unwrap()
                .is_empty());
            assert!(reopened
                .load_pending_direct_message_outbox_after_v1(&fixture.scope, Some(0), 1)
                .is_err());
            assert!(reopened
                .load_pending_direct_message_outbox_v1(&fixture.scope, 0)
                .is_err());
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn direct_outbox_receipt_loader_never_aliases_a_foreign_scope_uuid() {
        let db = VeilDb::open_memory(&[0xD8; 32]).unwrap();
        let fixture = install_direct_outbox_fixture(&db);
        let input = direct_outbox_input(&fixture, DIRECT_CLIENT_ID_1, b"scope-isolated receipt", 0);
        db.enqueue_direct_message_outbox_v1(&input).unwrap();
        assert!(matches!(
            db.load_direct_message_outbox_receipt_v1(&fixture.scope, DIRECT_CLIENT_ID_1)
                .unwrap(),
            Some(DirectMessageOutboxReceiptV1::Pending {
                ref local_message_id,
            })
                if local_message_id == DIRECT_CLIENT_ID_1
        ));

        db.conn
            .execute(
                "UPDATE direct_message_outbox_v1 SET device_id = ?1
                 WHERE client_message_id = ?2",
                rusqlite::params![[0x76_u8; 16].as_slice(), DIRECT_CLIENT_ID_1],
            )
            .unwrap();
        assert!(db
            .load_direct_message_outbox_receipt_v1(&fixture.scope, DIRECT_CLIENT_ID_1)
            .unwrap()
            .is_none());

        db.conn
            .execute(
                "UPDATE direct_message_outbox_v1
                 SET device_id = ?1, canonical_server_origin = ?2
                 WHERE client_message_id = ?3",
                rusqlite::params![
                    fixture.scope.device_id.as_slice(),
                    ORIGIN_B,
                    DIRECT_CLIENT_ID_1
                ],
            )
            .unwrap();
        assert!(db
            .load_direct_message_outbox_receipt_v1(&fixture.scope, DIRECT_CLIENT_ID_1)
            .unwrap()
            .is_none());
    }

    #[test]
    fn direct_outbox_scope_drift_and_uuid_reuse_after_ack_fail_closed() {
        let db = VeilDb::open_memory(&[0xD3; 32]).unwrap();
        let fixture = install_direct_outbox_fixture(&db);
        let input = direct_outbox_input(
            &fixture,
            DIRECT_CLIENT_ID_1,
            b"scope-bound exact payload",
            0,
        );
        db.enqueue_direct_message_outbox_v1(&input).unwrap();

        let mut wrong_origin = fixture.scope.clone();
        wrong_origin.canonical_server_origin = ORIGIN_B.to_string();
        let mut wrong_user = fixture.scope.clone();
        wrong_user.user_id = USER_B.to_string();
        let mut wrong_device = fixture.scope.clone();
        wrong_device.device_id = [0x76; 16];
        for wrong_scope in [wrong_origin, wrong_user, wrong_device] {
            assert!(db
                .load_pending_direct_message_outbox_v1(&wrong_scope, 1)
                .is_err());
        }

        let ack = db
            .acknowledge_direct_message_outbox_v1(
                &fixture.scope,
                DIRECT_CLIENT_ID_1,
                DIRECT_SERVER_ID_1,
                1_700_000_000_001,
            )
            .unwrap();
        assert!(!ack.already_acknowledged);
        let repeated = db
            .acknowledge_direct_message_outbox_v1(
                &fixture.scope,
                DIRECT_CLIENT_ID_1,
                DIRECT_SERVER_ID_1,
                1_700_000_000_001,
            )
            .unwrap();
        assert!(repeated.already_acknowledged);
        assert!(db
            .acknowledge_direct_message_outbox_v1(
                &fixture.scope,
                DIRECT_CLIENT_ID_1,
                DIRECT_SERVER_ID_1,
                1_700_000_000_002,
            )
            .is_err());
        assert!(db
            .acknowledge_direct_message_outbox_v1(
                &fixture.scope,
                DIRECT_CLIENT_ID_1,
                DIRECT_SERVER_ID_2,
                1_700_000_000_001,
            )
            .is_err());

        let receipt: (i64, Option<Vec<u8>>, Vec<u8>) = db
            .conn
            .query_row(
                "SELECT state, exact_send_message_payload, request_digest
                 FROM direct_message_outbox_v1 WHERE client_message_id = ?1",
                rusqlite::params![DIRECT_CLIENT_ID_1],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(receipt.0, 1);
        assert!(receipt.1.is_none());
        assert_eq!(
            receipt.2,
            direct_message_request_digest_v1(b"scope-bound exact payload")
        );

        let reuse = direct_outbox_input(
            &fixture,
            DIRECT_CLIENT_ID_1,
            b"different ciphertext under reused UUID",
            1,
        );
        assert!(db.enqueue_direct_message_outbox_v1(&reuse).is_err());
        assert_eq!(
            db.load_ratchet_session_with_revision_v1(&fixture.peer_account.locator.identity_key)
                .unwrap()
                .unwrap()
                .revision,
            1
        );

        db.delete_message(DIRECT_SERVER_ID_1).unwrap();
        let second = direct_outbox_input(
            &fixture,
            DIRECT_CLIENT_ID_2,
            b"route drift pending payload",
            1,
        );
        db.enqueue_direct_message_outbox_v1(&second).unwrap();
        assert!(db
            .acknowledge_direct_message_outbox_v1(
                &fixture.scope,
                DIRECT_CLIENT_ID_2,
                DIRECT_SERVER_ID_1,
                1_700_000_000_001,
            )
            .is_err());
        assert_eq!(message_status(&db, DIRECT_CLIENT_ID_2), Some(0));
        db.conn
            .execute(
                "UPDATE conversations SET peer_identity_key = ?2 WHERE id = ?1",
                rusqlite::params![DIRECT_CONVERSATION_ID, [0x99u8; 32].as_slice()],
            )
            .unwrap();
        assert!(db
            .load_pending_direct_message_outbox_v1(&fixture.scope, 1)
            .is_err());

        let mut split_id =
            direct_outbox_input(&fixture, DIRECT_CLIENT_ID_3, b"split local correlation", 2);
        split_id.local_message_id = DIRECT_LEGACY_ID_1.to_string();
        assert!(db.enqueue_direct_message_outbox_v1(&split_id).is_err());
    }

    #[test]
    fn direct_outbox_ack_collision_and_fault_roll_back_then_migrate_references() {
        const REPLY_ID: &str = "50000000-0000-4000-8000-000000000001";
        let db = VeilDb::open_memory(&[0xD4; 32]).unwrap();
        let fixture = install_direct_outbox_fixture(&db);
        let input =
            direct_outbox_input(&fixture, DIRECT_CLIENT_ID_1, b"ack atomic exact payload", 0);
        db.enqueue_direct_message_outbox_v1(&input).unwrap();

        db.insert_message(
            DIRECT_SERVER_ID_1,
            DIRECT_CONVERSATION_ID,
            &fixture.peer_account.locator.identity_key,
            "collision",
            false,
            Some(10),
            None,
        )
        .unwrap();
        assert!(db
            .acknowledge_direct_message_outbox_v1(
                &fixture.scope,
                DIRECT_CLIENT_ID_1,
                DIRECT_SERVER_ID_1,
                1_700_000_000_010,
            )
            .is_err());
        assert_eq!(message_status(&db, DIRECT_CLIENT_ID_1), Some(0));
        db.delete_message(DIRECT_SERVER_ID_1).unwrap();

        db.conn
            .execute_batch(
                "CREATE TRIGGER fail_direct_ack_receipt
                 BEFORE UPDATE OF state ON direct_message_outbox_v1
                 WHEN NEW.state = 1
                 BEGIN SELECT RAISE(ABORT, 'injected direct ACK failure'); END;",
            )
            .unwrap();
        assert!(db
            .acknowledge_direct_message_outbox_v1(
                &fixture.scope,
                DIRECT_CLIENT_ID_1,
                DIRECT_SERVER_ID_1,
                1_700_000_000_010,
            )
            .is_err());
        assert_eq!(message_status(&db, DIRECT_CLIENT_ID_1), Some(0));
        assert_eq!(message_status(&db, DIRECT_SERVER_ID_1), None);
        let pending_shape: (i64, bool) = db
            .conn
            .query_row(
                "SELECT state, exact_send_message_payload IS NOT NULL
                 FROM direct_message_outbox_v1 WHERE client_message_id = ?1",
                rusqlite::params![DIRECT_CLIENT_ID_1],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(pending_shape, (0, true));
        db.conn
            .execute_batch("DROP TRIGGER fail_direct_ack_receipt")
            .unwrap();

        db.insert_message(
            REPLY_ID,
            DIRECT_CONVERSATION_ID,
            &fixture.peer_account.locator.identity_key,
            "reply",
            false,
            Some(11),
            Some(DIRECT_CLIENT_ID_1),
        )
        .unwrap();
        db.conn
            .execute(
                "INSERT INTO reactions (message_id, user_id, emoji, username)
                 VALUES (?1, ?2, 'ok', 'peer')",
                rusqlite::params![DIRECT_CLIENT_ID_1, USER_B],
            )
            .unwrap();
        db.acknowledge_direct_message_outbox_v1(
            &fixture.scope,
            DIRECT_CLIENT_ID_1,
            DIRECT_SERVER_ID_1,
            1_700_000_000_010,
        )
        .unwrap();
        assert_eq!(message_status(&db, DIRECT_CLIENT_ID_1), None);
        assert_eq!(message_status(&db, DIRECT_SERVER_ID_1), Some(1));
        let timestamp: i64 = db
            .conn
            .query_row(
                "SELECT server_timestamp FROM messages WHERE id = ?1",
                rusqlite::params![DIRECT_SERVER_ID_1],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(timestamp, 1_700_000_000_010);
        let reply_target: String = db
            .conn
            .query_row(
                "SELECT reply_to_id FROM messages WHERE id = ?1",
                rusqlite::params![REPLY_ID],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reply_target, DIRECT_SERVER_ID_1);
        for table in ["message_attachments_v1", "message_author_snapshots_v1"] {
            let migrated: i64 = db
                .conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE message_id = ?1"),
                    rusqlite::params![DIRECT_SERVER_ID_1],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(migrated, 1, "table: {table}");
        }
        let reaction_target: String = db
            .conn
            .query_row("SELECT message_id FROM reactions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(reaction_target, DIRECT_SERVER_ID_1);
    }

    #[test]
    fn direct_outbox_recovery_transport_loss_and_permanent_rejection_split_cleanly() {
        const MISSING_ID: &str = "60000000-0000-4000-8000-000000000001";
        let db = VeilDb::open_memory(&[0xD5; 32]).unwrap();
        let fixture = install_direct_outbox_fixture(&db);
        let input =
            direct_outbox_input(&fixture, DIRECT_CLIENT_ID_1, b"retryable exact payload", 0);
        db.enqueue_direct_message_outbox_v1(&input).unwrap();
        db.insert_outgoing_pending_message(
            DIRECT_LEGACY_ID_1,
            DIRECT_CONVERSATION_ID,
            &fixture.self_account.locator.identity_key,
            "legacy sending one",
            None,
        )
        .unwrap();
        assert_eq!(db.recover_unacknowledged_outgoing_messages().unwrap(), 1);
        assert_eq!(message_status(&db, DIRECT_CLIENT_ID_1), Some(0));
        assert_eq!(message_status(&db, DIRECT_LEGACY_ID_1), Some(5));

        db.insert_outgoing_pending_message(
            DIRECT_LEGACY_ID_2,
            DIRECT_CONVERSATION_ID,
            &fixture.self_account.locator.identity_key,
            "legacy sending two",
            None,
        )
        .unwrap();
        assert_eq!(
            db.reconcile_outgoing_transport_loss_v1(&[
                DIRECT_CLIENT_ID_1.to_string(),
                DIRECT_LEGACY_ID_2.to_string(),
            ])
            .unwrap(),
            1
        );
        assert_eq!(message_status(&db, DIRECT_CLIENT_ID_1), Some(0));
        assert_eq!(message_status(&db, DIRECT_LEGACY_ID_2), Some(5));

        db.insert_outgoing_pending_message(
            DIRECT_LEGACY_ID_3,
            DIRECT_CONVERSATION_ID,
            &fixture.self_account.locator.identity_key,
            "legacy sending three",
            None,
        )
        .unwrap();
        assert!(db
            .reconcile_outgoing_transport_loss_v1(&[
                DIRECT_LEGACY_ID_3.to_string(),
                MISSING_ID.to_string(),
            ])
            .is_err());
        assert_eq!(message_status(&db, DIRECT_LEGACY_ID_3), Some(0));

        let rejected = db
            .reject_direct_message_outbox_v1(
                &fixture.scope,
                DIRECT_CLIENT_ID_1,
                "permission_denied",
            )
            .unwrap();
        assert!(!rejected.already_rejected);
        assert_eq!(message_status(&db, DIRECT_CLIENT_ID_1), Some(4));
        assert_eq!(
            db.count_pending_direct_message_outbox_v1(&fixture.scope)
                .unwrap(),
            0
        );
        let rejected_shape: (i64, Option<Vec<u8>>, Option<String>, Vec<u8>) = db
            .conn
            .query_row(
                "SELECT state, exact_send_message_payload, rejection_reason, request_digest
                 FROM direct_message_outbox_v1 WHERE client_message_id = ?1",
                rusqlite::params![DIRECT_CLIENT_ID_1],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(rejected_shape.0, 2);
        assert!(rejected_shape.1.is_none());
        assert_eq!(rejected_shape.2.as_deref(), Some("permission_denied"));
        assert_eq!(
            rejected_shape.3,
            direct_message_request_digest_v1(b"retryable exact payload")
        );
        assert!(
            db.reject_direct_message_outbox_v1(
                &fixture.scope,
                DIRECT_CLIENT_ID_1,
                "different_reason",
            )
            .is_err()
        );
        assert!(db
            .reject_direct_message_outbox_v1(
                &fixture.scope,
                DIRECT_CLIENT_ID_1,
                "Permission Denied",
            )
            .is_err());

        db.discard_failed_outgoing_message(DIRECT_CLIENT_ID_1)
            .unwrap();
        assert_eq!(message_status(&db, DIRECT_CLIENT_ID_1), None);
        assert!(
            db.reject_direct_message_outbox_v1(
                &fixture.scope,
                DIRECT_CLIENT_ID_1,
                "permission_denied",
            )
            .unwrap()
            .already_rejected
        );
        let reuse = direct_outbox_input(
            &fixture,
            DIRECT_CLIENT_ID_1,
            b"must not reuse rejected UUID",
            1,
        );
        assert!(db.enqueue_direct_message_outbox_v1(&reuse).is_err());
        assert_eq!(message_status(&db, DIRECT_CLIENT_ID_1), None);
        assert_eq!(
            db.load_ratchet_session_with_revision_v1(&fixture.peer_account.locator.identity_key)
                .unwrap()
                .unwrap()
                .revision,
            1
        );
    }

    #[test]
    fn direct_v1_vector_roundtrips_exact_ratchet_and_pending_header_through_sqlcipher_cas() {
        let vector_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../test-vectors/direct-v1/v1.json");
        let vector_json = std::fs::read_to_string(&vector_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", vector_path.display()));
        let vector: DirectV1StoreVector = serde_json::from_str(&vector_json)
            .unwrap_or_else(|error| panic!("parse {}: {error}", vector_path.display()));
        let peer_identity_key: [u8; 32] = decode_direct_v1_vector_b64(
            "Bob identity",
            &vector.expected.identities.bob.x25519_public_b64,
        )
        .try_into()
        .unwrap_or_else(|value: Vec<u8>| {
            panic!(
                "Direct-v1 Bob identity has {} bytes, expected 32",
                value.len()
            )
        });
        let peer_signing_key: [u8; 32] = decode_direct_v1_vector_b64(
            "Bob signing identity",
            &vector.expected.identities.bob.ed25519_public_b64,
        )
        .try_into()
        .unwrap_or_else(|value: Vec<u8>| {
            panic!(
                "Direct-v1 Bob signing identity has {} bytes, expected 32",
                value.len()
            )
        });
        let initiator_before = decode_direct_v1_vector_b64(
            "initiator pre-message session",
            &vector.expected.sessions.initiator_before_message_json_b64,
        );
        let initiator_after = decode_direct_v1_vector_b64(
            "initiator post-message session",
            &vector.expected.sessions.initiator_after_message_json_b64,
        );
        let pending_initial_header = decode_direct_v1_vector_b64(
            "pending initial header",
            &vector.expected.headers.pending_initial_json_b64,
        );
        assert!(!initiator_before.is_empty());
        assert!(!initiator_after.is_empty());
        assert_ne!(initiator_before, initiator_after);
        assert!(!pending_initial_header.is_empty());

        let path =
            std::env::temp_dir().join(format!("veil-direct-v1-vector-{}.db", uuid::Uuid::new_v4()));
        let key = [0x5A; 32];
        remove_sqlcipher_test_files(&path);

        let fixture;
        {
            let db = VeilDb::open(&path, &key).unwrap();
            fixture = install_direct_outbox_fixture_with_ratchet(
                &db,
                peer_identity_key,
                peer_signing_key,
                &initiator_before,
                &pending_initial_header,
            );
            let stored = db
                .load_ratchet_session_with_revision_v1(&peer_identity_key)
                .unwrap()
                .unwrap();
            assert_eq!(stored.session_data, initiator_before);
            assert_eq!(stored.revision, 0);
            assert_eq!(
                db.load_pending_initial_headers().unwrap(),
                vec![(peer_identity_key, pending_initial_header.clone())]
            );
        }

        {
            let db = VeilDb::open(&path, &key).unwrap();
            let stored = db
                .load_ratchet_session_with_revision_v1(&peer_identity_key)
                .unwrap()
                .unwrap();
            assert_eq!(stored.session_data, initiator_before);
            assert_eq!(stored.revision, 0);
            assert_eq!(
                db.load_pending_initial_headers().unwrap(),
                vec![(peer_identity_key, pending_initial_header.clone())]
            );

            let mut enqueue = direct_outbox_input(
                &fixture,
                DIRECT_CLIENT_ID_1,
                b"phase-5s Direct-v1 exact-byte store evidence",
                0,
            );
            enqueue.expected_ratchet_session = initiator_before.clone();
            enqueue.advanced_ratchet_session = initiator_after.clone();
            let committed = db.enqueue_direct_message_outbox_v1(&enqueue).unwrap();
            assert_eq!(committed.ratchet_revision, 1);

            let mut stale = direct_outbox_input(
                &fixture,
                DIRECT_CLIENT_ID_2,
                b"phase-5s stale Direct-v1 CAS",
                0,
            );
            stale.expected_ratchet_session = initiator_before.clone();
            stale.advanced_ratchet_session = initiator_before.clone();
            let stale_error = match db.enqueue_direct_message_outbox_v1(&stale) {
                Ok(_) => panic!("stale Direct-v1 ratchet CAS unexpectedly committed"),
                Err(error) => error,
            };
            assert!(stale_error.contains("ratchet revision changed"));
        }

        {
            let db = VeilDb::open(&path, &key).unwrap();
            let stored = db
                .load_ratchet_session_with_revision_v1(&peer_identity_key)
                .unwrap()
                .unwrap();
            assert_eq!(stored.session_data, initiator_after);
            assert_eq!(stored.revision, 1);
            assert_eq!(
                db.load_pending_initial_headers().unwrap(),
                vec![(peer_identity_key, pending_initial_header)]
            );
            assert_eq!(
                db.load_pending_direct_message_outbox_v1(&fixture.scope, 1)
                    .unwrap()[0]
                    .ratchet_revision,
                1
            );
            assert_eq!(
                db.count_pending_direct_message_outbox_v1(&fixture.scope)
                    .unwrap(),
                1
            );
        }

        remove_sqlcipher_test_files(&path);
    }

    fn transparency_proof(
        signing: &SigningKey,
        events: &[Vec<u8>],
        leaf_index: usize,
        consistency_from: usize,
        issued_at_ms: u64,
    ) -> IdentityTransparencyProofV1 {
        use veil_crypto::transparency::{
            consistency_proof_v1, inclusion_proof_v1, log_id_v1, tree_root_v1,
            TransparencyTreeHeadV1,
        };

        let node_signing_key = signing.verifying_key().to_bytes();
        let log_id = log_id_v1(ORIGIN_A, &node_signing_key).unwrap();
        let root_hash = tree_root_v1(events).unwrap();
        let head = TransparencyTreeHeadV1 {
            log_id,
            tree_size: events.len() as u64,
            root_hash,
            issued_at_ms,
        };
        let signature = signing
            .sign(&head.signing_message(ORIGIN_A).unwrap())
            .to_bytes();
        IdentityTransparencyProofV1 {
            canonical_server_origin: ORIGIN_A.to_string(),
            log_id,
            node_signing_key,
            tree_size: events.len() as u64,
            root_hash,
            issued_at_ms,
            tree_head_signature: signature,
            canonical_event: events[leaf_index].clone(),
            leaf_index: leaf_index as u64,
            inclusion_proof: inclusion_proof_v1(events, leaf_index).unwrap(),
            consistency_from: consistency_from as u64,
            consistency_proof: if consistency_from == 0 || consistency_from == events.len() {
                Vec::new()
            } else {
                consistency_proof_v1(events, consistency_from).unwrap()
            },
            witness_policy_hash: [0u8; 32],
            witness_quorum: 0,
        }
    }

    fn transparency_anchor_from_proof(
        proof: &IdentityTransparencyProofV1,
    ) -> IdentityTransparencyPinnedHeadV1 {
        IdentityTransparencyPinnedHeadV1 {
            canonical_server_origin: proof.canonical_server_origin.clone(),
            log_id: proof.log_id,
            node_signing_key: proof.node_signing_key,
            tree_size: proof.tree_size,
            root_hash: proof.root_hash,
            issued_at_ms: proof.issued_at_ms,
            tree_head_signature: proof.tree_head_signature,
            witness_policy_hash: proof.witness_policy_hash,
            witness_quorum: proof.witness_quorum,
        }
    }

    #[test]
    fn transparency_pin_is_append_only_and_preserves_signed_alarm_evidence() {
        let db = VeilDb::open_memory(&[0x5A; 32]).unwrap();
        let signing = SigningKey::from_bytes(&[0x61; 32]);
        let mut events = vec![b"account-a".to_vec(), b"device-a-v1".to_vec()];

        let first = transparency_proof(&signing, &events, 0, 0, 1_710_000_000_001);
        assert_eq!(
            db.verify_and_pin_identity_transparency_proof_v1(&first)
                .unwrap(),
            IdentityTransparencyAcceptanceV1::FirstContactPinned
        );
        let pinned = db
            .identity_transparency_pinned_head_v1(ORIGIN_A)
            .unwrap()
            .unwrap();
        assert_eq!(pinned.tree_size, 2);
        assert_eq!(pinned.root_hash, first.root_hash);
        assert_eq!(pinned.witness_quorum, 0);

        let current = transparency_proof(&signing, &events, 1, 2, 1_710_000_000_002);
        assert_eq!(
            db.verify_and_pin_identity_transparency_proof_v1(&current)
                .unwrap(),
            IdentityTransparencyAcceptanceV1::CurrentHeadConfirmed
        );

        events.push(b"device-a-v2".to_vec());
        let advance = transparency_proof(&signing, &events, 2, 2, 1_710_000_000_003);
        assert_eq!(
            db.verify_and_pin_identity_transparency_proof_v1(&advance)
                .unwrap(),
            IdentityTransparencyAcceptanceV1::AppendOnlyAdvancePinned
        );
        assert_eq!(
            db.identity_transparency_pinned_head_v1(ORIGIN_A)
                .unwrap()
                .unwrap()
                .tree_size,
            3
        );

        let rollback = transparency_proof(&signing, &events[..2], 0, 0, 1_710_000_000_004);
        assert!(db
            .verify_and_pin_identity_transparency_proof_v1(&rollback)
            .unwrap_err()
            .contains("rollback"));
        assert_eq!(
            db.identity_transparency_alarm_count_v1(ORIGIN_A).unwrap(),
            1
        );

        let split_events = vec![
            b"account-a".to_vec(),
            b"device-a-v1".to_vec(),
            b"attacker-split-leaf".to_vec(),
        ];
        let split = transparency_proof(&signing, &split_events, 2, 3, 1_710_000_000_005);
        assert!(db
            .verify_and_pin_identity_transparency_proof_v1(&split)
            .unwrap_err()
            .contains("split view"));
        assert_eq!(
            db.identity_transparency_alarm_count_v1(ORIGIN_A).unwrap(),
            2
        );

        events.push(b"account-b".to_vec());
        let mut non_append_only = transparency_proof(&signing, &events, 3, 3, 1_710_000_000_006);
        non_append_only.consistency_proof[0][0] ^= 1;
        assert!(db
            .verify_and_pin_identity_transparency_proof_v1(&non_append_only)
            .unwrap_err()
            .contains("non-append-only"));
        assert_eq!(
            db.identity_transparency_alarm_count_v1(ORIGIN_A).unwrap(),
            3
        );

        let replacement_signing = SigningKey::from_bytes(&[0x62; 32]);
        let replacement = transparency_proof(
            &replacement_signing,
            &[b"replacement-log".to_vec()],
            0,
            0,
            1_710_000_000_007,
        );
        assert!(db
            .verify_and_pin_identity_transparency_proof_v1(&replacement)
            .unwrap_err()
            .contains("replacement"));
        assert_eq!(
            db.identity_transparency_alarm_count_v1(ORIGIN_A).unwrap(),
            4
        );
        assert!(db
            .verify_and_pin_identity_transparency_proof_v1(&replacement)
            .is_err());
        assert_eq!(
            db.identity_transparency_alarm_count_v1(ORIGIN_A).unwrap(),
            4
        );

        let final_pin = db
            .identity_transparency_pinned_head_v1(ORIGIN_A)
            .unwrap()
            .unwrap();
        assert_eq!(final_pin.tree_size, 3);
        assert_eq!(final_pin.root_hash, advance.root_hash);
    }

    #[test]
    fn transparency_os_anchor_recovers_rolled_back_sqlcipher_and_rejects_split_views() {
        let signing = SigningKey::from_bytes(&[0x63; 32]);
        let events = vec![
            b"account-a".to_vec(),
            b"device-a-v1".to_vec(),
            b"device-a-v2".to_vec(),
        ];
        let db = VeilDb::open_memory(&[0x5B; 32]).unwrap();
        let old = transparency_proof(&signing, &events[..2], 0, 0, 1_710_000_001_001);
        db.verify_and_pin_identity_transparency_proof_v1(&old)
            .unwrap();

        let anchored_proof = transparency_proof(&signing, &events, 2, 3, 1_710_000_001_002);
        let anchor = transparency_anchor_from_proof(&anchored_proof);
        assert_eq!(
            db.verify_and_pin_identity_transparency_proof_with_anchor_v1(
                &anchored_proof,
                Some(&anchor),
            )
            .unwrap(),
            IdentityTransparencyAcceptanceV1::RollbackAnchorRecovered
        );
        assert_eq!(
            db.identity_transparency_pinned_head_v1(ORIGIN_A)
                .unwrap()
                .unwrap()
                .tree_size,
            3
        );

        let rollback = transparency_proof(&signing, &events[..2], 1, 2, 1_710_000_001_003);
        assert!(db
            .verify_and_pin_identity_transparency_proof_with_anchor_v1(&rollback, Some(&anchor),)
            .unwrap_err()
            .contains("rollback"));

        let split_db = VeilDb::open_memory(&[0x5C; 32]).unwrap();
        split_db
            .verify_and_pin_identity_transparency_proof_v1(&old)
            .unwrap();
        let split_events = vec![b"account-a".to_vec(), b"attacker-device".to_vec()];
        let split_proof = transparency_proof(&signing, &split_events, 1, 2, 1_710_000_001_004);
        let split_anchor = transparency_anchor_from_proof(&split_proof);
        assert!(split_db
            .verify_and_pin_identity_transparency_proof_with_anchor_v1(&old, Some(&split_anchor),)
            .unwrap_err()
            .contains("conflicts with the OS rollback anchor"));
        assert_eq!(
            split_db
                .identity_transparency_alarm_count_v1(ORIGIN_A)
                .unwrap(),
            1
        );
    }
}
