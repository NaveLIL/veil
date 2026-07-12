use serde::{Deserialize, Serialize};

/// Conversation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConversationType {
    DM = 0,
    Group = 1,
    Channel = 2,
}

/// Canonical account locator within one authenticated server origin.
///
/// A server-assigned user UUID is deliberately not treated as globally
/// unique: self-hosted Veil instances may issue the same UUID independently.
/// The account X25519 identity is part of the locator so a future, explicit
/// identity-change flow can distinguish old and new cryptographic identities.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileLocator {
    pub canonical_server_origin: String,
    pub user_id: String,
    pub identity_key: [u8; 32],
}

/// Authority of an account snapshot's presentation metadata.
///
/// Ordering is intentional. Historical message metadata is authenticated by
/// the retained message/device proof, but a current authenticated conversation
/// directory is authoritative for the current account presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum AccountSnapshotSource {
    AuthenticatedHistory = 1,
    AuthenticatedConversationDirectory = 2,
}

impl AccountSnapshotSource {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::AuthenticatedHistory),
            2 => Some(Self::AuthenticatedConversationDirectory),
            _ => None,
        }
    }
}

/// Origin-scoped account metadata retained inside SQLCipher.
///
/// Presentation fields never participate in crypto trust, ACL decisions, or
/// Sender-Key rotation. `profile_version = None` is a truthful statement that
/// the authenticated source did not provide versioned profile metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSnapshot {
    pub locator: ProfileLocator,
    pub signing_key: [u8; 32],
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub profile_version: Option<u64>,
    pub profile_origin: String,
    pub source: AccountSnapshotSource,
    pub observed_at: String,
}

/// Message delivery status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageStatus {
    Sending = 0,
    Sent = 1,
    Delivered = 2,
    Read = 3,
    Failed = 4,
    Unknown = 5,
}

/// A conversation (DM, group, or channel).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub conv_type: ConversationType,
    pub peer_identity_key: Option<Vec<u8>>,
    pub server_id: Option<String>,
    pub server_origin: Option<String>,
    pub peer_user_id: Option<String>,
    pub name: Option<String>,
    pub last_message_at: Option<String>,
    pub created_at: String,
}

/// A decrypted message (stored locally in SQLCipher).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub conversation_id: String,
    pub sender_key: Vec<u8>,
    pub plaintext: String,
    pub msg_type: u8,
    pub reply_to_id: Option<String>,
    pub is_outgoing: bool,
    pub status: MessageStatus,
    pub expires_at: Option<String>,
    pub server_timestamp: Option<i64>,
    pub created_at: String,
    pub author: Option<AccountSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteReaction {
    pub emoji: String,
    pub user_id: String,
    pub username: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RemoteMessageStateKind {
    Active = 0,
    Deleted = 1,
    Expired = 2,
    Unavailable = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteMessageState {
    pub message_id: String,
    pub conversation_id: String,
    pub sender_key: Vec<u8>,
    pub revision_ms: i64,
    pub state: RemoteMessageStateKind,
}

/// A contact (known user).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub identity_key: Vec<u8>,
    pub signing_key: Vec<u8>,
    pub username: String,
    pub verified: bool,
    pub created_at: String,
}

/// Role within a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum GroupRole {
    Member = 0,
    Admin = 1,
    Owner = 2,
}

/// A member of a group conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub group_id: String,
    pub identity_key: Vec<u8>,
    pub role: GroupRole,
    pub joined_at: String,
}

/// Local sender key state (persisted for group encryption).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSenderKey {
    pub group_id: String,
    pub sender_identity_key: Vec<u8>,
    pub key_data: Vec<u8>,
    pub is_outgoing: bool,
    pub updated_at: String,
}

// ─── Discord-like server cache models ──────────────────────────────────

/// Cached server (offline rendering of the server rail).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedServer {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub owner_id: String,
    pub position: i32,
    pub created_at: String,
}

/// Cached channel within a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedChannel {
    pub id: String,
    pub server_id: String,
    pub conversation_id: Option<String>,
    pub name: String,
    pub channel_type: i16, // 0=text, 1=voice, 2=category
    pub category_id: Option<String>,
    pub position: i32,
    pub topic: Option<String>,
    pub nsfw: bool,
    pub slowmode_secs: i32,
}

/// Cached role within a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRole {
    pub id: String,
    pub server_id: String,
    pub name: String,
    pub permissions: u64,
    pub position: i32,
    pub color: Option<i32>,
    pub is_default: bool,
    pub hoist: bool,
    pub mentionable: bool,
}

/// Cached server member with role assignments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedServerMember {
    pub server_id: String,
    pub user_id: String,
    pub username: String,
    pub nickname: Option<String>,
    pub role_ids: Vec<String>,
    pub joined_at: String,
}
