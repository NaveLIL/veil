use serde::{Deserialize, Serialize};

/// Conversation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConversationType {
    DM = 0,
    Group = 1,
    Channel = 2,
}

/// Message delivery status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageStatus {
    Sending = 0,
    Sent = 1,
    Delivered = 2,
    Read = 3,
}

/// A conversation (DM, group, or channel).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub conv_type: ConversationType,
    pub peer_identity_key: Option<Vec<u8>>,
    pub server_id: Option<String>,
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
