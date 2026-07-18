use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::mem::size_of;
use std::sync::{Arc, Mutex as StdMutex};

use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, watch, Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{protocol::WebSocketConfig, Message as WsMessage},
};
use tracing::{info, warn};
use uuid::Uuid;
use zeroize::Zeroize;

use veil_crypto::signature;
use veil_crypto::IdentityKeyPair;

use crate::device_identity::{
    device_binding_signing_bytes, DeviceBindingPublicV1, DeviceIdentityV1,
    DEVICE_BINDING_STATUS_ACTIVE, REQUIRED_DEVICE_CAPABILITIES,
};
use crate::protocol::proto;

const MAX_RETAINED_SKDM_EVENTS: usize = 2_048;
const MAX_RETAINED_SKDM_WIRE_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_RETAINED_SKDM_METADATA_BYTES: usize = 1024 * 1024;
const MAX_RETAINED_SKDM_WIRE_BYTES: usize = 4_096;
const AUTH_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
const OUTBOUND_QUEUE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) const LIVE_EVENT_QUEUE_CAPACITY: usize = 4_096;
pub(crate) const LIVE_EVENT_RETAINED_BYTES: usize = 32 * 1024 * 1024;
const MAX_TERMINAL_REASON_BYTES: usize = 4 * 1024;
const MAX_EVENT_ID_BYTES: usize = 256;
const MAX_EVENT_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MAX_EVENT_HEADER_BYTES: usize = 512;

fn client_version(client_id: &str) -> String {
    format!("{client_id}/{}", env!("CARGO_PKG_VERSION"))
}

fn node_access_invite_wire_value(invite: Option<&[u8]>) -> Result<Vec<u8>, String> {
    match invite {
        None => Ok(Vec::new()),
        Some(value) if value.len() == 32 => Ok(value.to_vec()),
        Some(_) => Err("node access pass must contain exactly 32 bytes".to_string()),
    }
}

/// Configuration for the WebSocket connection.
pub struct ConnectionConfig {
    pub server_url: String,
}

/// Reject cleartext remote transports. Local loopback WebSockets remain
/// available for development and integration tests.
fn validate_websocket_url(raw: &str) -> Result<(), String> {
    let parsed = url::Url::parse(raw).map_err(|e| format!("invalid WebSocket URL: {e}"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("WebSocket URLs must not contain userinfo or passwords".to_string());
    }
    if parsed.fragment().is_some() {
        return Err("WebSocket URLs must not contain fragments".to_string());
    }
    match parsed.scheme() {
        "wss" => Ok(()),
        "ws" => match parsed.host_str() {
            Some("localhost" | "127.0.0.1" | "::1" | "[::1]") => Ok(()),
            _ => Err("insecure ws:// is allowed only for localhost/loopback".to_string()),
        },
        scheme => Err(format!(
            "unsupported WebSocket scheme {scheme:?}; use wss://"
        )),
    }
}

fn websocket_auth_signature(
    identity: &IdentityKeyPair,
    challenge: &[u8],
) -> Result<[u8; 64], String> {
    let challenge_key: [u8; 32] = challenge
        .try_into()
        .map_err(|_| "invalid auth challenge: expected 32-byte X25519 key".to_string())?;
    let mut shared = identity.x25519_dh(&challenge_key);
    if bool::from(shared.ct_eq(&[0u8; 32])) {
        shared.zeroize();
        return Err("invalid auth challenge: all-zero X25519 shared secret".to_string());
    }
    let mut proof = Vec::with_capacity(b"veil-ws-auth-v2\0".len() + 64);
    proof.extend_from_slice(b"veil-ws-auth-v2\0");
    proof.extend_from_slice(&challenge_key);
    proof.extend_from_slice(&shared);
    let signature = signature::sign(identity, &proof);
    shared.zeroize();
    proof.zeroize();
    Ok(signature)
}

fn validate_per_device_auth_result(
    result: &proto::AuthResult,
    expected: &DeviceBindingPublicV1,
) -> Result<String, String> {
    if !result.success {
        let message = match proto::AuthFailureReason::try_from(result.failure_reason) {
            Ok(proto::AuthFailureReason::RegistrationClosed) => {
                "node access registration is closed; a valid access pass is required".to_string()
            }
            Ok(proto::AuthFailureReason::InviteInvalid) => {
                "node access pass is invalid, expired, or already used".to_string()
            }
            _ => {
                let detail = result.error_message.as_deref().unwrap_or_default().trim();
                if detail.is_empty() {
                    "authentication failed".to_string()
                } else {
                    format!("authentication failed: {detail}")
                }
            }
        };
        return Err(message);
    }
    if !result.per_device_secure {
        return Err(
            "server authenticated only the legacy account identity; per-device proof missing"
                .to_string(),
        );
    }
    if result.device_binding_version != expected.version {
        return Err("server confirmed a different device binding version".to_string());
    }
    if result.device_binding_status != i32::from(DEVICE_BINDING_STATUS_ACTIVE)
        || result.device_binding_status != i32::from(expected.status)
    {
        return Err("server did not confirm an active device binding".to_string());
    }
    let user_id = result.user_id.clone().unwrap_or_default();
    if user_id.is_empty() {
        return Err("server authenticated without a user id".to_string());
    }
    Ok(user_id)
}

/// Events emitted by the connection to the application layer.
#[derive(Debug, Clone)]
pub struct FriendInfo {
    pub user_id: String,
    pub username: String,
    pub status: i32,
    pub last_seen: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct FriendRequestInfo {
    pub request_id: String,
    pub from_user_id: String,
    pub from_username: String,
    pub message: Option<String>,
    pub timestamp: u64,
    pub outgoing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderKeyAckMetadataV1 {
    pub target_device_id: [u8; 16],
    pub conversation_id: String,
    pub generation: u32,
    pub roster_version: u64,
    pub envelope_commitment: [u8; 32],
}

/// Local mutation that becomes durable only after the server ACKs its
/// sequence number. The desktop uses this to update UI after authorization
/// and ownership checks have succeeded server-side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmedMutation {
    Edit {
        message_id: String,
        conversation_id: String,
        new_text: String,
    },
    Delete {
        message_id: String,
        conversation_id: String,
    },
    Reaction {
        message_id: String,
        conversation_id: String,
        emoji: String,
        user_id: String,
        add: bool,
    },
}

#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// Authentication succeeded — user_id from server.
    Authenticated { user_id: String },
    /// Authentication failed.
    AuthFailed { reason: String },
    /// Incoming message from another user.
    MessageReceived {
        message_id: String,
        conversation_id: String,
        sender_identity_key: Vec<u8>,
        sender_username: String,
        ciphertext: Vec<u8>,
        header: Vec<u8>,
        server_timestamp: u64,
        reply_to_id: Option<String>,
        msg_type: Option<i32>,
        ttl_seconds: Option<u32>,
        sealed: Option<bool>,
        attachments: Vec<crate::attachments::WireAttachmentV1>,
        security_context: Option<crate::api::MessageSecurityContextV1>,
    },
    /// A message was edited by its sender.
    MessageEdited {
        message_id: String,
        conversation_id: String,
        sender_identity_key: Vec<u8>,
        ciphertext: Vec<u8>,
        header: Vec<u8>,
        edit_timestamp: u64,
    },
    /// A message was deleted by its sender.
    MessageDeleted {
        message_id: String,
        conversation_id: String,
        sender_identity_key: Vec<u8>,
        delete_timestamp: u64,
    },
    /// A remote user started/stopped typing.
    TypingEvent {
        conversation_id: String,
        identity_key: Vec<u8>,
        started: bool,
    },
    /// A reaction was added/removed on a message.
    ReactionEvent {
        message_id: String,
        conversation_id: String,
        emoji: String,
        user_id: String,
        username: String,
        add: bool,
    },
    /// Presence update from a friend.
    PresenceUpdate {
        identity_key: Vec<u8>,
        status: i32,
        status_text: Option<String>,
        last_seen: Option<u64>,
    },
    /// Incoming friend request notification.
    FriendRequestReceived {
        request_id: String,
        from_user_id: String,
        from_username: String,
        message: Option<String>,
        timestamp: u64,
    },
    /// A friend request was accepted (new friend).
    FriendAccepted { user_id: String, username: String },
    /// A friend removed you.
    FriendRemoved { user_id: String },
    /// Full friend list response.
    FriendListReceived {
        friends: Vec<FriendInfo>,
        pending_requests: Vec<FriendRequestInfo>,
    },
    /// Presentation-only hint that an origin-scoped profile should be
    /// refetched through the signed REST surface.
    ProfileUpdated {
        user_id: String,
        profile_version: u64,
    },
    /// A server-level event (created/updated/deleted, member join/leave/kick/ban, role CRUD).
    ServerEvent {
        event_type: i32, // proto::server_event::EventType as i32
        server_id: String,
        server_info: Option<ServerInfoLite>,
        member_info: Option<MemberInfoLite>,
        role_info: Option<RoleInfoLite>,
    },
    /// A channel-level event (created/updated/deleted/reordered).
    ChannelEvent {
        event_type: i32, // proto::channel_event::EventType as i32
        server_id: String,
        channel: ChannelInfoLite,
    },
    /// Server acknowledged our sent message.
    MessageAcked {
        message_id: String,
        server_timestamp: u64,
        ref_seq: u64,
        /// Filled by VeilClient after reconciling its local pending row.
        local_message_id: Option<String>,
        /// Filled by VeilClient after committing an ACK-gated local mutation.
        mutation: Option<ConfirmedMutation>,
        sender_key: Option<SenderKeyAckMetadataV1>,
    },
    /// A Sender Key Distribution Message arrived from a peer.
    /// `sender_key_message` is a sealed envelope (see veil_crypto::sender_key::open_skdm).
    SenderKeyDist {
        sender_key_message: Vec<u8>,
        route: crate::api::SenderKeyRouteV1,
    },
    /// Connection closed.
    Disconnected { reason: String },
    /// Server error.
    Error {
        code: u32,
        message: String,
        ref_seq: Option<u64>,
        local_message_id: Option<String>,
        conversation_id: Option<String>,
        stale_roster_context: bool,
    },
}

/// Lightweight projection of ServerInfo for events crossing FFI/Tauri boundary.
#[derive(Debug, Clone)]
pub struct ServerInfoLite {
    pub id: String,
    pub name: String,
    pub icon_url: Option<String>,
    pub owner_identity_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MemberInfoLite {
    pub identity_key: Vec<u8>,
    pub username: String,
    pub role_ids: Vec<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RoleInfoLite {
    pub id: String,
    pub name: String,
    pub permissions: u64,
    pub position: u32,
    pub color: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ChannelInfoLite {
    pub id: String,
    pub server_id: String,
    pub name: String,
    pub channel_type: i32, // proto::ChannelType as i32
    pub category_id: Option<String>,
    pub position: u32,
    pub topic: Option<String>,
}

/// A fail-closed outcome from the single live-event budget shared by the
/// socket channel, the pre-auth retained barrier, and the API's deferred FIFO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionEventBufferErrorV1 {
    EventCountLimitExceeded {
        limit: usize,
    },
    RetainedSizeLimitExceeded {
        limit: usize,
        event_bytes: usize,
    },
    RetainedSizeAccountingOverflow,
    TransportEpochEnded,
    AuthenticationEpochAnomaly {
        envelope: &'static str,
    },
    /// A post-authentication frame used a malformed encoding or an invalid
    /// representation of an event this client understands. Continuing after
    /// silently dropping it could skip a Double Ratchet step, so the complete
    /// authenticated transport epoch becomes terminal instead.
    ProtocolViolation {
        envelope: &'static str,
    },
}

impl fmt::Display for ConnectionEventBufferErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventCountLimitExceeded { limit } => write!(
                formatter,
                "authenticated live-event buffer exceeded its {limit}-event limit"
            ),
            Self::RetainedSizeLimitExceeded { limit, event_bytes } => write!(
                formatter,
                "authenticated live-event buffer exceeded its {limit}-byte retained-size limit (next event retains {event_bytes} bytes)"
            ),
            Self::RetainedSizeAccountingOverflow => formatter.write_str(
                "authenticated live-event retained-size accounting overflowed",
            ),
            Self::TransportEpochEnded => {
                formatter.write_str("authenticated WebSocket epoch has ended")
            }
            Self::AuthenticationEpochAnomaly { envelope } => write!(
                formatter,
                "unexpected authentication envelope {envelope} after the authenticated barrier"
            ),
            Self::ProtocolViolation { envelope } => write!(
                formatter,
                "malformed {envelope} envelope after the authenticated barrier"
            ),
        }
    }
}

impl std::error::Error for ConnectionEventBufferErrorV1 {}

#[derive(Default)]
struct RetainedSizeCounterV1(usize);

impl RetainedSizeCounterV1 {
    fn add(&mut self, bytes: usize) -> Result<(), ConnectionEventBufferErrorV1> {
        self.0 = self
            .0
            .checked_add(bytes)
            .ok_or(ConnectionEventBufferErrorV1::RetainedSizeAccountingOverflow)?;
        Ok(())
    }

    fn add_items<T>(&mut self, capacity: usize) -> Result<(), ConnectionEventBufferErrorV1> {
        self.add(
            capacity
                .checked_mul(size_of::<T>())
                .ok_or(ConnectionEventBufferErrorV1::RetainedSizeAccountingOverflow)?,
        )
    }

    fn add_string(&mut self, value: &String) -> Result<(), ConnectionEventBufferErrorV1> {
        self.add(value.capacity())
    }

    fn add_bytes(&mut self, value: &Vec<u8>) -> Result<(), ConnectionEventBufferErrorV1> {
        self.add(value.capacity())
    }

    fn add_optional_string(
        &mut self,
        value: &Option<String>,
    ) -> Result<(), ConnectionEventBufferErrorV1> {
        if let Some(value) = value {
            self.add_string(value)?;
        }
        Ok(())
    }
}

/// Counts the complete retained allocation owned by an event: the enum's
/// inline storage plus every heap allocation reachable from it. Capacities,
/// rather than logical lengths, are used so spare allocation is never hidden
/// from the global 32 MiB limit.
pub(crate) fn connection_event_retained_size_v1(
    event: &ConnectionEvent,
) -> Result<usize, ConnectionEventBufferErrorV1> {
    // Events are queued inside `BudgetedConnectionEventV1`; count that complete
    // inline wrapper once, then add every allocation reachable from the event.
    let mut size = RetainedSizeCounterV1(size_of::<BudgetedConnectionEventV1>());
    match event {
        ConnectionEvent::Authenticated { user_id } => size.add_string(user_id)?,
        ConnectionEvent::AuthFailed { reason } | ConnectionEvent::Disconnected { reason } => {
            size.add_string(reason)?
        }
        ConnectionEvent::MessageReceived {
            message_id,
            conversation_id,
            sender_identity_key,
            sender_username,
            ciphertext,
            header,
            reply_to_id,
            attachments,
            ..
        } => {
            size.add_string(message_id)?;
            size.add_string(conversation_id)?;
            size.add_bytes(sender_identity_key)?;
            size.add_string(sender_username)?;
            size.add_bytes(ciphertext)?;
            size.add_bytes(header)?;
            size.add_optional_string(reply_to_id)?;
            size.add_items::<crate::attachments::WireAttachmentV1>(attachments.capacity())?;
            for attachment in attachments {
                size.add_string(&attachment.media_id)?;
                size.add_bytes(&attachment.encrypted_key)?;
                size.add_bytes(&attachment.nonce)?;
                size.add_string(&attachment.content_type)?;
            }
        }
        ConnectionEvent::MessageEdited {
            message_id,
            conversation_id,
            sender_identity_key,
            ciphertext,
            header,
            ..
        } => {
            size.add_string(message_id)?;
            size.add_string(conversation_id)?;
            size.add_bytes(sender_identity_key)?;
            size.add_bytes(ciphertext)?;
            size.add_bytes(header)?;
        }
        ConnectionEvent::MessageDeleted {
            message_id,
            conversation_id,
            sender_identity_key,
            ..
        } => {
            size.add_string(message_id)?;
            size.add_string(conversation_id)?;
            size.add_bytes(sender_identity_key)?;
        }
        ConnectionEvent::TypingEvent {
            conversation_id,
            identity_key,
            ..
        } => {
            size.add_string(conversation_id)?;
            size.add_bytes(identity_key)?;
        }
        ConnectionEvent::ReactionEvent {
            message_id,
            conversation_id,
            emoji,
            user_id,
            username,
            ..
        } => {
            size.add_string(message_id)?;
            size.add_string(conversation_id)?;
            size.add_string(emoji)?;
            size.add_string(user_id)?;
            size.add_string(username)?;
        }
        ConnectionEvent::PresenceUpdate {
            identity_key,
            status_text,
            ..
        } => {
            size.add_bytes(identity_key)?;
            size.add_optional_string(status_text)?;
        }
        ConnectionEvent::FriendRequestReceived {
            request_id,
            from_user_id,
            from_username,
            message,
            ..
        } => {
            size.add_string(request_id)?;
            size.add_string(from_user_id)?;
            size.add_string(from_username)?;
            size.add_optional_string(message)?;
        }
        ConnectionEvent::FriendAccepted { user_id, username } => {
            size.add_string(user_id)?;
            size.add_string(username)?;
        }
        ConnectionEvent::FriendRemoved { user_id }
        | ConnectionEvent::ProfileUpdated { user_id, .. } => size.add_string(user_id)?,
        ConnectionEvent::FriendListReceived {
            friends,
            pending_requests,
        } => {
            size.add_items::<FriendInfo>(friends.capacity())?;
            for friend in friends {
                size.add_string(&friend.user_id)?;
                size.add_string(&friend.username)?;
            }
            size.add_items::<FriendRequestInfo>(pending_requests.capacity())?;
            for request in pending_requests {
                size.add_string(&request.request_id)?;
                size.add_string(&request.from_user_id)?;
                size.add_string(&request.from_username)?;
                size.add_optional_string(&request.message)?;
            }
        }
        ConnectionEvent::ServerEvent {
            server_id,
            server_info,
            member_info,
            role_info,
            ..
        } => {
            size.add_string(server_id)?;
            if let Some(server) = server_info {
                size.add_string(&server.id)?;
                size.add_string(&server.name)?;
                size.add_optional_string(&server.icon_url)?;
                size.add_bytes(&server.owner_identity_key)?;
            }
            if let Some(member) = member_info {
                size.add_bytes(&member.identity_key)?;
                size.add_string(&member.username)?;
                size.add_items::<String>(member.role_ids.capacity())?;
                for role_id in &member.role_ids {
                    size.add_string(role_id)?;
                }
                size.add_optional_string(&member.reason)?;
            }
            if let Some(role) = role_info {
                size.add_string(&role.id)?;
                size.add_string(&role.name)?;
            }
        }
        ConnectionEvent::ChannelEvent {
            server_id, channel, ..
        } => {
            size.add_string(server_id)?;
            size.add_string(&channel.id)?;
            size.add_string(&channel.server_id)?;
            size.add_string(&channel.name)?;
            size.add_optional_string(&channel.category_id)?;
            size.add_optional_string(&channel.topic)?;
        }
        ConnectionEvent::MessageAcked {
            message_id,
            local_message_id,
            mutation,
            sender_key,
            ..
        } => {
            size.add_string(message_id)?;
            size.add_optional_string(local_message_id)?;
            if let Some(mutation) = mutation {
                match mutation {
                    ConfirmedMutation::Edit {
                        message_id,
                        conversation_id,
                        new_text,
                    } => {
                        size.add_string(message_id)?;
                        size.add_string(conversation_id)?;
                        size.add_string(new_text)?;
                    }
                    ConfirmedMutation::Delete {
                        message_id,
                        conversation_id,
                    } => {
                        size.add_string(message_id)?;
                        size.add_string(conversation_id)?;
                    }
                    ConfirmedMutation::Reaction {
                        message_id,
                        conversation_id,
                        emoji,
                        user_id,
                        ..
                    } => {
                        size.add_string(message_id)?;
                        size.add_string(conversation_id)?;
                        size.add_string(emoji)?;
                        size.add_string(user_id)?;
                    }
                }
            }
            if let Some(sender_key) = sender_key {
                size.add_string(&sender_key.conversation_id)?;
            }
        }
        ConnectionEvent::SenderKeyDist {
            sender_key_message,
            route,
        } => {
            size.add_bytes(sender_key_message)?;
            size.add_string(&route.conversation_id)?;
        }
        ConnectionEvent::Error {
            message,
            local_message_id,
            conversation_id,
            ..
        } => {
            size.add_string(message)?;
            size.add_optional_string(local_message_id)?;
            size.add_optional_string(conversation_id)?;
        }
    }
    Ok(size.0)
}

#[derive(Clone)]
pub(crate) struct ConnectionEventBudgetV1 {
    event_slots: Arc<Semaphore>,
    retained_bytes: Arc<Semaphore>,
    event_limit: usize,
    retained_byte_limit: usize,
}

impl ConnectionEventBudgetV1 {
    fn production() -> Self {
        Self::with_limits(LIVE_EVENT_QUEUE_CAPACITY, LIVE_EVENT_RETAINED_BYTES)
    }

    pub(crate) fn with_limits(event_limit: usize, retained_byte_limit: usize) -> Self {
        assert!(retained_byte_limit <= Semaphore::MAX_PERMITS);
        Self {
            event_slots: Arc::new(Semaphore::new(event_limit)),
            retained_bytes: Arc::new(Semaphore::new(retained_byte_limit)),
            event_limit,
            retained_byte_limit,
        }
    }

    pub(crate) fn try_wrap(
        &self,
        event: ConnectionEvent,
    ) -> Result<BudgetedConnectionEventV1, ConnectionEventBufferErrorV1> {
        let retained_bytes = connection_event_retained_size_v1(&event)?;
        if retained_bytes > self.retained_byte_limit || retained_bytes > u32::MAX as usize {
            return Err(ConnectionEventBufferErrorV1::RetainedSizeLimitExceeded {
                limit: self.retained_byte_limit,
                event_bytes: retained_bytes,
            });
        }
        let event_slot = self.event_slots.clone().try_acquire_owned().map_err(|_| {
            ConnectionEventBufferErrorV1::EventCountLimitExceeded {
                limit: self.event_limit,
            }
        })?;
        let retained_byte_permit = self
            .retained_bytes
            .clone()
            .try_acquire_many_owned(retained_bytes as u32)
            .map_err(
                |_| ConnectionEventBufferErrorV1::RetainedSizeLimitExceeded {
                    limit: self.retained_byte_limit,
                    event_bytes: retained_bytes,
                },
            )?;
        Ok(BudgetedConnectionEventV1 {
            event,
            retained_bytes,
            budget: Some(ConnectionEventBudgetGuardV1 {
                _event_slot: event_slot,
                _retained_bytes: retained_byte_permit,
            }),
            terminal_failure: None,
        })
    }
}

pub(crate) struct ConnectionEventBudgetGuardV1 {
    _event_slot: OwnedSemaphorePermit,
    _retained_bytes: OwnedSemaphorePermit,
}

pub(crate) struct BudgetedConnectionEventV1 {
    pub(crate) event: ConnectionEvent,
    retained_bytes: usize,
    budget: Option<ConnectionEventBudgetGuardV1>,
    terminal_failure: Option<ConnectionEventBufferErrorV1>,
}

impl BudgetedConnectionEventV1 {
    fn terminal(
        event: ConnectionEvent,
        terminal_failure: Option<ConnectionEventBufferErrorV1>,
    ) -> Self {
        let retained_bytes = connection_event_retained_size_v1(&event)
            .unwrap_or(size_of::<ConnectionEvent>() + MAX_TERMINAL_REASON_BYTES);
        Self {
            event,
            retained_bytes,
            budget: None,
            terminal_failure,
        }
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub(crate) fn into_event(self) -> ConnectionEvent {
        self.event
    }

    pub(crate) fn terminal_failure(&self) -> Option<&ConnectionEventBufferErrorV1> {
        self.terminal_failure.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn terminal_failure_for_test(error: ConnectionEventBufferErrorV1) -> Self {
        Self::terminal(
            ConnectionEvent::Disconnected {
                reason: error.to_string(),
            },
            Some(error),
        )
    }

    pub(crate) fn into_parts(self) -> (ConnectionEvent, Option<ConnectionEventBudgetGuardV1>) {
        (self.event, self.budget)
    }
}

#[derive(Default)]
struct ConnectionTerminalInnerV1 {
    cause: Option<ConnectionTerminalCauseV1>,
    delivered: bool,
}

#[derive(Clone)]
enum ConnectionTerminalCauseV1 {
    Transport(String),
    Buffer(ConnectionEventBufferErrorV1),
}

#[derive(Default)]
struct ConnectionTerminalStateV1 {
    inner: StdMutex<ConnectionTerminalInnerV1>,
    notify: Notify,
}

impl ConnectionTerminalStateV1 {
    fn report_transport(&self, mut reason: String) -> bool {
        if reason.len() > MAX_TERMINAL_REASON_BYTES {
            let mut boundary = MAX_TERMINAL_REASON_BYTES;
            while !reason.is_char_boundary(boundary) {
                boundary -= 1;
            }
            reason.truncate(boundary);
        }
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.cause.is_some() {
            return false;
        }
        state.cause = Some(ConnectionTerminalCauseV1::Transport(reason));
        drop(state);
        // There is exactly one receiver. `notify_one` retains a permit when
        // termination races the receiver between its state check and await.
        self.notify.notify_one();
        true
    }

    fn report_buffer_failure(&self, error: ConnectionEventBufferErrorV1) -> bool {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.cause.is_some() {
            return false;
        }
        state.cause = Some(ConnectionTerminalCauseV1::Buffer(error));
        drop(state);
        // There is exactly one receiver. `notify_one` retains a permit when
        // termination races the receiver between its state check and await.
        self.notify.notify_one();
        true
    }

    fn is_reported(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .cause
            .is_some()
    }

    fn take_for_delivery(&self) -> Option<ConnectionTerminalCauseV1> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.delivered {
            return None;
        }
        let cause = state.cause.clone()?;
        state.delivered = true;
        Some(cause)
    }
}

#[derive(Clone)]
struct ConnectionEventSenderV1 {
    sender: mpsc::Sender<BudgetedConnectionEventV1>,
    budget: ConnectionEventBudgetV1,
}

impl ConnectionEventSenderV1 {
    async fn send(&self, event: ConnectionEvent) -> Result<(), ConnectionEventBufferErrorV1> {
        let event = self.budget.try_wrap(event)?;
        self.sender
            .send(event)
            .await
            .map_err(|_| ConnectionEventBufferErrorV1::TransportEpochEnded)
    }
}

pub struct ConnectionEventReceiverV1 {
    receiver: mpsc::Receiver<BudgetedConnectionEventV1>,
    terminal: Arc<ConnectionTerminalStateV1>,
}

impl ConnectionEventReceiverV1 {
    fn terminal_event(&mut self) -> Option<BudgetedConnectionEventV1> {
        if !self.terminal.is_reported() {
            return None;
        }
        self.receiver.close();
        while self.receiver.try_recv().is_ok() {}
        self.terminal.take_for_delivery().map(|cause| match cause {
            ConnectionTerminalCauseV1::Transport(reason) => {
                BudgetedConnectionEventV1::terminal(ConnectionEvent::Disconnected { reason }, None)
            }
            ConnectionTerminalCauseV1::Buffer(error) => BudgetedConnectionEventV1::terminal(
                ConnectionEvent::Disconnected {
                    reason: error.to_string(),
                },
                Some(error),
            ),
        })
    }

    pub(crate) fn try_recv_budgeted(
        &mut self,
    ) -> Result<BudgetedConnectionEventV1, mpsc::error::TryRecvError> {
        if let Some(event) = self.terminal_event() {
            return Ok(event);
        }
        if self.terminal.is_reported() {
            return Err(mpsc::error::TryRecvError::Disconnected);
        }
        let candidate = self.receiver.try_recv();
        if let Some(event) = self.terminal_event() {
            drop(candidate);
            return Ok(event);
        }
        candidate
    }

    pub(crate) fn try_recv_terminal(&mut self) -> Option<BudgetedConnectionEventV1> {
        self.terminal_event()
    }

    pub fn try_recv(&mut self) -> Result<ConnectionEvent, mpsc::error::TryRecvError> {
        self.try_recv_budgeted()
            .map(BudgetedConnectionEventV1::into_event)
    }

    pub async fn recv(&mut self) -> Option<ConnectionEvent> {
        loop {
            if let Some(event) = self.terminal_event() {
                return Some(event.into_event());
            }
            if self.terminal.is_reported() {
                return None;
            }
            tokio::select! {
                event = self.receiver.recv() => {
                    if let Some(terminal) = self.terminal_event() {
                        drop(event);
                        return Some(terminal.into_event());
                    }
                    return event.map(BudgetedConnectionEventV1::into_event);
                }
                _ = self.terminal.notify.notified() => continue,
            }
        }
    }
}

/// Sender half — used to send protobuf envelopes to the server.
pub type WsSender = mpsc::Sender<Vec<u8>>;

/// Manages a WebSocket connection to the Veil gateway.
pub struct Connection {
    /// Send raw protobuf bytes to the WS write loop.
    pub sender: WsSender,
    /// Receive application-level events.
    pub events: ConnectionEventReceiverV1,
    /// Authenticated retained controls observed before the AuthResult FIFO
    /// barrier. They are kept outside the bounded live-event channel so the
    /// handshake cannot deadlock before the caller can drain that channel.
    pub(crate) retained_events: VecDeque<BudgetedConnectionEventV1>,
    /// Current sequence number for outgoing messages.
    seq: Arc<Mutex<u64>>,
    write_task: tokio::task::AbortHandle,
    read_task: tokio::task::AbortHandle,
}

fn signal_disconnected(
    terminal: &ConnectionTerminalStateV1,
    shutdown: &watch::Sender<bool>,
    reason: String,
) {
    // Closing either half makes the split WebSocket unusable. Stop its peer
    // immediately and emit exactly one terminal event for the connection.
    let _ = shutdown.send(true);
    terminal.report_transport(reason);
}

fn signal_event_buffer_failure(
    terminal: &ConnectionTerminalStateV1,
    shutdown: &watch::Sender<bool>,
    error: ConnectionEventBufferErrorV1,
) {
    let _ = shutdown.send(true);
    terminal.report_buffer_failure(error);
}

impl Connection {
    /// Connect to the server, perform auth challenge-response, and start
    /// background read/write loops. Returns immediately after auth completes.
    pub async fn connect(
        config: &ConnectionConfig,
        identity: &IdentityKeyPair,
        device_identity: &DeviceIdentityV1,
        device_name: &str,
        client_id: &str,
        node_access_invite: Option<&[u8]>,
    ) -> Result<Self, String> {
        let url = &config.server_url;
        validate_websocket_url(url)?;
        let node_access_invite = node_access_invite_wire_value(node_access_invite)?;
        // Keep endpoint and account metadata out of production diagnostics.
        info!("connecting to validated WebSocket endpoint");

        let websocket_config = WebSocketConfig {
            // Protocol payloads are capped far below this today. Keep enough
            // room for batched directory events while bounding a malicious
            // server's fragmented-message memory pressure.
            max_message_size: Some(4 << 20),
            max_frame_size: Some(1 << 20),
            ..WebSocketConfig::default()
        };
        let (ws_stream, _) = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            connect_async_with_config(url, Some(websocket_config), false),
        )
        .await
        .map_err(|_| format!("ws connect timed out after 8s: {url}"))?
        .map_err(|e| format!("ws connect failed: {e}"))?;

        let (mut ws_write, mut ws_read) = ws_stream.split();

        // Channel: app → WS write loop
        let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(256);

        let seq = Arc::new(Mutex::new(1u64));

        // --- Step 1: Wait for AuthChallenge ---
        let challenge = tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, async {
            loop {
                match ws_read.next().await {
                    Some(Ok(WsMessage::Binary(data))) => {
                        let env = proto::Envelope::decode(data.as_ref())
                            .map_err(|e| format!("decode challenge: {e}"))?;
                        if let Some(proto::envelope::Payload::AuthChallenge(ch)) = env.payload {
                            return Ok::<_, String>(ch.challenge);
                        }
                        warn!("expected auth_challenge, got other payload");
                    }
                    Some(Ok(WsMessage::Ping(_))) => continue,
                    Some(Err(e)) => return Err(format!("ws read error during auth: {e}")),
                    None => return Err("connection closed before auth challenge".into()),
                    _ => continue,
                }
            }
        })
        .await
        .map_err(|_| "timed out waiting for authentication challenge".to_string())??;

        info!("received auth challenge ({} bytes)", challenge.len());

        // --- Step 2: prove possession of both identity secrets. ---
        // The server challenge is an ephemeral X25519 public key. Binding its
        // DH result into the Ed25519 signature prevents cross-protocol signing
        // and proves that the client owns the advertised X25519 identity.
        let sig = websocket_auth_signature(identity, &challenge)?;
        let device_sig = device_identity.auth_signature(identity, &challenge)?;
        let binding = device_identity.binding();
        let mut auth_resp = proto::Envelope {
            seq: 2,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::AuthResponse(
                proto::AuthResponse {
                    identity_key: identity.x25519_public_bytes().to_vec(),
                    signing_key: identity.ed25519_public_bytes().to_vec(),
                    signature: sig.to_vec(),
                    device_id: binding.device_id.to_vec(),
                    device_name: device_name.to_string(),
                    client_version: client_version(client_id),
                    device_binding: Some(proto::DeviceBindingV1 {
                        device_id: binding.device_id.to_vec(),
                        device_identity_key: binding.device_identity_key.to_vec(),
                        device_signing_key: binding.device_signing_key.to_vec(),
                        version: binding.version,
                        capabilities: binding.capabilities,
                        status: i32::from(binding.status),
                        account_signature: binding.account_signature.to_vec(),
                    }),
                    device_signature: device_sig.to_vec(),
                    node_access_invite,
                },
            )),
        };
        let auth_bytes = auth_resp.encode_to_vec();
        if let Some(proto::envelope::Payload::AuthResponse(response)) = auth_resp.payload.as_mut() {
            response.node_access_invite.zeroize();
        }
        ws_write
            .send(WsMessage::Binary(auth_bytes))
            .await
            .map_err(|e| format!("send auth_response: {e}"))?;

        // --- Step 3: Receive retained encrypted control state, then AuthResult. ---
        // The server queues every retained SKDM before AuthResult and publishes
        // this socket to live fan-out only afterwards. AuthResult is therefore
        // an explicit FIFO barrier: once observed, the buffered set is complete.
        let mut retained_before_auth = Vec::new();
        let mut retained_wire_bytes = 0usize;
        let mut retained_metadata_bytes = 0usize;
        let user_id = tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, async {
            loop {
                match ws_read.next().await {
                    Some(Ok(WsMessage::Binary(data))) => {
                        let env = proto::Envelope::decode(data.as_ref())
                            .map_err(|e| format!("decode auth_result: {e}"))?;
                        match env.payload.as_ref() {
                            Some(proto::envelope::Payload::AuthResult(r)) => {
                                return validate_per_device_auth_result(r, binding);
                            }
                            Some(proto::envelope::Payload::SenderKeyDist(skd)) => {
                                if sender_key_route_from_proto(skd).is_none()
                                    || retained_before_auth.len() >= MAX_RETAINED_SKDM_EVENTS
                                {
                                    return Err("invalid or excessive retained sender-key state"
                                        .to_string());
                                }
                                // Count the complete protobuf except the bounded ciphertext
                                // bytes themselves. This automatically includes every routing
                                // and historical binding-proof field plus tag/length overhead.
                                let metadata_bytes = skd
                                    .encoded_len()
                                    .checked_sub(skd.sender_key_message.len())
                                    .ok_or_else(|| {
                                        "retained sender-key metadata count overflow".to_string()
                                    })?;
                                retained_metadata_bytes = retained_metadata_bytes
                                    .checked_add(metadata_bytes)
                                    .ok_or_else(|| {
                                        "retained sender-key metadata count overflow".to_string()
                                    })?;
                                retained_wire_bytes = retained_wire_bytes
                                    .checked_add(skd.sender_key_message.len())
                                    .ok_or_else(|| {
                                        "retained sender-key wire count overflow".to_string()
                                    })?;
                                if retained_wire_bytes > MAX_RETAINED_SKDM_WIRE_TOTAL_BYTES
                                    || retained_metadata_bytes > MAX_RETAINED_SKDM_METADATA_BYTES
                                {
                                    return Err("retained sender-key state exceeds client limit"
                                        .to_string());
                                }
                                retained_before_auth.push(env);
                            }
                            _ => {
                                return Err(
                                    "unexpected non-control envelope before authentication barrier"
                                        .to_string(),
                                );
                            }
                        }
                    }
                    Some(Ok(WsMessage::Ping(_))) => continue,
                    Some(Err(e)) => return Err(format!("ws read error during auth: {e}")),
                    None => return Err("connection closed during auth".into()),
                    _ => continue,
                }
            }
        })
        .await
        .map_err(|_| "timed out waiting for authentication result".to_string())??;

        info!("authenticated WebSocket session");

        let event_budget = ConnectionEventBudgetV1::production();
        let mut retained_events = VecDeque::with_capacity(retained_before_auth.len());
        for envelope in retained_before_auth {
            let event = connection_event_from_envelope(envelope)
                .map_err(|_| "invalid retained sender-key event".to_string())?
                .ok_or_else(|| "invalid retained sender-key event".to_string())?;
            retained_events.push_back(
                event_budget
                    .try_wrap(event)
                    .map_err(|error| error.to_string())?,
            );
        }
        // Channel: WS read loop → app. Retained controls live in their own
        // bounded buffer above, so this capacity remains a live backpressure
        // limit even for accounts with many channel memberships.
        let (raw_event_tx, raw_event_rx) =
            mpsc::channel::<BudgetedConnectionEventV1>(LIVE_EVENT_QUEUE_CAPACITY);
        let terminal = Arc::new(ConnectionTerminalStateV1::default());
        let event_tx = ConnectionEventSenderV1 {
            sender: raw_event_tx,
            budget: event_budget,
        };
        let event_rx = ConnectionEventReceiverV1 {
            receiver: raw_event_rx,
            terminal: terminal.clone(),
        };

        // Notify app about successful auth
        event_tx
            .send(ConnectionEvent::Authenticated {
                user_id: user_id.clone(),
            })
            .await
            .map_err(|error| error.to_string())?;

        // Both halves share a terminal signal. A write failure must stop the
        // reader as well (and vice versa), otherwise the application can keep
        // treating a half-dead socket as connected indefinitely.
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        // --- Background write loop ---
        let write_terminal = terminal.clone();
        let write_shutdown = shutdown_tx.clone();
        let mut write_shutdown_rx = shutdown_rx.clone();
        let write_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = write_shutdown_rx.changed() => {
                        if changed.is_err() || *write_shutdown_rx.borrow() {
                            break;
                        }
                    }
                    data = send_rx.recv() => {
                        let Some(data) = data else {
                            break;
                        };
                        if let Err(error) = ws_write.send(WsMessage::Binary(data)).await {
                            signal_disconnected(
                                &write_terminal,
                                &write_shutdown,
                                format!("ws write error: {error}"),
                            );
                            break;
                        }
                    }
                }
            }
        });
        let write_task = write_task.abort_handle();

        // --- Background read loop ---
        let evt = event_tx.clone();
        let read_terminal = terminal;
        let read_shutdown = shutdown_tx;
        let mut read_shutdown_rx = shutdown_rx;
        let read_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = read_shutdown_rx.changed() => {
                        if changed.is_err() || *read_shutdown_rx.borrow() {
                            break;
                        }
                    }
                    incoming = ws_read.next() => {
                        match incoming {
                            Some(Ok(message)) => match dispatch_authenticated_ws_message(&evt, message).await {
                                Ok(AuthenticatedWsMessageOutcomeV1::Continue) => continue,
                                Ok(AuthenticatedWsMessageOutcomeV1::Closed) => {
                                    signal_disconnected(
                                        &read_terminal,
                                        &read_shutdown,
                                        "server closed".into(),
                                    );
                                    break;
                                }
                                Err(error) => {
                                    signal_event_buffer_failure(
                                        &read_terminal,
                                        &read_shutdown,
                                        error,
                                    );
                                    break;
                                }
                            },
                            None => {
                                signal_disconnected(
                                    &read_terminal,
                                    &read_shutdown,
                                    "server closed".into(),
                                );
                                break;
                            }
                            Some(Err(error)) => {
                                signal_disconnected(
                                    &read_terminal,
                                    &read_shutdown,
                                    format!("ws read error: {error}"),
                                );
                                break;
                            }
                        }
                    }
                }
            }
        });
        let read_task = read_task.abort_handle();

        Ok(Self {
            sender: send_tx,
            events: event_rx,
            retained_events,
            seq,
            write_task,
            read_task,
        })
    }

    /// Get and increment the next sequence number.
    pub async fn next_seq(&self) -> u64 {
        let mut s = self.seq.lock().await;
        let v = *s;
        *s += 1;
        v
    }

    /// Send a protobuf-encoded envelope to the server.
    pub async fn send_envelope(&self, env: &proto::Envelope) -> Result<(), String> {
        let data = env.encode_to_vec();
        tokio::time::timeout(OUTBOUND_QUEUE_TIMEOUT, self.sender.send(data))
            .await
            .map_err(|_| "send timed out waiting for the bounded WebSocket queue".to_string())?
            .map_err(|e| format!("send failed: {e}"))
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn test_only_queued_connection() -> (Self, mpsc::Receiver<Vec<u8>>) {
        let write_join = tokio::spawn(std::future::pending::<()>());
        let read_join = tokio::spawn(std::future::pending::<()>());
        let (sender, outbound) = mpsc::channel(4);
        let (_event_sender, event_receiver) = mpsc::channel(1);
        let terminal = Arc::new(ConnectionTerminalStateV1::default());
        (
            Self {
                sender,
                events: ConnectionEventReceiverV1 {
                    receiver: event_receiver,
                    terminal,
                },
                retained_events: VecDeque::new(),
                seq: Arc::new(Mutex::new(1)),
                write_task: write_join.abort_handle(),
                read_task: read_join.abort_handle(),
            },
            outbound,
        )
    }

    /// Stop background I/O immediately. Dropping the client calls this through
    /// `Drop`, so a native app lock cannot leave a detached authenticated socket.
    pub fn disconnect(&self) {
        self.write_task.abort();
        self.read_task.abort();
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.disconnect();
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod url_policy_tests {
    use super::{
        client_version, node_access_invite_wire_value, signal_disconnected,
        validate_per_device_auth_result, validate_websocket_url, websocket_auth_signature,
        Connection, ConnectionEvent, ConnectionEventReceiverV1, ConnectionTerminalStateV1,
    };
    use crate::device_identity::{
        DeviceBindingPublicV1, DEVICE_BINDING_STATUS_ACTIVE, REQUIRED_DEVICE_CAPABILITIES,
    };
    use crate::protocol::proto;
    use std::sync::Arc;
    use veil_crypto::keys::IdentityKeyPair;

    #[test]
    fn client_version_uses_a_stable_product_id() {
        assert_eq!(
            client_version("veil-desktop"),
            concat!("veil-desktop/", env!("CARGO_PKG_VERSION"))
        );
        assert_ne!(
            client_version("veil-desktop"),
            client_version("MacBook Pro")
        );
    }

    #[test]
    fn existing_account_auth_omits_node_access_pass_and_new_registration_is_exact() {
        assert!(node_access_invite_wire_value(None).unwrap().is_empty());
        assert_eq!(
            node_access_invite_wire_value(Some(&[0x42; 32])).unwrap(),
            vec![0x42; 32]
        );
        assert!(node_access_invite_wire_value(Some(&[0x42; 31])).is_err());
        assert!(node_access_invite_wire_value(Some(&[0x42; 33])).is_err());
    }

    #[test]
    fn permits_secure_and_loopback_websocket_urls() {
        assert!(validate_websocket_url("wss://chat.example.test/ws").is_ok());
        assert!(validate_websocket_url("ws://localhost:9080/ws").is_ok());
        assert!(validate_websocket_url("ws://127.0.0.1:9080/ws").is_ok());
        assert!(validate_websocket_url("ws://[::1]:9080/ws").is_ok());
    }

    #[test]
    fn rejects_remote_cleartext_and_non_websocket_urls() {
        assert!(validate_websocket_url("ws://192.0.2.1:9080/ws").is_err());
        assert!(validate_websocket_url("ws://chat.example.test/ws").is_err());
        assert!(validate_websocket_url("https://chat.example.test/ws").is_err());
        assert!(validate_websocket_url("wss://user@chat.example.test/ws").is_err());
        assert!(validate_websocket_url("wss://chat.example.test/ws#fragment").is_err());
    }

    #[tokio::test]
    async fn dropping_connection_aborts_detached_io_tasks() {
        let write_join = tokio::spawn(std::future::pending::<()>());
        let read_join = tokio::spawn(std::future::pending::<()>());
        let (sender, _send_rx) = tokio::sync::mpsc::channel(1);
        let (_event_tx, event_rx) = tokio::sync::mpsc::channel(1);
        let terminal = Arc::new(ConnectionTerminalStateV1::default());
        let events = ConnectionEventReceiverV1 {
            receiver: event_rx,
            terminal,
        };
        let connection = Connection {
            sender,
            events,
            retained_events: std::collections::VecDeque::new(),
            seq: std::sync::Arc::new(tokio::sync::Mutex::new(1)),
            write_task: write_join.abort_handle(),
            read_task: read_join.abort_handle(),
        };

        drop(connection);
        tokio::task::yield_now().await;
        assert!(write_join.await.unwrap_err().is_cancelled());
        assert!(read_join.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn terminal_signal_stops_peer_and_emits_disconnected_once() {
        let (_event_tx, event_rx) = tokio::sync::mpsc::channel(2);
        let terminal = Arc::new(ConnectionTerminalStateV1::default());
        let mut event_rx = ConnectionEventReceiverV1 {
            receiver: event_rx,
            terminal: terminal.clone(),
        };
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        signal_disconnected(
            &terminal,
            &shutdown_tx,
            "ws write error: closed".to_string(),
        );
        // A concurrent failure in the reader cannot create a second terminal
        // event for the same socket epoch.
        signal_disconnected(&terminal, &shutdown_tx, "ws read error: closed".to_string());

        shutdown_rx.changed().await.unwrap();
        assert!(*shutdown_rx.borrow());
        assert!(matches!(
            event_rx.recv().await,
            Some(ConnectionEvent::Disconnected { reason })
                if reason == "ws write error: closed"
        ));
        assert!(matches!(
            event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn websocket_auth_signature_is_domain_separated_x25519_pop() {
        let identity = IdentityKeyPair::generate();
        let server = IdentityKeyPair::generate();
        let challenge = server.x25519_public_bytes();
        let signature = websocket_auth_signature(&identity, &challenge).unwrap();
        let shared = identity.x25519_dh(&challenge);
        let mut proof = b"veil-ws-auth-v2\0".to_vec();
        proof.extend_from_slice(&challenge);
        proof.extend_from_slice(&shared);
        assert!(veil_crypto::signature::verify(
            &identity.ed25519_public_bytes(),
            &proof,
            &signature,
        ));
        assert!(!veil_crypto::signature::verify(
            &identity.ed25519_public_bytes(),
            &challenge,
            &signature,
        ));
        assert!(websocket_auth_signature(&identity, &[0u8; 31]).is_err());
    }

    #[test]
    fn bound_client_rejects_legacy_or_mismatched_auth_results() {
        let binding = DeviceBindingPublicV1 {
            device_id: [1u8; 16],
            device_identity_key: [2u8; 32],
            device_signing_key: [3u8; 32],
            version: 1,
            capabilities: REQUIRED_DEVICE_CAPABILITIES,
            status: DEVICE_BINDING_STATUS_ACTIVE,
            account_signature: [4u8; 64],
        };
        let secure = proto::AuthResult {
            success: true,
            user_id: Some("user-1".to_string()),
            error_message: None,
            per_device_secure: true,
            device_binding_version: 1,
            device_binding_status: i32::from(DEVICE_BINDING_STATUS_ACTIVE),
            failure_reason: proto::AuthFailureReason::Unspecified as i32,
        };
        assert_eq!(
            validate_per_device_auth_result(&secure, &binding).unwrap(),
            "user-1"
        );

        let mut legacy = secure.clone();
        legacy.per_device_secure = false;
        assert!(validate_per_device_auth_result(&legacy, &binding).is_err());

        let mut wrong_version = secure.clone();
        wrong_version.device_binding_version = 2;
        assert!(validate_per_device_auth_result(&wrong_version, &binding).is_err());

        let mut excluded = secure;
        excluded.device_binding_status = 2;
        assert!(validate_per_device_auth_result(&excluded, &binding).is_err());
    }

    #[test]
    fn maps_closed_registration_and_invalid_pass_without_server_secret_detail() {
        let binding = DeviceBindingPublicV1 {
            device_id: [1u8; 16],
            device_identity_key: [2u8; 32],
            device_signing_key: [3u8; 32],
            version: 1,
            capabilities: REQUIRED_DEVICE_CAPABILITIES,
            status: DEVICE_BINDING_STATUS_ACTIVE,
            account_signature: [4u8; 64],
        };
        let mut failed = proto::AuthResult {
            success: false,
            user_id: None,
            error_message: Some("internal invite lookup detail".to_string()),
            per_device_secure: false,
            device_binding_version: 0,
            device_binding_status: 0,
            failure_reason: proto::AuthFailureReason::RegistrationClosed as i32,
        };
        assert_eq!(
            validate_per_device_auth_result(&failed, &binding).unwrap_err(),
            "node access registration is closed; a valid access pass is required"
        );

        failed.failure_reason = proto::AuthFailureReason::InviteInvalid as i32;
        let error = validate_per_device_auth_result(&failed, &binding).unwrap_err();
        assert_eq!(
            error,
            "node access pass is invalid, expired, or already used"
        );
        assert!(!error.contains("lookup"));
    }
}

/// Dispatch a received Envelope into a typed ConnectionEvent.
fn exact_bytes<const N: usize>(value: &[u8]) -> Option<[u8; N]> {
    value.try_into().ok()
}

fn sender_key_route_from_proto(
    skd: &proto::SenderKeyDistribution,
) -> Option<crate::api::SenderKeyRouteV1> {
    if skd.conversation_id.is_empty()
        || skd.conversation_id.len() > MAX_EVENT_ID_BYTES
        || skd.generation == 0
        || skd.sender_key_message.is_empty()
        || skd.sender_key_message.len() > MAX_RETAINED_SKDM_WIRE_BYTES
        || skd.roster_version == 0
        || skd.roster_version > i64::MAX as u64
        || skd.sender_binding_version == 0
        || skd.sender_binding_version > i64::MAX as u64
        || skd.target_binding_version == 0
        || skd.target_binding_version > i64::MAX as u64
        || skd.sender_device_capabilities > i64::MAX as u64
        || skd.sender_device_capabilities & REQUIRED_DEVICE_CAPABILITIES
            != REQUIRED_DEVICE_CAPABILITIES
        || skd.sender_device_binding_status != u32::from(DEVICE_BINDING_STATUS_ACTIVE)
    {
        return None;
    }
    let target_account_identity_key = exact_bytes(&skd.target_identity_key)?;
    let target_device_id = exact_bytes(&skd.target_device_id)?;
    let target_device_identity_key = exact_bytes(&skd.target_device_identity_key)?;
    let sender_device_id = exact_bytes(&skd.sender_device_id)?;
    let sender_account_identity_key = exact_bytes(&skd.sender_account_identity_key)?;
    let sender_account_signing_key = exact_bytes(&skd.sender_account_signing_key)?;
    let sender_device_identity_key = exact_bytes(&skd.sender_device_identity_key)?;
    let sender_device_signing_key = exact_bytes(&skd.sender_device_signing_key)?;
    let sender_account_signature = exact_bytes(&skd.sender_account_signature)?;
    let roster_commitment = exact_bytes(&skd.roster_commitment)?;
    if target_account_identity_key == [0u8; 32]
        || target_device_id == [0u8; 16]
        || target_device_identity_key == [0u8; 32]
        || sender_device_id == [0u8; 16]
        || sender_account_identity_key == [0u8; 32]
        || sender_account_signing_key == [0u8; 32]
        || sender_device_identity_key == [0u8; 32]
        || sender_device_signing_key == [0u8; 32]
        || HashSet::from([
            sender_account_identity_key,
            sender_account_signing_key,
            sender_device_identity_key,
            sender_device_signing_key,
        ])
        .len()
            != 4
    {
        return None;
    }
    let metadata = veil_crypto::sender_key::inspect_skdm_metadata(&skd.sender_key_message).ok()?;
    if metadata.group_id != skd.conversation_id
        || metadata.generation != skd.generation
        || metadata.sender_identity_key != sender_device_identity_key
        || metadata.sender_signing_key != sender_device_signing_key
    {
        return None;
    }
    let proof_bytes = device_binding_signing_bytes(
        &sender_account_identity_key,
        &sender_account_signing_key,
        &sender_device_id,
        skd.sender_binding_version,
        &sender_device_identity_key,
        &sender_device_signing_key,
        skd.sender_device_capabilities,
        DEVICE_BINDING_STATUS_ACTIVE,
    );
    if !signature::verify(
        &sender_account_signing_key,
        &proof_bytes,
        &sender_account_signature,
    ) {
        return None;
    }
    Some(crate::api::SenderKeyRouteV1 {
        conversation_id: skd.conversation_id.clone(),
        generation: skd.generation,
        target_account_identity_key,
        target_device_id,
        target_device_identity_key,
        sender_device_id,
        sender_account_identity_key,
        sender_account_signing_key,
        sender_device_identity_key,
        sender_device_signing_key,
        sender_device_capabilities: skd.sender_device_capabilities,
        sender_device_binding_status: DEVICE_BINDING_STATUS_ACTIVE,
        sender_account_signature,
        roster_version: skd.roster_version,
        roster_commitment,
        sender_binding_version: skd.sender_binding_version,
        target_binding_version: skd.target_binding_version,
        envelope_commitment: Sha256::digest(&skd.sender_key_message).into(),
    })
}

fn message_security_context_from_proto(
    message: &proto::MessageEvent,
) -> Option<Option<crate::api::MessageSecurityContextV1>> {
    let absent = message.crypto_profile.is_empty()
        && message.crypto_era == 0
        && message.roster_version == 0
        && message.roster_commitment.is_empty()
        && message.sender_device_id.is_empty()
        && message.target_device_id.is_empty()
        && message.sender_binding_version == 0;
    if absent {
        return Some(None);
    }
    if message.crypto_profile != "sender_key_v5"
        || message.crypto_era != 1
        || message.roster_version == 0
        || message.roster_version > i64::MAX as u64
        || message.sender_binding_version == 0
        || message.sender_binding_version > i64::MAX as u64
    {
        return None;
    }
    let sender_device_id = exact_bytes(&message.sender_device_id)?;
    let target_device_id = exact_bytes(&message.target_device_id)?;
    if sender_device_id == [0u8; 16] || target_device_id == [0u8; 16] {
        return None;
    }
    Some(Some(crate::api::MessageSecurityContextV1::SenderKeyV5(
        crate::api::SenderKeyMessageSecurityContextV1 {
            roster_version: message.roster_version,
            roster_commitment: exact_bytes(&message.roster_commitment)?,
            sender_device_id,
            target_device_id,
            sender_binding_version: message.sender_binding_version,
        },
    )))
}

fn sender_key_ack_from_proto(ack: &proto::MessageAck) -> Option<Option<SenderKeyAckMetadataV1>> {
    let route_fields_absent = ack.target_device_id.is_empty()
        && ack.conversation_id.is_none()
        && ack.sender_key_generation.is_none()
        && ack.envelope_commitment.is_none();
    // A durable chat-message ACK may carry the roster version used to accept
    // that ciphertext, but it is not a Sender-Key distribution ACK. Exact
    // distribution/receipt acknowledgement is identified by the complete
    // device route tuple below and remains fail-closed when any field is
    // missing or malformed.
    if route_fields_absent {
        return Some(None);
    }
    let conversation_id = ack.conversation_id.clone()?;
    let generation = ack.sender_key_generation?;
    let roster_version = ack.roster_version?;
    let envelope = ack.envelope_commitment.as_deref()?;
    if conversation_id.is_empty()
        || conversation_id.len() > MAX_EVENT_ID_BYTES
        || generation == 0
        || roster_version == 0
        || roster_version > i64::MAX as u64
    {
        return None;
    }
    Some(Some(SenderKeyAckMetadataV1 {
        target_device_id: exact_bytes(&ack.target_device_id)?,
        conversation_id,
        generation,
        roster_version,
        envelope_commitment: exact_bytes(envelope)?,
    }))
}

fn protocol_violation(envelope: &'static str) -> ConnectionEventBufferErrorV1 {
    ConnectionEventBufferErrorV1::ProtocolViolation { envelope }
}

fn is_canonical_lowercase_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| !parsed.is_nil() && parsed.to_string() == value)
}

/// Decode a post-authentication envelope which is part of the event contract.
///
/// Known payloads that this client intentionally does not consume remain an
/// explicit `Ok(None)` for protocol forward compatibility. A malformed payload
/// that *is* handled here is different: dropping it could hide an encrypted
/// chat or acknowledgement step, so it terminates the authenticated epoch.
fn connection_event_from_envelope(
    env: proto::Envelope,
) -> Result<Option<ConnectionEvent>, ConnectionEventBufferErrorV1> {
    let event = match env.payload {
        Some(proto::envelope::Payload::MessageEvent(me)) => {
            if !is_canonical_lowercase_uuid(&me.message_id)
                || !is_canonical_lowercase_uuid(&me.conversation_id)
                || me
                    .reply_to_id
                    .as_deref()
                    .is_some_and(|value| !is_canonical_lowercase_uuid(value))
                || me.sender_identity_key.len() != 32
                || me.sender_username.len() > MAX_EVENT_ID_BYTES
                || me
                    .ciphertext
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_EVENT_CIPHERTEXT_BYTES)
                || me
                    .header
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_EVENT_HEADER_BYTES)
                || me.attachments.len() > crate::attachments::MAX_ATTACHMENTS_PER_MESSAGE
            {
                return Err(protocol_violation("MessageEvent"));
            }
            let security_context = message_security_context_from_proto(&me)
                .ok_or_else(|| protocol_violation("MessageEvent"))?;
            let event_type = proto::message_event::EventType::try_from(me.event_type)
                .map_err(|_| protocol_violation("MessageEvent"))?;
            match event_type {
                proto::message_event::EventType::Edited if !me.attachments.is_empty() => {
                    return Err(protocol_violation("MessageEvent"));
                }
                proto::message_event::EventType::Edited => ConnectionEvent::MessageEdited {
                    message_id: me.message_id,
                    conversation_id: me.conversation_id,
                    sender_identity_key: me.sender_identity_key,
                    ciphertext: me.ciphertext.unwrap_or_default(),
                    header: me.header.unwrap_or_default(),
                    edit_timestamp: me.edit_timestamp.unwrap_or(me.server_timestamp),
                },
                proto::message_event::EventType::Deleted if !me.attachments.is_empty() => {
                    return Err(protocol_violation("MessageEvent"));
                }
                proto::message_event::EventType::Deleted => ConnectionEvent::MessageDeleted {
                    message_id: me.message_id,
                    conversation_id: me.conversation_id,
                    sender_identity_key: me.sender_identity_key,
                    delete_timestamp: me.edit_timestamp.unwrap_or(me.server_timestamp),
                },
                proto::message_event::EventType::New => ConnectionEvent::MessageReceived {
                    message_id: me.message_id,
                    conversation_id: me.conversation_id,
                    sender_identity_key: me.sender_identity_key,
                    sender_username: me.sender_username,
                    ciphertext: me.ciphertext.unwrap_or_default(),
                    header: me.header.unwrap_or_default(),
                    server_timestamp: me.server_timestamp,
                    reply_to_id: me.reply_to_id,
                    msg_type: me.msg_type,
                    ttl_seconds: me.ttl_seconds,
                    sealed: me.sealed,
                    attachments: me
                        .attachments
                        .into_iter()
                        .map(|attachment| crate::attachments::WireAttachmentV1 {
                            media_id: attachment.media_id,
                            encrypted_key: attachment.encrypted_key,
                            nonce: attachment.nonce,
                            size: attachment.size,
                            content_type: attachment.content_type,
                        })
                        .collect(),
                    security_context,
                },
            }
        }
        Some(proto::envelope::Payload::MessageAck(ack)) => {
            // MessageAck is also the generic command ACK and the Sender-Key
            // distribution/receipt ACK, so an empty message id and timestamp
            // are valid for those forms. All forms still correlate to a
            // positive client sequence; chat ACKs additionally require their
            // complete message result tuple.
            let chat_ack = !ack.message_id.is_empty();
            if ack.ref_seq == 0
                || ack.message_id.len() > MAX_EVENT_ID_BYTES
                || (ack.message_id.is_empty() != (ack.server_timestamp == 0))
                || (chat_ack && !is_canonical_lowercase_uuid(&ack.message_id))
            {
                return Err(protocol_violation("MessageAck"));
            }
            let sender_key =
                sender_key_ack_from_proto(&ack).ok_or_else(|| protocol_violation("MessageAck"))?;
            let valid_shape = match (chat_ack, sender_key.as_ref()) {
                // Chat ACKs may carry the accepted roster version, but never
                // the Sender-Key distribution route tuple.
                (true, None) => true,
                // Distribution/receipt ACKs use the complete route tuple and
                // intentionally have no chat message result.
                (false, Some(_)) => true,
                // A generic command ACK is only a sequence correlation. A
                // roster version without either chat or exact route metadata
                // is ambiguous and must not reach the mutation finalizers.
                (false, None) => ack.roster_version.is_none(),
                (true, Some(_)) => false,
            };
            if !valid_shape {
                return Err(protocol_violation("MessageAck"));
            }
            ConnectionEvent::MessageAcked {
                message_id: ack.message_id,
                server_timestamp: ack.server_timestamp,
                ref_seq: ack.ref_seq,
                local_message_id: None,
                mutation: None,
                sender_key,
            }
        }
        Some(proto::envelope::Payload::Error(e)) => ConnectionEvent::Error {
            code: e.code,
            message: e.message,
            ref_seq: e.ref_seq,
            local_message_id: None,
            conversation_id: None,
            stale_roster_context: false,
        },
        Some(proto::envelope::Payload::TypingEvent(te)) => ConnectionEvent::TypingEvent {
            conversation_id: te.conversation_id,
            identity_key: te.identity_key,
            started: te.started,
        },
        Some(proto::envelope::Payload::ReactionEvent(re)) => ConnectionEvent::ReactionEvent {
            message_id: re.message_id,
            conversation_id: re.conversation_id,
            emoji: re.emoji,
            user_id: re.user_id,
            username: re.username,
            add: re.add,
        },
        Some(proto::envelope::Payload::PresenceUpdate(pu)) => ConnectionEvent::PresenceUpdate {
            identity_key: pu.identity_key,
            status: pu.status,
            status_text: pu.status_text,
            last_seen: pu.last_seen,
        },
        Some(proto::envelope::Payload::FriendRequestEvent(fre)) => {
            ConnectionEvent::FriendRequestReceived {
                request_id: fre.request_id,
                from_user_id: fre.from_user_id,
                from_username: fre.from_username,
                message: fre.message,
                timestamp: fre.timestamp,
            }
        }
        Some(proto::envelope::Payload::FriendAcceptedEvent(fae)) => {
            ConnectionEvent::FriendAccepted {
                user_id: fae.user_id,
                username: fae.username,
            }
        }
        Some(proto::envelope::Payload::FriendRemovedEvent(fre)) => ConnectionEvent::FriendRemoved {
            user_id: fre.user_id,
        },
        Some(proto::envelope::Payload::FriendListResponse(flr)) => {
            ConnectionEvent::FriendListReceived {
                friends: flr
                    .friends
                    .into_iter()
                    .map(|f| FriendInfo {
                        user_id: f.user_id,
                        username: f.username,
                        status: f.status,
                        last_seen: f.last_seen,
                    })
                    .collect(),
                pending_requests: flr
                    .pending_requests
                    .into_iter()
                    .map(|r| FriendRequestInfo {
                        request_id: r.request_id,
                        from_user_id: r.from_user_id,
                        from_username: r.from_username,
                        message: r.message,
                        timestamp: r.timestamp,
                        outgoing: r.outgoing,
                    })
                    .collect(),
            }
        }
        Some(proto::envelope::Payload::ProfileUpdated(update)) => {
            let parsed_user_id = Uuid::parse_str(&update.user_id)
                .map_err(|_| protocol_violation("ProfileUpdated"))?;
            if parsed_user_id.to_string() != update.user_id
                || update.profile_version == 0
                || update.profile_version > i64::MAX as u64
            {
                return Err(protocol_violation("ProfileUpdated"));
            }
            ConnectionEvent::ProfileUpdated {
                user_id: update.user_id,
                profile_version: update.profile_version,
            }
        }
        Some(proto::envelope::Payload::ServerEvent(se)) => ConnectionEvent::ServerEvent {
            event_type: se.event_type,
            server_id: se.server_id,
            server_info: se.server_info.map(|si| ServerInfoLite {
                id: si.id,
                name: si.name,
                icon_url: si.icon_url,
                owner_identity_key: si.owner_identity_key,
            }),
            member_info: se.member_info.map(|mi| MemberInfoLite {
                identity_key: mi.identity_key,
                username: mi.username,
                role_ids: mi.role_ids,
                reason: mi.reason,
            }),
            role_info: se.role_info.map(|ri| RoleInfoLite {
                id: ri.id,
                name: ri.name,
                permissions: ri.permissions,
                position: ri.position,
                color: ri.color,
            }),
        },
        Some(proto::envelope::Payload::ChannelEvent(ce)) => {
            let info = ce.channel_info.unwrap_or_default();
            ConnectionEvent::ChannelEvent {
                event_type: ce.event_type,
                server_id: ce.server_id,
                channel: ChannelInfoLite {
                    id: info.id,
                    server_id: info.server_id,
                    name: info.name,
                    channel_type: info.channel_type,
                    category_id: info.category_id,
                    position: info.position,
                    topic: info.topic,
                },
            }
        }
        Some(proto::envelope::Payload::SenderKeyDist(skd)) => {
            let route = sender_key_route_from_proto(&skd)
                .ok_or_else(|| protocol_violation("SenderKeyDistribution"))?;
            ConnectionEvent::SenderKeyDist {
                sender_key_message: skd.sender_key_message,
                route,
            }
        }
        // Known payloads without a ConnectionEvent consumer are intentionally
        // ignored. In particular, an absent payload may be a future oneof field
        // unknown to this generated client, so it is not sufficient evidence
        // of a protocol violation by itself.
        _ => return Ok(None),
    };
    Ok(Some(event))
}

async fn dispatch_event(
    tx: &ConnectionEventSenderV1,
    env: proto::Envelope,
) -> Result<(), ConnectionEventBufferErrorV1> {
    let authentication_envelope = match env.payload.as_ref() {
        Some(proto::envelope::Payload::AuthChallenge(_)) => Some("AuthChallenge"),
        Some(proto::envelope::Payload::AuthResponse(_)) => Some("AuthResponse"),
        Some(proto::envelope::Payload::AuthResult(_)) => Some("AuthResult"),
        _ => None,
    };
    if let Some(envelope) = authentication_envelope {
        return Err(ConnectionEventBufferErrorV1::AuthenticationEpochAnomaly { envelope });
    }
    if let Some(event) = connection_event_from_envelope(env)? {
        tx.send(event).await?;
    }
    Ok(())
}

async fn dispatch_authenticated_binary_frame(
    tx: &ConnectionEventSenderV1,
    wire: &[u8],
) -> Result<(), ConnectionEventBufferErrorV1> {
    let env = proto::Envelope::decode(wire).map_err(|_| protocol_violation("Envelope"))?;
    dispatch_event(tx, env).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticatedWsMessageOutcomeV1 {
    Continue,
    Closed,
}

async fn dispatch_authenticated_ws_message(
    tx: &ConnectionEventSenderV1,
    message: WsMessage,
) -> Result<AuthenticatedWsMessageOutcomeV1, ConnectionEventBufferErrorV1> {
    match message {
        WsMessage::Binary(data) => {
            dispatch_authenticated_binary_frame(tx, data.as_ref()).await?;
            Ok(AuthenticatedWsMessageOutcomeV1::Continue)
        }
        // The authenticated Veil application protocol is protobuf-only.
        // Ignoring another data-message type can create the same invisible
        // protocol gap as dropping a malformed binary envelope.
        WsMessage::Text(_) => Err(protocol_violation("WebSocket Text data frame")),
        // Tungstenite documents that raw frames are not yielded while reading,
        // but keep the boundary exhaustive and fail closed if that changes.
        WsMessage::Frame(_) => Err(protocol_violation("WebSocket raw data frame")),
        WsMessage::Ping(_) | WsMessage::Pong(_) => Ok(AuthenticatedWsMessageOutcomeV1::Continue),
        WsMessage::Close(_) => Ok(AuthenticatedWsMessageOutcomeV1::Closed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MESSAGE_ID: &str = "a0000000-0000-4000-8000-000000000001";
    const TEST_REPLY_ID: &str = "c0000000-0000-4000-8000-000000000002";
    const TEST_CONVERSATION_ID: &str = "b0000000-0000-4000-8000-000000000001";

    fn error_event_with_capacity(capacity: usize) -> ConnectionEvent {
        let mut message = String::with_capacity(capacity);
        message.push('x');
        ConnectionEvent::Error {
            code: 500,
            message,
            ref_seq: None,
            local_message_id: None,
            conversation_id: None,
            stale_roster_context: false,
        }
    }

    #[test]
    fn global_event_budget_accepts_exact_boundaries_and_rejects_one_more() {
        let event = error_event_with_capacity(128);
        let retained = connection_event_retained_size_v1(&event).unwrap();

        let exact_bytes = ConnectionEventBudgetV1::with_limits(1, retained);
        let exact = exact_bytes.try_wrap(event).unwrap();
        assert_eq!(exact.retained_bytes(), retained);
        assert!(matches!(
            exact_bytes.try_wrap(error_event_with_capacity(1)),
            Err(ConnectionEventBufferErrorV1::EventCountLimitExceeded { limit: 1 })
        ));
        drop(exact);

        let one_byte_short = ConnectionEventBudgetV1::with_limits(1, retained - 1);
        assert!(matches!(
            one_byte_short.try_wrap(error_event_with_capacity(128)),
            Err(ConnectionEventBufferErrorV1::RetainedSizeLimitExceeded {
                limit,
                event_bytes,
            }) if limit == retained - 1 && event_bytes == retained
        ));

        let two_events = ConnectionEventBudgetV1::with_limits(2, retained * 2);
        let first = two_events.try_wrap(error_event_with_capacity(128)).unwrap();
        let second = two_events.try_wrap(error_event_with_capacity(128)).unwrap();
        assert!(matches!(
            two_events.try_wrap(error_event_with_capacity(1)),
            Err(ConnectionEventBufferErrorV1::EventCountLimitExceeded { limit: 2 })
        ));
        drop((first, second));
    }

    #[test]
    fn retained_size_counts_huge_nested_friend_and_server_allocations() {
        let mut username = String::with_capacity(2 * 1024 * 1024);
        username.push('a');
        let mut message = String::with_capacity(1024 * 1024);
        message.push('b');
        let mut friends = Vec::with_capacity(7);
        friends.push(FriendInfo {
            user_id: "friend".to_string(),
            username,
            status: 1,
            last_seen: None,
        });
        let mut pending_requests = Vec::with_capacity(9);
        pending_requests.push(FriendRequestInfo {
            request_id: "request".to_string(),
            from_user_id: "from".to_string(),
            from_username: "sender".to_string(),
            message: Some(message),
            timestamp: 1,
            outgoing: false,
        });
        let friend_list = ConnectionEvent::FriendListReceived {
            friends,
            pending_requests,
        };
        let friend_bytes = connection_event_retained_size_v1(&friend_list).unwrap();
        assert!(friend_bytes > 3 * 1024 * 1024);

        let mut role_id = String::with_capacity(2 * 1024 * 1024);
        role_id.push('r');
        let mut role_ids = Vec::with_capacity(16);
        role_ids.push(role_id);
        let server = ConnectionEvent::ServerEvent {
            event_type: 1,
            server_id: "server".to_string(),
            server_info: Some(ServerInfoLite {
                id: "server".to_string(),
                name: "name".to_string(),
                icon_url: Some("icon".to_string()),
                owner_identity_key: vec![1; 32],
            }),
            member_info: Some(MemberInfoLite {
                identity_key: vec![2; 32],
                username: "member".to_string(),
                role_ids,
                reason: Some("reason".to_string()),
            }),
            role_info: Some(RoleInfoLite {
                id: "role".to_string(),
                name: "role name".to_string(),
                permissions: 1,
                position: 1,
                color: None,
            }),
        };
        assert!(connection_event_retained_size_v1(&server).unwrap() > 2 * 1024 * 1024);
    }

    #[test]
    fn retained_size_accounting_uses_checked_arithmetic() {
        let mut counter = RetainedSizeCounterV1::default();
        counter.add(usize::MAX).unwrap();
        assert_eq!(
            counter.add(1).unwrap_err(),
            ConnectionEventBufferErrorV1::RetainedSizeAccountingOverflow
        );

        let mut counter = RetainedSizeCounterV1::default();
        assert_eq!(
            counter.add_items::<u64>(usize::MAX).unwrap_err(),
            ConnectionEventBufferErrorV1::RetainedSizeAccountingOverflow
        );
    }

    #[tokio::test]
    async fn terminal_preempts_a_full_channel_drops_permits_and_is_delivered_once() {
        let probe = error_event_with_capacity(32);
        let bytes = connection_event_retained_size_v1(&probe).unwrap();
        let budget = ConnectionEventBudgetV1::with_limits(2, bytes * 2);
        let (raw_tx, raw_rx) = mpsc::channel(2);
        let terminal = Arc::new(ConnectionTerminalStateV1::default());
        let sender = ConnectionEventSenderV1 {
            sender: raw_tx,
            budget: budget.clone(),
        };
        let mut receiver = ConnectionEventReceiverV1 {
            receiver: raw_rx,
            terminal: terminal.clone(),
        };

        sender.send(error_event_with_capacity(32)).await.unwrap();
        sender.send(error_event_with_capacity(32)).await.unwrap();
        assert!(matches!(
            sender.send(error_event_with_capacity(1)).await,
            Err(ConnectionEventBufferErrorV1::EventCountLimitExceeded { limit: 2 })
        ));

        let terminal_error = ConnectionEventBufferErrorV1::EventCountLimitExceeded { limit: 2 };
        assert!(terminal.report_buffer_failure(terminal_error.clone()));
        let terminal_event = receiver.try_recv_budgeted().unwrap();
        assert_eq!(terminal_event.terminal_failure(), Some(&terminal_error));
        assert!(matches!(
            terminal_event.into_event(),
            ConnectionEvent::Disconnected { reason }
                if reason.contains("2-event limit")
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));

        // Draining the stale full channel dropped both guards. A fresh epoch
        // budget user can acquire the exact same two slots and bytes again.
        let first = budget.try_wrap(error_event_with_capacity(32)).unwrap();
        let second = budget.try_wrap(error_event_with_capacity(32)).unwrap();
        drop((first, second));
    }

    #[tokio::test]
    async fn terminal_notification_cannot_be_lost_by_async_recv_race() {
        let (_raw_tx, raw_rx) = mpsc::channel(1);
        let terminal = Arc::new(ConnectionTerminalStateV1::default());
        let mut receiver = ConnectionEventReceiverV1 {
            receiver: raw_rx,
            terminal: terminal.clone(),
        };
        let receive = tokio::spawn(async move { receiver.recv().await });
        tokio::task::yield_now().await;
        assert!(terminal.report_transport("closed during wait".to_string()));
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), receive)
            .await
            .expect("terminal notification was lost")
            .unwrap();
        assert!(matches!(
            event,
            Some(ConnectionEvent::Disconnected { reason }) if reason == "closed during wait"
        ));
    }

    #[tokio::test]
    async fn malformed_authenticated_binary_preempts_queued_ciphertext_with_typed_terminal() {
        let budget = ConnectionEventBudgetV1::with_limits(2, LIVE_EVENT_RETAINED_BYTES);
        let (raw_tx, raw_rx) = mpsc::channel(2);
        let terminal = Arc::new(ConnectionTerminalStateV1::default());
        let sender = ConnectionEventSenderV1 {
            sender: raw_tx,
            budget: budget.clone(),
        };
        let mut receiver = ConnectionEventReceiverV1 {
            receiver: raw_rx,
            terminal: terminal.clone(),
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Queue an encrypted event first. A later malformed authenticated
        // frame must preempt it rather than letting a consumer observe an
        // apparently quiescent FIFO and then advance past a missing ratchet
        // step.
        let valid = proto::Envelope {
            payload: Some(proto::envelope::Payload::MessageEvent(base_message_event())),
            ..Default::default()
        }
        .encode_to_vec();
        dispatch_authenticated_binary_frame(&sender, &valid)
            .await
            .unwrap();

        let error = dispatch_authenticated_binary_frame(&sender, &[0x80])
            .await
            .unwrap_err();
        assert_eq!(
            error,
            ConnectionEventBufferErrorV1::ProtocolViolation {
                envelope: "Envelope"
            }
        );
        signal_event_buffer_failure(&terminal, &shutdown_tx, error.clone());

        let terminal_event = receiver.try_recv_budgeted().unwrap();
        assert_eq!(terminal_event.terminal_failure(), Some(&error));
        assert!(matches!(
            terminal_event.into_event(),
            ConnectionEvent::Disconnected { reason }
                if reason == "malformed Envelope envelope after the authenticated barrier"
        ));
        assert!(*shutdown_rx.borrow());
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));

        // Terminal preemption drained the earlier ciphertext and released its
        // shared permit; it can never be delivered after the protocol gap.
        let replacement = budget.try_wrap(error_event_with_capacity(1)).unwrap();
        drop(replacement);
    }

    #[tokio::test]
    async fn authenticated_text_frame_preempts_queued_event_and_releases_its_permit() {
        let budget = ConnectionEventBudgetV1::with_limits(1, LIVE_EVENT_RETAINED_BYTES);
        let (raw_tx, raw_rx) = mpsc::channel(1);
        let terminal = Arc::new(ConnectionTerminalStateV1::default());
        let sender = ConnectionEventSenderV1 {
            sender: raw_tx,
            budget: budget.clone(),
        };
        let mut receiver = ConnectionEventReceiverV1 {
            receiver: raw_rx,
            terminal: terminal.clone(),
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Control frames are legal throughout an authenticated epoch.
        for control in [WsMessage::Ping(Vec::new()), WsMessage::Pong(Vec::new())] {
            assert_eq!(
                dispatch_authenticated_ws_message(&sender, control)
                    .await
                    .unwrap(),
                AuthenticatedWsMessageOutcomeV1::Continue
            );
        }

        let valid = proto::Envelope {
            payload: Some(proto::envelope::Payload::MessageEvent(base_message_event())),
            ..Default::default()
        }
        .encode_to_vec();
        assert_eq!(
            dispatch_authenticated_ws_message(&sender, WsMessage::Binary(valid))
                .await
                .unwrap(),
            AuthenticatedWsMessageOutcomeV1::Continue
        );

        let error =
            dispatch_authenticated_ws_message(&sender, WsMessage::Text("not protobuf".to_string()))
                .await
                .unwrap_err();
        assert_eq!(
            error,
            ConnectionEventBufferErrorV1::ProtocolViolation {
                envelope: "WebSocket Text data frame"
            }
        );
        signal_event_buffer_failure(&terminal, &shutdown_tx, error.clone());

        let terminal_event = receiver.try_recv_budgeted().unwrap();
        assert_eq!(terminal_event.terminal_failure(), Some(&error));
        assert!(matches!(
            terminal_event.into_event(),
            ConnectionEvent::Disconnected { reason }
                if reason.contains("WebSocket Text data frame")
        ));
        assert!(*shutdown_rx.borrow());
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));

        // The queued event owned the epoch's only permit. Terminal preemption
        // drained it, so the same budget can be acquired again immediately.
        let replacement = budget.try_wrap(error_event_with_capacity(1)).unwrap();
        drop(replacement);
    }

    #[tokio::test]
    async fn malformed_handled_chat_events_are_protocol_terminals() {
        let budget = ConnectionEventBudgetV1::with_limits(1, LIVE_EVENT_RETAINED_BYTES);
        let (raw_tx, _raw_rx) = mpsc::channel(1);
        let sender = ConnectionEventSenderV1 {
            sender: raw_tx,
            budget,
        };

        let mut invalid_message = base_message_event();
        invalid_message.event_type = 99;
        let invalid_message = proto::Envelope {
            payload: Some(proto::envelope::Payload::MessageEvent(invalid_message)),
            ..Default::default()
        }
        .encode_to_vec();
        assert_eq!(
            dispatch_authenticated_binary_frame(&sender, &invalid_message)
                .await
                .unwrap_err(),
            ConnectionEventBufferErrorV1::ProtocolViolation {
                envelope: "MessageEvent"
            }
        );

        let partial_sender_key_ack = proto::Envelope {
            payload: Some(proto::envelope::Payload::MessageAck(proto::MessageAck {
                message_id: TEST_MESSAGE_ID.to_string(),
                server_timestamp: 1,
                ref_seq: 1,
                target_device_id: vec![0x22; 16],
                ..Default::default()
            })),
            ..Default::default()
        }
        .encode_to_vec();
        assert_eq!(
            dispatch_authenticated_binary_frame(&sender, &partial_sender_key_ack)
                .await
                .unwrap_err(),
            ConnectionEventBufferErrorV1::ProtocolViolation {
                envelope: "MessageAck"
            }
        );
    }

    #[tokio::test]
    async fn mutually_exclusive_ack_shapes_are_enforced_before_enqueue() {
        let budget = ConnectionEventBudgetV1::with_limits(2, LIVE_EVENT_RETAINED_BYTES);
        let (raw_tx, mut raw_rx) = mpsc::channel(2);
        let sender = ConnectionEventSenderV1 {
            sender: raw_tx,
            budget,
        };

        let combined_chat_and_sender_key = proto::MessageAck {
            message_id: TEST_MESSAGE_ID.to_string(),
            server_timestamp: 1,
            ref_seq: 1,
            target_device_id: vec![0x22; 16],
            conversation_id: Some("conversation-1".to_string()),
            sender_key_generation: Some(1),
            roster_version: Some(4),
            envelope_commitment: Some(vec![0x33; 32]),
        };
        let generic_with_orphan_roster = proto::MessageAck {
            ref_seq: 2,
            roster_version: Some(4),
            ..Default::default()
        };

        for ack in [combined_chat_and_sender_key, generic_with_orphan_roster] {
            let wire = proto::Envelope {
                payload: Some(proto::envelope::Payload::MessageAck(ack)),
                ..Default::default()
            }
            .encode_to_vec();
            assert_eq!(
                dispatch_authenticated_binary_frame(&sender, &wire)
                    .await
                    .unwrap_err(),
                ConnectionEventBufferErrorV1::ProtocolViolation {
                    envelope: "MessageAck"
                }
            );
            assert!(matches!(
                raw_rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }
    }

    #[tokio::test]
    async fn explicitly_unsupported_post_auth_payloads_remain_forward_compatible() {
        let budget = ConnectionEventBudgetV1::with_limits(1, LIVE_EVENT_RETAINED_BYTES);
        let (raw_tx, mut raw_rx) = mpsc::channel(1);
        let sender = ConnectionEventSenderV1 {
            sender: raw_tx,
            budget,
        };
        let delivered = proto::Envelope {
            payload: Some(proto::envelope::Payload::MessageDelivered(
                proto::MessageDelivered {
                    message_id: "message-1".to_string(),
                    conversation_id: "conversation-1".to_string(),
                    timestamp: 1,
                },
            )),
            ..Default::default()
        }
        .encode_to_vec();

        dispatch_authenticated_binary_frame(&sender, &delivered)
            .await
            .unwrap();
        assert!(matches!(
            raw_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        // Prost represents an unknown future oneof field as no known payload.
        // Absence alone therefore stays ignorable rather than making every
        // future server event fatal to older clients.
        let future_payload = proto::Envelope::default().encode_to_vec();
        dispatch_authenticated_binary_frame(&sender, &future_payload)
            .await
            .unwrap();
        assert!(matches!(
            raw_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    fn base_message_event() -> proto::MessageEvent {
        proto::MessageEvent {
            event_type: proto::message_event::EventType::New as i32,
            message_id: TEST_MESSAGE_ID.to_string(),
            conversation_id: TEST_CONVERSATION_ID.to_string(),
            sender_identity_key: vec![0x11; 32],
            sender_username: "Alice".to_string(),
            server_timestamp: 1,
            ciphertext: Some(vec![0x22]),
            header: Some(vec![0x03]),
            ..Default::default()
        }
    }

    #[test]
    fn message_event_preserves_optional_policy_metadata_and_absence() {
        let absent = connection_event_from_envelope(proto::Envelope {
            payload: Some(proto::envelope::Payload::MessageEvent(base_message_event())),
            ..Default::default()
        })
        .unwrap()
        .unwrap();
        assert!(matches!(
            &absent,
            ConnectionEvent::MessageReceived {
                msg_type: None,
                ttl_seconds: None,
                sealed: None,
                ..
            }
        ));

        let mut wire = base_message_event();
        wire.msg_type = Some(proto::MessageType::File as i32);
        wire.ttl_seconds = Some(0);
        wire.sealed = Some(false);
        let present = connection_event_from_envelope(proto::Envelope {
            payload: Some(proto::envelope::Payload::MessageEvent(wire)),
            ..Default::default()
        })
        .unwrap()
        .unwrap();
        assert!(matches!(
            &present,
            ConnectionEvent::MessageReceived {
                msg_type: Some(value),
                ttl_seconds: Some(0),
                sealed: Some(false),
                ..
            } if *value == proto::MessageType::File as i32
        ));

        // These optional scalars live inline in the enum. Presence must stay
        // distinguishable without being double-counted as retained heap data.
        assert_eq!(
            connection_event_retained_size_v1(&absent).unwrap(),
            connection_event_retained_size_v1(&present).unwrap()
        );
    }

    #[tokio::test]
    async fn live_message_and_chat_ack_ids_require_canonical_non_nil_lowercase_uuids_before_enqueue(
    ) {
        let budget = ConnectionEventBudgetV1::with_limits(2, LIVE_EVENT_RETAINED_BYTES);
        let (raw_tx, mut raw_rx) = mpsc::channel(2);
        let sender = ConnectionEventSenderV1 {
            sender: raw_tx,
            budget,
        };

        let mut uppercase_message = base_message_event();
        uppercase_message.message_id = TEST_MESSAGE_ID.to_uppercase();
        let mut compact_conversation = base_message_event();
        compact_conversation.conversation_id = TEST_CONVERSATION_ID.replace('-', "");
        let mut uppercase_reply = base_message_event();
        uppercase_reply.reply_to_id = Some(TEST_REPLY_ID.to_uppercase());
        let mut nil_message = base_message_event();
        nil_message.message_id = Uuid::nil().to_string();
        let mut nil_conversation = base_message_event();
        nil_conversation.conversation_id = Uuid::nil().to_string();
        let mut nil_reply = base_message_event();
        nil_reply.reply_to_id = Some(Uuid::nil().to_string());

        for invalid in [
            uppercase_message,
            compact_conversation,
            uppercase_reply,
            nil_message,
            nil_conversation,
            nil_reply,
        ] {
            let wire = proto::Envelope {
                payload: Some(proto::envelope::Payload::MessageEvent(invalid)),
                ..Default::default()
            }
            .encode_to_vec();
            assert_eq!(
                dispatch_authenticated_binary_frame(&sender, &wire)
                    .await
                    .unwrap_err(),
                ConnectionEventBufferErrorV1::ProtocolViolation {
                    envelope: "MessageEvent"
                }
            );
            assert!(matches!(
                raw_rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }

        for invalid_message_id in [
            TEST_MESSAGE_ID.to_uppercase(),
            TEST_MESSAGE_ID.replace('-', ""),
            Uuid::nil().to_string(),
        ] {
            let wire = proto::Envelope {
                payload: Some(proto::envelope::Payload::MessageAck(proto::MessageAck {
                    message_id: invalid_message_id,
                    server_timestamp: 1,
                    ref_seq: 1,
                    ..Default::default()
                })),
                ..Default::default()
            }
            .encode_to_vec();
            assert_eq!(
                dispatch_authenticated_binary_frame(&sender, &wire)
                    .await
                    .unwrap_err(),
                ConnectionEventBufferErrorV1::ProtocolViolation {
                    envelope: "MessageAck"
                }
            );
            assert!(matches!(
                raw_rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }

        let mut valid_message = base_message_event();
        valid_message.reply_to_id = Some(TEST_REPLY_ID.to_string());
        let valid_message = proto::Envelope {
            payload: Some(proto::envelope::Payload::MessageEvent(valid_message)),
            ..Default::default()
        }
        .encode_to_vec();
        dispatch_authenticated_binary_frame(&sender, &valid_message)
            .await
            .unwrap();
        assert!(matches!(
            raw_rx.try_recv().unwrap().into_event(),
            ConnectionEvent::MessageReceived {
                message_id,
                conversation_id,
                reply_to_id: Some(reply_to_id),
                ..
            } if message_id == TEST_MESSAGE_ID
                && conversation_id == TEST_CONVERSATION_ID
                && reply_to_id == TEST_REPLY_ID
        ));

        let valid_ack = proto::Envelope {
            payload: Some(proto::envelope::Payload::MessageAck(proto::MessageAck {
                message_id: TEST_MESSAGE_ID.to_string(),
                server_timestamp: 1,
                ref_seq: 2,
                ..Default::default()
            })),
            ..Default::default()
        }
        .encode_to_vec();
        dispatch_authenticated_binary_frame(&sender, &valid_ack)
            .await
            .unwrap();
        assert!(matches!(
            raw_rx.try_recv().unwrap().into_event(),
            ConnectionEvent::MessageAcked {
                message_id,
                ref_seq: 2,
                sender_key: None,
                ..
            } if message_id == TEST_MESSAGE_ID
        ));
    }

    #[test]
    fn unknown_message_event_enum_and_partial_security_context_are_rejected() {
        let mut unknown = base_message_event();
        unknown.event_type = 99;
        assert!(connection_event_from_envelope(proto::Envelope {
            payload: Some(proto::envelope::Payload::MessageEvent(unknown)),
            ..Default::default()
        })
        .is_err());

        // Protobuf enums are open. Preserve a future message type so policy at
        // the consumer boundary can quarantine or render it without forcing an
        // older client into a reconnect loop during a rolling upgrade.
        let mut unknown_message_type = base_message_event();
        unknown_message_type.msg_type = Some(i32::MAX);
        assert!(matches!(
            connection_event_from_envelope(proto::Envelope {
                payload: Some(proto::envelope::Payload::MessageEvent(unknown_message_type)),
                ..Default::default()
            }),
            Ok(Some(ConnectionEvent::MessageReceived {
                msg_type: Some(i32::MAX),
                ..
            }))
        ));

        let mut partial = base_message_event();
        partial.crypto_profile = "sender_key_v5".to_string();
        assert!(connection_event_from_envelope(proto::Envelope {
            payload: Some(proto::envelope::Payload::MessageEvent(partial)),
            ..Default::default()
        })
        .is_err());

        let mut exact = base_message_event();
        exact.crypto_profile = "sender_key_v5".to_string();
        exact.crypto_era = 1;
        exact.roster_version = 7;
        exact.roster_commitment = vec![0x33; 32];
        exact.sender_device_id = vec![0x44; 16];
        exact.target_device_id = vec![0x55; 16];
        exact.sender_binding_version = 2;
        assert!(matches!(
            connection_event_from_envelope(proto::Envelope {
                payload: Some(proto::envelope::Payload::MessageEvent(exact)),
                ..Default::default()
            }),
            Ok(Some(ConnectionEvent::MessageReceived {
                security_context: Some(crate::api::MessageSecurityContextV1::SenderKeyV5(_)),
                ..
            }))
        ));
    }

    #[test]
    fn profile_update_requires_a_canonical_user_and_bounded_positive_version() {
        let user_id = "5a636f65-3ab4-48b9-84b8-f4996ab73c88";
        assert!(matches!(
            connection_event_from_envelope(proto::Envelope {
                payload: Some(proto::envelope::Payload::ProfileUpdated(
                    proto::ProfileUpdated {
                        user_id: user_id.to_string(),
                        profile_version: i64::MAX as u64,
                    },
                )),
                ..Default::default()
            }),
            Ok(Some(ConnectionEvent::ProfileUpdated {
                user_id: accepted_user_id,
                profile_version,
            })) if accepted_user_id == user_id && profile_version == i64::MAX as u64
        ));

        for update in [
            proto::ProfileUpdated {
                user_id: user_id.to_uppercase(),
                profile_version: 1,
            },
            proto::ProfileUpdated {
                user_id: user_id.to_string(),
                profile_version: 0,
            },
            proto::ProfileUpdated {
                user_id: user_id.to_string(),
                profile_version: i64::MAX as u64 + 1,
            },
        ] {
            assert!(connection_event_from_envelope(proto::Envelope {
                payload: Some(proto::envelope::Payload::ProfileUpdated(update)),
                ..Default::default()
            })
            .is_err());
        }
    }

    #[test]
    fn sender_key_route_and_ack_require_exact_metadata_and_aligned_bounds() {
        assert_eq!(MAX_RETAINED_SKDM_EVENTS, 2_048);
        assert_eq!(MAX_RETAINED_SKDM_WIRE_TOTAL_BYTES, 4 * 1024 * 1024);
        assert_eq!(MAX_RETAINED_SKDM_WIRE_BYTES, 4_096);

        let sender_account = IdentityKeyPair::generate();
        let recipient_account = IdentityKeyPair::generate();
        let sender = DeviceIdentityV1::from_stored(
            &sender_account,
            DeviceIdentityV1::generate_stored(&sender_account, [0x33; 16]).unwrap(),
        )
        .unwrap();
        let recipient = DeviceIdentityV1::from_stored(
            &recipient_account,
            DeviceIdentityV1::generate_stored(&recipient_account, [0x22; 16]).unwrap(),
        )
        .unwrap();
        let sealed = veil_crypto::sender_key::seal_skdm_authenticated_with_device(
            &sender.binding().device_identity_key,
            sender.ed25519_signing_key(),
            &recipient.binding().device_identity_key,
            "conversation-1",
            1,
            b"payload",
        )
        .unwrap();
        let skdm = proto::SenderKeyDistribution {
            conversation_id: "conversation-1".to_string(),
            sender_key_message: sealed,
            generation: 1,
            target_identity_key: recipient_account.x25519_public_bytes().to_vec(),
            target_device_id: vec![0x22; 16],
            target_device_identity_key: recipient.binding().device_identity_key.to_vec(),
            sender_device_id: vec![0x33; 16],
            roster_version: 4,
            roster_commitment: vec![0x44; 32],
            sender_binding_version: sender.binding().version,
            target_binding_version: 3,
            sender_account_identity_key: sender_account.x25519_public_bytes().to_vec(),
            sender_account_signing_key: sender_account.ed25519_public_bytes().to_vec(),
            sender_device_identity_key: sender.binding().device_identity_key.to_vec(),
            sender_device_signing_key: sender.binding().device_signing_key.to_vec(),
            sender_device_capabilities: sender.binding().capabilities,
            sender_device_binding_status: u32::from(sender.binding().status),
            sender_account_signature: sender.binding().account_signature.to_vec(),
        };
        assert!(sender_key_route_from_proto(&skdm).is_some());
        let mut oversized = skdm.clone();
        oversized.sender_key_message = vec![0x55; MAX_RETAINED_SKDM_WIRE_BYTES + 1];
        assert!(sender_key_route_from_proto(&oversized).is_none());
        let mut zero_device = skdm;
        zero_device.sender_device_id = vec![0; 16];
        assert!(sender_key_route_from_proto(&zero_device).is_none());

        let partial_ack = proto::MessageAck {
            target_device_id: vec![0x22; 16],
            ..Default::default()
        };
        assert!(sender_key_ack_from_proto(&partial_ack).is_none());
        let generic_command_ack = proto::MessageAck {
            ref_seq: 1,
            ..Default::default()
        };
        assert!(matches!(
            connection_event_from_envelope(proto::Envelope {
                payload: Some(proto::envelope::Payload::MessageAck(generic_command_ack)),
                ..Default::default()
            }),
            Ok(Some(ConnectionEvent::MessageAcked {
                message_id,
                server_timestamp: 0,
                ref_seq: 1,
                sender_key: None,
                ..
            })) if message_id.is_empty()
        ));
        let secure_message_ack = proto::MessageAck {
            message_id: TEST_MESSAGE_ID.to_string(),
            server_timestamp: 1,
            ref_seq: 1,
            roster_version: Some(4),
            ..Default::default()
        };
        assert!(matches!(
            connection_event_from_envelope(proto::Envelope {
                payload: Some(proto::envelope::Payload::MessageAck(secure_message_ack)),
                ..Default::default()
            }),
            Ok(Some(ConnectionEvent::MessageAcked {
                message_id,
                sender_key: None,
                ..
            })) if message_id == TEST_MESSAGE_ID
        ));
        let exact_ack = proto::MessageAck {
            ref_seq: 2,
            target_device_id: vec![0x22; 16],
            conversation_id: Some("conversation-1".to_string()),
            sender_key_generation: Some(1),
            roster_version: Some(4),
            envelope_commitment: Some(vec![0x66; 32]),
            ..Default::default()
        };
        assert!(matches!(
            sender_key_ack_from_proto(&exact_ack),
            Some(Some(_))
        ));
        assert!(matches!(
            connection_event_from_envelope(proto::Envelope {
                payload: Some(proto::envelope::Payload::MessageAck(exact_ack)),
                ..Default::default()
            }),
            Ok(Some(ConnectionEvent::MessageAcked {
                ref_seq: 2,
                sender_key: Some(_),
                ..
            }))
        ));
    }
}
