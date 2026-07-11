use std::collections::VecDeque;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{protocol::WebSocketConfig, Message as WsMessage},
};
use tracing::{info, warn};
use zeroize::Zeroize;

use veil_crypto::signature;
use veil_crypto::IdentityKeyPair;

use crate::protocol::proto;

const MAX_RETAINED_SKDM_EVENTS: usize = 4_096;
const MAX_RETAINED_SKDM_BYTES: usize = 16 * 1024 * 1024;
const MAX_RETAINED_SKDM_WIRE_BYTES: usize = 64 * 1024;
const AUTH_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
const OUTBOUND_QUEUE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const LIVE_EVENT_QUEUE_CAPACITY: usize = 4_096;
const MAX_EVENT_ID_BYTES: usize = 256;
const MAX_EVENT_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MAX_EVENT_HEADER_BYTES: usize = 512;

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
    },
    /// A Sender Key Distribution Message arrived from a peer.
    /// `sender_key_message` is a sealed envelope (see veil_crypto::sender_key::open_skdm).
    SenderKeyDist {
        conversation_id: String,
        sender_key_message: Vec<u8>,
        generation: u32,
        target_identity_key: Vec<u8>,
    },
    /// Connection closed.
    Disconnected { reason: String },
    /// Server error.
    Error {
        code: u32,
        message: String,
        ref_seq: Option<u64>,
        local_message_id: Option<String>,
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

/// Sender half — used to send protobuf envelopes to the server.
pub type WsSender = mpsc::Sender<Vec<u8>>;

/// Manages a WebSocket connection to the Veil gateway.
pub struct Connection {
    /// Send raw protobuf bytes to the WS write loop.
    pub sender: WsSender,
    /// Receive application-level events.
    pub events: mpsc::Receiver<ConnectionEvent>,
    /// Authenticated retained controls observed before the AuthResult FIFO
    /// barrier. They are kept outside the bounded live-event channel so the
    /// handshake cannot deadlock before the caller can drain that channel.
    pub(crate) retained_events: VecDeque<ConnectionEvent>,
    /// Current sequence number for outgoing messages.
    seq: Arc<Mutex<u64>>,
    write_task: tokio::task::AbortHandle,
    read_task: tokio::task::AbortHandle,
}

impl Connection {
    /// Connect to the server, perform auth challenge-response, and start
    /// background read/write loops. Returns immediately after auth completes.
    pub async fn connect(
        config: &ConnectionConfig,
        identity: &IdentityKeyPair,
        device_id: &[u8; 16],
        device_name: &str,
    ) -> Result<Self, String> {
        let url = &config.server_url;
        validate_websocket_url(url)?;
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
        let auth_resp = proto::Envelope {
            seq: 2,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::AuthResponse(
                proto::AuthResponse {
                    identity_key: identity.x25519_public_bytes().to_vec(),
                    signing_key: identity.ed25519_public_bytes().to_vec(),
                    signature: sig.to_vec(),
                    device_id: device_id.to_vec(),
                    device_name: device_name.to_string(),
                    client_version: "veil-desktop/0.1.0".to_string(),
                },
            )),
        };
        let auth_bytes = auth_resp.encode_to_vec();
        ws_write
            .send(WsMessage::Binary(auth_bytes))
            .await
            .map_err(|e| format!("send auth_response: {e}"))?;

        // --- Step 3: Receive retained encrypted control state, then AuthResult. ---
        // The server queues every retained SKDM before AuthResult and publishes
        // this socket to live fan-out only afterwards. AuthResult is therefore
        // an explicit FIFO barrier: once observed, the buffered set is complete.
        let mut retained_before_auth = Vec::new();
        let mut retained_bytes = 0usize;
        let user_id = tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, async {
            loop {
                match ws_read.next().await {
                    Some(Ok(WsMessage::Binary(data))) => {
                        let env = proto::Envelope::decode(data.as_ref())
                            .map_err(|e| format!("decode auth_result: {e}"))?;
                        match env.payload.as_ref() {
                            Some(proto::envelope::Payload::AuthResult(r)) => {
                                if r.success {
                                    return Ok::<_, String>(r.user_id.clone().unwrap_or_default());
                                }
                                return Err(format!(
                                    "auth failed: {}",
                                    r.error_message.clone().unwrap_or_default()
                                ));
                            }
                            Some(proto::envelope::Payload::SenderKeyDist(skd)) => {
                                if skd.conversation_id.is_empty()
                                    || skd.conversation_id.len() > 256
                                    || skd.target_identity_key.len() != 32
                                    || skd.sender_key_message.is_empty()
                                    || skd.sender_key_message.len() > MAX_RETAINED_SKDM_WIRE_BYTES
                                    || retained_before_auth.len() >= MAX_RETAINED_SKDM_EVENTS
                                {
                                    return Err("invalid or excessive retained sender-key state"
                                        .to_string());
                                }
                                let event_bytes = skd
                                    .conversation_id
                                    .len()
                                    .checked_add(skd.target_identity_key.len())
                                    .and_then(|size| size.checked_add(skd.sender_key_message.len()))
                                    .ok_or_else(|| {
                                        "retained sender-key byte count overflow".to_string()
                                    })?;
                                retained_bytes =
                                    retained_bytes.checked_add(event_bytes).ok_or_else(|| {
                                        "retained sender-key byte count overflow".to_string()
                                    })?;
                                if retained_bytes > MAX_RETAINED_SKDM_BYTES {
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

        let retained_events = retained_before_auth
            .into_iter()
            .filter_map(connection_event_from_envelope)
            .collect();
        // Channel: WS read loop → app. Retained controls live in their own
        // bounded buffer above, so this capacity remains a live backpressure
        // limit even for accounts with many channel memberships.
        let (event_tx, event_rx) = mpsc::channel::<ConnectionEvent>(LIVE_EVENT_QUEUE_CAPACITY);

        // Notify app about successful auth
        let _ = event_tx
            .send(ConnectionEvent::Authenticated {
                user_id: user_id.clone(),
            })
            .await;

        // --- Background write loop ---
        let write_task = tokio::spawn(async move {
            while let Some(data) = send_rx.recv().await {
                if ws_write.send(WsMessage::Binary(data)).await.is_err() {
                    break;
                }
            }
        });
        let write_task = write_task.abort_handle();

        // --- Background read loop ---
        let evt = event_tx.clone();
        let read_task = tokio::spawn(async move {
            loop {
                match ws_read.next().await {
                    Some(Ok(WsMessage::Binary(data))) => {
                        if let Ok(env) = proto::Envelope::decode(data.as_ref()) {
                            dispatch_event(&evt, env).await;
                        }
                    }
                    Some(Ok(WsMessage::Ping(_))) | Some(Ok(WsMessage::Pong(_))) => continue,
                    Some(Ok(WsMessage::Close(_))) | None => {
                        let _ = evt
                            .send(ConnectionEvent::Disconnected {
                                reason: "server closed".into(),
                            })
                            .await;
                        break;
                    }
                    Some(Err(e)) => {
                        let _ = evt
                            .send(ConnectionEvent::Disconnected {
                                reason: format!("{e}"),
                            })
                            .await;
                        break;
                    }
                    _ => continue,
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
    use super::{validate_websocket_url, websocket_auth_signature, Connection};
    use veil_crypto::keys::IdentityKeyPair;

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
        let (_event_tx, events) = tokio::sync::mpsc::channel(1);
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
}

/// Dispatch a received Envelope into a typed ConnectionEvent.
fn connection_event_from_envelope(env: proto::Envelope) -> Option<ConnectionEvent> {
    let event = match env.payload {
        Some(proto::envelope::Payload::MessageEvent(me)) => {
            if me.message_id.is_empty()
                || me.message_id.len() > MAX_EVENT_ID_BYTES
                || me.conversation_id.is_empty()
                || me.conversation_id.len() > MAX_EVENT_ID_BYTES
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
            {
                return None;
            }
            match me.event_type() {
                proto::message_event::EventType::Edited => ConnectionEvent::MessageEdited {
                    message_id: me.message_id,
                    conversation_id: me.conversation_id,
                    sender_identity_key: me.sender_identity_key,
                    ciphertext: me.ciphertext.unwrap_or_default(),
                    header: me.header.unwrap_or_default(),
                    edit_timestamp: me.edit_timestamp.unwrap_or(me.server_timestamp),
                },
                proto::message_event::EventType::Deleted => ConnectionEvent::MessageDeleted {
                    message_id: me.message_id,
                    conversation_id: me.conversation_id,
                    sender_identity_key: me.sender_identity_key,
                    delete_timestamp: me.edit_timestamp.unwrap_or(me.server_timestamp),
                },
                _ => ConnectionEvent::MessageReceived {
                    message_id: me.message_id,
                    conversation_id: me.conversation_id,
                    sender_identity_key: me.sender_identity_key,
                    sender_username: me.sender_username,
                    ciphertext: me.ciphertext.unwrap_or_default(),
                    header: me.header.unwrap_or_default(),
                    server_timestamp: me.server_timestamp,
                    reply_to_id: me.reply_to_id,
                },
            }
        }
        Some(proto::envelope::Payload::MessageAck(ack)) => ConnectionEvent::MessageAcked {
            message_id: ack.message_id,
            server_timestamp: ack.server_timestamp,
            ref_seq: ack.ref_seq,
            local_message_id: None,
            mutation: None,
        },
        Some(proto::envelope::Payload::Error(e)) => ConnectionEvent::Error {
            code: e.code,
            message: e.message,
            ref_seq: e.ref_seq,
            local_message_id: None,
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
            if skd.conversation_id.is_empty()
                || skd.conversation_id.len() > MAX_EVENT_ID_BYTES
                || skd.sender_key_message.is_empty()
                || skd.sender_key_message.len() > MAX_RETAINED_SKDM_WIRE_BYTES
                || skd.target_identity_key.len() != 32
            {
                return None;
            }
            ConnectionEvent::SenderKeyDist {
                conversation_id: skd.conversation_id,
                sender_key_message: skd.sender_key_message,
                generation: skd.generation,
                target_identity_key: skd.target_identity_key,
            }
        }
        _ => return None, // Ignore unhandled types for now
    };
    Some(event)
}

async fn dispatch_event(tx: &mpsc::Sender<ConnectionEvent>, env: proto::Envelope) {
    if let Some(event) = connection_event_from_envelope(env) {
        let _ = tx.send(event).await;
    }
}
