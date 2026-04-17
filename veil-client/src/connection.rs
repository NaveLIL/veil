use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tracing::{info, warn};

use veil_crypto::signature;
use veil_crypto::IdentityKeyPair;

use crate::protocol::proto;

/// Configuration for the WebSocket connection.
pub struct ConnectionConfig {
    pub server_url: String,
    pub cert_pins: Vec<String>,
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
    FriendAccepted {
        user_id: String,
        username: String,
    },
    /// A friend removed you.
    FriendRemoved {
        user_id: String,
    },
    /// Full friend list response.
    FriendListReceived {
        friends: Vec<FriendInfo>,
        pending_requests: Vec<FriendRequestInfo>,
    },
    /// Server acknowledged our sent message.
    MessageAcked {
        message_id: String,
        server_timestamp: u64,
        ref_seq: u64,
    },
    /// Connection closed.
    Disconnected { reason: String },
    /// Server error.
    Error { code: u32, message: String },
}

/// Sender half — used to send protobuf envelopes to the server.
pub type WsSender = mpsc::Sender<Vec<u8>>;

/// Manages a WebSocket connection to the Veil gateway.
pub struct Connection {
    /// Send raw protobuf bytes to the WS write loop.
    pub sender: WsSender,
    /// Receive application-level events.
    pub events: mpsc::Receiver<ConnectionEvent>,
    /// Current sequence number for outgoing messages.
    seq: Arc<Mutex<u64>>,
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
        info!("connecting to {url}");

        let (ws_stream, _) =
            tokio::time::timeout(std::time::Duration::from_secs(8), connect_async(url))
                .await
                .map_err(|_| format!("ws connect timed out after 8s: {url}"))?
                .map_err(|e| format!("ws connect failed: {e}"))?;

        let (mut ws_write, mut ws_read) = ws_stream.split();

        // Channel: app → WS write loop
        let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(256);
        // Channel: WS read loop → app
        let (event_tx, event_rx) = mpsc::channel::<ConnectionEvent>(256);

        let seq = Arc::new(Mutex::new(1u64));

        // --- Step 1: Wait for AuthChallenge ---
        let challenge = loop {
            match ws_read.next().await {
                Some(Ok(WsMessage::Binary(data))) => {
                    let env = proto::Envelope::decode(data.as_ref())
                        .map_err(|e| format!("decode challenge: {e}"))?;
                    if let Some(proto::envelope::Payload::AuthChallenge(ch)) = env.payload {
                        break ch.challenge;
                    }
                    warn!("expected auth_challenge, got other payload");
                }
                Some(Ok(WsMessage::Ping(_))) => continue,
                Some(Err(e)) => return Err(format!("ws read error during auth: {e}")),
                None => return Err("connection closed before auth challenge".into()),
                _ => continue,
            }
        };

        info!("received auth challenge ({} bytes)", challenge.len());

        // --- Step 2: Sign challenge and send AuthResponse ---
        let sig = signature::sign(identity, &challenge);
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

        // --- Step 3: Wait for AuthResult ---
        let user_id = loop {
            match ws_read.next().await {
                Some(Ok(WsMessage::Binary(data))) => {
                    let env = proto::Envelope::decode(data.as_ref())
                        .map_err(|e| format!("decode auth_result: {e}"))?;
                    if let Some(proto::envelope::Payload::AuthResult(r)) = env.payload {
                        if r.success {
                            break r.user_id.unwrap_or_default();
                        } else {
                            return Err(format!(
                                "auth failed: {}",
                                r.error_message.unwrap_or_default()
                            ));
                        }
                    }
                }
                Some(Ok(WsMessage::Ping(_))) => continue,
                Some(Err(e)) => return Err(format!("ws read error during auth: {e}")),
                None => return Err("connection closed during auth".into()),
                _ => continue,
            }
        };

        info!("authenticated as user_id={user_id}");

        // Notify app about successful auth
        let _ = event_tx
            .send(ConnectionEvent::Authenticated {
                user_id: user_id.clone(),
            })
            .await;

        // --- Background write loop ---
        tokio::spawn(async move {
            while let Some(data) = send_rx.recv().await {
                if ws_write.send(WsMessage::Binary(data)).await.is_err() {
                    break;
                }
            }
        });

        // --- Background read loop ---
        let evt = event_tx.clone();
        tokio::spawn(async move {
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

        Ok(Self {
            sender: send_tx,
            events: event_rx,
            seq,
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
        self.sender
            .send(data)
            .await
            .map_err(|e| format!("send failed: {e}"))
    }
}

/// Dispatch a received Envelope into a typed ConnectionEvent.
async fn dispatch_event(tx: &mpsc::Sender<ConnectionEvent>, env: proto::Envelope) {
    let event = match env.payload {
        Some(proto::envelope::Payload::MessageEvent(me)) => {
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
        },
        Some(proto::envelope::Payload::Error(e)) => ConnectionEvent::Error {
            code: e.code,
            message: e.message,
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
        Some(proto::envelope::Payload::FriendRemovedEvent(fre)) => {
            ConnectionEvent::FriendRemoved {
                user_id: fre.user_id,
            }
        }
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
        _ => return, // Ignore unhandled types for now
    };
    let _ = tx.send(event).await;
}
