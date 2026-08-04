//! Background WebSocket events engine for the v3 subprotocol (`/v3/events`).
//!
//! # Scope: what this module owns
//!  1. The authenticated v3 connect: exact-target validation, AuthChallengeV3
//!     -> `prepare_ws_auth_response_v3` -> AuthResultV3 validation. All proof
//!     construction stays in `ws_auth_v3.rs`; this module only moves bytes.
//!  2. Heartbeat liveness: client-driven Ping plus a read-side traffic
//!     deadline, so a half-dead socket is detected in bounded time.
//!  3. The reconnect decision state machine (`ReconnectDeciderV3`, pure and
//!     unit-tested) and the background supervisor loop (`run_ws_events_v3`).
//!
//! # Scope: what this module deliberately does NOT own
//!  - Decrypt, Double Ratchet advancement, or SQLCipher writes. Authenticated
//!    envelopes are decoded into the existing bounded `ConnectionEvent`
//!    pipeline (`connection.rs`), which the engine already drains and
//!    persists atomically. A second decrypt/upsert path here would fork
//!    ratchet state between two consumers and permanently poison sessions.
//!  - Process-death / doze survival. Rust cannot outlive its own process.
//!    The Android host must run this engine inside a Foreground Service (or
//!    resurrect the process via FCM/WorkManager), then perform an ordinary
//!    "plain reconnect": load the credential-free target persisted in
//!    SQLCipher (veil-ffi `mobile_reconnect_target`) and drive one normal v3
//!    connect. There is no session resumption and no authentication shortcut.
//!
//! # Reconnect policy (Roadmap Phase 5B)
//!  - Only source-classified `RetryableTransport` outcomes may reconnect
//!    automatically. Authentication denials, protocol violations, epoch
//!    failures, and bounded-buffer terminals stay fail-closed: retrying them
//!    would hammer a rejecting Node or mask an active attack. This matches
//!    the existing allowlist contract in `connection.rs` and the veil-ffi
//!    reconnect plan.
//!  - After the first allowed error following a stable session the client
//!    performs exactly ONE zero-delay plain reconnect (ordinal 0). Every
//!    further consecutive allowed error backs off exponentially with jitter,
//!    capped, until an authenticated session proves stable again.
//!
//! # INTEGRATION CHECKLIST (exact, mechanical)
//!  In `veil-client/src/lib.rs`: add `mod ws_events_v3;` and remove the
//!  `#![cfg_attr(not(test), allow(dead_code))]` gate from `ws_auth_v3.rs`
//!  once this module is wired.
//!
//!  In `connection.rs`, widen visibility to `pub(crate)` (no logic changes):
//!   - fn websocket_connector_for_validated_url_v1
//!   - fn classify_websocket_handshake_error_v1
//!   - fn classify_websocket_handshake_close_v1
//!   - fn signal_disconnected / signal_websocket_error_v1
//!     / signal_websocket_close_v1 / signal_event_buffer_failure
//!   - fn dispatch_authenticated_ws_message + enum AuthenticatedWsMessageOutcomeV1
//!   - fn connection_event_from_envelope, fn sender_key_route_from_proto
//!   - struct ConnectionEventSenderV1 (+ its fields), struct
//!     ConnectionTerminalStateV1, struct BudgetedConnectionEventV1
//!   - ConnectionEventBudgetV1::production, ConnectionEventReceiverV1 field
//!     construction (or add a pub(crate) constructor)
//!   - ConnectionConnectErrorV1 constructors: retryable_transport,
//!     epoch_invalid, authentication_rejected, registration_closed,
//!     invite_invalid
//!   - consts MAX_RETAINED_SKDM_EVENTS, MAX_RETAINED_SKDM_WIRE_TOTAL_BYTES,
//!     MAX_RETAINED_SKDM_METADATA_BYTES
//!
//!  ASSUMPTIONS to verify against code I could not see:
//!   - `WsAuthV3Target::parse(websocket_url, canonical_origin)` argument
//!     order/shape (I only saw the first parameter).
//!   - proto envelope payload variants are named `AuthChallengeV3` /
//!     `AuthResultV3` (the test
//!     `every_v3_auth_envelope_is_terminal_after_authenticated_barrier`
//!     implies they exist).
//!   - Whether the v3 server also replays retained SenderKeyDist before
//!     AuthResultV3 like the legacy `/ws` path does. This module implements
//!     the same bounded buffering; if v3 never does this, the branch is dead
//!     but harmless.

use std::collections::hash_map::RandomState;
use std::collections::VecDeque;
use std::hash::{BuildHasher, Hasher};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use tokio::sync::{mpsc, watch, Mutex, Notify};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{protocol::WebSocketConfig, Message as WsMessage},
};
use tracing::info;

use veil_crypto::IdentityKeyPair;

use crate::connection::{
    classify_websocket_handshake_close_v1, classify_websocket_handshake_error_v1,
    connection_event_from_envelope, dispatch_authenticated_ws_message,
    sender_key_route_from_proto, signal_disconnected, signal_event_buffer_failure,
    signal_websocket_close_v1, signal_websocket_error_v1,
    websocket_connector_for_validated_url_v1, AuthenticatedWsMessageOutcomeV1,
    BudgetedConnectionEventV1, ConnectionConnectErrorV1, ConnectionConnectStopV1,
    ConnectionEvent, ConnectionEventBudgetV1, ConnectionEventReceiverV1,
    ConnectionEventSenderV1, ConnectionTerminalStateV1, LIVE_EVENT_QUEUE_CAPACITY,
    MAX_RETAINED_SKDM_EVENTS, MAX_RETAINED_SKDM_METADATA_BYTES,
    MAX_RETAINED_SKDM_WIRE_TOTAL_BYTES,
};
use crate::device_identity::DeviceIdentityV1;
use crate::protocol::proto;
use crate::ws_auth_v3::{
    prepare_ws_auth_response_v3, validate_ws_auth_result_v3, WsAuthV3Error, WsAuthV3Target,
    WsRegistrationModeV3,
};

/// Exact required path of the v3 events endpoint. Never derived from server
/// input; the configured URL must already spell it exactly.
const WS_EVENTS_V3_PATH: &str = "/v3/events";

const WS_EVENTS_CONNECT_TIMEOUT_V1: Duration = Duration::from_secs(8);
const WS_EVENTS_AUTH_TIMEOUT_V1: Duration = Duration::from_secs(8);

/// Client-driven keepalive. tungstenite answers server Pings automatically;
/// this interval exists so an idle NAT/doze path still carries traffic and
/// so the liveness deadline below has something to observe.
const HEARTBEAT_PING_INTERVAL_V1: Duration = Duration::from_secs(25);
/// Read-side liveness deadline: any inbound frame (Pong included) resets it.
/// Three missed heartbeats == dead transport, classified retryable.
const HEARTBEAT_LIVENESS_DEADLINE_V1: Duration = Duration::from_secs(75);

const BACKOFF_BASE_V1: Duration = Duration::from_secs(1);
const BACKOFF_CAP_V1: Duration = Duration::from_secs(60);
const BACKOFF_MAX_SHIFT_V1: u32 = 6;
/// An authenticated session must stay up this long before the decider
/// re-arms the single zero-delay reconnect and resets the backoff ordinal.
/// Prevents a flapping link from producing an infinite zero-delay loop.
const STABLE_SESSION_THRESHOLD_V1: Duration = Duration::from_secs(30);

/// Endpoint/identity-free configuration for the background events client.
/// Registration is never performed here: a background reconnect always signs
/// `WsRegistrationModeV3::Existing`. Account creation is a foreground user
/// intent and must not be replayable by an automatic controller.
pub struct WsEventsV3Config {
    /// Exact `wss://<node>/v3/events` spelling. Validated, never normalized.
    pub websocket_url: String,
    /// The already-canonical Node origin paired with the endpoint.
    pub canonical_origin: String,
    pub device_name: String,
    pub client_id: String,
}

/// Source-classified reason one authenticated v3 session stopped.
/// The handler derives this from the existing terminal classification in
/// `connection.rs` / veil-ffi; free-text diagnostics never select policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsSessionStopV3 {
    RetryableTransport,
    FailClosed,
}

/// Typed decider input for exactly one finished connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WsSessionEndV3 {
    pub stop: WsSessionStopV3,
    /// How long the session was authenticated, or None when the attempt
    /// failed before the AuthResultV3 barrier.
    pub authenticated_uptime: Option<Duration>,
}

/// Next supervisor action. `Immediate` is the single Roadmap-mandated
/// zero-delay plain reconnect (ordinal 0 after the first allowed error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NextAttemptV3 {
    Immediate,
    After(Duration),
    /// Fail-closed terminal. Automatic reconnection stops; only an explicit
    /// host/user intent may start a new controller.
    Stop,
}

/// Pure reconnect decision state machine. No I/O, no clocks, no randomness:
/// callers inject uptime and a jitter unit, so every policy branch is
/// deterministic under test.
pub(crate) struct ReconnectDeciderV3 {
    consecutive_failures: u32,
}

impl ReconnectDeciderV3 {
    pub(crate) fn new() -> Self {
        Self {
            consecutive_failures: 0,
        }
    }

    pub(crate) fn next_attempt(&mut self, end: WsSessionEndV3, jitter_unit: f64) -> NextAttemptV3 {
        match end.stop {
            WsSessionStopV3::FailClosed => NextAttemptV3::Stop,
            WsSessionStopV3::RetryableTransport => {
                // A session that authenticated and stayed up long enough
                // proves the route works: reset the ordinal and re-arm the
                // single zero-delay reconnect.
                if end
                    .authenticated_uptime
                    .is_some_and(|uptime| uptime >= STABLE_SESSION_THRESHOLD_V1)
                {
                    self.consecutive_failures = 0;
                }
                let ordinal = self.consecutive_failures;
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                if ordinal == 0 {
                    NextAttemptV3::Immediate
                } else {
                    NextAttemptV3::After(backoff_delay_v1(ordinal, jitter_unit))
                }
            }
        }
    }
}

/// Exponential backoff with a floor of half the ceiling. Full-range jitter
/// deliberately does not reach zero: a zero here would silently manufacture
/// extra zero-delay reconnects and defeat the ordinal-0 contract.
fn backoff_delay_v1(ordinal: u32, jitter_unit: f64) -> Duration {
    let shift = ordinal.saturating_sub(1).min(BACKOFF_MAX_SHIFT_V1);
    let ceiling = std::cmp::min(BACKOFF_BASE_V1.saturating_mul(1u32 << shift), BACKOFF_CAP_V1);
    let unit = if jitter_unit.is_finite() {
        jitter_unit.clamp(0.0, 1.0)
    } else {
        1.0
    };
    let half = ceiling / 2;
    half + Duration::from_secs_f64(half.as_secs_f64() * unit)
}

/// Process-seeded, std-only jitter source. Not cryptographic and must never
/// be: it only disperses reconnect herds across devices.
fn jitter_unit_v1(attempt: u64) -> f64 {
    static STATE: OnceLock<RandomState> = OnceLock::new();
    let mut hasher = STATE.get_or_init(RandomState::new).build_hasher();
    hasher.write_u64(attempt);
    (hasher.finish() % 10_000) as f64 / 9_999.0
}

fn classify_ws_auth_v3_error(error: WsAuthV3Error) -> ConnectionConnectErrorV1 {
    match error {
        WsAuthV3Error::AuthenticationRejected => {
            ConnectionConnectErrorV1::authentication_rejected()
        }
        WsAuthV3Error::RegistrationClosed => ConnectionConnectErrorV1::registration_closed(),
        WsAuthV3Error::NodeAccessPassInvalid => ConnectionConnectErrorV1::invite_invalid(),
        // Every remaining v3 auth failure is a local/protocol inconsistency:
        // outside the reconnect allowlist, fail closed.
        other => ConnectionConnectErrorV1::epoch_invalid(other.to_string()),
    }
}

/// One authenticated background v3 connection. Mirrors `Connection` but is
/// owned by this module so heartbeat lives inside the I/O loops.
pub struct WsEventsV3Connection {
    /// Send raw protobuf bytes to the WS write loop.
    pub sender: mpsc::Sender<Vec<u8>>,
    /// Receive application-level events; drains into the existing engine.
    pub events: ConnectionEventReceiverV1,
    /// Retained controls observed before the AuthResultV3 FIFO barrier.
    pub(crate) retained_events: VecDeque<BudgetedConnectionEventV1>,
    seq: Arc<Mutex<u64>>,
    write_task: tokio::task::AbortHandle,
    read_task: tokio::task::AbortHandle,
}

impl WsEventsV3Connection {
    pub(crate) async fn next_seq(&self) -> u64 {
        let mut seq = self.seq.lock().await;
        let value = *seq;
        *seq += 1;
        value
    }

    /// Stop background I/O immediately. Dropping the handle calls this too.
    pub(crate) fn disconnect(&self) {
        self.write_task.abort();
        self.read_task.abort();
    }

    /// Extract retained events for background controller injection.
    pub fn drain_retained(&mut self) -> Vec<crate::connection::ConnectionEvent> {
        self.retained_events.drain(..).map(|e| e.into_event()).collect()
    }

    /// Read the terminal buffer error from the connection events channel.
    pub fn terminal_error(&self) -> Option<crate::connection::ConnectionEventBufferErrorV1> {
        self.events.terminal_buffer_error_v1()
    }
}

impl Drop for WsEventsV3Connection {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// Connect to the exact v3 events endpoint and complete the v3 handshake.
///
/// Callers may automatically retry only `RetryableTransport`, identical to
/// the legacy `connect_classified_v1` contract.
pub(crate) async fn connect_events_v3_classified(
    config: &WsEventsV3Config,
    account: &IdentityKeyPair,
    device_identity: &DeviceIdentityV1,
) -> Result<WsEventsV3Connection, ConnectionConnectErrorV1> {
    // ASSUMPTION: WsAuthV3Target::parse(websocket_url, canonical_origin).
    // It validates the original spelling before Url normalization; keep it
    // as the only trust gate for both values.
    let target = WsAuthV3Target::parse(&config.websocket_url, &config.canonical_origin)
        .map_err(|error| ConnectionConnectErrorV1::epoch_invalid(error.to_string()))?;
    if target.websocket_url().path() != WS_EVENTS_V3_PATH {
        return Err(ConnectionConnectErrorV1::epoch_invalid(
            "v3 events endpoint path must be exactly /v3/events",
        ));
    }
    info!("connecting to validated v3 events endpoint");

    let websocket_config = WebSocketConfig {
        // Same fragmented-message memory bounds as the legacy path.
        max_message_size: Some(4 << 20),
        max_frame_size: Some(1 << 20),
        ..WebSocketConfig::default()
    };
    let websocket_connector = websocket_connector_for_validated_url_v1(target.websocket_url())?;
    let (ws_stream, _) = tokio::time::timeout(
        WS_EVENTS_CONNECT_TIMEOUT_V1,
        connect_async_tls_with_config(
            config.websocket_url.as_str(),
            Some(websocket_config),
            false,
            Some(websocket_connector),
        ),
    )
    .await
    .map_err(|_| ConnectionConnectErrorV1::retryable_transport("v3 ws connect timed out after 8s"))?
    .map_err(|error| classify_websocket_handshake_error_v1("v3 ws connect failed", error))?;

    let (mut ws_write, mut ws_read) = ws_stream.split();

    // --- Step 1: dedicated v3 challenge. ---
    let challenge = tokio::time::timeout(WS_EVENTS_AUTH_TIMEOUT_V1, async {
        loop {
            match ws_read.next().await {
                Some(Ok(WsMessage::Binary(data))) => {
                    let envelope = proto::Envelope::decode(data.as_ref()).map_err(|error| {
                        ConnectionConnectErrorV1::epoch_invalid(format!(
                            "decode v3 challenge: {error}"
                        ))
                    })?;
                    return match envelope.payload {
                        Some(proto::envelope::Payload::AuthChallengeV3(challenge)) => {
                            Ok::<_, ConnectionConnectErrorV1>(challenge)
                        }
                        _ => Err(ConnectionConnectErrorV1::epoch_invalid(
                            "unexpected envelope before v3 authentication challenge",
                        )),
                    };
                }
                Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
                Some(Ok(WsMessage::Close(frame))) => {
                    return Err(classify_websocket_handshake_close_v1(
                        "connection closed before v3 auth challenge",
                        frame.as_ref().map(|frame| frame.code),
                    ))
                }
                None => {
                    return Err(ConnectionConnectErrorV1::retryable_transport(
                        "connection closed before v3 auth challenge",
                    ))
                }
                Some(Err(error)) => {
                    return Err(classify_websocket_handshake_error_v1(
                        "ws read error during v3 auth",
                        error,
                    ))
                }
                Some(Ok(WsMessage::Text(_) | WsMessage::Frame(_))) => {
                    return Err(ConnectionConnectErrorV1::epoch_invalid(
                        "unexpected WebSocket data before v3 authentication challenge",
                    ))
                }
            }
        }
    })
    .await
    .map_err(|_| {
        ConnectionConnectErrorV1::retryable_transport(
            "timed out waiting for v3 authentication challenge",
        )
    })??;

    // --- Step 2: both possession proofs, prepared purely in ws_auth_v3. ---
    // Background reconnects always sign Existing: no Pass copy ever exists
    // on this path, so the encoded envelope below carries no secret.
    let client_version = format!("{}/{}", config.client_id, env!("CARGO_PKG_VERSION"));
    let prepared = prepare_ws_auth_response_v3(
        &target,
        &challenge,
        account,
        device_identity,
        &config.device_name,
        &client_version,
        WsRegistrationModeV3::Existing,
    )
    .map_err(classify_ws_auth_v3_error)?;
    let (encoded, expectation) = prepared.into_envelope_bytes(2);
    ws_write
        .send(WsMessage::Binary(encoded.to_vec()))
        .await
        .map_err(|error| classify_websocket_handshake_error_v1("send v3 auth_response", error))?;

    // --- Step 3: bounded retained controls, then the AuthResultV3 barrier. ---
    // Identical parity with the legacy path: the server may queue retained
    // SKDM state before the result; the result is the FIFO completeness
    // barrier. Every bound is enforced before buffering.
    let mut expectation = Some(expectation);
    let mut retained_before_auth = Vec::new();
    let mut retained_wire_bytes = 0usize;
    let mut retained_metadata_bytes = 0usize;
    let user_id = tokio::time::timeout(WS_EVENTS_AUTH_TIMEOUT_V1, async {
        loop {
            match ws_read.next().await {
                Some(Ok(WsMessage::Binary(data))) => {
                    let envelope = proto::Envelope::decode(data.as_ref()).map_err(|error| {
                        ConnectionConnectErrorV1::epoch_invalid(format!(
                            "decode v3 auth_result: {error}"
                        ))
                    })?;
                    match envelope.payload.as_ref() {
                        Some(proto::envelope::Payload::AuthResultV3(result)) => {
                            let expectation = expectation
                                .take()
                                .expect("v3 result expectation consumed exactly once");
                            return validate_ws_auth_result_v3(result, expectation)
                                .map_err(classify_ws_auth_v3_error);
                        }
                        Some(proto::envelope::Payload::SenderKeyDist(skd)) => {
                            if sender_key_route_from_proto(skd).is_none()
                                || retained_before_auth.len() >= MAX_RETAINED_SKDM_EVENTS
                            {
                                return Err(ConnectionConnectErrorV1::epoch_invalid(
                                    "invalid or excessive retained sender-key state",
                                ));
                            }
                            let metadata_bytes = skd
                                .encoded_len()
                                .checked_sub(skd.sender_key_message.len())
                                .ok_or_else(|| {
                                    ConnectionConnectErrorV1::epoch_invalid(
                                        "retained sender-key metadata count overflow",
                                    )
                                })?;
                            retained_metadata_bytes = retained_metadata_bytes
                                .checked_add(metadata_bytes)
                                .ok_or_else(|| {
                                    ConnectionConnectErrorV1::epoch_invalid(
                                        "retained sender-key metadata count overflow",
                                    )
                                })?;
                            retained_wire_bytes = retained_wire_bytes
                                .checked_add(skd.sender_key_message.len())
                                .ok_or_else(|| {
                                    ConnectionConnectErrorV1::epoch_invalid(
                                        "retained sender-key wire count overflow",
                                    )
                                })?;
                            if retained_wire_bytes > MAX_RETAINED_SKDM_WIRE_TOTAL_BYTES
                                || retained_metadata_bytes > MAX_RETAINED_SKDM_METADATA_BYTES
                            {
                                return Err(ConnectionConnectErrorV1::epoch_invalid(
                                    "retained sender-key state exceeds client limit",
                                ));
                            }
                            retained_before_auth.push(envelope);
                        }
                        _ => {
                            return Err(ConnectionConnectErrorV1::epoch_invalid(
                                "unexpected non-control envelope before v3 authentication barrier",
                            ));
                        }
                    }
                }
                Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
                Some(Ok(WsMessage::Close(frame))) => {
                    return Err(classify_websocket_handshake_close_v1(
                        "connection closed during v3 auth",
                        frame.as_ref().map(|frame| frame.code),
                    ))
                }
                None => {
                    return Err(ConnectionConnectErrorV1::retryable_transport(
                        "connection closed during v3 auth",
                    ))
                }
                Some(Err(error)) => {
                    return Err(classify_websocket_handshake_error_v1(
                        "ws read error during v3 auth",
                        error,
                    ))
                }
                Some(Ok(WsMessage::Text(_) | WsMessage::Frame(_))) => {
                    return Err(ConnectionConnectErrorV1::epoch_invalid(
                        "unexpected WebSocket data before v3 authentication barrier",
                    ))
                }
            }
        }
    })
    .await
    .map_err(|_| {
        ConnectionConnectErrorV1::retryable_transport(
            "timed out waiting for v3 authentication result",
        )
    })??;

    info!("authenticated v3 events WebSocket session");

    // --- Post-auth wiring: identical budgets, plus heartbeat-aware loops. ---
    let event_budget = ConnectionEventBudgetV1::production();
    let mut retained_events = VecDeque::with_capacity(retained_before_auth.len());
    for envelope in retained_before_auth {
        let event = connection_event_from_envelope(envelope)
            .map_err(|_| {
                ConnectionConnectErrorV1::epoch_invalid("invalid retained sender-key event")
            })?
            .ok_or_else(|| {
                ConnectionConnectErrorV1::epoch_invalid("invalid retained sender-key event")
            })?;
        retained_events.push_back(
            event_budget
                .try_wrap(event)
                .map_err(|error| ConnectionConnectErrorV1::epoch_invalid(error.to_string()))?,
        );
    }

    let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(256);
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

    event_tx
        .send(ConnectionEvent::Authenticated {
            user_id: user_id.clone(),
        })
        .await
        .map_err(|error| ConnectionConnectErrorV1::epoch_invalid(error.to_string()))?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // --- Write loop: outbound bytes + client heartbeat Ping. ---
    let write_terminal = terminal.clone();
    let write_shutdown = shutdown_tx.clone();
    let mut write_shutdown_rx = shutdown_rx.clone();
    let write_task = tokio::spawn(async move {
        let mut ping_interval = tokio::time::interval(HEARTBEAT_PING_INTERVAL_V1);
        // Losing ticks after resume is correct here: one fresh Ping proves
        // liveness; a burst of catch-up Pings proves nothing extra.
        ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The immediate first tick doubles as a post-auth path probe.
        loop {
            tokio::select! {
                changed = write_shutdown_rx.changed() => {
                    if changed.is_err() || *write_shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = ping_interval.tick() => {
                    if let Err(error) = ws_write.send(WsMessage::Ping(Vec::new())).await {
                        signal_websocket_error_v1(
                            &write_terminal,
                            &write_shutdown,
                            "v3 heartbeat write transport",
                            error,
                        );
                        break;
                    }
                }
                data = send_rx.recv() => {
                    let Some(data) = data else {
                        break;
                    };
                    if let Err(error) = ws_write.send(WsMessage::Binary(data)).await {
                        signal_websocket_error_v1(
                            &write_terminal,
                            &write_shutdown,
                            "v3 WebSocket write transport",
                            error,
                        );
                        break;
                    }
                }
            }
        }
    });
    let write_task = write_task.abort_handle();

    // --- Read loop: dispatch + liveness deadline. ---
    let evt = event_tx.clone();
    let read_terminal = terminal;
    let read_shutdown = shutdown_tx;
    let mut read_shutdown_rx = shutdown_rx;
    let read_task = tokio::spawn(async move {
        let mut liveness_deadline = Instant::now() + HEARTBEAT_LIVENESS_DEADLINE_V1;
        loop {
            tokio::select! {
                changed = read_shutdown_rx.changed() => {
                    if changed.is_err() || *read_shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = tokio::time::sleep_until(liveness_deadline) => {
                    // No frame of any kind within the deadline. The socket is
                    // half-dead (radio drop, NAT expiry, doze). This is a
                    // transport condition, not a protocol violation, so it
                    // stays inside the reconnect allowlist.
                    signal_disconnected(
                        &read_terminal,
                        &read_shutdown,
                        "v3 heartbeat liveness deadline exceeded".into(),
                    );
                    break;
                }
                incoming = ws_read.next() => {
                    // Any inbound frame is proof of life, including Pong and
                    // server Ping, both of which dispatch as Continue.
                    liveness_deadline = Instant::now() + HEARTBEAT_LIVENESS_DEADLINE_V1;
                    match incoming {
                        Some(Ok(message)) => match dispatch_authenticated_ws_message(&evt, message).await {
                            Ok(AuthenticatedWsMessageOutcomeV1::Continue) => continue,
                            Ok(AuthenticatedWsMessageOutcomeV1::Closed(code)) => {
                                signal_websocket_close_v1(
                                    &read_terminal,
                                    &read_shutdown,
                                    "v3 WebSocket peer close",
                                    code,
                                );
                                break;
                            }
                            Err(error) => {
                                signal_event_buffer_failure(&read_terminal, &read_shutdown, error);
                                break;
                            }
                        },
                        None => {
                            signal_disconnected(&read_terminal, &read_shutdown, "server closed".into());
                            break;
                        }
                        Some(Err(error)) => {
                            signal_websocket_error_v1(
                                &read_terminal,
                                &read_shutdown,
                                "v3 WebSocket read transport",
                                error,
                            );
                            break;
                        }
                    }
                }
            }
        }
    });
    let read_task = read_task.abort_handle();

    Ok(WsEventsV3Connection {
        sender: send_tx,
        events: event_rx,
        retained_events,
        seq: Arc::new(Mutex::new(3u64)),
        write_task,
        read_task,
    })
}

/// Why the supervisor exited. There is no "retrying" exit: the loop only
/// returns when reconnection is no longer allowed or no longer wanted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsEventsV3SupervisorExit {
    /// Host flipped the cancellation watch (app shutdown, logout, service
    /// stop). Clean, silent exit.
    Cancelled,
    /// A fail-closed terminal (auth denial, epoch/protocol violation,
    /// bounded-buffer failure). The host must surface this and require an
    /// explicit intent before any new controller starts.
    FailClosed,
}

/// Background supervisor: connect -> hand the session to the existing engine
/// -> classify the stop -> decide -> wait -> repeat.
///
/// `handle_session` receives each authenticated connection and must drain
/// `events` into the existing decrypt/persist pipeline until terminal, then
/// return the source-classified stop. It must observe host cancellation
/// itself (drop the connection to abort I/O immediately).
///
/// `network_hint` is Android's connectivity-restored signal: it wakes a
/// backoff sleep early, but never bypasses the decider - the zero-delay
/// budget and fail-closed stops still apply.
pub async fn run_ws_events_v3<F, Fut>(
    config: &WsEventsV3Config,
    account: &IdentityKeyPair,
    device_identity: &DeviceIdentityV1,
    mut handle_session: F,
    mut cancel: watch::Receiver<bool>,
    network_hint: Arc<Notify>,
) -> WsEventsV3SupervisorExit
where
    F: FnMut(WsEventsV3Connection) -> Fut,
    Fut: std::future::Future<Output = WsSessionStopV3>,
{
    let mut decider = ReconnectDeciderV3::new();
    let mut attempt: u64 = 0;
    loop {
        if *cancel.borrow() {
            return WsEventsV3SupervisorExit::Cancelled;
        }
        attempt = attempt.saturating_add(1);
        let end = match connect_events_v3_classified(config, account, device_identity).await {
            Ok(session) => {
                let authenticated_at = Instant::now();
                let stop = handle_session(session).await;
                WsSessionEndV3 {
                    stop,
                    authenticated_uptime: Some(authenticated_at.elapsed()),
                }
            }
            Err(error) => WsSessionEndV3 {
                stop: match error.stop {
                    ConnectionConnectStopV1::RetryableTransport => {
                        WsSessionStopV3::RetryableTransport
                    }
                    // Authentication denials, registration/invite outcomes,
                    // and epoch failures never re-enter the loop.
                    _ => WsSessionStopV3::FailClosed,
                },
                authenticated_uptime: None,
            },
        };
        match decider.next_attempt(end, jitter_unit_v1(attempt)) {
            NextAttemptV3::Stop => return WsEventsV3SupervisorExit::FailClosed,
            NextAttemptV3::Immediate => continue,
            NextAttemptV3::After(delay) => {
                tokio::select! {
                    changed = cancel.changed() => {
                        if changed.is_err() || *cancel.borrow() {
                            return WsEventsV3SupervisorExit::Cancelled;
                        }
                    }
                    _ = network_hint.notified() => {}
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Kotlin host contract (for the JNI/UniFFI layer; keep in sync with veil-ffi)
//
//  - Host = Foreground Service owning one tokio runtime + one supervisor.
//    WakeLocks, doze exemptions, FCM resurrection, and notification UX are
//    exclusively Kotlin's. Rust never manages power state.
//  - Service start (including restart after process death):
//      1. veil-ffi `mobile_reconnect_target()` -> credential-free target
//         from SQLCipher; absent target => do not start the controller.
//      2. Start `run_ws_events_v3`. The first attempt is an ordinary full
//         v3 handshake (the "plain reconnect") - no resumption, no shortcut.
//  - ConnectivityManager onAvailable -> network_hint.notify_one().
//  - Logout / service stop -> cancel watch = true.
//  - Surface WsEventsV3SupervisorExit::FailClosed as a user-visible state.
//    Never auto-restart the controller on FailClosed.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn retryable(uptime: Option<Duration>) -> WsSessionEndV3 {
        WsSessionEndV3 {
            stop: WsSessionStopV3::RetryableTransport,
            authenticated_uptime: uptime,
        }
    }

    #[test]
    fn fail_closed_never_reconnects() {
        let mut decider = ReconnectDeciderV3::new();
        let end = WsSessionEndV3 {
            stop: WsSessionStopV3::FailClosed,
            authenticated_uptime: Some(Duration::from_secs(600)),
        };
        assert_eq!(decider.next_attempt(end, 0.5), NextAttemptV3::Stop);
        // Sticky: a later retryable error still starts from ordinal 0 only
        // because FailClosed terminated the controller; a fresh controller
        // is an explicit host decision.
    }

    #[test]
    fn first_allowed_error_is_the_single_zero_delay_reconnect() {
        let mut decider = ReconnectDeciderV3::new();
        assert_eq!(
            decider.next_attempt(retryable(None), 0.5),
            NextAttemptV3::Immediate
        );
        // Second consecutive failure must already back off.
        match decider.next_attempt(retryable(None), 0.0) {
            NextAttemptV3::After(delay) => {
                assert!(delay >= Duration::from_millis(500));
                assert!(delay <= Duration::from_secs(1));
            }
            other => panic!("expected backoff, got {other:?}"),
        }
    }

    #[test]
    fn backoff_grows_exponentially_and_caps() {
        let mut decider = ReconnectDeciderV3::new();
        assert_eq!(
            decider.next_attempt(retryable(None), 1.0),
            NextAttemptV3::Immediate
        );
        let mut previous = Duration::ZERO;
        for _ in 0..12 {
            match decider.next_attempt(retryable(None), 1.0) {
                NextAttemptV3::After(delay) => {
                    assert!(delay >= previous);
                    assert!(delay <= BACKOFF_CAP_V1);
                    previous = delay;
                }
                other => panic!("expected backoff, got {other:?}"),
            }
        }
        assert_eq!(previous, BACKOFF_CAP_V1);
    }

    #[test]
    fn stable_session_rearms_the_zero_delay_reconnect() {
        let mut decider = ReconnectDeciderV3::new();
        assert_eq!(
            decider.next_attempt(retryable(None), 0.5),
            NextAttemptV3::Immediate
        );
        assert!(matches!(
            decider.next_attempt(retryable(None), 0.5),
            NextAttemptV3::After(_)
        ));
        // A session that stayed authenticated past the threshold resets the
        // ordinal: the next allowed error is Immediate again.
        assert_eq!(
            decider.next_attempt(retryable(Some(STABLE_SESSION_THRESHOLD_V1)), 0.5),
            NextAttemptV3::Immediate
        );
    }

    #[test]
    fn short_lived_session_does_not_rearm_zero_delay() {
        let mut decider = ReconnectDeciderV3::new();
        assert_eq!(
            decider.next_attempt(retryable(None), 0.5),
            NextAttemptV3::Immediate
        );
        // Flapping link: authenticated but died quickly. Must keep backing
        // off instead of manufacturing zero-delay loops.
        assert!(matches!(
            decider.next_attempt(retryable(Some(Duration::from_secs(1))), 0.5),
            NextAttemptV3::After(_)
        ));
    }

    #[test]
    fn jitter_is_clamped_and_total_delay_never_reaches_zero() {
        for unit in [f64::NAN, f64::INFINITY, -3.0, 0.0, 0.5, 1.0, 42.0] {
            let delay = backoff_delay_v1(1, unit);
            assert!(delay >= Duration::from_millis(500));
            assert!(delay <= Duration::from_secs(1));
        }
    }
}
