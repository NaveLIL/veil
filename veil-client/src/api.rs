use prost::Message as ProstMessage;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use veil_crypto::kdf;
use veil_crypto::keys::{generate_mnemonic, validate_mnemonic, IdentityKeyPair};
use veil_crypto::membership::{
    verify_membership_epoch_bootstrap_v1, verify_membership_epoch_transition_v1,
    MembershipEpochHashV1, MembershipEpochSignatureV1, MembershipEpochV1, MembershipPolicySignerV1,
    MembershipPolicyV1, MEMBERSHIP_CRYPTO_ERA_V1, MEMBERSHIP_CRYPTO_PROFILE_SENDER_KEY_V6,
};
use veil_crypto::ratchet::{MessageHeader, RatchetSession};
use veil_crypto::sender_key::{SenderKeyDistribution, SenderKeyStore};
use veil_crypto::x3dh;
use veil_search::Indexer;
use veil_store::db::{
    DeviceBindingPinV1, DeviceRosterSnapshotV1, DirectMessageOutboxEnqueueV1,
    DirectMessageOutboxReceiptV1, DirectMessageOutboxScopeV1, HistoricalDeviceBindingProofV1,
    IncomingSenderKeyRouteV1, LocalPreKey, LocalPreKeyPublicationV1, MembershipEpochPinV1,
    PendingDirectMessageOutboxV1, PendingSenderKeyDeviceEnvelopeV1, VeilDb,
    DIRECT_MESSAGE_OUTBOX_MAX_PENDING_V1,
};
use veil_store::models::{
    AccountSnapshot, ConversationType, LocalIdentityVerification, Message, MessageAuthorContext,
    ProfileLocator, RemoteMessageStateKind, RemoteReaction,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::connection::{
    BudgetedConnectionEventV1, ConfirmedMutation, Connection, ConnectionConfig,
    ConnectionConnectErrorV1, ConnectionConnectStopV1, ConnectionEvent,
    ConnectionEventBudgetGuardV1, ConnectionEventBufferErrorV1, ConnectionSendErrorV1,
    LIVE_EVENT_QUEUE_CAPACITY, LIVE_EVENT_RETAINED_BYTES,
};
use crate::device_identity::{
    device_binding_signing_bytes, DeviceIdentityV1, DEVICE_BINDING_STATUS_ACTIVE,
    DEVICE_CAPABILITY_MEMBERSHIP_EPOCH_V1, REQUIRED_DEVICE_CAPABILITIES,
};
use crate::direct_v2::{
    DirectAccountCoordinateV2, DirectDeviceCoordinateV2, DirectInitialKeyAgreementV2,
    DirectParticipantCoordinateV2, DirectSessionContextV2, DirectSessionStateV2,
};
use crate::prekeys::{
    canonical_own_prekey_request_body, validate_own_prekey_count_response,
    validate_own_prekey_upload_ack, OwnPreKeyAcknowledgeResult, OwnPreKeyPublication,
    OWN_PREKEY_BATCH_SIZE, OWN_PREKEY_LOW_WATERMARK,
};
use crate::protocol::proto;
use crate::ws_auth_v3::WsRegistrationModeV3;
use crate::ws_events_v3::{connect_primary_v3_classified, WsEventsV3Config};

// Wire header type tags
const HEADER_INITIAL: u8 = 0x01; // X3DH init + ratchet header
const HEADER_RATCHET: u8 = 0x02; // Ratchet header only
const HEADER_INITIAL_V2: u8 = 0x11; // Direct v2 session commitment + X3DH + ratchet
const HEADER_RATCHET_V2: u8 = 0x12; // Direct v2 session commitment + ratchet
const HEADER_SENDER_KEY: u8 = 0x05; // Group/channel sender-key encrypted message

// Inner type bytes (inside ratchet-decrypted plaintext for pairwise channel)
const INNER_TEXT: u8 = 0x00; // UTF-8 text message
const INNER_SKDM: u8 = 0x01; // Sender Key Distribution Message (JSON)
#[cfg(any(test, feature = "test-utils"))]
const RATCHET_AD_DOMAIN: &[u8] = b"veil-ratchet-message-v1";
const DIRECT_CRYPTO_PROFILE_V2: &str = "direct_v2";
const DIRECT_CRYPTO_ERA_V2: u64 = 1;
pub const DIRECT_DEVICE_BINDING_STATUS_ACTIVE_V2: u8 = DEVICE_BINDING_STATUS_ACTIVE;
const MAX_PLAINTEXT_BYTES: usize = 32 * 1024;
const DEVICE_ROSTER_COMMITMENT_DOMAIN: &[u8] = b"veil-conversation-device-roster-v1\0";
const SEND_MESSAGE_REQUEST_DIGEST_DOMAIN_V1: &[u8] = b"veil.message.send.v1\0";

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingInitialHeader {
    ephemeral_public: [u8; 32],
    signed_prekey_id: u32,
    one_time_prekey_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    direct_v2_session_id: Option<[u8; 32]>,
}

#[derive(Clone)]
struct PendingOutgoingMessage {
    local_message_id: String,
    conversation_id: String,
    sender_identity_key: [u8; 32],
    plaintext: String,
    /// True only when SQLCipher owns the exact retry bytes and the ratchet
    /// step in `direct_message_outbox_v1`. ACK/Error reconciliation must use
    /// that durable receipt instead of the legacy message-only helpers.
    durable_direct_outbox: bool,
    /// Process-local monotonic deadline for the ACK of an exact durable Direct
    /// frame accepted by the current transport queue. It is deliberately not
    /// persisted: a new socket epoch installs a fresh sequence correlation and
    /// deadline while SQLCipher continues to own the immutable retry bytes.
    direct_ack_deadline: Option<Instant>,
}

struct PreparedDirectCiphertextV1 {
    peer_identity_key: [u8; 32],
    candidate: RatchetSession,
    ciphertext: Vec<u8>,
    header: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MessageAckCorrelationV1 {
    CurrentOutgoing,
    RepeatedDirectReceipt,
    Mutation,
    SenderKey,
    Generic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ErrorCorrelationV1 {
    CurrentOutgoing,
    RepeatedDirectReceipt,
    PendingCommand,
    Generic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionReconciliationV1 {
    None,
    MessageAck(MessageAckCorrelationV1),
    Error(ErrorCorrelationV1),
}

enum ConnectionReconciliationValidationErrorV1 {
    ProtocolViolation(String),
    StorageUncertain(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectLiveEmptyPollV1 {
    Quiescent,
    ContinueFrozenFifo,
    AckDeadline,
}

impl Drop for PendingOutgoingMessage {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingSenderKeyEnvelopeKey {
    conversation_id: String,
    generation: u32,
    target_device_id: [u8; 16],
    target_binding_version: u64,
    roster_version: u64,
    roster_commitment: [u8; 32],
    membership_epoch: u64,
    membership_epoch_hash: [u8; 32],
    envelope_commitment: [u8; 32],
}

struct ReceiveCryptoSnapshot {
    ratchet_sessions: HashMap<[u8; 32], RatchetSession>,
    direct_v2_sessions: HashMap<[u8; 32], DirectSessionStateV2>,
    otk_secrets: HashMap<u32, [u8; 32]>,
    sender_keys: SenderKeyStore,
    channel_conversations: HashSet<String>,
    sender_key_distribution_pending: HashSet<String>,
    pending_initial_headers: HashMap<[u8; 32], PendingInitialHeader>,
    pending_initial_sequences: HashMap<u64, [u8; 32]>,
}

impl Drop for ReceiveCryptoSnapshot {
    fn drop(&mut self) {
        for secret in self.otk_secrets.values_mut() {
            secret.zeroize();
        }
        self.otk_secrets.clear();
        // RatchetSession and SenderKeyStore zeroize their own secret material
        // on drop; clearing here makes that destruction explicit on the
        // successful receive path where the rollback snapshot is unused.
        self.ratchet_sessions.clear();
        self.direct_v2_sessions.clear();
        self.sender_keys = SenderKeyStore::new();
    }
}

#[cfg(any(test, feature = "test-utils"))]
fn ratchet_associated_data(
    conversation_id: &str,
    sender_identity_key: &[u8; 32],
    recipient_identity_key: &[u8; 32],
    wire_prefix: &[u8],
) -> Result<Vec<u8>, String> {
    let conversation_len =
        u32::try_from(conversation_id.len()).map_err(|_| "conversation id too long".to_string())?;
    let prefix_len =
        u32::try_from(wire_prefix.len()).map_err(|_| "ratchet wire prefix too long".to_string())?;
    let mut ad = Vec::with_capacity(
        RATCHET_AD_DOMAIN.len() + 4 + conversation_id.len() + 32 + 32 + 4 + wire_prefix.len(),
    );
    ad.extend_from_slice(RATCHET_AD_DOMAIN);
    ad.extend_from_slice(&conversation_len.to_be_bytes());
    ad.extend_from_slice(conversation_id.as_bytes());
    ad.extend_from_slice(sender_identity_key);
    ad.extend_from_slice(recipient_identity_key);
    ad.extend_from_slice(&prefix_len.to_be_bytes());
    ad.extend_from_slice(wire_prefix);
    Ok(ad)
}

fn persist_existing_ratchet_transition_v1(
    db: &VeilDb,
    peer_identity_key: &[u8; 32],
    expected_session: &RatchetSession,
    advanced_session: &RatchetSession,
) -> Result<u64, String> {
    let persisted = db
        .load_ratchet_session_with_revision_v1(peer_identity_key)?
        .ok_or_else(|| "ratchet session is absent from SQLCipher".to_string())?;
    if !expected_session.matches_serialized_v1(&persisted.session_data)? {
        return Err("in-memory ratchet differs from its SQLCipher revision".to_string());
    }
    let advanced = Zeroizing::new(advanced_session.serialize()?);
    db.compare_and_swap_ratchet_session_v1(
        peer_identity_key,
        persisted.revision,
        &persisted.session_data,
        &advanced,
    )
}

fn random_device_id() -> [u8; 16] {
    loop {
        let mut device_id = [0u8; 16];
        // `fill_bytes` fails closed if the operating-system CSPRNG is
        // unavailable. Never silently register the all-zero device used by
        // an earlier best-effort implementation.
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut device_id);
        if device_id != [0u8; 16] {
            return device_id;
        }
    }
}

fn canonical_server_origin_from_websocket_url_v1(server_url: &str) -> Result<String, String> {
    let parsed = url::Url::parse(server_url)
        .map_err(|_| "invalid authenticated WebSocket server URL".to_string())?;
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err("authenticated WebSocket URL has an invalid authority".to_string());
    }
    let origin_scheme = match parsed.scheme() {
        "wss" => "https",
        "ws" => "http",
        _ => return Err("authenticated WebSocket URL has an unsupported scheme".to_string()),
    };
    let host = parsed
        .host_str()
        .ok_or_else(|| "authenticated WebSocket URL has no host".to_string())?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "authenticated WebSocket URL has no effective port".to_string())?;
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let canonical = format!("{origin_scheme}://{authority}:{port}");
    crate::direct::validate_canonical_origin(&canonical)?;
    Ok(canonical)
}

/// Result of decrypting an incoming message.
#[derive(Debug)]
pub enum DecryptedPayload {
    /// Real text or binary content for the UI / persistence.
    Text(Vec<u8>),
    /// Internal control frame (e.g. SKDM) — already processed; do not surface.
    Control,
}

/// Outcome of the atomic inbound receive path.
#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveMessageResult {
    Stored { plaintext: String },
    Duplicate,
}

/// Internal classification used by authenticated inbound mutations.
///
/// Public desktop APIs deliberately keep their established `String` surface;
/// this type exists so a peer-controlled cryptographic rejection can be
/// quarantined without ever confusing it with an uncertain SQLCipher commit.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DirectHistoryMutationError {
    ConversationRejected(String),
    StorageUncertain(String),
}

impl DirectHistoryMutationError {
    fn rejected(error: impl Into<String>) -> Self {
        Self::ConversationRejected(error.into())
    }

    fn storage(error: impl Into<String>) -> Self {
        Self::StorageUncertain(error.into())
    }

    fn into_detail(self) -> String {
        match self {
            Self::ConversationRejected(detail) | Self::StorageUncertain(detail) => detail,
        }
    }
}

/// Typed failure boundary for one outgoing Direct message attempt.
///
/// Callers may present `Rejected` as a definite, not-accepted failure. A
/// `StorageUncertain` result means SQLCipher may have advanced the send ratchet
/// or published the pending local row; the active native epoch must be revoked
/// before any retry can be considered.
#[derive(Debug, PartialEq, Eq)]
pub enum DirectSendErrorV1 {
    Rejected(String),
    StorageUncertain(String),
}

/// Source-classified failure for a complete authenticated client connection.
///
/// Only `RetryableTransport` may be used by a native reconnect controller.
/// Rendered diagnostics are retained for legacy/manual callers but are never a
/// retry policy input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MobileConnectStopV1 {
    RetryableTransport,
    AuthenticationRejected,
    RegistrationClosed,
    InviteInvalid,
    EpochInvalid,
    StorageUncertain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileConnectErrorV1 {
    pub stop: MobileConnectStopV1,
    pub detail: String,
}

impl MobileConnectErrorV1 {
    fn new(stop: MobileConnectStopV1, detail: impl Into<String>) -> Self {
        Self {
            stop,
            detail: detail.into(),
        }
    }

    fn from_connection(error: ConnectionConnectErrorV1) -> Self {
        let stop = match error.stop {
            ConnectionConnectStopV1::RetryableTransport => MobileConnectStopV1::RetryableTransport,
            ConnectionConnectStopV1::AuthenticationRejected => {
                MobileConnectStopV1::AuthenticationRejected
            }
            ConnectionConnectStopV1::RegistrationClosed => MobileConnectStopV1::RegistrationClosed,
            ConnectionConnectStopV1::InviteInvalid => MobileConnectStopV1::InviteInvalid,
            ConnectionConnectStopV1::EpochInvalid => MobileConnectStopV1::EpochInvalid,
        };
        Self::new(stop, error.detail)
    }

    pub fn into_detail(self) -> String {
        self.detail
    }
}

impl std::fmt::Display for MobileConnectErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for MobileConnectErrorV1 {}

/// Durable enqueue result for one native Direct user intent. A false
/// `transport_enqueued` still means the SQLCipher outbox owns the intent and a
/// later Ready lease must replay it; callers must not create a second intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectMessageEnqueueReportV1 {
    pub sequence: u64,
    pub transport_enqueued: bool,
    /// Source-typed terminal observed at the enqueue boundary. Every failed
    /// enqueue has an explicit stop; `None` is valid only when the exact frame
    /// entered the bounded queue and no concurrent terminal was published.
    pub transport_stop: Option<DirectLiveReplayStopV1>,
}

/// One bounded pass over the durable Direct outbox. Queue cursors are opaque
/// monotonic integers and expose no conversation, account, or message IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirectOutboxReplayReportV1 {
    pub visited: usize,
    pub enqueued: usize,
    pub pending_total: usize,
    pub next_queue_order: Option<u64>,
    pub reached_end: bool,
    pub transport_blocked: bool,
}

impl DirectSendErrorV1 {
    fn rejected(error: impl Into<String>) -> Self {
        Self::Rejected(error.into())
    }

    fn storage(error: impl Into<String>) -> Self {
        Self::StorageUncertain(error.into())
    }
}

fn send_message_request_digest_v1(exact_send_message_payload: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(SEND_MESSAGE_REQUEST_DIGEST_DOMAIN_V1);
    digest.update(exact_send_message_payload);
    digest.finalize().into()
}

fn is_retryable_correlated_send_error_v1(code: u32, reason: Option<&str>) -> bool {
    code == 429
        || (500..=599).contains(&code)
        || (code == 401 && reason == Some("not_authenticated"))
}

/// Internal classification for initiator/responder X3DH persistence.
/// Cryptographic or peer-bundle rejection is definite; a SQLCipher error is
/// not, because the ratchet/header transaction may already have committed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DirectSessionEstablishErrorV1 {
    Rejected(String),
    StorageUncertain(String),
}

impl DirectSessionEstablishErrorV1 {
    fn rejected(error: impl Into<String>) -> Self {
        Self::Rejected(error.into())
    }

    fn storage(error: impl Into<String>) -> Self {
        Self::StorageUncertain(error.into())
    }
}

/// One native Direct live-replay turn never consumes more than this many
/// authenticated socket events. The caller must schedule another turn when
/// `quiescent` is false, giving lifecycle/terminal checks a bounded cadence.
pub const DIRECT_LIVE_REPLAY_MAX_BATCH_V1: usize = 64;
/// A queued exact Direct frame must either receive its correlated ACK/error or
/// relinquish the current socket epoch within this monotonic interval.
const DIRECT_ACK_DEADLINE_V1: Duration = Duration::from_secs(15);

fn next_direct_ack_deadline_v1() -> Instant {
    Instant::now()
        .checked_add(DIRECT_ACK_DEADLINE_V1)
        .expect("15-second Direct ACK deadline fits the monotonic clock")
}
/// Shared upper bound used by native controllers when validating aggregate
/// durable Direct outbox replay reports. Individual queue orders and IDs stay
/// inside the client/store boundary.
pub const DIRECT_OUTBOX_MAX_PENDING_V1: usize = DIRECT_MESSAGE_OUTBOX_MAX_PENDING_V1;

/// Deliberately coarse output from one Direct live-replay turn.
///
/// No account locator, conversation id, ciphertext, plaintext, or key material
/// crosses this boundary. Renderer-facing projections are read separately
/// from SQLCipher after replay has committed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectLiveReplayReportV1 {
    pub consumed: usize,
    pub stored: usize,
    pub duplicates: usize,
    pub ignored: usize,
    pub newly_blocked: usize,
    pub visible_mutations: usize,
    /// True only when this turn explicitly observed `poll_event() == None`
    /// before reaching the hard batch bound.
    pub quiescent: bool,
}

/// Fail-closed reason which stopped Direct live replay globally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectLiveReplayStopV1 {
    /// The authenticated transport ended without invalidating native state.
    RetryableTransport,
    /// An exact durable Direct frame remained unacknowledged past its
    /// process-local monotonic deadline.
    AckDeadline,
    /// The authenticated epoch violated a protocol, routing, authentication,
    /// or bounded-buffer invariant and must not be retried automatically.
    EpochInvalid,
    /// A native mutation could not establish whether durable state committed.
    StorageUncertain,
}

/// Typed failure from the pre-history live-buffer boundary. The legacy buffer
/// error is retained only for desktop compatibility; native retry policy uses
/// `stop` and therefore cannot confuse sticky SQLCipher ambiguity with an
/// ordinary ended socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectLiveBufferErrorV1 {
    pub stop: DirectLiveReplayStopV1,
    pub buffer_error: Option<ConnectionEventBufferErrorV1>,
}

/// Typed global stop with the aggregate work completed before the stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectLiveReplayErrorV1 {
    pub stop: DirectLiveReplayStopV1,
    pub report: DirectLiveReplayReportV1,
}

impl std::fmt::Display for DirectLiveReplayErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.stop {
            DirectLiveReplayStopV1::RetryableTransport => {
                formatter.write_str("authenticated Direct live transport ended and may be retried")
            }
            DirectLiveReplayStopV1::AckDeadline => {
                formatter.write_str("authenticated Direct acknowledgement deadline elapsed")
            }
            DirectLiveReplayStopV1::EpochInvalid => {
                formatter.write_str("authenticated Direct live epoch is invalid")
            }
            DirectLiveReplayStopV1::StorageUncertain => {
                formatter.write_str("Direct live SQLCipher state is uncertain")
            }
        }
    }
}

impl std::error::Error for DirectLiveReplayErrorV1 {}

/// Native-safe availability for one caller-supplied conversation id.
///
/// The result never enumerates or returns conversation identifiers. A future
/// FFI projection must ask about the exact id it is about to expose.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectConversationAvailabilityV1 {
    /// Policy/crypto availability only; transport connectivity is separate.
    Available = 0,
    Quarantined = 1,
    RuntimeRevoked = 2,
    NotDirect = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectIdentityVerificationProofV2 {
    NotCompared,
    VerifiedOnThisDevice,
    IdentityChanged,
}

const DIRECT_IDENTITY_QR_PREFIX_V1: &str = "veil-identity:account-v2:";

fn direct_identity_qr_payload_v1(fingerprint_hex: &str) -> Result<String, String> {
    let mut fingerprint = [0u8; 32];
    if fingerprint_hex.len() != 64
        || !fingerprint_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || hex::decode_to_slice(fingerprint_hex, &mut fingerprint).is_err()
    {
        return Err("computed Direct identity fingerprint is invalid".to_string());
    }
    Ok(format!("{DIRECT_IDENTITY_QR_PREFIX_V1}{fingerprint_hex}"))
}

fn direct_identity_qr_fingerprint_v1(payload: &str) -> Result<[u8; 32], String> {
    let expected_len = DIRECT_IDENTITY_QR_PREFIX_V1.len() + 64;
    if payload.len() != expected_len || !payload.is_ascii() {
        return Err("scanned Direct identity QR payload is invalid".to_string());
    }
    let fingerprint_hex = payload
        .strip_prefix(DIRECT_IDENTITY_QR_PREFIX_V1)
        .ok_or_else(|| "scanned Direct identity QR payload is invalid".to_string())?;
    if !fingerprint_hex
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("scanned Direct identity QR payload is invalid".to_string());
    }
    let mut fingerprint = [0u8; 32];
    hex::decode_to_slice(fingerprint_hex, &mut fingerprint)
        .map_err(|_| "scanned Direct identity QR payload is invalid".to_string())?;
    Ok(fingerprint)
}

impl From<LocalIdentityVerification> for DirectIdentityVerificationProofV2 {
    fn from(value: LocalIdentityVerification) -> Self {
        match value {
            LocalIdentityVerification::NotCompared => Self::NotCompared,
            LocalIdentityVerification::VerifiedOnThisDevice => Self::VerifiedOnThisDevice,
            LocalIdentityVerification::IdentityChanged => Self::IdentityChanged,
        }
    }
}

/// Exact account-v2 safety number and device-local comparison state for one
/// authenticated Direct route. The fingerprint binds the canonical Node
/// origin, both account UUIDs, and both accounts' X25519 + Ed25519 public keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectIdentityVerificationV2 {
    pub canonical_server_origin: String,
    pub peer_user_id: String,
    pub peer_identity_key: [u8; 32],
    pub peer_signing_key: [u8; 32],
    pub fingerprint_emoji: String,
    pub fingerprint_hex: String,
    pub qr_payload: String,
    pub proof: DirectIdentityVerificationProofV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectLiveEventOutcomeV1 {
    Stored,
    Duplicate,
    Ignored,
}

enum ClassifiedReceiveResultV1 {
    Stored { plaintext: Zeroizing<String> },
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtomicReceiveDecryptMode {
    General,
    DirectHistory,
}

pub struct RemoteMessageMetadata<'a> {
    pub revision_ms: i64,
    pub reactions: Option<&'a [RemoteReaction]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteReconcileAction {
    Unchanged,
    NeedsInitialCiphertext,
    NeedsEncryptedEdit,
    Deleted,
    Unavailable,
    SelfStateOnly,
}

/// Describes whether restoring Sender-Key state from durable storage already
/// performed the mandatory fresh-generation transition for an offline sync.
/// The desktop orchestration carries this value through backlog processing so
/// distribution cannot accidentally rotate the same conversation twice.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineSenderKeyRefresh {
    /// No fresh outgoing generation is prepared in this native session.
    /// Offline sync must create one before distributing to the live roster.
    Required,
    /// A persisted outgoing generation was restored and immediately rotated,
    /// or another native caller already prepared the same still-pending
    /// refresh. Distribution must reuse that exact generation.
    AlreadyRotated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceBindingCandidateV1 {
    pub device_id: [u8; 16],
    pub device_identity_key: [u8; 32],
    pub device_signing_key: [u8; 32],
    pub version: u64,
    pub capabilities: u64,
    pub status: u8,
    pub account_signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRosterEntryV1 {
    pub user_id: [u8; 16],
    pub account_identity_key: [u8; 32],
    pub account_signing_key: [u8; 32],
    pub device_id: [u8; 16],
    pub binding: Option<DeviceBindingCandidateV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRosterCandidateV1 {
    pub conversation_id: String,
    pub roster_version: u64,
    pub roster_commitment: [u8; 32],
    pub required_capabilities: u64,
    pub ready: bool,
    pub member_user_ids: Vec<[u8; 16]>,
    pub devices: Vec<DeviceRosterEntryV1>,
    pub crypto_profile: String,
    pub membership_activated: bool,
    pub membership_ready: bool,
    pub membership_epoch: u64,
    pub membership_epoch_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipEpochRecordCandidateV1 {
    pub epoch: MembershipEpochV1,
    pub epoch_hash: MembershipEpochHashV1,
    pub signatures: Vec<MembershipEpochSignatureV1>,
    pub bootstrap_owner: Option<MembershipPolicySignerV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipEpochChainCandidateV1 {
    pub canonical_origin: String,
    pub conversation_id: String,
    pub head_epoch: u64,
    pub head_hash: MembershipEpochHashV1,
    pub records: Vec<MembershipEpochRecordCandidateV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedMembershipEpochV1 {
    pub epoch: MembershipEpochV1,
    pub epoch_hash: MembershipEpochHashV1,
    pub signatures: Vec<MembershipEpochSignatureV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTargetV1 {
    pub conversation_id: String,
    pub user_id: [u8; 16],
    pub account_identity_key: [u8; 32],
    pub account_signing_key: [u8; 32],
    pub device_id: [u8; 16],
    pub device_identity_key: [u8; 32],
    pub device_signing_key: [u8; 32],
    pub binding_version: u64,
    pub capabilities: u64,
    pub account_signature: [u8; 64],
    pub roster_version: u64,
    pub roster_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderKeyMessageSecurityContextV1 {
    pub roster_version: u64,
    pub roster_commitment: [u8; 32],
    pub sender_device_id: [u8; 16],
    pub target_device_id: [u8; 16],
    pub sender_binding_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderKeyMessageSecurityContextV6 {
    pub roster_version: u64,
    pub roster_commitment: [u8; 32],
    pub sender_device_id: [u8; 16],
    pub target_device_id: [u8; 16],
    pub sender_binding_version: u64,
    pub membership_epoch: u64,
    pub membership_epoch_hash: [u8; 32],
}

/// Persisted outer routing/authentication coordinates for a Direct v2
/// ciphertext.  The account key is supplied separately by the authenticated
/// directory; this value carries the exact account-signed sender device
/// binding selected by the WS v3 principal and the exact local target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectMessageSecurityContextV2 {
    pub sender_user_id: String,
    pub sender_device_id: [u8; 16],
    pub sender_binding_version: u64,
    pub sender_device_identity_key: [u8; 32],
    pub sender_device_signing_key: [u8; 32],
    pub sender_device_capabilities: u64,
    pub sender_device_binding_status: u8,
    pub sender_account_signature: [u8; 64],
    pub target_device_id: [u8; 16],
    pub target_binding_version: u64,
    pub direct_session_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageSecurityContextV1 {
    SenderKeyV5(SenderKeyMessageSecurityContextV1),
    SenderKeyV6(SenderKeyMessageSecurityContextV6),
    DirectV2(DirectMessageSecurityContextV2),
}

/// Result of checking whether a persisted Sender-Key v5 wire has an exact
/// trusted route. `MissingExactRoute` is not authentication success and never
/// authorizes decryption or receive-chain mutation. Native orchestration may
/// use its bounded metadata only with independent device-admission evidence.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderKeyMessageContextInspectionV1 {
    Verified,
    MissingExactRoute {
        target_device_id: [u8; 16],
        message_roster_version: u64,
        message_roster_commitment: [u8; 32],
        installed_roster_version: u64,
        installed_roster_commitment: [u8; 32],
    },
}

enum ValidatedSenderKeyRouteForMessageV1 {
    Verified {
        generation: u32,
        route: Box<IncomingSenderKeyRouteV1>,
    },
    MissingExactRoute {
        target_device_id: [u8; 16],
        message_roster_version: u64,
        message_roster_commitment: [u8; 32],
        installed_roster_version: u64,
        installed_roster_commitment: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderKeyRouteV1 {
    pub conversation_id: String,
    pub generation: u32,
    pub target_account_identity_key: [u8; 32],
    pub target_device_id: [u8; 16],
    pub target_device_identity_key: [u8; 32],
    pub sender_device_id: [u8; 16],
    pub sender_account_identity_key: [u8; 32],
    pub sender_account_signing_key: [u8; 32],
    pub sender_device_identity_key: [u8; 32],
    pub sender_device_signing_key: [u8; 32],
    pub sender_device_capabilities: u64,
    pub sender_device_binding_status: u8,
    pub sender_account_signature: [u8; 64],
    pub roster_version: u64,
    pub roster_commitment: [u8; 32],
    pub membership_epoch: u64,
    pub membership_epoch_hash: [u8; 32],
    pub sender_binding_version: u64,
    pub target_binding_version: u64,
    pub envelope_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PendingSenderKeyReceiptV1 {
    pub conversation_id: String,
    pub owner_device_id: [u8; 16],
    pub target_device_id: [u8; 16],
    pub generation: u32,
    pub roster_version: u64,
    pub membership_epoch: u64,
    pub membership_epoch_hash: [u8; 32],
    pub envelope_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedSenderKeyDiagnosticV1 {
    pub conversation_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RetainedSenderKeyProcessReportV1 {
    pub processed: usize,
    pub diagnostics: Vec<RetainedSenderKeyDiagnosticV1>,
}

/// Canonical public wire values for one authenticated REST v2 request.
///
/// The client chooses the bound origin/account, timestamp and nonce internally;
/// callers can neither redirect a proof to another account nor provide their
/// own freshness. This value intentionally implements neither `Clone` nor
/// `Debug` because the signature and nonce are single-request bearer material.
pub struct AuthenticatedRestHeadersV2 {
    version: &'static str,
    user_id: String,
    timestamp_ms: String,
    nonce: String,
    signature: String,
}

impl AuthenticatedRestHeadersV2 {
    pub fn version(&self) -> &str {
        self.version
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn timestamp_ms(&self) -> &str {
        &self.timestamp_ms
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SenderKeyDistributionModeV1 {
    Live,
    /// Pre-auth replay may carry a former sender absent from the current
    /// roster. A first observation is deliberately service-mediated TOFU,
    /// never a "Verified identity" claim: the account/device chain is pinned
    /// atomically so later substitution fails closed, while Phase 4D
    /// out-of-band verification remains the user-authentication boundary.
    Retained,
}

#[derive(Clone)]
struct ValidatedDeviceRosterV1 {
    version: u64,
    commitment: [u8; 32],
    required_capabilities: u64,
    authorized_account_identities: HashSet<[u8; 32]>,
    targets: Vec<DeviceTargetV1>,
    eligible_devices: HashMap<[u8; 16], DeviceTargetV1>,
    account_signing_keys: HashMap<[u8; 16], [u8; 32]>,
    membership_activated: bool,
    membership_epoch: u64,
    membership_epoch_hash: [u8; 32],
}

#[derive(Clone)]
struct ValidatedMembershipEpochHeadV1 {
    epoch: u64,
    hash: MembershipEpochHashV1,
    roster_version: u64,
    roster_commitment: [u8; 32],
}

struct PreparedDeviceRosterV1 {
    validated: ValidatedDeviceRosterV1,
    bindings: Vec<DeviceBindingPinV1>,
    canonical_snapshot: Vec<u8>,
}

/// Prekey set generated for uploading to the server.
pub struct PreKeySet {
    pub spk_public: [u8; 32],
    pub spk_id: u32,
    pub spk_signature: [u8; 64],
    pub signing_key: [u8; 32],
    pub otk_publics: Vec<([u8; 32], u32)>,
}

struct GeneratedPreKeyBatch {
    prekeys: PreKeySet,
    local_prekeys: Vec<LocalPreKey>,
}

struct GeneratedPreKeyRefill {
    prekeys: PreKeySet,
    signed_prekey: LocalPreKey,
    one_time_prekeys: Vec<LocalPreKey>,
}

/// Main client API — the single entry point for all UI interactions.
///
/// All methods are synchronous from the caller's perspective.
/// Crypto operations happen in Rust, never exposed to UI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DeferredConnectionEventStateV1 {
    Open,
    Terminal,
    Failed(ConnectionEventBufferErrorV1),
}

struct DeferredConnectionEventQueueV1 {
    events: VecDeque<BudgetedConnectionEventV1>,
    retained_bytes: usize,
    state: DeferredConnectionEventStateV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeferredConnectionEventAppendV1 {
    buffered: usize,
    terminal: bool,
}

impl Default for DeferredConnectionEventQueueV1 {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            retained_bytes: 0,
            state: DeferredConnectionEventStateV1::Open,
        }
    }
}

impl DeferredConnectionEventQueueV1 {
    fn reset_for_new_epoch(&mut self) {
        self.events.clear();
        self.retained_bytes = 0;
        self.state = DeferredConnectionEventStateV1::Open;
    }

    fn failure(&self) -> Option<ConnectionEventBufferErrorV1> {
        match &self.state {
            DeferredConnectionEventStateV1::Failed(error) => Some(error.clone()),
            _ => None,
        }
    }

    fn is_terminal(&self) -> bool {
        !matches!(self.state, DeferredConnectionEventStateV1::Open)
    }

    fn fail(&mut self, error: ConnectionEventBufferErrorV1) {
        self.events.clear();
        self.retained_bytes = 0;
        self.state = DeferredConnectionEventStateV1::Failed(error);
    }

    fn close_epoch(&mut self) {
        self.events.clear();
        self.retained_bytes = 0;
        self.state = DeferredConnectionEventStateV1::Terminal;
    }

    fn try_extend(
        &mut self,
        incoming: Vec<BudgetedConnectionEventV1>,
    ) -> Result<DeferredConnectionEventAppendV1, ConnectionEventBufferErrorV1> {
        match &self.state {
            DeferredConnectionEventStateV1::Failed(error) => return Err(error.clone()),
            DeferredConnectionEventStateV1::Terminal => {
                return Err(ConnectionEventBufferErrorV1::TransportEpochEnded)
            }
            DeferredConnectionEventStateV1::Open => {}
        }

        if let Some(error) = incoming
            .iter()
            .find_map(BudgetedConnectionEventV1::terminal_failure)
            .cloned()
        {
            self.fail(error.clone());
            return Err(error);
        }

        let first_control = incoming.iter().position(|queued| {
            matches!(
                queued.event,
                ConnectionEvent::Authenticated { .. }
                    | ConnectionEvent::AuthFailed { .. }
                    | ConnectionEvent::Disconnected { .. }
            )
        });
        if let Some(position) = first_control {
            let control = &incoming[position].event;
            if matches!(
                control,
                ConnectionEvent::Authenticated { .. } | ConnectionEvent::AuthFailed { .. }
            ) {
                let error = ConnectionEventBufferErrorV1::AuthenticationEpochAnomaly {
                    envelope: match control {
                        ConnectionEvent::Authenticated { .. } => "Authenticated event",
                        ConnectionEvent::AuthFailed { .. } => "AuthFailed event",
                        _ => unreachable!(),
                    },
                };
                self.fail(error.clone());
                return Err(error);
            }

            let terminal = incoming
                .into_iter()
                .nth(position)
                .ok_or(ConnectionEventBufferErrorV1::RetainedSizeAccountingOverflow)?;
            let retained_bytes = terminal.retained_bytes();
            if retained_bytes > LIVE_EVENT_RETAINED_BYTES {
                let error = ConnectionEventBufferErrorV1::RetainedSizeLimitExceeded {
                    limit: LIVE_EVENT_RETAINED_BYTES,
                    event_bytes: retained_bytes,
                };
                self.fail(error.clone());
                return Err(error);
            }
            self.events.clear();
            self.retained_bytes = retained_bytes;
            self.events.push_back(terminal);
            self.state = DeferredConnectionEventStateV1::Terminal;
            return Ok(DeferredConnectionEventAppendV1 {
                buffered: 1,
                terminal: true,
            });
        }

        let final_count = self
            .events
            .len()
            .checked_add(incoming.len())
            .ok_or(ConnectionEventBufferErrorV1::RetainedSizeAccountingOverflow);
        let incoming_bytes = incoming.iter().try_fold(0usize, |total, event| {
            total
                .checked_add(event.retained_bytes())
                .ok_or(ConnectionEventBufferErrorV1::RetainedSizeAccountingOverflow)
        });
        let final_bytes = incoming_bytes.and_then(|incoming_bytes| {
            self.retained_bytes
                .checked_add(incoming_bytes)
                .ok_or(ConnectionEventBufferErrorV1::RetainedSizeAccountingOverflow)
        });
        let final_count = match final_count {
            Ok(count) => count,
            Err(error) => {
                self.fail(error.clone());
                return Err(error);
            }
        };
        let final_bytes = match final_bytes {
            Ok(bytes) => bytes,
            Err(error) => {
                self.fail(error.clone());
                return Err(error);
            }
        };
        if final_count > LIVE_EVENT_QUEUE_CAPACITY {
            let error = ConnectionEventBufferErrorV1::EventCountLimitExceeded {
                limit: LIVE_EVENT_QUEUE_CAPACITY,
            };
            self.fail(error.clone());
            return Err(error);
        }
        if final_bytes > LIVE_EVENT_RETAINED_BYTES {
            let error = ConnectionEventBufferErrorV1::RetainedSizeLimitExceeded {
                limit: LIVE_EVENT_RETAINED_BYTES,
                event_bytes: incoming
                    .last()
                    .map(BudgetedConnectionEventV1::retained_bytes)
                    .unwrap_or(0),
            };
            self.fail(error.clone());
            return Err(error);
        }

        let buffered = incoming.len();
        self.events.extend(incoming);
        self.retained_bytes = final_bytes;
        Ok(DeferredConnectionEventAppendV1 {
            buffered,
            terminal: false,
        })
    }

    fn pop_front(&mut self) -> Option<BudgetedConnectionEventV1> {
        let event = self.events.pop_front()?;
        self.retained_bytes = self
            .retained_bytes
            .checked_sub(event.retained_bytes())
            .expect("deferred live-event byte invariant");
        Some(event)
    }
}

pub struct VeilClient {
    identity: Option<IdentityKeyPair>,
    /// Independent per-install keypair loaded only after SQLCipher unlock.
    /// It is deliberately not exposed through the renderer-facing API.
    device_identity: Option<DeviceIdentityV1>,
    db: Option<VeilDb>,
    connection: Option<Connection>,
    /// Non-control events observed while installing the authenticated retained
    /// SKDM barrier are replayed to the normal live dispatcher afterwards.
    deferred_connection_events: DeferredConnectionEventQueueV1,
    /// Server-assigned UUID from the authenticated WebSocket session.
    authenticated_user_id: Option<String>,
    /// Canonical HTTPS/loopback-HTTP origin derived from the exact WebSocket
    /// URL which authenticated `authenticated_user_id`. Cleared with the
    /// transport epoch so non-global server UUIDs can never select old routes.
    authenticated_server_origin: Option<String>,
    device_id: [u8; 16],
    /// Active ratchet sessions keyed by peer identity key (X25519 public).
    ratchet_sessions: HashMap<[u8; 32], RatchetSession>,
    /// Sticky origin/account/device/session coordinates for upgraded Direct
    /// ratchets. Presence means v1 wire is permanently rejected for that peer.
    direct_v2_sessions: HashMap<[u8; 32], DirectSessionStateV2>,
    /// Our signed prekey secret (for X3DH responder).
    spk_secrets: HashMap<u32, ([u8; 32], [u8; 32])>,
    spk_next_id: u32,
    /// One-time prekey secrets (for X3DH responder).
    otk_secrets: HashMap<u32, [u8; 32]>,
    otk_next_id: u32,
    /// X3DH metadata which must accompany the first ratchet message to a peer.
    pending_initial_headers: HashMap<[u8; 32], PendingInitialHeader>,
    /// Initial-message sequence numbers awaiting a server acknowledgement.
    /// Until one is acknowledged, every packet retains the X3DH header.
    pending_initial_sequences: HashMap<u64, [u8; 32]>,
    pending_outgoing_messages: HashMap<u64, PendingOutgoingMessage>,
    pending_mutations: HashMap<u64, ConfirmedMutation>,
    /// Explicit DM conversation -> peer identity binding. Unknown conversations
    /// are never treated as plaintext.
    dm_conversations: HashMap<String, [u8; 32]>,
    /// User IDs learned from authenticated directory lookups.
    known_user_keys: HashMap<String, [u8; 32]>,
    /// Ed25519 keys pinned to X25519 identities by authenticated directory
    /// responses. Required for incoming authenticated SKDM verification.
    trusted_signing_keys: HashMap<[u8; 32], [u8; 32]>,
    /// Sender-key store for channel/group E2E.
    sender_keys: SenderKeyStore,
    /// Conversations that should be encrypted with sender keys (channels & encrypted groups).
    channel_conversations: HashSet<String>,
    /// Current live sender authorization learned only from an authenticated,
    /// permission-filtered conversation directory. Historical sync has a
    /// separate path so former members can never inject fresh live ciphertext.
    authorized_conversation_senders: HashMap<String, HashSet<[u8; 32]>>,
    /// Authenticated, locally pinned per-device directory for each encrypted
    /// conversation. This is deliberately process-local: every connection
    /// epoch must obtain a fresh HTTPS directory while SQLCipher retains only
    /// the monotonic rollback/key-replacement pins.
    device_rosters: HashMap<String, ValidatedDeviceRosterV1>,
    membership_epoch_heads: HashMap<String, ValidatedMembershipEpochHeadV1>,
    last_invalidated_device_rosters: HashMap<String, (u64, [u8; 32])>,
    /// A roster was durably accepted but rotating the previous outgoing
    /// generation has not yet succeeded. Keeping this distinct from ordinary
    /// fan-out state makes an install retry rotate exactly once.
    device_roster_rotation_pending: HashSet<String>,
    /// Channels whose fresh outgoing key has not yet been delivered to the
    /// complete current member set. Sending remains blocked while present.
    sender_key_distribution_pending: HashSet<String>,
    /// Conversations for which the current in-memory outgoing generation was
    /// freshly created for the still-pending distribution gate. This separates
    /// an immutable retry from a security invalidation that still needs a
    /// rotation, and keeps cold-restore orchestration idempotent even when an
    /// earlier hydration result was discarded by another native caller.
    prepared_sender_key_generations: HashSet<String>,
    pending_sender_key_sequences: HashMap<u64, PendingSenderKeyEnvelopeKey>,
    /// Process-local mirror of the SQLCipher exact-retry cache. Rows are
    /// written durably before the first network send and survive transport
    /// loss; this map also gives no-database test/embedded clients safe retry.
    pending_sender_key_envelopes: HashMap<PendingSenderKeyEnvelopeKey, Vec<u8>>,
    pending_sender_key_receipts: VecDeque<PendingSenderKeyReceiptV1>,
    pending_sender_key_receipt_set: HashSet<PendingSenderKeyReceiptV1>,
    pending_sender_key_receipt_sequences: HashMap<u64, PendingSenderKeyReceiptV1>,
    failed_sender_key_distributions: HashSet<String>,
    /// Process-lifetime quarantine for Direct conversations whose live stream
    /// violated immutable routing/policy/cryptographic invariants. A later
    /// event for another Direct remains independently processable.
    direct_live_blocked_conversations: HashSet<String>,
    /// Sticky global stop after an uncertain SQLCipher outcome. Continuing a
    /// ratchet in this process could diverge from durable state, so only a
    /// successful native reinitialization may clear it.
    direct_live_storage_uncertain: bool,
    /// Typed terminal cause for the current authenticated Direct socket epoch.
    /// Storage uncertainty has higher precedence and is also guarded by the
    /// process-wide sticky bit above.
    direct_live_stop: Option<DirectLiveReplayStopV1>,
    /// Per-sequence number of events that were already ahead of each expired
    /// durable Direct correlation when that deadline was first observed. A
    /// separate finite FIFO watermark prevents a later-expiring send from
    /// inheriting another send's partially drained grace window.
    direct_ack_expiry_grace_remaining: HashMap<u64, usize>,
    #[cfg(any(test, feature = "test-utils"))]
    test_only_epoch_invalid_after_direct_commit: bool,
    #[cfg(any(test, feature = "test-utils"))]
    test_only_retryable_after_direct_commit: bool,
    #[cfg(any(test, feature = "test-utils"))]
    test_only_epoch_invalid_after_direct_outbox_enqueue: bool,
    /// Optional local-only full-text index. Index calls are best-effort and never fatal.
    indexer: Option<Arc<Indexer>>,
}

impl VeilClient {
    fn zeroize_prekey_secrets(&mut self) {
        for (secret, _) in self.spk_secrets.values_mut() {
            secret.zeroize();
        }
        for secret in self.otk_secrets.values_mut() {
            secret.zeroize();
        }
        self.spk_secrets.clear();
        self.otk_secrets.clear();
    }

    fn receive_crypto_snapshot(&self) -> ReceiveCryptoSnapshot {
        ReceiveCryptoSnapshot {
            ratchet_sessions: self.ratchet_sessions.clone(),
            direct_v2_sessions: self.direct_v2_sessions.clone(),
            otk_secrets: self.otk_secrets.clone(),
            sender_keys: self.sender_keys.clone(),
            channel_conversations: self.channel_conversations.clone(),
            sender_key_distribution_pending: self.sender_key_distribution_pending.clone(),
            pending_initial_headers: self.pending_initial_headers.clone(),
            pending_initial_sequences: self.pending_initial_sequences.clone(),
        }
    }

    fn restore_receive_crypto(&mut self, mut snapshot: ReceiveCryptoSnapshot) {
        self.ratchet_sessions = std::mem::take(&mut snapshot.ratchet_sessions);
        self.direct_v2_sessions = std::mem::take(&mut snapshot.direct_v2_sessions);
        self.otk_secrets = std::mem::take(&mut snapshot.otk_secrets);
        self.sender_keys = std::mem::replace(&mut snapshot.sender_keys, SenderKeyStore::new());
        self.channel_conversations = std::mem::take(&mut snapshot.channel_conversations);
        self.sender_key_distribution_pending =
            std::mem::take(&mut snapshot.sender_key_distribution_pending);
        self.pending_initial_headers = std::mem::take(&mut snapshot.pending_initial_headers);
        self.pending_initial_sequences = std::mem::take(&mut snapshot.pending_initial_sequences);
    }

    pub fn new() -> Self {
        let device_id = random_device_id();
        Self {
            identity: None,
            device_identity: None,
            db: None,
            connection: None,
            deferred_connection_events: DeferredConnectionEventQueueV1::default(),
            authenticated_user_id: None,
            authenticated_server_origin: None,
            device_id,
            ratchet_sessions: HashMap::new(),
            direct_v2_sessions: HashMap::new(),
            spk_secrets: HashMap::new(),
            spk_next_id: 1,
            otk_secrets: HashMap::new(),
            otk_next_id: 1,
            pending_initial_headers: HashMap::new(),
            pending_initial_sequences: HashMap::new(),
            pending_outgoing_messages: HashMap::new(),
            pending_mutations: HashMap::new(),
            dm_conversations: HashMap::new(),
            known_user_keys: HashMap::new(),
            trusted_signing_keys: HashMap::new(),
            sender_keys: SenderKeyStore::new(),
            channel_conversations: HashSet::new(),
            authorized_conversation_senders: HashMap::new(),
            device_rosters: HashMap::new(),
            membership_epoch_heads: HashMap::new(),
            last_invalidated_device_rosters: HashMap::new(),
            device_roster_rotation_pending: HashSet::new(),
            sender_key_distribution_pending: HashSet::new(),
            prepared_sender_key_generations: HashSet::new(),
            pending_sender_key_sequences: HashMap::new(),
            pending_sender_key_envelopes: HashMap::new(),
            pending_sender_key_receipts: VecDeque::new(),
            pending_sender_key_receipt_set: HashSet::new(),
            pending_sender_key_receipt_sequences: HashMap::new(),
            failed_sender_key_distributions: HashSet::new(),
            direct_live_blocked_conversations: HashSet::new(),
            direct_live_storage_uncertain: false,
            direct_live_stop: None,
            direct_ack_expiry_grace_remaining: HashMap::new(),
            #[cfg(any(test, feature = "test-utils"))]
            test_only_epoch_invalid_after_direct_commit: false,
            #[cfg(any(test, feature = "test-utils"))]
            test_only_retryable_after_direct_commit: false,
            #[cfg(any(test, feature = "test-utils"))]
            test_only_epoch_invalid_after_direct_outbox_enqueue: false,
            indexer: None,
        }
    }

    /// Create a VeilClient with a pre-existing identity (no DB).
    pub fn from_identity(identity: IdentityKeyPair) -> Self {
        let device_id = random_device_id();
        Self {
            identity: Some(identity),
            device_identity: None,
            db: None,
            connection: None,
            deferred_connection_events: DeferredConnectionEventQueueV1::default(),
            authenticated_user_id: None,
            authenticated_server_origin: None,
            device_id,
            ratchet_sessions: HashMap::new(),
            direct_v2_sessions: HashMap::new(),
            spk_secrets: HashMap::new(),
            spk_next_id: 1,
            otk_secrets: HashMap::new(),
            otk_next_id: 1,
            pending_initial_headers: HashMap::new(),
            pending_initial_sequences: HashMap::new(),
            pending_outgoing_messages: HashMap::new(),
            pending_mutations: HashMap::new(),
            dm_conversations: HashMap::new(),
            known_user_keys: HashMap::new(),
            trusted_signing_keys: HashMap::new(),
            sender_keys: SenderKeyStore::new(),
            channel_conversations: HashSet::new(),
            authorized_conversation_senders: HashMap::new(),
            device_rosters: HashMap::new(),
            membership_epoch_heads: HashMap::new(),
            last_invalidated_device_rosters: HashMap::new(),
            device_roster_rotation_pending: HashSet::new(),
            sender_key_distribution_pending: HashSet::new(),
            prepared_sender_key_generations: HashSet::new(),
            pending_sender_key_sequences: HashMap::new(),
            pending_sender_key_envelopes: HashMap::new(),
            pending_sender_key_receipts: VecDeque::new(),
            pending_sender_key_receipt_set: HashSet::new(),
            pending_sender_key_receipt_sequences: HashMap::new(),
            failed_sender_key_distributions: HashSet::new(),
            direct_live_blocked_conversations: HashSet::new(),
            direct_live_storage_uncertain: false,
            direct_live_stop: None,
            direct_ack_expiry_grace_remaining: HashMap::new(),
            #[cfg(any(test, feature = "test-utils"))]
            test_only_epoch_invalid_after_direct_commit: false,
            #[cfg(any(test, feature = "test-utils"))]
            test_only_retryable_after_direct_commit: false,
            #[cfg(any(test, feature = "test-utils"))]
            test_only_epoch_invalid_after_direct_outbox_enqueue: false,
            indexer: None,
        }
    }

    /// Attach a local search index. Subsequent message inserts/edits/deletes
    /// will be mirrored into it on a best-effort basis.
    pub fn set_indexer(&mut self, indexer: Arc<Indexer>) -> Result<(), String> {
        if self.direct_live_storage_uncertain {
            return Err("cannot attach a search index after uncertain durable storage".to_string());
        }
        let reset_pending = self
            .db
            .as_ref()
            .map(|db| db.messaging_state_reset_notice_pending_v3())
            .transpose()?
            .unwrap_or(false);
        if reset_pending {
            // The index contains derived plaintext outside SQLCipher. Never
            // expose pre-cutover search hits after the encrypted messaging
            // epoch was reset. A clear failure aborts initialization and keeps
            // the durable notice pending for a complete retry.
            indexer
                .clear()
                .map_err(|error| format!("clear pre-v0.3 search index: {error}"))?;
        }
        self.indexer = Some(indexer);
        Ok(())
    }

    /// Borrow the local search index, if attached.
    pub fn indexer(&self) -> Option<Arc<Indexer>> {
        self.indexer.clone()
    }

    /// Generate a new BIP39 mnemonic (12 words).
    /// Returns the mnemonic string for the user to back up.
    pub fn generate_mnemonic(&self) -> String {
        generate_mnemonic().to_string()
    }

    /// Validate a BIP39 mnemonic string.
    pub fn validate_mnemonic(&self, mnemonic: &str) -> bool {
        validate_mnemonic(mnemonic)
    }

    /// Initialize the client with a mnemonic.
    /// Derives identity keys and opens the encrypted local database.
    pub fn init_with_mnemonic(&mut self, mnemonic: &str, db_path: &Path) -> Result<(), String> {
        if !self.direct_live_storage_uncertain
            && (self.db.is_some()
                || self.identity.is_some()
                || self.device_identity.is_some()
                || self.connection.is_some()
                || self.authenticated_user_id.is_some()
                || self.authenticated_server_origin.is_some())
        {
            // Replacing only identity/DB material would leave the authenticated
            // transport, origin, and queued ciphertext attached to the wrong
            // account epoch. Recovery is intentionally allowed only after the
            // complete runtime has entered the sticky revoked state.
            return Err(
                "client is already initialized; revoke the active runtime before recovery"
                    .to_string(),
            );
        }
        let previous_device_id = self.device_id;
        let result = self.init_with_mnemonic_inner_v1(mnemonic, db_path);
        if result.is_err() {
            // Initialization may fail after loading some SQLCipher-backed
            // secrets and runtime routes. Never expose that partial epoch, and
            // never keep an older authenticated transport alive after a
            // failed identity/database switch. A later complete retry is the
            // only operation allowed to clear this sticky revoke.
            self.revoke_after_storage_uncertain_v1();
            self.device_id = previous_device_id;
        }
        result
    }

    fn init_with_mnemonic_inner_v1(
        &mut self,
        mnemonic: &str,
        db_path: &Path,
    ) -> Result<(), String> {
        let identity = IdentityKeyPair::from_mnemonic(mnemonic)?;

        let db_key = Zeroizing::new(kdf::derive_db_key(mnemonic)?);
        let db = VeilDb::open(db_path, &db_key)?;
        db.recover_unacknowledged_outgoing_messages()?;
        self.device_id = db.get_or_create_device_id(self.device_id)?;
        let stored_device_identity = match db.load_device_identity_v1()? {
            Some(stored) => stored,
            None => {
                // Legacy migration happens here, after the mnemonic-derived
                // SQLCipher key has unlocked the DB and the account signer is
                // resident in native Rust. Schema migration alone never
                // creates or signs device credentials.
                let generated = DeviceIdentityV1::generate_stored(&identity, self.device_id)?;
                db.create_device_identity_v1(&generated)?;
                db.load_device_identity_v1()?
                    .ok_or("device identity creation committed no durable row")?
            }
        };
        let device_identity = DeviceIdentityV1::from_stored(&identity, stored_device_identity)?;
        if device_identity.binding().device_id != self.device_id {
            return Err("device binding does not match the stable installation id".to_string());
        }

        self.zeroize_prekey_secrets();
        for mut prekey in db.load_local_prekeys()? {
            let mut secret = std::mem::take(&mut prekey.secret_key);
            let derived_public =
                X25519PublicKey::from(&X25519StaticSecret::from(secret)).to_bytes();
            if secret == [0u8; 32]
                || prekey.public_key == [0u8; 32]
                || derived_public != prekey.public_key
            {
                secret.zeroize();
                return Err(format!(
                    "local prekey {} public key differs from its secret",
                    prekey.protocol_key_id
                ));
            }
            match prekey.key_type {
                0 => {
                    let Some(signature) = prekey.signature else {
                        secret.zeroize();
                        return Err(format!(
                            "local signed prekey {} signature is unavailable",
                            prekey.protocol_key_id
                        ));
                    };
                    if !veil_crypto::signature::verify(
                        &identity.ed25519_public_bytes(),
                        &x3dh::signed_prekey_signature_message(&prekey.public_key),
                        &signature,
                    ) {
                        secret.zeroize();
                        return Err(format!(
                            "local signed prekey {} failed domain verification",
                            prekey.protocol_key_id
                        ));
                    }
                    self.spk_secrets
                        .insert(prekey.protocol_key_id, (secret, prekey.public_key));
                }
                1 => {
                    if prekey.signature.is_some() {
                        secret.zeroize();
                        return Err(format!(
                            "local one-time prekey {} unexpectedly contains a signature",
                            prekey.protocol_key_id
                        ));
                    }
                    self.otk_secrets.insert(prekey.protocol_key_id, secret);
                }
                _ => {
                    secret.zeroize();
                    return Err("invalid local prekey type".to_string());
                }
            }
            // Arrays are Copy; erase the stack copy after the map received its
            // owned value. LocalPreKey's Drop erases the (now empty) field.
            secret.zeroize();
        }
        (self.spk_next_id, self.otk_next_id) = db.synchronize_local_prekey_allocator()?;
        self.trusted_signing_keys = db.load_trusted_signing_keys()?.into_iter().collect();

        // Restore ratchet material, but never publish bare conversation UUID
        // routing before an authenticated origin directory is selected. Sync
        // rebinds only conversations accepted for the current origin.
        self.dm_conversations.clear();
        self.authorized_conversation_senders.clear();
        self.ratchet_sessions.clear();
        self.direct_v2_sessions.clear();
        self.pending_initial_headers.clear();
        self.pending_initial_sequences.clear();
        let mut decoded_ratchet_sessions = HashMap::new();
        for (peer, persisted) in db.load_all_ratchet_sessions_with_revision_v1()? {
            let session = RatchetSession::deserialize(&persisted.session_data)
                .map_err(|error| format!("decode persisted ratchet session: {error}"))?;
            if decoded_ratchet_sessions.insert(peer, session).is_some() {
                return Err("duplicate persisted ratchet peer identity key".to_string());
            }
        }
        let mut hydrated_ratchet_sessions = HashMap::new();
        for conversation in db.get_conversations()? {
            if let Some(peer) = conversation.peer_identity_key {
                let peer: [u8; 32] = peer.try_into().map_err(|peer: Vec<u8>| {
                    format!(
                        "persisted Direct conversation peer identity key has invalid length {}",
                        peer.len()
                    )
                })?;
                if let Some(session) = decoded_ratchet_sessions.get(&peer) {
                    hydrated_ratchet_sessions.insert(peer, session.clone());
                }
            }
        }
        let mut hydrated_pending_initial_headers = HashMap::new();
        for (peer, header_data) in db.load_pending_initial_headers()? {
            let header: PendingInitialHeader = serde_json::from_slice(&header_data)
                .map_err(|e| format!("decode pending X3DH header: {e}"))?;
            if header.ephemeral_public == [0u8; 32] || header.signed_prekey_id == 0 {
                return Err("invalid persisted pending X3DH header".to_string());
            }
            if let std::collections::hash_map::Entry::Vacant(entry) =
                hydrated_ratchet_sessions.entry(peer)
            {
                let session = decoded_ratchet_sessions
                    .get(&peer)
                    .cloned()
                    .ok_or("pending X3DH header has no ratchet session")?;
                entry.insert(session);
            }
            if hydrated_pending_initial_headers
                .insert(peer, header)
                .is_some()
            {
                return Err("duplicate persisted pending X3DH peer identity key".to_string());
            }
        }
        let mut hydrated_direct_v2_sessions = HashMap::new();
        for blob in db.load_all_direct_session_bindings_v2()? {
            let state = DirectSessionStateV2::from_store_blob(&blob)?;
            let local = state.local();
            if local.account.identity_key != identity.x25519_public_bytes()
                || local.account.signing_key != identity.ed25519_public_bytes()
                || local.device.device_id != device_identity.binding().device_id
                || local.device.binding_version != device_identity.binding().version
                || local.device.capabilities != device_identity.binding().capabilities
                || local.device.status != device_identity.binding().status
                || local.device.identity_key != device_identity.binding().device_identity_key
                || local.device.signing_key != device_identity.binding().device_signing_key
                || local.device.account_signature != device_identity.binding().account_signature
            {
                return Err(
                    "persisted Direct v2 binding does not belong to this account/device"
                        .to_string(),
                );
            }
            if !hydrated_ratchet_sessions.contains_key(&blob.peer_identity_key) {
                return Err(
                    "persisted Direct v2 binding has no authorized conversation ratchet"
                        .to_string(),
                );
            }
            if hydrated_direct_v2_sessions
                .insert(blob.peer_identity_key, state)
                .is_some()
            {
                return Err("duplicate persisted Direct v2 peer binding".to_string());
            }
        }
        self.ratchet_sessions = hydrated_ratchet_sessions;
        self.direct_v2_sessions = hydrated_direct_v2_sessions;
        self.pending_initial_headers = hydrated_pending_initial_headers;

        self.device_identity = Some(device_identity);
        self.identity = Some(identity);
        self.db = Some(db);
        self.direct_live_blocked_conversations.clear();
        self.direct_live_storage_uncertain = false;
        self.direct_live_stop = None;
        self.direct_ack_expiry_grace_remaining.clear();
        Ok(())
    }

    /// Get a reference to the DB (if open).
    pub fn db(&self) -> Option<&VeilDb> {
        self.db.as_ref()
    }

    /// Get a mutable reference to the DB (if open) — needed for transactions.
    pub fn db_mut(&mut self) -> Option<&mut VeilDb> {
        self.db.as_mut()
    }

    /// Get our X25519 public key (identity).
    pub fn identity_key(&self) -> Result<[u8; 32], String> {
        self.identity
            .as_ref()
            .map(|id| id.x25519_public_bytes())
            .ok_or("not initialized".to_string())
    }

    /// Get our Ed25519 public key (signing).
    pub fn signing_key(&self) -> Result<[u8; 32], String> {
        self.identity
            .as_ref()
            .map(|id| id.ed25519_public_bytes())
            .ok_or("not initialized".to_string())
    }

    /// Authenticated server UUID, available only after WebSocket auth succeeds.
    pub fn authenticated_user_id(&self) -> Result<String, String> {
        self.authenticated_user_id
            .clone()
            .ok_or_else(|| "not authenticated".to_string())
    }

    pub(crate) fn authenticated_server_origin_v1(&self) -> Result<String, String> {
        self.authenticated_server_origin
            .clone()
            .ok_or_else(|| "not authenticated to a canonical server origin".to_string())
    }

    /// Last SQLCipher-pinned transparency head size for the current origin.
    /// Zero means no first-contact head has been accepted yet.
    pub fn identity_transparency_request_from_size_v1(&self) -> Result<u64, String> {
        let origin = self.authenticated_server_origin_v1()?;
        crate::transparency::identity_transparency_request_from_size_v1(
            self.db.as_ref().ok_or("database not initialized")?,
            &origin,
        )
    }

    /// Cloned signing material for the background events controller.
    /// Never exposed over FFI; consumed inside this process only.
    pub fn background_events_v3_material(
        &self,
    ) -> Result<
        (
            veil_crypto::IdentityKeyPair,
            crate::device_identity::DeviceIdentityV1,
        ),
        String,
    > {
        if self.connection.is_some()
            || self.authenticated_user_id.is_some()
            || self.authenticated_server_origin.is_some()
        {
            return Err(
                "background events cannot start while a primary authenticated transport is active"
                    .to_string(),
            );
        }
        let account = self
            .identity
            .as_ref()
            .map(|k| k.clone_for_background())
            .ok_or_else(|| "not initialized".to_string())?;
        let device = self
            .device_identity
            .as_ref()
            .map(|d| d.clone_for_background())
            .ok_or_else(|| "not initialized".to_string())?;
        Ok((account, device))
    }

    /// Bind an authenticated background session to the exact durable mobile
    /// reconnect selection. This does not install a command transport and can
    /// never run alongside the primary Connection.
    pub fn activate_background_events_v3_binding(
        &mut self,
        canonical_server_origin: &str,
        user_id: &str,
    ) -> Result<(), String> {
        self.require_crypto_runtime_active_v1()?;
        if self.connection.is_some()
            || self.authenticated_user_id.is_some()
            || self.authenticated_server_origin.is_some()
        {
            return Err("another authenticated transport is already active".to_string());
        }
        let identity_key = self.identity_key()?;
        let signing_key = self.signing_key()?;
        let target = self
            .db
            .as_ref()
            .ok_or("database not initialized")?
            .load_mobile_reconnect_target_v1(&identity_key, &signing_key)?
            .ok_or("durable mobile reconnect target is absent")?;
        if target.canonical_server_origin != canonical_server_origin
            || target.expected_user_id != user_id
        {
            return Err(
                "background authentication changed its durable account binding".to_string(),
            );
        }
        self.reconcile_previous_transport_before_install_v1()?;
        self.deferred_connection_events.reset_for_new_epoch();
        self.direct_live_stop = None;
        self.direct_ack_expiry_grace_remaining.clear();
        self.authenticated_server_origin = Some(canonical_server_origin.to_string());
        self.authenticated_user_id = Some(user_id.to_string());
        Ok(())
    }

    /// Clear only the exact background binding; a concurrently installed
    /// primary Connection always wins and is never revoked by a stale task.
    pub fn deactivate_background_events_v3_binding(
        &mut self,
        canonical_server_origin: &str,
        user_id: &str,
    ) {
        if self.connection.is_none()
            && self.authenticated_server_origin.as_deref() == Some(canonical_server_origin)
            && self.authenticated_user_id.as_deref() == Some(user_id)
        {
            self.authenticated_server_origin = None;
            self.authenticated_user_id = None;
            self.deferred_connection_events.close_epoch();
            self.direct_ack_expiry_grace_remaining.clear();
        }
    }

    /// Feed one background ConnectionEvent into the same bounded deferred FIFO
    /// consumed by replay_direct_live_events_v1. Decrypt, ratchet advancement
    /// and persistence remain exclusive to the turn-based pump.
    pub fn ingest_background_connection_event_v1(
        &mut self,
        event: crate::connection::ConnectionEvent,
    ) -> Result<(), String> {
        if self.connection.is_some()
            || self.authenticated_user_id.is_none()
            || self.authenticated_server_origin.is_none()
        {
            return Err("background event arrived outside its authenticated epoch".to_string());
        }
        let budget = crate::connection::ConnectionEventBudgetV1::production();
        let budgeted = budget
            .try_wrap(event)
            .map_err(|error| format!("budget wrap failed: {:?}", error))?;
        self.deferred_connection_events
            .try_extend(vec![budgeted])
            .map_err(|error| format!("buffer event failed: {:?}", error))?;
        Ok(())
    }

    /// Test-only bridge for native integration fixtures that cannot perform a
    /// real WebSocket handshake. The feature is disabled in production.
    /// Durable origin/user/account continuity is checked before process state
    /// is changed; failure leaves `authenticated_user_id` untouched.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only_restore_authenticated_user_from_durable_binding(
        &mut self,
        canonical_server_origin: &str,
        user_id: &str,
    ) -> Result<(), String> {
        let identity_key = self.identity_key()?;
        let signing_key = self.signing_key()?;
        self.db
            .as_ref()
            .ok_or("database not initialized")?
            .bind_authenticated_self(
                canonical_server_origin,
                user_id,
                &identity_key,
                &signing_key,
            )?;
        self.authenticated_user_id = Some(user_id.to_string());
        self.authenticated_server_origin = Some(canonical_server_origin.to_string());
        Ok(())
    }

    /// Stable device key sent during WebSocket auth and used by the prekey API.
    pub fn device_id(&self) -> [u8; 16] {
        self.device_id
    }

    pub fn current_device_binding_version_v1(&self) -> Option<u64> {
        self.device_identity
            .as_ref()
            .map(|device| device.binding().version)
    }

    fn prepare_device_roster_v1(
        &self,
        candidate: &DeviceRosterCandidateV1,
    ) -> Result<PreparedDeviceRosterV1, String> {
        const LEGACY_UNBOUND_STATUS: u8 = 4;
        if !candidate.ready || !candidate.membership_ready {
            return Err("device roster is not ready for encrypted traffic".to_string());
        }
        match candidate.membership_activated {
            #[cfg(any(test, feature = "test-utils"))]
            false
                if candidate.crypto_profile == "sender_key_v5"
                    && candidate.membership_epoch == 0
                    && candidate.membership_epoch_hash == [0u8; 32] => {}
            true if candidate.crypto_profile == "sender_key_v6"
                && candidate.membership_epoch > 0
                && candidate.membership_epoch <= i64::MAX as u64
                && candidate.membership_epoch_hash != [0u8; 32] => {}
            _ => return Err("device roster membership profile is invalid".to_string()),
        }
        if candidate.roster_version == 0 || candidate.roster_version > i64::MAX as u64 {
            return Err("invalid device roster version".to_string());
        }
        if candidate.required_capabilities != REQUIRED_DEVICE_CAPABILITIES {
            return Err("device roster uses an unsupported capability suite".to_string());
        }
        let conversation_uuid = uuid::Uuid::parse_str(&candidate.conversation_id)
            .map_err(|_| "device roster conversation id is not a UUID".to_string())?;
        if conversation_uuid.hyphenated().to_string() != candidate.conversation_id {
            return Err("device roster conversation id is not canonical".to_string());
        }
        if candidate.member_user_ids.is_empty() || candidate.member_user_ids.len() > 100_000 {
            return Err("invalid device roster member count".to_string());
        }
        if candidate.devices.len() > 200_000 {
            return Err("device roster contains too many devices".to_string());
        }

        let member_set: HashSet<[u8; 16]> = candidate.member_user_ids.iter().copied().collect();
        if member_set.len() != candidate.member_user_ids.len() || member_set.contains(&[0u8; 16]) {
            return Err("device roster contains an invalid or duplicate member".to_string());
        }
        let mut grouped: BTreeMap<[u8; 16], Vec<&DeviceRosterEntryV1>> = member_set
            .iter()
            .copied()
            .map(|member| (member, Vec::new()))
            .collect();
        let mut unique_devices = HashSet::new();
        let mut account_keys = BTreeMap::new();
        let mut account_identity_owners = HashMap::new();
        let mut account_signing_owners = HashMap::new();
        for entry in &candidate.devices {
            let devices = grouped
                .get_mut(&entry.user_id)
                .ok_or("device roster contains a device for a non-member")?;
            if entry.device_id == [0u8; 16] || !unique_devices.insert(entry.device_id) {
                return Err("device roster contains an invalid or duplicate device id".to_string());
            }
            if entry.account_identity_key == [0u8; 32] || entry.account_signing_key == [0u8; 32] {
                return Err("device roster contains an invalid account key".to_string());
            }
            if account_identity_owners
                .insert(entry.account_identity_key, entry.user_id)
                .is_some_and(|owner| owner != entry.user_id)
                || account_signing_owners
                    .insert(entry.account_signing_key, entry.user_id)
                    .is_some_and(|owner| owner != entry.user_id)
            {
                return Err("device roster reuses an account key across members".to_string());
            }
            match account_keys.entry(entry.user_id) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert((entry.account_identity_key, entry.account_signing_key));
                }
                std::collections::btree_map::Entry::Occupied(slot)
                    if slot.get() != &(entry.account_identity_key, entry.account_signing_key) =>
                {
                    return Err("device roster changed account keys within one member".to_string());
                }
                _ => {}
            }
            devices.push(entry);
        }
        let mut unique_public_keys = HashSet::new();
        for (account_identity_key, account_signing_key) in account_keys.values() {
            if account_identity_key == account_signing_key
                || !unique_public_keys.insert(*account_identity_key)
                || !unique_public_keys.insert(*account_signing_key)
            {
                return Err("device roster reuses a key across cryptographic domains".to_string());
            }
        }

        let mut canonical = Vec::with_capacity(
            DEVICE_ROSTER_COMMITMENT_DOMAIN.len() + 16 + 8 + 4 + candidate.devices.len() * 193,
        );
        canonical.extend_from_slice(DEVICE_ROSTER_COMMITMENT_DOMAIN);
        canonical.extend_from_slice(conversation_uuid.as_bytes());
        canonical.extend_from_slice(&candidate.required_capabilities.to_be_bytes());
        canonical.extend_from_slice(&(grouped.len() as u32).to_be_bytes());

        let mut targets = Vec::new();
        let mut eligible_devices = HashMap::new();
        let mut bindings = Vec::new();
        let mut current_device = None;
        let local = self
            .device_identity
            .as_ref()
            .ok_or("per-device identity is not initialized")?;
        let local_binding = local.binding();
        let local_account_identity = self.identity_key()?;
        let local_account_signing = self.signing_key()?;
        let local_user_id_text = self.authenticated_user_id.as_deref().ok_or_else(|| {
            "device roster cannot be installed before authenticated user binding".to_string()
        })?;
        let local_user_uuid = uuid::Uuid::parse_str(local_user_id_text)
            .map_err(|_| "authenticated user id is not a UUID".to_string())?;
        if local_user_uuid.hyphenated().to_string() != local_user_id_text {
            return Err("authenticated user id is not canonical".to_string());
        }
        let local_user_id = *local_user_uuid.as_bytes();

        for (member_id, devices) in &mut grouped {
            canonical.extend_from_slice(member_id);
            devices.sort_by_key(|entry| entry.device_id);
            canonical.extend_from_slice(&(devices.len() as u32).to_be_bytes());
            let mut eligible_count = 0usize;
            for entry in devices.iter() {
                canonical.extend_from_slice(&entry.device_id);
                let Some(binding) = entry.binding.as_ref() else {
                    canonical.push(LEGACY_UNBOUND_STATUS);
                    canonical.extend_from_slice(&0u64.to_be_bytes());
                    canonical.extend_from_slice(&0u64.to_be_bytes());
                    canonical.extend_from_slice(&[0u8; 32]);
                    canonical.extend_from_slice(&[0u8; 32]);
                    canonical.extend_from_slice(&[0u8; 64]);
                    return Err("ready device roster contains a legacy unbound device".to_string());
                };
                if binding.device_id != entry.device_id
                    || binding.version == 0
                    || binding.version > i64::MAX as u64
                    || binding.capabilities > i64::MAX as u64
                    || !(1..=3).contains(&binding.status)
                    || binding.device_identity_key == [0u8; 32]
                    || binding.device_signing_key == [0u8; 32]
                    || binding.device_identity_key == entry.account_identity_key
                    || binding.device_signing_key == entry.account_signing_key
                    || !unique_public_keys.insert(binding.device_identity_key)
                    || !unique_public_keys.insert(binding.device_signing_key)
                {
                    return Err("device roster contains an invalid device binding".to_string());
                }
                let signing_bytes = device_binding_signing_bytes(
                    &entry.account_identity_key,
                    &entry.account_signing_key,
                    &entry.device_id,
                    binding.version,
                    &binding.device_identity_key,
                    &binding.device_signing_key,
                    binding.capabilities,
                    binding.status,
                );
                if !veil_crypto::signature::verify(
                    &entry.account_signing_key,
                    &signing_bytes,
                    &binding.account_signature,
                ) {
                    return Err("device binding account signature is invalid".to_string());
                }

                canonical.push(binding.status);
                canonical.extend_from_slice(&binding.version.to_be_bytes());
                canonical.extend_from_slice(&binding.capabilities.to_be_bytes());
                canonical.extend_from_slice(&binding.device_identity_key);
                canonical.extend_from_slice(&binding.device_signing_key);
                canonical.extend_from_slice(&binding.account_signature);
                bindings.push(DeviceBindingPinV1 {
                    device_id: entry.device_id,
                    account_identity_key: entry.account_identity_key,
                    account_signing_key: entry.account_signing_key,
                    device_identity_key: binding.device_identity_key,
                    device_signing_key: binding.device_signing_key,
                    binding_version: binding.version,
                    capabilities: binding.capabilities,
                    status: binding.status,
                    account_signature: binding.account_signature,
                });

                if binding.status == DEVICE_BINDING_STATUS_ACTIVE {
                    if binding.capabilities & candidate.required_capabilities
                        != candidate.required_capabilities
                    {
                        return Err(
                            "ready device roster contains an active device without required capabilities"
                                .to_string(),
                        );
                    }
                    if candidate.membership_activated
                        && binding.capabilities & DEVICE_CAPABILITY_MEMBERSHIP_EPOCH_V1 == 0
                    {
                        return Err(
                            "membership epoch roster contains a device without v6 support"
                                .to_string(),
                        );
                    }
                    eligible_count += 1;
                    let target = DeviceTargetV1 {
                        conversation_id: candidate.conversation_id.clone(),
                        user_id: *member_id,
                        account_identity_key: entry.account_identity_key,
                        account_signing_key: entry.account_signing_key,
                        device_id: entry.device_id,
                        device_identity_key: binding.device_identity_key,
                        device_signing_key: binding.device_signing_key,
                        binding_version: binding.version,
                        capabilities: binding.capabilities,
                        account_signature: binding.account_signature,
                        roster_version: candidate.roster_version,
                        roster_commitment: candidate.roster_commitment,
                    };
                    if target.device_id == self.device_id {
                        if target.device_identity_key != local_binding.device_identity_key
                            || target.device_signing_key != local_binding.device_signing_key
                            || target.binding_version != local_binding.version
                            || target.capabilities != local_binding.capabilities
                            || target.account_signature != local_binding.account_signature
                            || target.account_identity_key != local_account_identity
                            || entry.account_signing_key != local_account_signing
                            || target.user_id != local_user_id
                        {
                            return Err(
                                "current device roster binding does not match local private identity"
                                    .to_string(),
                            );
                        }
                        current_device = Some(target.clone());
                    } else {
                        targets.push(target.clone());
                    }
                    eligible_devices.insert(target.device_id, target);
                }
            }
            if eligible_count == 0 {
                return Err("ready device roster member has no eligible active device".to_string());
            }
        }
        if account_keys.len() != grouped.len() {
            return Err("ready device roster member has no device/account binding".to_string());
        }
        let _current_device = current_device
            .ok_or("ready device roster does not contain the current authenticated device")?;
        let computed: [u8; 32] = Sha256::digest(&canonical).into();
        if !bool::from(computed.ct_eq(&candidate.roster_commitment)) {
            return Err("device roster commitment does not match canonical contents".to_string());
        }
        targets.sort_by_key(|target| target.device_id);
        bindings.sort_by_key(|binding| binding.device_id);
        Ok(PreparedDeviceRosterV1 {
            validated: ValidatedDeviceRosterV1 {
                version: candidate.roster_version,
                commitment: candidate.roster_commitment,
                required_capabilities: candidate.required_capabilities,
                authorized_account_identities: candidate
                    .devices
                    .iter()
                    .map(|entry| entry.account_identity_key)
                    .collect(),
                targets,
                eligible_devices,
                account_signing_keys: account_keys
                    .iter()
                    .map(|(account_id, (_, signing_key))| (*account_id, *signing_key))
                    .collect(),
                membership_activated: candidate.membership_activated,
                membership_epoch: candidate.membership_epoch,
                membership_epoch_hash: candidate.membership_epoch_hash,
            },
            bindings,
            canonical_snapshot: canonical,
        })
    }

    /// Validate a signed-directory device roster, pin its monotonic history,
    /// and rotate to a device-owned Sender-Key generation when the snapshot
    /// changes. Any invalid/not-ready candidate invalidates the old runtime
    /// proof before returning an error.
    pub fn install_device_roster_v1(
        &mut self,
        candidate: DeviceRosterCandidateV1,
    ) -> Result<bool, String> {
        self.require_direct_conversation_available_v1(&candidate.conversation_id)?;
        let conversation_id = candidate.conversation_id.clone();
        let previous = self
            .device_rosters
            .get(&conversation_id)
            .map(|roster| (roster.version, roster.commitment))
            .or_else(|| {
                self.last_invalidated_device_rosters
                    .get(&conversation_id)
                    .copied()
            });
        let fresh_generation_already_prepared = self
            .prepared_sender_key_generations
            .contains(&conversation_id);
        self.invalidate_device_roster_v1(&conversation_id);
        let prepared = self.prepare_device_roster_v1(&candidate)?;
        if let Some(db) = self.db.as_ref() {
            if let Some(pinned) = db.load_membership_epoch_head_v1(&conversation_id)? {
                if !prepared.validated.membership_activated
                    || prepared.validated.membership_epoch < pinned.epoch
                    || prepared.validated.membership_epoch == pinned.epoch
                        && prepared.validated.membership_epoch_hash != pinned.epoch_hash
                {
                    return Err("membership epoch downgrade or equivocation rejected".to_string());
                }
            }
        }
        if let Some(db) = self.db.as_ref() {
            db.commit_device_roster_snapshot_v1(&DeviceRosterSnapshotV1 {
                conversation_id: &conversation_id,
                roster_version: prepared.validated.version,
                roster_commitment: prepared.validated.commitment,
                required_capabilities: prepared.validated.required_capabilities,
                canonical_snapshot: &prepared.canonical_snapshot,
                bindings: &prepared.bindings,
            })?;
        }
        let changed = previous.is_none_or(|old| {
            old.0 != prepared.validated.version || old.1 != prepared.validated.commitment
        });
        let no_targets = prepared.validated.targets.is_empty();
        let local_owner = self
            .device_identity
            .as_ref()
            .ok_or("per-device identity is not initialized")?
            .binding()
            .device_identity_key;
        let single_device_generation_stale = no_targets
            && (self.sender_keys.needs_rotation(&conversation_id)
                || self
                    .sender_keys
                    .outgoing_owner_identity_key(&conversation_id)
                    != Some(local_owner));
        // A fresh cold-restored generation has never been distributed in this
        // process and can be bound to the first authenticated roster. Once an
        // earlier runtime roster is known, however, any changed commitment
        // must rotate even if an unrelated generation is already pending.
        let reusable_cold_generation = previous.is_none() && fresh_generation_already_prepared;
        if (changed
            || !self.sender_keys.has_outgoing(&conversation_id)
            || single_device_generation_stale)
            && (!reusable_cold_generation || single_device_generation_stale)
        {
            self.rotate_sender_key(&conversation_id)?;
        } else {
            self.device_roster_rotation_pending.remove(&conversation_id);
        }
        self.authorized_conversation_senders.insert(
            conversation_id.clone(),
            prepared.validated.authorized_account_identities.clone(),
        );
        self.device_rosters
            .insert(conversation_id.clone(), prepared.validated);
        self.last_invalidated_device_rosters
            .remove(&conversation_id);
        if no_targets {
            self.sender_key_distribution_pending
                .remove(&conversation_id);
            self.prepared_sender_key_generations
                .remove(&conversation_id);
        }
        Ok(changed)
    }

    /// Verify the complete client-authorized membership chain, bind it to the
    /// exact already-validated device roster, and pin every predecessor in
    /// SQLCipher before Sender-Key v6 traffic can be produced.
    fn require_live_membership_context_v1(
        &self,
        conversation_id: &str,
        roster: &ValidatedDeviceRosterV1,
        membership_epoch: u64,
        membership_epoch_hash: &[u8; 32],
    ) -> Result<(), String> {
        if !roster.membership_activated {
            if membership_epoch == 0 && membership_epoch_hash == &[0u8; 32] {
                return Ok(());
            }
            return Err("legacy group carried an unexpected membership epoch".to_string());
        }
        let head = self
            .membership_epoch_heads
            .get(conversation_id)
            .ok_or("verified membership epoch is unavailable")?;
        if membership_epoch == 0
            || membership_epoch != roster.membership_epoch
            || membership_epoch_hash != &roster.membership_epoch_hash
            || head.epoch != membership_epoch
            || &head.hash != membership_epoch_hash
            || head.roster_version != roster.version
            || head.roster_commitment != roster.commitment
        {
            return Err("membership epoch does not match the verified roster head".to_string());
        }
        Ok(())
    }

    fn prepare_membership_epoch_signature_v1(
        &self,
        epoch: MembershipEpochV1,
        signer_account_id: [u8; 16],
    ) -> Result<PreparedMembershipEpochV1, String> {
        let local_user_id = self
            .authenticated_user_id
            .as_deref()
            .ok_or("membership signing requires an authenticated account")?;
        let local_user_id = uuid::Uuid::parse_str(local_user_id)
            .map_err(|_| "authenticated membership signer id is invalid".to_string())?;
        if *local_user_id.as_bytes() != signer_account_id {
            return Err("membership signer is not the authenticated account".to_string());
        }
        let message = epoch.signature_message()?;
        let signature = veil_crypto::signature::sign(
            self.identity
                .as_ref()
                .ok_or("identity is not initialized")?,
            &message,
        );
        Ok(PreparedMembershipEpochV1 {
            epoch_hash: epoch.hash()?,
            epoch,
            signatures: vec![MembershipEpochSignatureV1 {
                signer_account_id,
                signature,
            }],
        })
    }

    pub fn prepare_membership_epoch_bootstrap_v1(
        &self,
        conversation_id: &str,
        conversation_kind: u8,
        roster_version: u64,
        roster_commitment: [u8; 32],
        owner: MembershipPolicySignerV1,
    ) -> Result<PreparedMembershipEpochV1, String> {
        let canonical_origin = self.authenticated_server_origin_v1()?;
        let conversation_uuid = uuid::Uuid::parse_str(conversation_id)
            .map_err(|_| "membership conversation id is invalid".to_string())?;
        if conversation_uuid.hyphenated().to_string() != conversation_id {
            return Err("membership conversation id is not canonical".to_string());
        }
        let mut mutation_nonce = [0u8; 32];
        while mutation_nonce == [0u8; 32] {
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut mutation_nonce);
        }
        let epoch = MembershipEpochV1 {
            canonical_origin,
            conversation_id: *conversation_uuid.as_bytes(),
            conversation_kind,
            epoch: 1,
            predecessor_hash: [0u8; 32],
            roster_version,
            roster_commitment,
            successor_policy: MembershipPolicyV1 {
                threshold: 1,
                signers: vec![owner],
            },
            crypto_profile: MEMBERSHIP_CRYPTO_PROFILE_SENDER_KEY_V6,
            crypto_era: MEMBERSHIP_CRYPTO_ERA_V1,
            mutation_nonce,
        };
        let prepared = self.prepare_membership_epoch_signature_v1(epoch, owner.account_id)?;
        verify_membership_epoch_bootstrap_v1(&prepared.epoch, &owner, &prepared.signatures)?;
        Ok(prepared)
    }

    pub fn prepare_membership_epoch_transition_v1(
        &self,
        predecessor: &MembershipEpochV1,
        roster_version: u64,
        roster_commitment: [u8; 32],
    ) -> Result<PreparedMembershipEpochV1, String> {
        let canonical_origin = self.authenticated_server_origin_v1()?;
        if predecessor.canonical_origin != canonical_origin
            || predecessor.successor_policy.threshold != 1
        {
            return Err(
                "membership transition requires the supported single-owner policy".to_string(),
            );
        }
        let local_user_id = self
            .authenticated_user_id
            .as_deref()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .map(|value| *value.as_bytes())
            .ok_or("authenticated membership signer id is invalid")?;
        let local_signer = predecessor
            .successor_policy
            .signers
            .iter()
            .find(|signer| signer.account_id == local_user_id)
            .copied()
            .ok_or("authenticated account cannot authorize the next membership epoch")?;
        if local_signer.account_signing_key != self.signing_key()? {
            return Err(
                "membership predecessor policy substituted the local signing key".to_string(),
            );
        }
        let mut mutation_nonce = [0u8; 32];
        while mutation_nonce == [0u8; 32] {
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut mutation_nonce);
        }
        let epoch = MembershipEpochV1 {
            canonical_origin,
            conversation_id: predecessor.conversation_id,
            conversation_kind: predecessor.conversation_kind,
            epoch: predecessor
                .epoch
                .checked_add(1)
                .ok_or("membership epoch number is exhausted")?,
            predecessor_hash: predecessor.hash()?,
            roster_version,
            roster_commitment,
            successor_policy: predecessor.successor_policy.clone(),
            crypto_profile: MEMBERSHIP_CRYPTO_PROFILE_SENDER_KEY_V6,
            crypto_era: MEMBERSHIP_CRYPTO_ERA_V1,
            mutation_nonce,
        };
        let prepared = self.prepare_membership_epoch_signature_v1(epoch, local_user_id)?;
        verify_membership_epoch_transition_v1(predecessor, &prepared.epoch, &prepared.signatures)?;
        Ok(prepared)
    }

    pub fn install_membership_epoch_chain_v1(
        &mut self,
        candidate: MembershipEpochChainCandidateV1,
    ) -> Result<bool, String> {
        const MAX_EPOCHS: usize = 100_000;
        self.require_direct_conversation_available_v1(&candidate.conversation_id)?;
        let authenticated_origin = self
            .authenticated_server_origin
            .as_deref()
            .ok_or("membership epochs require an authenticated server origin")?;
        if candidate.canonical_origin != authenticated_origin
            || candidate.records.is_empty()
            || candidate.records.len() > MAX_EPOCHS
            || candidate.head_epoch == 0
            || candidate.head_hash == [0u8; 32]
        {
            return Err("membership epoch chain scope is invalid".to_string());
        }
        let conversation_uuid = uuid::Uuid::parse_str(&candidate.conversation_id)
            .map_err(|_| "membership conversation id is invalid".to_string())?;
        if conversation_uuid.hyphenated().to_string() != candidate.conversation_id {
            return Err("membership conversation id is not canonical".to_string());
        }
        let roster = self
            .device_rosters
            .get(&candidate.conversation_id)
            .ok_or("validated device roster is unavailable for membership verification")?;
        if !roster.membership_activated
            || !self
                .channel_conversations
                .contains(&candidate.conversation_id)
        {
            return Err("conversation has not activated membership epochs".to_string());
        }

        let durable_head = self
            .db
            .as_ref()
            .ok_or("SQLCipher database is unavailable")?
            .load_membership_epoch_head_v1(&candidate.conversation_id)?;
        let mut pins = Vec::with_capacity(candidate.records.len());
        let mut predecessor: Option<&MembershipEpochV1> = None;
        for (index, record) in candidate.records.iter().enumerate() {
            let expected_number = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or("membership epoch number overflow")?;
            if record.epoch.canonical_origin != candidate.canonical_origin
                || record.epoch.conversation_id != *conversation_uuid.as_bytes()
                || record.epoch.epoch != expected_number
                || record.epoch.hash()? != record.epoch_hash
            {
                return Err("membership epoch chain is not canonical".to_string());
            }
            match predecessor {
                None => {
                    let owner = record
                        .bootstrap_owner
                        .as_ref()
                        .ok_or("membership bootstrap owner is missing")?;
                    if durable_head.is_none()
                        && roster.account_signing_keys.get(&owner.account_id)
                            != Some(&owner.account_signing_key)
                    {
                        return Err(
                            "membership bootstrap owner is not independently pinned".to_string()
                        );
                    }
                    verify_membership_epoch_bootstrap_v1(&record.epoch, owner, &record.signatures)?;
                }
                Some(previous) => {
                    if record.bootstrap_owner.is_some() {
                        return Err("membership transition repeats bootstrap authority".to_string());
                    }
                    verify_membership_epoch_transition_v1(
                        previous,
                        &record.epoch,
                        &record.signatures,
                    )?;
                }
            }
            pins.push(MembershipEpochPinV1 {
                conversation_id: candidate.conversation_id.clone(),
                epoch: record.epoch.epoch,
                epoch_hash: record.epoch_hash,
                predecessor_hash: record.epoch.predecessor_hash,
                roster_version: record.epoch.roster_version,
                roster_commitment: record.epoch.roster_commitment,
                canonical_unsigned: record.epoch.canonical_unsigned_bytes()?,
                bootstrap_owner_id: record
                    .bootstrap_owner
                    .as_ref()
                    .map(|owner| owner.account_id),
                bootstrap_owner_signing_key: record
                    .bootstrap_owner
                    .as_ref()
                    .map(|owner| owner.account_signing_key),
            });
            predecessor = Some(&record.epoch);
        }
        let last = candidate
            .records
            .last()
            .ok_or("membership epoch head is missing")?;
        if last.epoch.epoch != candidate.head_epoch
            || last.epoch_hash != candidate.head_hash
            || candidate.head_epoch != roster.membership_epoch
            || candidate.head_hash != roster.membership_epoch_hash
            || last.epoch.roster_version != roster.version
            || last.epoch.roster_commitment != roster.commitment
        {
            return Err("membership epoch head does not authorize the current roster".to_string());
        }
        let pinned = self
            .db
            .as_ref()
            .ok_or("SQLCipher database is unavailable")?
            .commit_membership_epoch_chain_v1(&pins)?;
        if pinned.epoch != candidate.head_epoch
            || pinned.epoch_hash != candidate.head_hash
            || pinned.roster_version != roster.version
            || pinned.roster_commitment != roster.commitment
        {
            return Err("persisted membership epoch head changed".to_string());
        }
        let had_runtime_head = self
            .membership_epoch_heads
            .contains_key(&candidate.conversation_id);
        let changed = self
            .membership_epoch_heads
            .get(&candidate.conversation_id)
            .is_none_or(|head| {
                head.epoch != candidate.head_epoch || head.hash != candidate.head_hash
            });
        self.membership_epoch_heads.insert(
            candidate.conversation_id.clone(),
            ValidatedMembershipEpochHeadV1 {
                epoch: candidate.head_epoch,
                hash: candidate.head_hash,
                roster_version: roster.version,
                roster_commitment: roster.commitment,
            },
        );
        // First activation and every in-process epoch transition must never
        // reuse a generation prepared under the prior (possibly legacy v5)
        // authorization context. During restart, a durable head plus the
        // hydrate path's already-fresh generation avoids a second rotation.
        if changed
            && (durable_head.is_none()
                || had_runtime_head
                || !self
                    .prepared_sender_key_generations
                    .contains(&candidate.conversation_id))
        {
            self.rotate_sender_key(&candidate.conversation_id)?;
        }
        Ok(changed)
    }

    pub fn invalidate_device_roster_v1(&mut self, conversation_id: &str) {
        if self.direct_live_storage_uncertain
            || self
                .direct_live_blocked_conversations
                .contains(conversation_id)
        {
            return;
        }
        if let Some(roster) = self.device_rosters.remove(conversation_id) {
            self.last_invalidated_device_rosters.insert(
                conversation_id.to_string(),
                (roster.version, roster.commitment),
            );
        }
        self.authorized_conversation_senders.remove(conversation_id);
        self.device_roster_rotation_pending
            .insert(conversation_id.to_string());
        self.sender_key_distribution_pending
            .insert(conversation_id.to_string());
    }

    pub fn clear_device_rosters_v1(&mut self) {
        let conversations: Vec<String> = self.device_rosters.keys().cloned().collect();
        for conversation_id in conversations {
            self.invalidate_device_roster_v1(&conversation_id);
        }
    }

    pub fn sender_key_device_targets(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<DeviceTargetV1>, String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        self.device_rosters
            .get(conversation_id)
            .map(|roster| roster.targets.clone())
            .ok_or("validated current device roster is unavailable".to_string())
    }

    /// Remember a server user ID to identity-key binding obtained from a signed
    /// directory response. This is deliberately not populated from UI input.
    pub fn remember_user_identity(
        &mut self,
        user_id: &str,
        identity_key: [u8; 32],
    ) -> Result<(), String> {
        self.require_crypto_runtime_active_v1()?;
        self.ensure_user_identity_binding_compatible(user_id, identity_key)?;
        self.known_user_keys
            .entry(user_id.to_string())
            .or_insert(identity_key);
        Ok(())
    }

    /// Validate a server-scoped user lookup without publishing it. Native
    /// directory ingestion uses this for an all-or-nothing runtime preflight.
    pub fn ensure_user_identity_binding_compatible(
        &self,
        user_id: &str,
        identity_key: [u8; 32],
    ) -> Result<(), String> {
        if user_id.is_empty() {
            return Err("user identity binding requires a non-empty user id".to_string());
        }
        if identity_key == [0u8; 32] {
            return Err("user identity binding rejects an all-zero identity key".to_string());
        }
        if self
            .known_user_keys
            .get(user_id)
            .is_some_and(|stored| stored != &identity_key)
        {
            return Err(
                "authenticated directory changed the identity key for a known user".to_string(),
            );
        }
        Ok(())
    }

    /// Clear server-scoped user-ID bindings before authenticating a different
    /// origin/session. Cryptographic identity-to-signing-key continuity pins
    /// are intentionally retained and managed separately.
    pub fn clear_known_user_identities(&mut self) {
        self.known_user_keys.clear();
    }

    /// Clear bare conversation UUID routing before selecting another server
    /// origin. Durable ratchets and Sender-Key material remain encrypted at
    /// rest, but cannot be addressed until the current authenticated directory
    /// republishes an origin-accepted conversation.
    pub fn clear_server_scoped_conversation_routing(&mut self) {
        self.dm_conversations.clear();
        self.channel_conversations.clear();
    }

    pub fn known_user_identity(&self, user_id: &str) -> Option<[u8; 32]> {
        self.known_user_keys.get(user_id).copied()
    }

    pub fn pin_peer_signing_key(
        &mut self,
        identity_key: [u8; 32],
        signing_key: [u8; 32],
    ) -> Result<(), String> {
        self.require_crypto_runtime_active_v1()?;
        self.ensure_peer_signing_key_compatible(identity_key, signing_key)?;
        if let Some(existing) = self.trusted_signing_keys.get(&identity_key) {
            debug_assert_eq!(existing, &signing_key);
            return Ok(());
        }
        if let Some(db) = self.db.as_ref() {
            db.pin_trusted_signing_key(&identity_key, &signing_key)?;
        }
        self.trusted_signing_keys.insert(identity_key, signing_key);
        Ok(())
    }

    /// Validate an identity-to-signing-key continuity pin without changing
    /// durable or runtime trust state.
    pub fn ensure_peer_signing_key_compatible(
        &self,
        identity_key: [u8; 32],
        signing_key: [u8; 32],
    ) -> Result<(), String> {
        if identity_key == [0u8; 32] || signing_key == [0u8; 32] {
            return Err("trusted signing pin rejects all-zero account keys".to_string());
        }
        if self
            .trusted_signing_keys
            .get(&identity_key)
            .is_some_and(|existing| existing != &signing_key)
        {
            return Err("trusted signing key changed for peer identity".to_string());
        }
        Ok(())
    }

    /// Check an existing durable/in-memory X25519 -> Ed25519 directory pin
    /// without creating trust from the message being inspected.
    pub fn peer_signing_key_is_pinned(
        &self,
        identity_key: &[u8; 32],
        signing_key: &[u8; 32],
    ) -> bool {
        self.trusted_signing_keys.get(identity_key) == Some(signing_key)
    }

    /// Bind a DM conversation to the authenticated peer identity. Sending is
    /// fail-closed unless this binding and a ratchet session both exist.
    pub fn bind_dm_conversation(
        &mut self,
        conversation_id: &str,
        peer_identity_key: [u8; 32],
    ) -> Result<(), String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        self.ensure_dm_conversation_binding_compatible(conversation_id, peer_identity_key)?;
        self.dm_conversations
            .insert(conversation_id.to_string(), peer_identity_key);
        Ok(())
    }

    /// Validate an authenticated Direct route without publishing it. A page
    /// installer uses this to preflight every durable conversation before any
    /// process-local route from that page becomes addressable.
    pub fn ensure_dm_conversation_binding_compatible(
        &self,
        conversation_id: &str,
        peer_identity_key: [u8; 32],
    ) -> Result<(), String> {
        if conversation_id.is_empty() || peer_identity_key == [0u8; 32] {
            return Err("DM binding requires a conversation id and peer identity".to_string());
        }
        if self
            .dm_conversations
            .get(conversation_id)
            .is_some_and(|stored| stored != &peer_identity_key)
        {
            return Err("DM conversation is already bound to another peer identity".to_string());
        }
        if let Some(ref db) = self.db {
            let conversations = db.get_conversations()?;
            let stored = conversations
                .iter()
                .find(|conversation| conversation.id == conversation_id)
                .ok_or("DM binding requires authoritative durable conversation metadata")?;
            let stored_origin = stored
                .server_origin
                .as_deref()
                .ok_or("durable DM conversation binding has no authoritative server origin")?;
            if stored.conv_type != ConversationType::DM
                || stored.peer_identity_key.as_deref() != Some(peer_identity_key.as_slice())
                || stored.peer_user_id.is_none()
            {
                return Err(
                    "durable DM conversation binding is unscoped or conflicts with the peer identity"
                        .to_string(),
                );
            }
            if conversations.iter().any(|candidate| {
                candidate.id != conversation_id
                    && candidate.peer_identity_key.as_deref() == Some(peer_identity_key.as_slice())
                    && candidate.server_origin.as_deref() != Some(stored_origin)
            }) {
                return Err(
                    "DM peer identity exists on multiple server origins; origin-scoped ratchet storage is required"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    /// Sign an arbitrary message with our Ed25519 identity key. Used for
    /// authenticating REST requests via the X-Veil-Signature header scheme.
    pub fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], String> {
        self.require_crypto_runtime_active_v1()?;
        let id = self.identity.as_ref().ok_or("not initialized")?;
        Ok(veil_crypto::signature::sign(id, message))
    }

    /// Prepare REST auth v2 for the exact authenticated WebSocket account and
    /// Node origin. Method, target and body remain caller-owned wire bytes, but
    /// origin/account/freshness cannot be supplied or downgraded by a renderer.
    pub fn prepare_authenticated_rest_headers_v2(
        &self,
        method: &str,
        request_target: &str,
        body: &[u8],
    ) -> Result<AuthenticatedRestHeadersV2, String> {
        self.require_crypto_runtime_active_v1()?;
        let account = self.identity.as_ref().ok_or("not initialized")?;
        let canonical_origin = self
            .authenticated_server_origin
            .as_deref()
            .ok_or_else(|| "not authenticated".to_string())?;
        let user_id = self
            .authenticated_user_id
            .as_deref()
            .ok_or_else(|| "not authenticated".to_string())?;
        let prepared = crate::rest_auth_v2::prepare_rest_auth_v2(
            account,
            canonical_origin,
            user_id,
            method,
            request_target,
            body,
        )
        .map_err(|error| error.to_string())?;
        let headers = prepared.into_headers();
        Ok(AuthenticatedRestHeadersV2 {
            version: headers.version(),
            user_id: headers.user_id().to_owned(),
            timestamp_ms: headers.timestamp_ms().to_owned(),
            nonce: headers.nonce().to_owned(),
            signature: headers.signature().to_owned(),
        })
    }

    // ─── Connection ──────────────────────────────────

    /// Connect to the Veil gateway server via WebSocket.
    /// Performs Ed25519 challenge-response authentication.
    /// Returns the server-assigned user_id (UUID).
    pub async fn connect(&mut self, server_url: &str) -> Result<String, String> {
        self.connect_with_client_metadata_and_node_access(
            server_url,
            "veil-desktop",
            "veil-desktop",
            None,
        )
        .await
    }

    /// Connect while presenting an optional origin-scoped Node Access Pass.
    /// The caller owns pass lifetime and storage; the client copies it only
    /// into the TLS-protected authentication envelope for this attempt.
    pub async fn connect_with_node_access_invite(
        &mut self,
        server_url: &str,
        node_access_invite: Option<&[u8]>,
    ) -> Result<String, String> {
        self.connect_with_client_metadata_and_node_access(
            server_url,
            "veil-desktop",
            "veil-desktop",
            node_access_invite,
        )
        .await
    }

    /// Connect with a fixed, native-platform device label. Product frontends
    /// must not accept this value from untrusted network or message metadata.
    pub async fn connect_with_device_name(
        &mut self,
        server_url: &str,
        device_name: &str,
    ) -> Result<String, String> {
        self.connect_with_client_metadata(server_url, device_name, "veil-desktop")
            .await
    }

    /// Connect with separate human-readable device and stable product labels.
    /// The client id becomes part of the protocol-level version string and
    /// must never be derived from a user-editable device name.
    pub async fn connect_with_client_metadata(
        &mut self,
        server_url: &str,
        device_name: &str,
        client_id: &str,
    ) -> Result<String, String> {
        self.connect_with_client_metadata_and_node_access(server_url, device_name, client_id, None)
            .await
    }

    /// Connect with fixed client metadata and an optional, single-use Node
    /// Access Pass. The pass is borrowed only for the duration of this
    /// attempt; callers remain responsible for zeroizing their owning buffer.
    pub async fn connect_with_client_metadata_and_access_pass(
        &mut self,
        server_url: &str,
        device_name: &str,
        client_id: &str,
        node_access_pass: Option<&[u8]>,
    ) -> Result<String, String> {
        self.connect_with_client_metadata_and_access_pass_classified_v1(
            server_url,
            device_name,
            client_id,
            node_access_pass,
        )
        .await
        .map_err(MobileConnectErrorV1::into_detail)
    }

    /// Typed mobile/native connection boundary. Automatic reconnect is
    /// permitted only when the returned stop is `RetryableTransport`.
    pub async fn connect_with_client_metadata_and_access_pass_classified_v1(
        &mut self,
        server_url: &str,
        device_name: &str,
        client_id: &str,
        node_access_pass: Option<&[u8]>,
    ) -> Result<String, MobileConnectErrorV1> {
        self.connect_with_client_metadata_and_node_access_classified_v1(
            server_url,
            device_name,
            client_id,
            node_access_pass,
        )
        .await
    }

    async fn connect_with_client_metadata_and_node_access(
        &mut self,
        server_url: &str,
        device_name: &str,
        client_id: &str,
        node_access_invite: Option<&[u8]>,
    ) -> Result<String, String> {
        self.connect_with_client_metadata_and_node_access_classified_v1(
            server_url,
            device_name,
            client_id,
            node_access_invite,
        )
        .await
        .map_err(MobileConnectErrorV1::into_detail)
    }

    async fn connect_with_client_metadata_and_node_access_classified_v1(
        &mut self,
        server_url: &str,
        device_name: &str,
        client_id: &str,
        node_access_invite: Option<&[u8]>,
    ) -> Result<String, MobileConnectErrorV1> {
        // An uncertain SQLCipher outcome invalidates the whole native epoch.
        // Reconnect cannot repair that ambiguity; only a successful unlock
        // reconstructs runtime state from durable storage.
        self.require_crypto_runtime_active_v1().map_err(|detail| {
            MobileConnectErrorV1::new(MobileConnectStopV1::StorageUncertain, detail)
        })?;
        let authenticated_server_origin = canonical_server_origin_from_websocket_url_v1(server_url)
            .map_err(|detail| {
                MobileConnectErrorV1::new(MobileConnectStopV1::EpochInvalid, detail)
            })?;
        if node_access_invite.is_some_and(|invite| invite.len() != 32) {
            return Err(MobileConnectErrorV1::new(
                MobileConnectStopV1::EpochInvalid,
                "node access pass must contain exactly 32 bytes",
            ));
        }
        if device_name.is_empty()
            || device_name.len() > 128
            || device_name.chars().any(|character| {
                character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
            })
        {
            return Err(MobileConnectErrorV1::new(
                MobileConnectStopV1::EpochInvalid,
                "device name is invalid",
            ));
        }
        if client_id.is_empty()
            || client_id.len() > 64
            || !client_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(MobileConnectErrorV1::new(
                MobileConnectStopV1::EpochInvalid,
                "client id is invalid",
            ));
        }
        let identity = self.identity.as_ref().ok_or_else(|| {
            MobileConnectErrorV1::new(MobileConnectStopV1::EpochInvalid, "not initialized")
        })?;
        let existing_device_identity = self.device_identity.as_ref().ok_or_else(|| {
            MobileConnectErrorV1::new(
                MobileConnectStopV1::EpochInvalid,
                "per-device identity is missing; unlock migration is required",
            )
        })?;
        let mut capability_upgrade = existing_device_identity
            .capability_upgrade_v1(identity)
            .map_err(|detail| {
                MobileConnectErrorV1::new(MobileConnectStopV1::EpochInvalid, detail)
            })?;
        let connection_device_identity = capability_upgrade
            .as_ref()
            .unwrap_or(existing_device_identity);
        let websocket_path = url::Url::parse(server_url)
            .map_err(|_| {
                MobileConnectErrorV1::new(
                    MobileConnectStopV1::EpochInvalid,
                    "invalid authenticated WebSocket server URL",
                )
            })?
            .path()
            .to_string();
        let mut conn = if websocket_path == crate::ws_auth_v3::WS_AUTH_V3_PATH {
            let config = WsEventsV3Config {
                websocket_url: server_url.to_string(),
                canonical_origin: authenticated_server_origin.clone(),
                device_name: device_name.to_string(),
                client_id: client_id.to_string(),
            };
            let registration = match node_access_invite {
                Some(pass) => WsRegistrationModeV3::Pass(
                    pass.try_into()
                        .expect("Node Access Pass length was validated above"),
                ),
                None => WsRegistrationModeV3::Open,
            };
            connect_primary_v3_classified(
                &config,
                identity,
                connection_device_identity,
                registration,
            )
            .await
            .map_err(MobileConnectErrorV1::from_connection)?
        } else {
            let config = ConnectionConfig {
                server_url: server_url.to_string(),
            };
            Connection::connect_classified_v1(
                &config,
                identity,
                connection_device_identity,
                device_name,
                client_id,
                node_access_invite,
            )
            .await
            .map_err(MobileConnectErrorV1::from_connection)?
        };

        // Drain the Authenticated event to get user_id
        let user_id = match conn.events.try_recv() {
            Ok(ConnectionEvent::Authenticated { user_id }) => user_id,
            _ => String::new(),
        };

        if user_id.is_empty() {
            return Err(MobileConnectErrorV1::new(
                MobileConnectStopV1::EpochInvalid,
                "server authenticated without a user id",
            ));
        }

        if let Some(upgraded) = capability_upgrade.take() {
            let stored = upgraded.to_stored_v1(identity);
            if let Err(detail) = self
                .db
                .as_ref()
                .ok_or("database not initialized".to_string())
                .and_then(|db| db.advance_device_identity_binding_v1(&stored))
            {
                drop(conn);
                return Err(MobileConnectErrorV1::new(
                    MobileConnectStopV1::StorageUncertain,
                    format!("persist authenticated device capability upgrade: {detail}"),
                ));
            }
            self.device_identity = Some(upgraded);
        }

        // Sequence numbers restart for every WebSocket. Resolve all old
        // pending entries before installing the new connection so a new ACK
        // can never confirm an unrelated pre-reconnect message or mutation.
        self.reconcile_previous_transport_before_install_v1()
            .map_err(|detail| {
                MobileConnectErrorV1::new(MobileConnectStopV1::StorageUncertain, detail)
            })?;
        // REST backlog is authoritative for anything not processed from the
        // previous socket. Never replay its deferred events in the new epoch.
        self.deferred_connection_events.reset_for_new_epoch();
        self.direct_live_stop = None;
        self.direct_ack_expiry_grace_remaining.clear();
        self.authenticated_user_id = Some(user_id.clone());
        self.authenticated_server_origin = Some(authenticated_server_origin);
        self.connection = Some(conn);
        Ok(user_id)
    }

    /// Stop the authenticated transport and erase its process-local account
    /// binding. Durable SQLCipher trust pins remain available for a later
    /// authenticated reconnect.
    pub fn disconnect(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.disconnect();
        }
        self.authenticated_user_id = None;
        self.authenticated_server_origin = None;
        self.deferred_connection_events.reset_for_new_epoch();
        self.direct_ack_expiry_grace_remaining.clear();
    }

    /// Install retained SKDMs that were authenticated before the WS AuthResult
    /// barrier. Call only after the signed conversation/member directory has
    /// been pinned and before decrypting REST history.
    pub fn process_retained_sender_keys_before_sync(
        &mut self,
    ) -> Result<RetainedSenderKeyProcessReportV1, String> {
        self.require_crypto_runtime_active_v1()?;
        let mut retained = Vec::new();
        let mut live = Vec::new();
        if let Some(connection) = self.connection.as_mut() {
            retained.extend(connection.retained_events.drain(..));
            // AuthResult is the protocol barrier. Everything in the live
            // channel arrived after it and must later pass the exact-current
            // live route checks, even when SenderKeyDist is the first event.
            while let Ok(event) = connection.events.try_recv_budgeted() {
                live.push(event);
            }
        }
        self.process_retained_and_defer_live_events_v1(retained, live)
    }

    fn process_retained_and_defer_live_events_v1(
        &mut self,
        retained: Vec<BudgetedConnectionEventV1>,
        live: Vec<BudgetedConnectionEventV1>,
    ) -> Result<RetainedSenderKeyProcessReportV1, String> {
        let append = match self.deferred_connection_events.try_extend(live) {
            Ok(append) => append,
            Err(error) => {
                self.terminate_connection_after_deferred_failure_v1();
                return Err(error.to_string());
            }
        };
        if append.terminal {
            self.terminate_connection_after_deferred_failure_v1();
            return Err(ConnectionEventBufferErrorV1::TransportEpochEnded.to_string());
        }

        // The guards remain alive while retained SKDMs are authenticated and
        // installed, so the socket cannot refill the shared budget behind the
        // still-owned event allocations.
        let mut retained_events = Vec::with_capacity(retained.len());
        let mut retained_guards: Vec<Option<ConnectionEventBudgetGuardV1>> =
            Vec::with_capacity(retained.len());
        for event in retained {
            let (event, guard) = event.into_parts();
            retained_events.push(event);
            retained_guards.push(guard);
        }
        let result = self.process_retained_sender_key_events_v1(retained_events);
        drop(retained_guards);
        result
    }

    fn process_retained_sender_key_events_v1(
        &mut self,
        retained: Vec<ConnectionEvent>,
    ) -> Result<RetainedSenderKeyProcessReportV1, String> {
        let mut conversation_order = Vec::new();
        let mut batches: HashMap<String, Vec<(Vec<u8>, SenderKeyRouteV1)>> = HashMap::new();
        for event in retained {
            match event {
                ConnectionEvent::SenderKeyDist {
                    sender_key_message,
                    route,
                } => {
                    if !batches.contains_key(&route.conversation_id) {
                        conversation_order.push(route.conversation_id.clone());
                    }
                    batches
                        .entry(route.conversation_id.clone())
                        .or_default()
                        .push((sender_key_message, route));
                }
                _ => unreachable!("retained prefix contains only sender-key envelopes"),
            }
        }

        let mut report = RetainedSenderKeyProcessReportV1::default();
        for conversation_id in conversation_order {
            let batch = batches
                .remove(&conversation_id)
                .ok_or("retained Sender-Key batch disappeared")?;
            let sender_keys_before = self.sender_keys.clone();
            let channel_conversations_before = self.channel_conversations.clone();
            let trusted_signing_keys_before = self.trusted_signing_keys.clone();
            let receipts_before = self.pending_sender_key_receipts.clone();
            let receipt_set_before = self.pending_sender_key_receipt_set.clone();
            let savepoint_started = if let Some(db) = self.db.as_ref() {
                match db.begin_retained_sender_key_conversation_v1() {
                    Ok(()) => true,
                    Err(reason) => {
                        report.diagnostics.push(RetainedSenderKeyDiagnosticV1 {
                            conversation_id,
                            reason,
                        });
                        continue;
                    }
                }
            } else {
                false
            };

            let mut processed = 0usize;
            let mut failure = None;
            for (sender_key_message, route) in batch {
                match self.process_sender_key_distribution_inner_v1(
                    &sender_key_message,
                    &route,
                    SenderKeyDistributionModeV1::Retained,
                ) {
                    Ok(_) => processed += 1,
                    Err(reason) => {
                        failure = Some(reason);
                        break;
                    }
                }
            }
            if failure.is_none() && savepoint_started {
                if let Err(reason) = self
                    .db
                    .as_ref()
                    .ok_or("database disappeared during retained Sender-Key batch")?
                    .commit_retained_sender_key_conversation_v1()
                {
                    failure = Some(reason);
                }
            }
            if let Some(reason) = failure {
                let rollback_error = if savepoint_started {
                    self.db
                        .as_ref()
                        .ok_or("database disappeared during retained Sender-Key rollback")?
                        .rollback_retained_sender_key_conversation_v1()
                        .err()
                } else {
                    None
                };
                // Runtime state must fail closed even if SQLite reports that
                // its rollback could not be completed and durable state is
                // therefore uncertain.
                self.sender_keys = sender_keys_before;
                self.channel_conversations = channel_conversations_before;
                self.trusted_signing_keys = trusted_signing_keys_before;
                self.pending_sender_key_receipts = receipts_before;
                self.pending_sender_key_receipt_set = receipt_set_before;
                if let Some(rollback) = rollback_error {
                    return Err(format!(
                        "{reason}; retained Sender-Key conversation rollback failed: {rollback}"
                    ));
                }
                report.diagnostics.push(RetainedSenderKeyDiagnosticV1 {
                    conversation_id,
                    reason,
                });
            } else {
                report.processed += processed;
            }
        }
        Ok(report)
    }

    /// Move already-authenticated live events out of the bounded socket queue
    /// while an ordered REST backlog or large Sender-Key refresh is running.
    /// They remain FIFO and are reconciled by `poll_event` once sync enables
    /// the dispatcher; no ratchet/ACK side effect is applied early.
    pub fn buffer_connection_events_during_sync(
        &mut self,
    ) -> Result<usize, ConnectionEventBufferErrorV1> {
        self.buffer_connection_events_during_sync_classified_v1()
            .map_err(|error| {
                error
                    .buffer_error
                    .unwrap_or(ConnectionEventBufferErrorV1::TransportEpochEnded)
            })
    }

    /// Source-typed native buffer boundary. Unlike the legacy wrapper above,
    /// sticky SQLCipher revocation is never represented as transport loss.
    pub fn buffer_connection_events_during_sync_classified_v1(
        &mut self,
    ) -> Result<usize, DirectLiveBufferErrorV1> {
        if self.direct_live_storage_uncertain {
            return Err(DirectLiveBufferErrorV1 {
                stop: DirectLiveReplayStopV1::StorageUncertain,
                buffer_error: None,
            });
        }
        let mut incoming = Vec::new();
        if let Some(connection) = self.connection.as_mut() {
            while let Ok(event) = connection.events.try_recv_budgeted() {
                incoming.push(event);
            }
        }
        match self.deferred_connection_events.try_extend(incoming) {
            Ok(append) if !append.terminal => Ok(append.buffered),
            Ok(_) => {
                self.terminate_connection_after_deferred_failure_v1();
                Err(DirectLiveBufferErrorV1 {
                    stop: self
                        .current_direct_live_stop_v1()
                        .unwrap_or(DirectLiveReplayStopV1::RetryableTransport),
                    buffer_error: Some(ConnectionEventBufferErrorV1::TransportEpochEnded),
                })
            }
            Err(error) => {
                self.terminate_connection_after_deferred_failure_v1();
                Err(DirectLiveBufferErrorV1 {
                    stop: self
                        .current_direct_live_stop_v1()
                        .unwrap_or_else(|| Self::direct_live_stop_for_buffer_error_v1(&error)),
                    buffer_error: Some(error),
                })
            }
        }
    }

    fn direct_live_stop_for_buffer_error_v1(
        error: &ConnectionEventBufferErrorV1,
    ) -> DirectLiveReplayStopV1 {
        match error {
            ConnectionEventBufferErrorV1::TransportEpochEnded => {
                DirectLiveReplayStopV1::RetryableTransport
            }
            ConnectionEventBufferErrorV1::EventCountLimitExceeded { .. }
            | ConnectionEventBufferErrorV1::RetainedSizeLimitExceeded { .. }
            | ConnectionEventBufferErrorV1::RetainedSizeAccountingOverflow
            | ConnectionEventBufferErrorV1::AuthenticationEpochAnomaly { .. }
            | ConnectionEventBufferErrorV1::ProtocolViolation { .. } => {
                DirectLiveReplayStopV1::EpochInvalid
            }
        }
    }

    fn direct_live_stop_precedence_v1(stop: DirectLiveReplayStopV1) -> u8 {
        match stop {
            DirectLiveReplayStopV1::RetryableTransport | DirectLiveReplayStopV1::AckDeadline => 1,
            DirectLiveReplayStopV1::EpochInvalid => 2,
            DirectLiveReplayStopV1::StorageUncertain => 3,
        }
    }

    fn record_direct_live_stop_v1(&mut self, stop: DirectLiveReplayStopV1) {
        if self.direct_live_stop.is_none_or(|current| {
            Self::direct_live_stop_precedence_v1(stop)
                > Self::direct_live_stop_precedence_v1(current)
        }) {
            self.direct_live_stop = Some(stop);
        }
    }

    fn current_direct_live_stop_v1(&self) -> Option<DirectLiveReplayStopV1> {
        if self.direct_live_storage_uncertain {
            return Some(DirectLiveReplayStopV1::StorageUncertain);
        }
        let inferred = if let Some(error) = self.deferred_connection_events.failure() {
            Some(Self::direct_live_stop_for_buffer_error_v1(&error))
        } else if self.deferred_connection_events.is_terminal()
            && self.deferred_connection_events.events.is_empty()
        {
            Some(DirectLiveReplayStopV1::RetryableTransport)
        } else if self.direct_live_stop.is_none()
            && (self.authenticated_user_id.is_none() || self.authenticated_server_origin.is_none())
        {
            Some(DirectLiveReplayStopV1::EpochInvalid)
        } else {
            None
        };
        match (self.direct_live_stop, inferred) {
            (Some(current), Some(inferred))
                if Self::direct_live_stop_precedence_v1(inferred)
                    > Self::direct_live_stop_precedence_v1(current) =>
            {
                Some(inferred)
            }
            (Some(current), _) => Some(current),
            (None, inferred) => inferred,
        }
    }

    fn observe_connection_terminal_stop_v1(&mut self) -> Option<DirectLiveReplayStopV1> {
        let error = self
            .connection
            .as_ref()
            .and_then(|connection| connection.events.terminal_buffer_error_v1())?;
        let stop = Self::direct_live_stop_for_buffer_error_v1(&error);
        self.record_direct_live_stop_v1(stop);
        self.current_direct_live_stop_v1()
    }

    fn classify_direct_enqueue_result_v1(
        &mut self,
        result: &Result<(), ConnectionSendErrorV1>,
    ) -> Option<DirectLiveReplayStopV1> {
        let observed = self.observe_connection_terminal_stop_v1();
        if let Err(error) = result {
            match error {
                ConnectionSendErrorV1::QueueTimeout => {
                    self.record_direct_live_stop_v1(DirectLiveReplayStopV1::RetryableTransport);
                }
                ConnectionSendErrorV1::QueueClosed if observed.is_none() => {
                    // A source helper must publish its typed terminal before
                    // closing the peer queue. Closure without that source is
                    // an invariant failure, never reconnect permission.
                    self.record_direct_live_stop_v1(DirectLiveReplayStopV1::EpochInvalid);
                }
                ConnectionSendErrorV1::Rejected(_) => {
                    // The exact payload has already passed the caller's
                    // construction/persistence boundary. A local envelope
                    // rejection is deterministic epoch corruption.
                    self.record_direct_live_stop_v1(DirectLiveReplayStopV1::EpochInvalid);
                }
                ConnectionSendErrorV1::QueueClosed => {}
            }
        }
        self.current_direct_live_stop_v1()
    }

    fn stop_direct_outbox_replay_if_terminal_v1(
        &mut self,
        report: &mut DirectOutboxReplayReportV1,
    ) -> Result<bool, DirectSendErrorV1> {
        let stop = self
            .observe_connection_terminal_stop_v1()
            .or_else(|| self.current_direct_live_stop_v1());
        match stop {
            Some(DirectLiveReplayStopV1::EpochInvalid) => Err(DirectSendErrorV1::rejected(
                "authenticated Direct transport epoch is invalid",
            )),
            Some(DirectLiveReplayStopV1::StorageUncertain) => Err(DirectSendErrorV1::storage(
                "Direct outbox replay storage is uncertain",
            )),
            Some(
                DirectLiveReplayStopV1::RetryableTransport | DirectLiveReplayStopV1::AckDeadline,
            ) => {
                report.transport_blocked = true;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn terminate_connection_after_deferred_failure_v1(&mut self) {
        let stop = self
            .deferred_connection_events
            .failure()
            .as_ref()
            .map(Self::direct_live_stop_for_buffer_error_v1)
            .unwrap_or(DirectLiveReplayStopV1::RetryableTransport);
        self.record_direct_live_stop_v1(stop);
        self.direct_ack_expiry_grace_remaining.clear();
        if let Some(connection) = self.connection.take() {
            connection.disconnect();
        }
        self.authenticated_user_id = None;
        self.authenticated_server_origin = None;
        // A fail-closed buffer terminal is transport loss. If recording the
        // delivery-unknown state itself is uncertain, revoke the complete
        // native epoch instead of hiding a SQLCipher failure behind transport.
        if self.mark_all_pending_sequences_unknown().is_err() {
            self.revoke_after_storage_uncertain_v1();
        }
    }

    fn resolve_budgeted_connection_event_v1(
        &mut self,
        queued_event: Option<BudgetedConnectionEventV1>,
    ) -> Result<Option<ConnectionEvent>, String> {
        if let Some(error) = queued_event
            .as_ref()
            .and_then(BudgetedConnectionEventV1::terminal_failure)
            .cloned()
        {
            self.deferred_connection_events.fail(error.clone());
            self.terminate_connection_after_deferred_failure_v1();
            return Err(error.to_string());
        }
        Ok(queued_event.map(BudgetedConnectionEventV1::into_event))
    }

    /// Poll for the next incoming event from the server.
    /// Returns None if no event is available (non-blocking).
    pub async fn poll_event(&mut self) -> Result<Option<ConnectionEvent>, String> {
        self.require_crypto_runtime_active_v1()?;
        if let Some(error) = self.deferred_connection_events.failure() {
            return Err(error.to_string());
        }

        // A transport terminal preempts every earlier deferred item. Query it
        // before the FIFO so an ended epoch can never drain stale ciphertext.
        let transport_terminal = self
            .connection
            .as_mut()
            .and_then(|connection| connection.events.try_recv_terminal());
        if let Some(terminal) = transport_terminal {
            if let Err(error) = self.deferred_connection_events.try_extend(vec![terminal]) {
                self.terminate_connection_after_deferred_failure_v1();
                return Err(error.to_string());
            }
        }

        let queued_event = if let Some(event) = self.deferred_connection_events.pop_front() {
            Some(event)
        } else if self.deferred_connection_events.is_terminal() {
            None
        } else if let Some(ref mut conn) = self.connection {
            conn.events.try_recv_budgeted().ok()
        } else {
            None
        };

        // The terminal may publish after the explicit precheck above but
        // before the fallback receive. Preserve its typed failure metadata
        // instead of degrading an overflow/auth anomaly into Disconnected.
        let mut event = self.resolve_budgeted_connection_event_v1(queued_event)?;

        if matches!(
            event.as_ref(),
            Some(ConnectionEvent::Authenticated { .. } | ConnectionEvent::AuthFailed { .. })
        ) {
            let error = ConnectionEventBufferErrorV1::AuthenticationEpochAnomaly {
                envelope: match event.as_ref() {
                    Some(ConnectionEvent::Authenticated { .. }) => "Authenticated event",
                    Some(ConnectionEvent::AuthFailed { .. }) => "AuthFailed event",
                    _ => unreachable!(),
                },
            };
            self.deferred_connection_events.fail(error.clone());
            self.terminate_connection_after_deferred_failure_v1();
            return Err(error.to_string());
        }
        let reconciliation_plan = match event.as_ref() {
            Some(event) => match self.validate_connection_reconciliation_event_v1(event) {
                Ok(plan) => plan,
                Err(ConnectionReconciliationValidationErrorV1::ProtocolViolation(detail)) => {
                    // All authenticated ACK/error correlation and routing
                    // fields are validated before the first SQLCipher or
                    // in-memory mutation. A deterministic mismatch poisons
                    // only this socket epoch; it must never masquerade as
                    // uncertain storage.
                    self.deferred_connection_events.fail(
                        ConnectionEventBufferErrorV1::ProtocolViolation {
                            envelope: "ACK/error reconciliation",
                        },
                    );
                    self.terminate_connection_after_deferred_failure_v1();
                    return Err(detail);
                }
                Err(ConnectionReconciliationValidationErrorV1::StorageUncertain(detail)) => {
                    self.revoke_after_storage_uncertain_v1();
                    return Err(detail);
                }
            },
            None => ConnectionReconciliationV1::None,
        };
        let reconciliation = (|| -> Result<(), String> {
            match (event.as_mut(), reconciliation_plan) {
                (
                    Some(ConnectionEvent::MessageAcked {
                        message_id,
                        server_timestamp,
                        ref_seq,
                        client_message_id,
                        local_message_id,
                        mutation,
                        sender_key,
                    }),
                    ConnectionReconciliationV1::MessageAck(correlation),
                ) => match correlation {
                    MessageAckCorrelationV1::CurrentOutgoing => {
                        *local_message_id = self.finalize_outgoing_message(
                            *ref_seq,
                            client_message_id.as_deref(),
                            message_id,
                            *server_timestamp,
                        )?;
                        self.confirm_initial_message(*ref_seq)?;
                    }
                    MessageAckCorrelationV1::RepeatedDirectReceipt => {
                        *local_message_id = self.finalize_outgoing_message(
                            *ref_seq,
                            client_message_id.as_deref(),
                            message_id,
                            *server_timestamp,
                        )?;
                    }
                    MessageAckCorrelationV1::Mutation => {
                        self.confirm_initial_message(*ref_seq)?;
                        // Move a confirmed edit (and its plaintext) into the
                        // caller-visible event only after initial correlation
                        // is cleared. The ratchet step was already committed by
                        // send and ACK deliberately performs no ratchet write.
                        *mutation = self.confirm_pending_mutation(*ref_seq, *server_timestamp)?;
                    }
                    MessageAckCorrelationV1::SenderKey => {
                        self.confirm_sender_key_distribution(*ref_seq, sender_key.as_ref())?;
                    }
                    MessageAckCorrelationV1::Generic => {}
                },
                (
                    Some(ConnectionEvent::Error {
                        code,
                        ref_seq: Some(ref_seq),
                        client_message_id,
                        reason,
                        local_message_id,
                        conversation_id,
                        stale_roster_context,
                        ..
                    }),
                    ConnectionReconciliationV1::Error(_),
                ) => {
                    let retryable_direct_error = self
                        .pending_outgoing_messages
                        .get(ref_seq)
                        .is_some_and(|pending| pending.durable_direct_outbox)
                        && is_retryable_correlated_send_error_v1(*code, reason.as_deref());
                    let pending_conversation = self
                        .pending_sender_key_sequences
                        .get(ref_seq)
                        .map(|pending| pending.conversation_id.clone())
                        .or_else(|| {
                            self.pending_outgoing_messages
                                .get(ref_seq)
                                .map(|pending| pending.conversation_id.clone())
                        });
                    let roster_invalidated = matches!(
                        reason.as_deref(),
                        Some("secure_roster_changed" | "device_not_eligible")
                    );
                    if *code == 409 && roster_invalidated {
                        if let Some(pending_conversation) = pending_conversation.as_ref() {
                            if self.channel_conversations.contains(pending_conversation) {
                                self.invalidate_device_roster_v1(pending_conversation);
                                *conversation_id = Some(pending_conversation.clone());
                                *stale_roster_context = true;
                            }
                        }
                    }
                    *local_message_id = self.reconcile_outgoing_error_v1(
                        *ref_seq,
                        *code,
                        client_message_id.as_deref(),
                        reason.as_deref(),
                    )?;
                    if retryable_direct_error {
                        self.record_direct_live_stop_v1(DirectLiveReplayStopV1::RetryableTransport);
                        self.mark_all_pending_sequences_unknown().map_err(|error| {
                            format!("persist retryable Direct transport loss: {error}")
                        })?;
                        if let Some(connection) = self.connection.take() {
                            connection.disconnect();
                        }
                        if let Some(mut user_id) = self.authenticated_user_id.take() {
                            user_id.zeroize();
                        }
                        if let Some(mut origin) = self.authenticated_server_origin.take() {
                            origin.zeroize();
                        }
                        self.deferred_connection_events.close_epoch();
                    }
                }
                (Some(ConnectionEvent::Disconnected { .. }), ConnectionReconciliationV1::None) => {
                    // There can be no trustworthy delivery conclusion once the
                    // socket epoch ends: a frame may have reached the gateway
                    // and only its ACK may have been lost. Legacy rows become
                    // DeliveryUnknown; exact Direct outbox rows remain Sending
                    // and may replay only their original protobuf payload.
                    self.record_direct_live_stop_v1(DirectLiveReplayStopV1::RetryableTransport);
                    self.connection = None;
                    self.authenticated_user_id = None;
                    self.authenticated_server_origin = None;
                    self.deferred_connection_events.close_epoch();
                    self.mark_all_pending_sequences_unknown()
                        .map_err(|error| format!("persist disconnected delivery state: {error}"))?;
                }
                (_, ConnectionReconciliationV1::None) => {}
                _ => unreachable!("validated reconciliation plan must match its event"),
            }
            Ok(())
        })();
        if let Err(error) = reconciliation {
            self.revoke_after_storage_uncertain_v1();
            return Err(error);
        }
        Ok(event)
    }

    fn direct_live_replay_error_v1(
        stop: DirectLiveReplayStopV1,
        report: DirectLiveReplayReportV1,
    ) -> DirectLiveReplayErrorV1 {
        DirectLiveReplayErrorV1 { stop, report }
    }

    pub fn direct_conversation_availability_v1(
        &self,
        conversation_id: &str,
    ) -> DirectConversationAvailabilityV1 {
        if self.direct_live_storage_uncertain {
            DirectConversationAvailabilityV1::RuntimeRevoked
        } else if self
            .direct_live_blocked_conversations
            .contains(conversation_id)
        {
            DirectConversationAvailabilityV1::Quarantined
        } else if !self.dm_conversations.contains_key(conversation_id) {
            DirectConversationAvailabilityV1::NotDirect
        } else {
            DirectConversationAvailabilityV1::Available
        }
    }

    fn exact_direct_identity_verification_v2(
        &self,
        conversation_id: &str,
    ) -> Result<DirectIdentityVerificationV2, String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        let peer_identity_key = self
            .dm_conversations
            .get(conversation_id)
            .copied()
            .ok_or("conversation is not an available Direct route")?;
        let canonical_server_origin = self
            .authenticated_server_origin
            .as_deref()
            .ok_or("server origin is not authenticated")?;
        let authenticated_user_id = self
            .authenticated_user_id
            .as_deref()
            .ok_or("account is not authenticated")?;
        let self_identity_key = self.identity_key()?;
        let self_signing_key = self.signing_key()?;
        let db = self.db.as_ref().ok_or("database not initialized")?;
        let scope = db.resolve_authenticated_direct_history_scope_v1(
            canonical_server_origin,
            authenticated_user_id,
            conversation_id,
        )?;

        if scope.conversation_id != conversation_id
            || scope.self_account.locator.canonical_server_origin != canonical_server_origin
            || scope.self_account.locator.user_id != authenticated_user_id
            || scope.self_account.locator.identity_key != self_identity_key
            || scope.self_account.signing_key != self_signing_key
            || scope.self_account.source.as_u8() != 2
            || scope.peer_account.locator.canonical_server_origin != canonical_server_origin
            || scope.peer_account.locator.identity_key != peer_identity_key
            || scope.peer_account.source.as_u8() != 2
            || self
                .known_user_keys
                .get(&scope.peer_account.locator.user_id)
                != Some(&peer_identity_key)
            || self.trusted_signing_keys.get(&peer_identity_key)
                != Some(&scope.peer_account.signing_key)
        {
            return Err(
                "Direct identity verification route differs from authenticated directory state"
                    .to_string(),
            );
        }
        self.ensure_dm_conversation_binding_compatible(conversation_id, peer_identity_key)?;

        let locator = ProfileLocator {
            canonical_server_origin: canonical_server_origin.to_string(),
            user_id: scope.peer_account.locator.user_id.clone(),
            identity_key: peer_identity_key,
        };
        let proof = db.local_identity_verification_for_unlocked_account(
            &self_identity_key,
            &self_signing_key,
            &locator,
        )?;
        let (fingerprint_emoji, fingerprint_hex) = veil_crypto::fingerprint::generate_account_v2(
            canonical_server_origin,
            veil_crypto::fingerprint::AccountFingerprintTuple {
                user_id: authenticated_user_id,
                identity_key: &self_identity_key,
                signing_key: &self_signing_key,
            },
            veil_crypto::fingerprint::AccountFingerprintTuple {
                user_id: &scope.peer_account.locator.user_id,
                identity_key: &peer_identity_key,
                signing_key: &scope.peer_account.signing_key,
            },
        );
        let qr_payload = direct_identity_qr_payload_v1(&fingerprint_hex)?;
        Ok(DirectIdentityVerificationV2 {
            canonical_server_origin: canonical_server_origin.to_string(),
            peer_user_id: scope.peer_account.locator.user_id,
            peer_identity_key,
            peer_signing_key: scope.peer_account.signing_key,
            fingerprint_emoji,
            fingerprint_hex,
            qr_payload,
            proof: proof.into(),
        })
    }

    /// Return the account-v2 safety number for one exact authenticated Direct.
    /// This is a read-only comparison view; service-mediated directory trust
    /// remains `NotCompared` until the user explicitly confirms it out of band.
    pub fn direct_identity_verification_v2(
        &self,
        conversation_id: &str,
    ) -> Result<DirectIdentityVerificationV2, String> {
        self.exact_direct_identity_verification_v2(conversation_id)
    }

    /// Confirm an account-v2 safety number displayed by a trusted native UI.
    /// The exact route is re-derived and the supplied 32-byte digest is checked
    /// in constant time before SQLCipher records a device-local proof.
    pub fn confirm_direct_identity_verification_v2(
        &self,
        conversation_id: &str,
        expected_fingerprint: &[u8; 32],
    ) -> Result<DirectIdentityVerificationV2, String> {
        let mut view = self.exact_direct_identity_verification_v2(conversation_id)?;
        let mut actual_fingerprint = [0u8; 32];
        hex::decode_to_slice(&view.fingerprint_hex, &mut actual_fingerprint)
            .map_err(|_| "computed Direct identity fingerprint is invalid".to_string())?;
        if expected_fingerprint.ct_eq(&actual_fingerprint).unwrap_u8() != 1 {
            return Err("displayed Direct identity fingerprint is stale or mismatched".to_string());
        }

        let locator = ProfileLocator {
            canonical_server_origin: view.canonical_server_origin.clone(),
            user_id: view.peer_user_id.clone(),
            identity_key: view.peer_identity_key,
        };
        let db = self.db.as_ref().ok_or("database not initialized")?;
        let verified_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        db.mark_account_verified_v2(&locator, &verified_at)?;
        view.proof = db
            .local_identity_verification_for_unlocked_account(
                &self.identity_key()?,
                &self.signing_key()?,
                &locator,
            )?
            .into();
        Ok(view)
    }

    /// Confirm a QR payload generated by the peer's trusted native account-v2
    /// view. Parsing is exact and bounded; the extracted digest is still
    /// compared in constant time with the freshly-derived current route before
    /// any durable verification state is written.
    pub fn confirm_direct_identity_verification_qr_v1(
        &self,
        conversation_id: &str,
        scanned_qr_payload: &str,
    ) -> Result<DirectIdentityVerificationV2, String> {
        let expected_fingerprint = direct_identity_qr_fingerprint_v1(scanned_qr_payload)?;
        self.confirm_direct_identity_verification_v2(conversation_id, &expected_fingerprint)
    }

    /// Exact native projection boundary for Stage-5 Direct history. Callers
    /// receive no quarantine identifiers and cannot use a route that was
    /// rejected by live replay; known non-Direct projections keep their
    /// existing channel/group path.
    pub fn direct_messages_projection_v1(
        &self,
        conversation_id: &str,
        limit: u32,
    ) -> Result<Vec<Message>, String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        if !self.dm_conversations.contains_key(conversation_id) {
            return Err("conversation is not an available Direct route".to_string());
        }
        if limit == 0 || limit > 500 {
            return Err("Direct message projection limit is invalid".to_string());
        }
        self.db
            .as_ref()
            .ok_or("database not initialized")?
            .get_messages(conversation_id, limit)
    }

    fn require_crypto_runtime_active_v1(&self) -> Result<(), String> {
        if self.direct_live_storage_uncertain {
            Err("native cryptographic runtime is revoked after uncertain storage state".to_string())
        } else {
            Ok(())
        }
    }

    fn require_direct_conversation_available_v1(
        &self,
        conversation_id: &str,
    ) -> Result<(), String> {
        self.require_crypto_runtime_active_v1()?;
        if self
            .direct_live_blocked_conversations
            .contains(conversation_id)
        {
            Err("Direct conversation is quarantined in the native runtime".to_string())
        } else {
            Ok(())
        }
    }

    fn require_message_conversation_available_v1(&self, message_id: &str) -> Result<(), String> {
        self.require_crypto_runtime_active_v1()?;
        let Some(db) = self.db.as_ref() else {
            return Err("database not initialized".to_string());
        };
        let (conversation_id, _, _, _) = db
            .get_message_binding(message_id)?
            .ok_or("message conversation binding is unavailable")?;
        self.require_direct_conversation_available_v1(&conversation_id)?;
        Ok(())
    }

    fn require_classified_receive_available_v1(
        &self,
        conversation_id: &str,
    ) -> Result<(), DirectHistoryMutationError> {
        if self.direct_live_storage_uncertain {
            return Err(DirectHistoryMutationError::storage(
                "native cryptographic runtime is revoked after uncertain storage state",
            ));
        }
        if self
            .direct_live_blocked_conversations
            .contains(conversation_id)
        {
            return Err(DirectHistoryMutationError::rejected(
                "Direct conversation is quarantined in the native runtime",
            ));
        }
        Ok(())
    }

    fn validate_inbound_author_snapshot_classified_v1(
        &self,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        author_snapshot: Option<&AccountSnapshot>,
    ) -> Result<(), DirectHistoryMutationError> {
        let Some(author_snapshot) = author_snapshot else {
            return Ok(());
        };
        if author_snapshot.locator.identity_key != *sender_identity_key
            || author_snapshot.profile_origin != author_snapshot.locator.canonical_server_origin
        {
            return Err(DirectHistoryMutationError::rejected(
                "inbound author snapshot conflicts with the authenticated sender scope",
            ));
        }
        let durable = self
            .db
            .as_ref()
            .ok_or_else(|| DirectHistoryMutationError::storage("database not initialized"))?
            .resolve_account_by_conversation_sender(conversation_id, sender_identity_key)
            .map_err(DirectHistoryMutationError::storage)?
            .ok_or_else(|| {
                DirectHistoryMutationError::rejected(
                    "inbound author is absent from the authenticated conversation origin",
                )
            })?;
        if durable.locator != author_snapshot.locator
            || durable.signing_key != author_snapshot.signing_key
        {
            return Err(DirectHistoryMutationError::rejected(
                "inbound author snapshot changed its immutable account binding",
            ));
        }
        Ok(())
    }

    fn zeroize_pending_mutation_v1(mutation: &mut ConfirmedMutation) {
        match mutation {
            ConfirmedMutation::Edit {
                message_id,
                conversation_id,
                new_text,
            } => {
                message_id.zeroize();
                conversation_id.zeroize();
                new_text.zeroize();
            }
            ConfirmedMutation::Delete {
                message_id,
                conversation_id,
            } => {
                message_id.zeroize();
                conversation_id.zeroize();
            }
            ConfirmedMutation::Reaction {
                message_id,
                conversation_id,
                emoji,
                user_id,
                ..
            } => {
                message_id.zeroize();
                conversation_id.zeroize();
                emoji.zeroize();
                user_id.zeroize();
            }
        }
    }

    /// Revoke the complete process-local epoch after an uncertain SQLCipher
    /// outcome. This path deliberately performs no further database writes.
    fn revoke_after_storage_uncertain_v1(&mut self) {
        self.direct_live_storage_uncertain = true;
        self.direct_live_stop = Some(DirectLiveReplayStopV1::StorageUncertain);
        self.direct_ack_expiry_grace_remaining.clear();
        if let Some(connection) = self.connection.take() {
            connection.disconnect();
        }
        if let Some(mut authenticated_user_id) = self.authenticated_user_id.take() {
            authenticated_user_id.zeroize();
        }
        if let Some(mut authenticated_server_origin) = self.authenticated_server_origin.take() {
            authenticated_server_origin.zeroize();
        }
        self.deferred_connection_events.reset_for_new_epoch();

        for pending in self.pending_outgoing_messages.values_mut() {
            pending.local_message_id.zeroize();
            pending.conversation_id.zeroize();
            pending.plaintext.zeroize();
        }
        self.pending_outgoing_messages.clear();
        for mutation in self.pending_mutations.values_mut() {
            Self::zeroize_pending_mutation_v1(mutation);
        }
        self.pending_mutations.clear();
        self.pending_initial_sequences.clear();
        self.pending_initial_headers.clear();
        self.pending_sender_key_sequences.clear();
        for wire in self.pending_sender_key_envelopes.values_mut() {
            wire.zeroize();
        }
        self.pending_sender_key_envelopes.clear();
        self.pending_sender_key_receipts.clear();
        self.pending_sender_key_receipt_set.clear();
        self.pending_sender_key_receipt_sequences.clear();
        self.failed_sender_key_distributions.clear();

        // Make the sticky bit defense-in-depth instead of the only barrier:
        // legacy `db()`/identity accessors and any future missed call-site
        // cannot touch an ambiguous SQLCipher or ratchet epoch. A successful
        // `init_with_mnemonic` reconstructs all of this from durable state.
        self.db = None;
        self.indexer = None;
        self.identity = None;
        self.device_identity = None;
        self.ratchet_sessions.clear();
        self.direct_v2_sessions.clear();
        self.zeroize_prekey_secrets();
        self.spk_next_id = 1;
        self.otk_next_id = 1;
        self.sender_keys = SenderKeyStore::new();
        self.dm_conversations.clear();
        self.known_user_keys.clear();
        self.trusted_signing_keys.clear();
        self.channel_conversations.clear();
        self.authorized_conversation_senders.clear();
        self.device_rosters.clear();
        self.last_invalidated_device_rosters.clear();
        self.device_roster_rotation_pending.clear();
        self.sender_key_distribution_pending.clear();
        self.prepared_sender_key_generations.clear();
        self.direct_live_blocked_conversations.clear();
    }

    pub(crate) fn revoke_storage_uncertain_epoch_v1(&mut self) {
        self.revoke_after_storage_uncertain_v1();
    }

    fn resolve_public_classified_mutation_v1<T>(
        &mut self,
        result: Result<T, DirectHistoryMutationError>,
    ) -> Result<T, String> {
        match result {
            Ok(value) => Ok(value),
            Err(DirectHistoryMutationError::ConversationRejected(detail)) => Err(detail),
            Err(DirectHistoryMutationError::StorageUncertain(detail)) => {
                self.revoke_after_storage_uncertain_v1();
                Err(detail)
            }
        }
    }

    fn resolve_public_session_establish_v1<T>(
        &mut self,
        result: Result<T, DirectSessionEstablishErrorV1>,
    ) -> Result<T, String> {
        match result {
            Ok(value) => Ok(value),
            Err(DirectSessionEstablishErrorV1::Rejected(detail)) => Err(detail),
            Err(DirectSessionEstablishErrorV1::StorageUncertain(detail)) => {
                self.revoke_after_storage_uncertain_v1();
                Err(detail)
            }
        }
    }

    fn resolve_public_direct_send_v1<T>(
        &mut self,
        result: Result<T, DirectSendErrorV1>,
    ) -> Result<T, String> {
        match result {
            Ok(value) => Ok(value),
            Err(DirectSendErrorV1::Rejected(detail)) => Err(detail),
            Err(DirectSendErrorV1::StorageUncertain(detail)) => {
                self.revoke_after_storage_uncertain_v1();
                Err(detail)
            }
        }
    }

    fn current_direct_outbox_scope_v1(
        &self,
    ) -> Result<DirectMessageOutboxScopeV1, DirectSendErrorV1> {
        self.require_crypto_runtime_active_v1()
            .map_err(DirectSendErrorV1::rejected)?;
        if self.connection.is_none() {
            return Err(DirectSendErrorV1::rejected(
                "authenticated transport is unavailable",
            ));
        }
        if self.db.is_none() {
            return Err(DirectSendErrorV1::rejected(
                "SQLCipher database is unavailable",
            ));
        }
        let canonical_server_origin = self
            .authenticated_server_origin
            .clone()
            .ok_or_else(|| DirectSendErrorV1::rejected("server origin is not authenticated"))?;
        crate::direct::validate_canonical_origin(&canonical_server_origin)
            .map_err(DirectSendErrorV1::rejected)?;
        let user_id = self
            .authenticated_user_id
            .clone()
            .ok_or_else(|| DirectSendErrorV1::rejected("account is not authenticated"))?;
        if !Self::is_canonical_live_uuid_v1(&user_id) {
            return Err(DirectSendErrorV1::rejected(
                "authenticated account id is not canonical",
            ));
        }
        let device = self
            .device_identity
            .as_ref()
            .ok_or_else(|| DirectSendErrorV1::rejected("device identity is unavailable"))?;
        if self.device_id == [0u8; 16]
            || device.binding().device_id != self.device_id
            || device.binding().status != DEVICE_BINDING_STATUS_ACTIVE
        {
            return Err(DirectSendErrorV1::rejected(
                "active device binding does not match this installation",
            ));
        }
        Ok(DirectMessageOutboxScopeV1 {
            canonical_server_origin,
            user_id,
            device_id: self.device_id,
        })
    }

    fn validate_pending_direct_outbox_payload_v1(
        &self,
        scope: &DirectMessageOutboxScopeV1,
        pending: &PendingDirectMessageOutboxV1,
    ) -> Result<proto::SendMessage, DirectSendErrorV1> {
        if pending.scope.canonical_server_origin != scope.canonical_server_origin
            || pending.scope.user_id != scope.user_id
            || pending.scope.device_id != scope.device_id
            || pending.client_message_id != pending.local_message_id
            || !Self::is_canonical_live_uuid_v1(&pending.client_message_id)
            || !Self::is_canonical_live_uuid_v1(&pending.conversation_id)
        {
            return Err(DirectSendErrorV1::storage(
                "durable Direct outbox scope or UUID binding is invalid",
            ));
        }
        self.require_direct_conversation_available_v1(&pending.conversation_id)
            .map_err(DirectSendErrorV1::rejected)?;
        if self
            .channel_conversations
            .contains(&pending.conversation_id)
            || self.dm_conversations.get(&pending.conversation_id)
                != Some(&pending.peer_identity_key)
            || self.trusted_signing_keys.get(&pending.peer_identity_key)
                != Some(&pending.peer_signing_key)
        {
            return Err(DirectSendErrorV1::storage(
                "durable Direct outbox route differs from the authenticated runtime",
            ));
        }
        if send_message_request_digest_v1(&pending.exact_send_message_payload)
            != pending.request_digest
        {
            return Err(DirectSendErrorV1::storage(
                "durable Direct outbox request digest is invalid",
            ));
        }
        let decoded = proto::SendMessage::decode(pending.exact_send_message_payload.as_slice())
            .map_err(|_| {
                DirectSendErrorV1::storage("durable Direct outbox payload is not SendMessage")
            })?;
        let direct_state = self
            .direct_v2_sessions
            .get(&pending.peer_identity_key)
            .ok_or_else(|| {
                DirectSendErrorV1::storage(
                    "durable Direct outbox has no authenticated Direct v2 session",
                )
            })?;
        let valid_direct_header = matches!(
            decoded.header.as_slice(),
            [HEADER_INITIAL_V2, ..] | [HEADER_RATCHET_V2, ..]
        ) && ((decoded.header[0] == HEADER_INITIAL_V2
            && decoded.header.len() == 114)
            || (decoded.header[0] == HEADER_RATCHET_V2 && decoded.header.len() == 74))
            && decoded.header.get(1..33) == Some(decoded.direct_session_id.as_slice());
        if decoded.encode_to_vec() != pending.exact_send_message_payload
            || decoded.conversation_id != pending.conversation_id
            || decoded.client_message_id != pending.client_message_id
            || decoded.ciphertext.is_empty()
            || decoded.header.is_empty()
            || !valid_direct_header
            || decoded.msg_type != proto::MessageType::Text as i32
            || decoded.reply_to_id.is_some()
            || decoded.ttl_seconds.is_some()
            || !decoded.attachments.is_empty()
            || decoded.sealed
            || decoded.roster_version != 0
            || !decoded.roster_commitment.is_empty()
            || decoded.crypto_profile != DIRECT_CRYPTO_PROFILE_V2
            || decoded.crypto_era != DIRECT_CRYPTO_ERA_V2
            || decoded.target_device_id != direct_state.peer().device.device_id
            || decoded.target_binding_version != direct_state.peer().device.binding_version
            || decoded.direct_session_id != direct_state.session_id()
            || decoded.membership_epoch != 0
            || !decoded.membership_epoch_hash.is_empty()
        {
            return Err(DirectSendErrorV1::storage(
                "durable Direct outbox payload violates the Direct text contract",
            ));
        }
        Ok(decoded)
    }

    /// Check sticky global state before every individual FIFO receive. This is
    /// intentionally repeated inside the bounded loop so a terminal published
    /// between two events preempts the next ratchet step.
    fn direct_live_terminal_precheck_v1(
        &self,
        report: DirectLiveReplayReportV1,
    ) -> Result<(), DirectLiveReplayErrorV1> {
        if let Some(stop) = self.current_direct_live_stop_v1() {
            return Err(Self::direct_live_replay_error_v1(stop, report));
        }
        Ok(())
    }

    fn is_canonical_live_uuid_v1(value: &str) -> bool {
        uuid::Uuid::parse_str(value)
            .is_ok_and(|parsed| !parsed.is_nil() && parsed.hyphenated().to_string() == value)
    }

    fn quarantine_known_direct_live_conversation_v1(&mut self, conversation_id: &str) -> bool {
        self.dm_conversations.contains_key(conversation_id)
            && self
                .direct_live_blocked_conversations
                .insert(conversation_id.to_string())
    }

    fn process_direct_live_message_v1(
        &mut self,
        event: ConnectionEvent,
    ) -> Result<DirectLiveEventOutcomeV1, DirectHistoryMutationError> {
        let ConnectionEvent::MessageReceived {
            message_id,
            conversation_id,
            sender_identity_key,
            sender_username: _,
            ciphertext,
            header,
            server_timestamp,
            reply_to_id,
            msg_type,
            ttl_seconds,
            sealed,
            attachments,
            security_context,
        } = event
        else {
            return Ok(DirectLiveEventOutcomeV1::Ignored);
        };

        let Some(expected_peer) = self.dm_conversations.get(&conversation_id).copied() else {
            if self.channel_conversations.contains(&conversation_id) {
                // Stage 5 is Direct-only. A known channel/group event remains
                // encrypted, unapplied, and discarded by this Direct-only
                // replay; it cannot select a Direct ratchet.
                return Ok(DirectLiveEventOutcomeV1::Ignored);
            }
            // Silently dropping an event for an unknown route and later
            // claiming quiescence could skip a ratchet step. The caller turns
            // this unscoped rejection into a protocol-terminal epoch.
            return Err(DirectHistoryMutationError::rejected(
                "Direct live event references an unknown conversation route",
            ));
        };
        if self
            .direct_live_blocked_conversations
            .contains(&conversation_id)
        {
            return Ok(DirectLiveEventOutcomeV1::Ignored);
        }

        if !Self::is_canonical_live_uuid_v1(&message_id)
            || !Self::is_canonical_live_uuid_v1(&conversation_id)
            || reply_to_id
                .as_deref()
                .is_some_and(|reply| !Self::is_canonical_live_uuid_v1(reply))
            || reply_to_id.as_deref() == Some(message_id.as_str())
        {
            return Err(DirectHistoryMutationError::rejected(
                "Direct live event contains a non-canonical UUID",
            ));
        }
        let sender_identity_key: [u8; 32] = sender_identity_key.try_into().map_err(|_| {
            DirectHistoryMutationError::rejected("Direct live sender identity has the wrong length")
        })?;
        if sender_identity_key != expected_peer
            || self.channel_conversations.contains(&conversation_id)
            || !self.is_currently_authorized_sender(&conversation_id, &sender_identity_key)
        {
            return Err(DirectHistoryMutationError::rejected(
                "Direct live sender conflicts with the immutable current route",
            ));
        }
        let authenticated_user_id = self.authenticated_user_id.clone().ok_or_else(|| {
            DirectHistoryMutationError::rejected("Direct live replay is not authenticated")
        })?;
        if !Self::is_canonical_live_uuid_v1(&authenticated_user_id) {
            return Err(DirectHistoryMutationError::rejected(
                "Direct live authenticated user id is not canonical",
            ));
        }
        let authenticated_server_origin =
            self.authenticated_server_origin.clone().ok_or_else(|| {
                DirectHistoryMutationError::rejected(
                    "Direct live replay has no authenticated server origin",
                )
            })?;
        if msg_type != Some(proto::MessageType::Text as i32)
            || ttl_seconds.is_some()
            || sealed != Some(false)
            || !attachments.is_empty()
            || matches!(
                security_context,
                Some(
                    MessageSecurityContextV1::SenderKeyV5(_)
                        | MessageSecurityContextV1::SenderKeyV6(_)
                )
            )
            || header.is_empty()
            || ciphertext.is_empty()
            || header.first() == Some(&HEADER_SENDER_KEY)
        {
            return Err(DirectHistoryMutationError::rejected(
                "Direct live preview received an unsupported message policy",
            ));
        }
        // Gateway live fanout is UnixNano while retained REST history and the
        // SQLCipher binding are UnixMilli. Normalize before duplicate
        // classification so reconnect history is exactly idempotent.
        let server_timestamp_ms = server_timestamp / 1_000_000;
        if server_timestamp == 0 || server_timestamp_ms == 0 {
            return Err(DirectHistoryMutationError::rejected(
                "Direct live timestamp is not a positive UnixNano value",
            ));
        }
        let server_timestamp = i64::try_from(server_timestamp_ms).map_err(|_| {
            DirectHistoryMutationError::rejected("Direct live timestamp exceeds SQLCipher range")
        })?;

        let scope = self
            .db
            .as_ref()
            .ok_or_else(|| DirectHistoryMutationError::storage("database not initialized"))?
            .resolve_authenticated_direct_history_scope_v1(
                &authenticated_server_origin,
                &authenticated_user_id,
                &conversation_id,
            )
            .map_err(DirectHistoryMutationError::storage)?;
        let local_identity_key = self
            .identity_key()
            .map_err(DirectHistoryMutationError::storage)?;
        let local_signing_key = self
            .signing_key()
            .map_err(DirectHistoryMutationError::storage)?;
        if scope.self_account.locator.identity_key != local_identity_key
            || scope.self_account.signing_key != local_signing_key
            || scope.self_account.locator.user_id != authenticated_user_id
            || scope.peer_account.locator.identity_key != expected_peer
        {
            return Err(DirectHistoryMutationError::rejected(
                "Direct live scope conflicts with the authenticated account route",
            ));
        }
        let author = scope.peer_account;
        if author.source
            != veil_store::models::AccountSnapshotSource::AuthenticatedConversationDirectory
            || author.locator.identity_key != sender_identity_key
            || author.locator.user_id == authenticated_user_id
            || !self.peer_signing_key_is_pinned(&sender_identity_key, &author.signing_key)
        {
            return Err(DirectHistoryMutationError::rejected(
                "Direct live author tuple conflicts with authenticated directory pins",
            ));
        }

        match self.receive_and_persist_direct_history_message(
            &message_id,
            &conversation_id,
            &sender_identity_key,
            &author,
            MessageAuthorContext::DirectoryMemberAtObservation,
            security_context.as_ref(),
            &header,
            &ciphertext,
            Some(server_timestamp),
            reply_to_id.as_deref(),
            None,
        )? {
            ReceiveMessageResult::Stored { mut plaintext } => {
                plaintext.zeroize();
                Ok(DirectLiveEventOutcomeV1::Stored)
            }
            ReceiveMessageResult::Duplicate => Ok(DirectLiveEventOutcomeV1::Duplicate),
        }
    }

    fn apply_direct_live_event_v1(
        &mut self,
        event: ConnectionEvent,
        report: &mut DirectLiveReplayReportV1,
    ) -> Result<(), DirectHistoryMutationError> {
        match event {
            event @ ConnectionEvent::MessageReceived { .. } => {
                let conversation_id = match &event {
                    ConnectionEvent::MessageReceived {
                        conversation_id, ..
                    } => conversation_id.clone(),
                    _ => unreachable!(),
                };
                match self.process_direct_live_message_v1(event) {
                    Ok(DirectLiveEventOutcomeV1::Stored) => {
                        report.stored += 1;
                        report.visible_mutations += 1;
                    }
                    Ok(DirectLiveEventOutcomeV1::Duplicate) => {
                        report.duplicates += 1;
                        // Duplicate reconciliation may repair absent legacy
                        // author metadata. Conservatively signal a projection
                        // refresh without exposing a message identifier.
                        report.visible_mutations += 1;
                    }
                    Ok(DirectLiveEventOutcomeV1::Ignored) => report.ignored += 1,
                    Err(DirectHistoryMutationError::ConversationRejected(_)) => {
                        if self.quarantine_known_direct_live_conversation_v1(&conversation_id) {
                            report.newly_blocked += 1;
                            report.ignored += 1;
                        } else {
                            return Err(DirectHistoryMutationError::rejected(
                                "Direct live event could not be scoped to a known conversation",
                            ));
                        }
                    }
                    Err(error @ DirectHistoryMutationError::StorageUncertain(_)) => {
                        return Err(error)
                    }
                }
            }
            ConnectionEvent::MessageEdited {
                conversation_id, ..
            }
            | ConnectionEvent::MessageDeleted {
                conversation_id, ..
            }
            | ConnectionEvent::ReactionEvent {
                conversation_id, ..
            } => {
                if self.dm_conversations.contains_key(&conversation_id) {
                    if self.quarantine_known_direct_live_conversation_v1(&conversation_id) {
                        report.newly_blocked += 1;
                    }
                } else if !self.channel_conversations.contains(&conversation_id) {
                    return Err(DirectHistoryMutationError::rejected(
                        "Direct live mutation references an unknown conversation route",
                    ));
                }
                report.ignored += 1;
            }
            ConnectionEvent::SenderKeyDist { route, .. } => {
                if self.dm_conversations.contains_key(&route.conversation_id) {
                    if self.quarantine_known_direct_live_conversation_v1(&route.conversation_id) {
                        report.newly_blocked += 1;
                    }
                } else if !self.channel_conversations.contains(&route.conversation_id) {
                    return Err(DirectHistoryMutationError::rejected(
                        "Sender-Key distribution references an unknown conversation route",
                    ));
                }
                report.ignored += 1;
            }
            ConnectionEvent::MessageAcked {
                local_message_id,
                mut mutation,
                ..
            } => {
                if local_message_id.is_some() || mutation.is_some() {
                    report.visible_mutations += 1;
                }
                if let Some(ConfirmedMutation::Edit { new_text, .. }) = mutation.as_mut() {
                    new_text.zeroize();
                }
                report.ignored += 1;
            }
            ConnectionEvent::Error {
                local_message_id, ..
            } => {
                if local_message_id.is_some() {
                    report.visible_mutations += 1;
                }
                report.ignored += 1;
            }
            ConnectionEvent::Authenticated { .. }
            | ConnectionEvent::AuthFailed { .. }
            | ConnectionEvent::Disconnected { .. } => {
                return Err(DirectHistoryMutationError::rejected(
                    "transport control reached Direct live event application",
                ));
            }
            ConnectionEvent::TypingEvent { .. }
            | ConnectionEvent::PresenceUpdate { .. }
            | ConnectionEvent::FriendRequestReceived { .. }
            | ConnectionEvent::FriendAccepted { .. }
            | ConnectionEvent::FriendRemoved { .. }
            | ConnectionEvent::FriendListReceived { .. }
            | ConnectionEvent::ProfileUpdated { .. }
            | ConnectionEvent::ConversationAvailable { .. }
            | ConnectionEvent::ServerEvent { .. }
            | ConnectionEvent::ChannelEvent { .. } => report.ignored += 1,
        }
        Ok(())
    }

    /// Consume a bounded, gap-free slice of authenticated live events for the
    /// Stage-5 Direct text preview. `poll_event` remains the sole FIFO/ACK
    /// reconciler and is called exactly once per loop iteration.
    pub async fn replay_direct_live_events_v1(
        &mut self,
    ) -> Result<DirectLiveReplayReportV1, DirectLiveReplayErrorV1> {
        self.replay_direct_live_events_inner_v1(|_, _| {}).await
    }

    fn has_expired_direct_ack_deadline_v1(&self, now: Instant) -> bool {
        self.pending_outgoing_messages.values().any(|pending| {
            pending.durable_direct_outbox
                && pending
                    .direct_ack_deadline
                    .is_some_and(|deadline| deadline <= now)
        })
    }

    fn direct_ack_expiry_fifo_snapshot_v1(&self) -> usize {
        let deferred = self.deferred_connection_events.events.len();
        // Retained pre-auth Sender-Key controls are consumed only by the
        // explicit sync barrier and can never contain a Direct ACK. Counting
        // them here would create grace that poll_event cannot drain.
        let connection = self
            .connection
            .as_ref()
            .map_or(0, |connection| connection.events.queued_len_v1());
        deferred
            .checked_add(connection)
            .expect("bounded Direct ACK grace snapshot fits usize")
    }

    /// Freeze the exact number of events already queued when each ACK expiry
    /// is first observed. FIFO ordering means consuming that sequence's
    /// snapshot is sufficient for its already-queued ACK to reconcile. Later
    /// arrivals sit behind the watermark and cannot replenish it.
    fn refresh_direct_ack_expiry_grace_v1(&mut self, now: Instant) {
        let pending_outgoing_messages = &self.pending_outgoing_messages;
        self.direct_ack_expiry_grace_remaining
            .retain(|sequence, _| {
                pending_outgoing_messages
                    .get(sequence)
                    .is_some_and(|pending| {
                        pending.durable_direct_outbox
                            && pending
                                .direct_ack_deadline
                                .is_some_and(|deadline| deadline <= now)
                    })
            });
        let newly_expired: Vec<u64> = self
            .pending_outgoing_messages
            .iter()
            .filter_map(|(sequence, pending)| {
                (pending.durable_direct_outbox
                    && pending
                        .direct_ack_deadline
                        .is_some_and(|deadline| deadline <= now)
                    && !self
                        .direct_ack_expiry_grace_remaining
                        .contains_key(sequence))
                .then_some(*sequence)
            })
            .collect();
        if !newly_expired.is_empty() {
            let snapshot = self.direct_ack_expiry_fifo_snapshot_v1();
            for sequence in newly_expired {
                self.direct_ack_expiry_grace_remaining
                    .insert(sequence, snapshot);
            }
        }
    }

    fn consume_direct_ack_expiry_grace_event_v1(&mut self, now: Instant) {
        // Only watermarks that existed before this event include it. A
        // correlation whose deadline crossed while poll_event was running
        // snapshots the remaining FIFO afterwards and must not charge the
        // already-consumed event.
        for remaining in self.direct_ack_expiry_grace_remaining.values_mut() {
            *remaining = remaining
                .checked_sub(1)
                .expect("an ACK-expiry grace event is consumed only after polling one event");
        }
        self.refresh_direct_ack_expiry_grace_v1(now);
    }

    fn has_exhausted_direct_ack_expiry_grace_v1(&self) -> bool {
        self.direct_ack_expiry_grace_remaining
            .values()
            .any(|remaining| *remaining == 0)
    }

    fn classify_direct_live_empty_poll_v1(&mut self, now: Instant) -> DirectLiveEmptyPollV1 {
        // The deadline may cross after the pre-loop refresh, while a socket
        // task concurrently queues the ACK just after poll_event observed an
        // empty FIFO. Freeze that newly visible FIFO before deciding to end
        // the epoch.
        self.refresh_direct_ack_expiry_grace_v1(now);
        if !self.has_expired_direct_ack_deadline_v1(now) {
            DirectLiveEmptyPollV1::Quiescent
        } else if self.has_exhausted_direct_ack_expiry_grace_v1() {
            DirectLiveEmptyPollV1::AckDeadline
        } else {
            DirectLiveEmptyPollV1::ContinueFrozenFifo
        }
    }

    /// End the socket epoch after an exact durable Direct correlation missed
    /// its monotonic ACK deadline. SQLCipher keeps the immutable outbox row in
    /// Sending state; only the ephemeral sequence correlation is discarded.
    fn terminate_after_direct_ack_deadline_v1(&mut self) -> DirectLiveReplayStopV1 {
        self.record_direct_live_stop_v1(DirectLiveReplayStopV1::AckDeadline);
        self.direct_ack_expiry_grace_remaining.clear();
        if let Some(connection) = self.connection.take() {
            connection.disconnect();
        }
        if let Some(mut user_id) = self.authenticated_user_id.take() {
            user_id.zeroize();
        }
        if let Some(mut origin) = self.authenticated_server_origin.take() {
            origin.zeroize();
        }
        self.deferred_connection_events.close_epoch();
        if self.mark_all_pending_sequences_unknown().is_err() {
            self.revoke_after_storage_uncertain_v1();
            DirectLiveReplayStopV1::StorageUncertain
        } else {
            DirectLiveReplayStopV1::AckDeadline
        }
    }

    async fn replay_direct_live_events_inner_v1<F>(
        &mut self,
        mut after_event: F,
    ) -> Result<DirectLiveReplayReportV1, DirectLiveReplayErrorV1>
    where
        F: FnMut(&mut Self, usize),
    {
        let mut report = DirectLiveReplayReportV1::default();
        while report.consumed < DIRECT_LIVE_REPLAY_MAX_BATCH_V1 {
            self.direct_live_terminal_precheck_v1(report)?;
            self.refresh_direct_ack_expiry_grace_v1(Instant::now());
            if self.has_exhausted_direct_ack_expiry_grace_v1() {
                let stop = self.terminate_after_direct_ack_deadline_v1();
                return Err(Self::direct_live_replay_error_v1(stop, report));
            }
            let event = match self.poll_event().await {
                Ok(Some(event)) => event,
                Ok(None) => match self.classify_direct_live_empty_poll_v1(Instant::now()) {
                    DirectLiveEmptyPollV1::AckDeadline => {
                        let stop = self.terminate_after_direct_ack_deadline_v1();
                        return Err(Self::direct_live_replay_error_v1(stop, report));
                    }
                    DirectLiveEmptyPollV1::ContinueFrozenFifo => continue,
                    DirectLiveEmptyPollV1::Quiescent => {
                        report.quiescent = true;
                        return Ok(report);
                    }
                },
                Err(_) => {
                    if let Some(stop) = self.current_direct_live_stop_v1() {
                        return Err(Self::direct_live_replay_error_v1(stop, report));
                    }
                    self.revoke_after_storage_uncertain_v1();
                    return Err(Self::direct_live_replay_error_v1(
                        DirectLiveReplayStopV1::StorageUncertain,
                        report,
                    ));
                }
            };
            report.consumed += 1;
            self.consume_direct_ack_expiry_grace_event_v1(Instant::now());

            if matches!(event, ConnectionEvent::Disconnected { .. }) {
                return Err(Self::direct_live_replay_error_v1(
                    DirectLiveReplayStopV1::RetryableTransport,
                    report,
                ));
            }
            if let Err(error) = self.apply_direct_live_event_v1(event, &mut report) {
                match error {
                    DirectHistoryMutationError::StorageUncertain(_) => {
                        self.revoke_after_storage_uncertain_v1();
                        return Err(Self::direct_live_replay_error_v1(
                            DirectLiveReplayStopV1::StorageUncertain,
                            report,
                        ));
                    }
                    DirectHistoryMutationError::ConversationRejected(_) => {
                        // A rejection with no known Direct quarantine target is
                        // an authenticated protocol anomaly. Poison the whole
                        // epoch so a later call cannot claim quiescence after
                        // silently losing this event.
                        self.deferred_connection_events.fail(
                            ConnectionEventBufferErrorV1::ProtocolViolation {
                                envelope: "Direct live route",
                            },
                        );
                        self.terminate_connection_after_deferred_failure_v1();
                        let stop = self
                            .current_direct_live_stop_v1()
                            .unwrap_or(DirectLiveReplayStopV1::EpochInvalid);
                        return Err(Self::direct_live_replay_error_v1(stop, report));
                    }
                }
            }
            after_event(self, report.consumed);
        }
        Ok(report)
    }

    fn mark_all_pending_sequences_unknown(&mut self) -> Result<(), String> {
        for receipt in self.pending_sender_key_receipt_sequences.values() {
            self.pending_sender_key_receipt_set.remove(receipt);
        }
        self.pending_sender_key_receipt_sequences.clear();
        let stale_sequences: HashSet<u64> = self
            .pending_outgoing_messages
            .keys()
            .chain(self.pending_mutations.keys())
            .chain(self.pending_initial_sequences.keys())
            .chain(self.pending_sender_key_sequences.keys())
            .copied()
            .collect();
        let local_message_ids: Vec<String> = stale_sequences
            .iter()
            .filter_map(|sequence| {
                self.pending_outgoing_messages
                    .get(sequence)
                    .map(|pending| pending.local_message_id.clone())
            })
            .collect();
        if let Some(db) = self.db.as_ref() {
            db.reconcile_outgoing_transport_loss_v1(&local_message_ids)?;
        }
        for sequence in stale_sequences {
            self.pending_initial_sequences.remove(&sequence);
            if let Some(ConfirmedMutation::Edit { new_text, .. }) =
                self.pending_mutations.remove(&sequence).as_mut()
            {
                new_text.zeroize();
            }
            if let Some(pending) = self.pending_sender_key_sequences.remove(&sequence) {
                self.failed_sender_key_distributions
                    .insert(pending.conversation_id);
            }
            self.pending_outgoing_messages.remove(&sequence);
        }
        Ok(())
    }

    fn pending_outgoing_sequence_for_client_id_v1(
        &self,
        client_message_id: &str,
    ) -> Result<Option<u64>, String> {
        let mut matched = None;
        for (sequence, pending) in &self.pending_outgoing_messages {
            if pending.local_message_id == client_message_id && matched.replace(*sequence).is_some()
            {
                return Err(
                    "client message id has multiple live transport correlations".to_string()
                );
            }
        }
        Ok(matched)
    }

    fn validate_outgoing_message_ack_v1(
        &self,
        sequence: u64,
        client_message_id: Option<&str>,
        server_message_id: &str,
        server_timestamp: u64,
    ) -> Result<(), String> {
        let pending = self.pending_outgoing_messages.get(&sequence);
        if !server_message_id.is_empty() {
            let timestamp_ms = i64::try_from(server_timestamp / 1_000_000)
                .map_err(|_| "server message timestamp exceeds i64".to_string())?;
            if timestamp_ms <= 0 {
                return Err(
                    "server message timestamp is below the durable millisecond contract"
                        .to_string(),
                );
            }
        }
        if pending.is_none() && client_message_id.is_none() {
            return Ok(());
        }
        if let Some(client_message_id) = client_message_id {
            if self
                .pending_outgoing_sequence_for_client_id_v1(client_message_id)?
                .is_some_and(|authoritative_sequence| authoritative_sequence != sequence)
            {
                return Err(
                    "message ACK sequence does not match its live client message correlation"
                        .to_string(),
                );
            }
        }
        if let Some(pending) = pending {
            if client_message_id != Some(pending.local_message_id.as_str()) {
                return Err("message ACK client id does not match the pending send".to_string());
            }
        }
        if server_message_id.is_empty() {
            return Err("message ACK is missing the server message id".to_string());
        }
        Ok(())
    }

    fn validate_outgoing_error_v1(
        &self,
        sequence: u64,
        code: u32,
        client_message_id: Option<&str>,
        reason: Option<&str>,
    ) -> Result<(), String> {
        let pending = self.pending_outgoing_messages.get(&sequence);
        if !(400..=599).contains(&code) {
            return Err(
                "correlated send error code is outside the HTTP error contract".to_string(),
            );
        }
        if let Some(client_message_id) = client_message_id {
            if self
                .pending_outgoing_sequence_for_client_id_v1(client_message_id)?
                .is_some_and(|authoritative_sequence| authoritative_sequence != sequence)
            {
                return Err(
                    "send error sequence does not match its live client message correlation"
                        .to_string(),
                );
            }
        }
        if let Some(pending) = pending {
            if client_message_id != Some(pending.local_message_id.as_str()) || reason.is_none() {
                return Err("send error does not match its exact client message id".to_string());
            }
        }
        if reason == Some("client_message_id_conflict") {
            return Err("server rejected a reused client message id".to_string());
        }
        if client_message_id.is_some()
            && pending.is_none()
            && is_retryable_correlated_send_error_v1(code, reason)
        {
            return Err(
                "retryable send error references no current Direct outbox sequence".to_string(),
            );
        }
        if client_message_id.is_some()
            && !is_retryable_correlated_send_error_v1(code, reason)
            && reason.is_none()
        {
            return Err("correlated Direct send error omitted its stable rejection reason".into());
        }
        Ok(())
    }

    fn validate_sender_key_ack_v1(
        &self,
        sequence: u64,
        ack: Option<&crate::connection::SenderKeyAckMetadataV1>,
    ) -> Result<(), String> {
        if let Some(receipt) = self.pending_sender_key_receipt_sequences.get(&sequence) {
            let ack = ack.ok_or("Sender-Key receipt acknowledgement omitted exact metadata")?;
            if ack.conversation_id != receipt.conversation_id
                || ack.generation != receipt.generation
                || ack.target_device_id != receipt.target_device_id
                || ack.roster_version != receipt.roster_version
                || ack.membership_epoch != receipt.membership_epoch
                || ack.membership_epoch_hash != receipt.membership_epoch_hash
                || ack.envelope_commitment != receipt.envelope_commitment
            {
                return Err("Sender-Key receipt acknowledgement metadata mismatch".to_string());
            }
            return Ok(());
        }
        let Some(pending) = self.pending_sender_key_sequences.get(&sequence) else {
            return if ack.is_some() {
                Err("unexpected Sender-Key acknowledgement sequence".to_string())
            } else {
                Ok(())
            };
        };
        let ack = ack.ok_or("Sender-Key acknowledgement omitted exact route metadata")?;
        if ack.conversation_id != pending.conversation_id
            || ack.generation != pending.generation
            || ack.target_device_id != pending.target_device_id
            || ack.roster_version != pending.roster_version
            || ack.membership_epoch != pending.membership_epoch
            || ack.membership_epoch_hash != pending.membership_epoch_hash
            || ack.envelope_commitment != pending.envelope_commitment
        {
            return Err("Sender-Key acknowledgement route metadata mismatch".to_string());
        }
        let roster = self
            .device_rosters
            .get(&pending.conversation_id)
            .ok_or("Sender-Key acknowledgement arrived without a current roster proof")?;
        if roster.version != pending.roster_version
            || roster.commitment != pending.roster_commitment
        {
            return Err("Sender-Key acknowledgement belongs to a stale roster".to_string());
        }
        Ok(())
    }

    fn validate_message_ack_correlation_v1(
        &self,
        sequence: u64,
        client_message_id: Option<&str>,
        server_message_id: &str,
        server_timestamp: u64,
        sender_key: Option<&crate::connection::SenderKeyAckMetadataV1>,
    ) -> Result<MessageAckCorrelationV1, String> {
        let outgoing = self.pending_outgoing_messages.contains_key(&sequence);
        let mutation = self.pending_mutations.contains_key(&sequence);
        let initial = self.pending_initial_sequences.contains_key(&sequence);
        let sender_key_distribution = self.pending_sender_key_sequences.contains_key(&sequence);
        let sender_key_receipt = self
            .pending_sender_key_receipt_sequences
            .contains_key(&sequence);

        self.validate_outgoing_message_ack_v1(
            sequence,
            client_message_id,
            server_message_id,
            server_timestamp,
        )?;

        if client_message_id.is_some() {
            if sender_key.is_some() || mutation || sender_key_distribution || sender_key_receipt {
                return Err(
                    "chat ACK sequence collides with a non-message live correlation".to_string(),
                );
            }
            if outgoing {
                // An initial X3DH send deliberately owns both the outgoing
                // message and initial-session maps under the same sequence.
                return Ok(MessageAckCorrelationV1::CurrentOutgoing);
            }
            if initial {
                return Err(
                    "repeated Direct ACK sequence collides with an initial-session correlation"
                        .to_string(),
                );
            }
            // The durable receipt is validated by client_message_id during
            // finalization. Its stale wire ref_seq is otherwise inert and may
            // never select a live correlation from another command.
            return Ok(MessageAckCorrelationV1::RepeatedDirectReceipt);
        }

        if outgoing {
            return Err("outgoing message ACK omitted its exact client message id".to_string());
        }
        if sender_key_distribution || sender_key_receipt || sender_key.is_some() {
            if sender_key_distribution && sender_key_receipt {
                return Err(
                    "Sender-Key ACK sequence has multiple live route correlations".to_string(),
                );
            }
            if mutation || initial {
                return Err(
                    "Sender-Key ACK sequence collides with another live correlation".to_string(),
                );
            }
            self.validate_sender_key_ack_v1(sequence, sender_key)?;
            return Ok(MessageAckCorrelationV1::SenderKey);
        }
        if mutation {
            // An edit may legitimately be the first X3DH packet, so its
            // mutation and initial-session maps share one sequence.
            let expected_message_id = match self
                .pending_mutations
                .get(&sequence)
                .expect("mutation correlation was checked above")
            {
                ConfirmedMutation::Edit { message_id, .. }
                | ConfirmedMutation::Delete { message_id, .. }
                | ConfirmedMutation::Reaction { message_id, .. } => message_id,
            };
            if server_message_id != expected_message_id {
                return Err(
                    "mutation ACK message id does not match its live correlation".to_string(),
                );
            }
            return Ok(MessageAckCorrelationV1::Mutation);
        }
        if initial {
            return Err(
                "initial-session ACK has no matching outgoing command correlation".to_string(),
            );
        }
        if !server_message_id.is_empty() {
            return Err("chat-shaped ACK has no live message correlation".to_string());
        }
        Ok(MessageAckCorrelationV1::Generic)
    }

    fn validate_error_correlation_v1(
        &self,
        sequence: u64,
        code: u32,
        client_message_id: Option<&str>,
        reason: Option<&str>,
    ) -> Result<ErrorCorrelationV1, String> {
        let outgoing = self.pending_outgoing_messages.contains_key(&sequence);
        let mutation = self.pending_mutations.contains_key(&sequence);
        let initial = self.pending_initial_sequences.contains_key(&sequence);
        let sender_key_distribution = self.pending_sender_key_sequences.contains_key(&sequence);
        let sender_key_receipt = self
            .pending_sender_key_receipt_sequences
            .contains_key(&sequence);

        self.validate_outgoing_error_v1(sequence, code, client_message_id, reason)?;

        if client_message_id.is_some() {
            if mutation || sender_key_distribution || sender_key_receipt {
                return Err(
                    "correlated send error sequence collides with a non-message live correlation"
                        .to_string(),
                );
            }
            if outgoing {
                // A failed initial X3DH message clears both correlations.
                return Ok(ErrorCorrelationV1::CurrentOutgoing);
            }
            if initial {
                return Err(
                    "repeated Direct error sequence collides with an initial-session correlation"
                        .to_string(),
                );
            }
            return Ok(ErrorCorrelationV1::RepeatedDirectReceipt);
        }

        if outgoing {
            return Err("outgoing send error omitted its exact client message id".to_string());
        }
        if mutation {
            if sender_key_distribution || sender_key_receipt {
                return Err(
                    "mutation error sequence collides with a Sender-Key live correlation"
                        .to_string(),
                );
            }
            // As with its ACK, an initial encrypted edit legitimately shares
            // the initial-session sequence and both are rejected together.
            return Ok(ErrorCorrelationV1::PendingCommand);
        }
        if sender_key_distribution || sender_key_receipt {
            if sender_key_distribution && sender_key_receipt {
                return Err(
                    "Sender-Key error sequence has multiple live route correlations".to_string(),
                );
            }
            if initial {
                return Err(
                    "Sender-Key error sequence collides with an initial-session correlation"
                        .to_string(),
                );
            }
            return Ok(ErrorCorrelationV1::PendingCommand);
        }
        if initial {
            return Err(
                "initial-session error has no matching outgoing command correlation".to_string(),
            );
        }
        Ok(ErrorCorrelationV1::Generic)
    }

    fn validate_repeated_direct_ack_receipt_v1(
        &self,
        client_message_id: &str,
        server_message_id: &str,
        server_timestamp: u64,
    ) -> Result<(), ConnectionReconciliationValidationErrorV1> {
        let server_timestamp_ms = i64::try_from(server_timestamp / 1_000_000).map_err(|_| {
            ConnectionReconciliationValidationErrorV1::ProtocolViolation(
                "server message timestamp exceeds i64".to_string(),
            )
        })?;
        let scope = self
            .current_direct_outbox_scope_v1()
            .map_err(|error| match error {
                DirectSendErrorV1::Rejected(detail) => {
                    ConnectionReconciliationValidationErrorV1::ProtocolViolation(detail)
                }
                DirectSendErrorV1::StorageUncertain(detail) => {
                    ConnectionReconciliationValidationErrorV1::StorageUncertain(detail)
                }
            })?;
        let receipt = self
            .db
            .as_ref()
            .ok_or_else(|| {
                ConnectionReconciliationValidationErrorV1::StorageUncertain(
                    "SQLCipher database is unavailable during repeated Direct ACK validation"
                        .to_string(),
                )
            })?
            .load_direct_message_outbox_receipt_v1(&scope, client_message_id)
            .map_err(ConnectionReconciliationValidationErrorV1::StorageUncertain)?;
        match receipt.as_ref() {
            Some(DirectMessageOutboxReceiptV1::Acknowledged {
                server_message_id: durable_server_message_id,
                server_timestamp_ms: durable_server_timestamp_ms,
                ..
            }) if durable_server_message_id == server_message_id
                && *durable_server_timestamp_ms == server_timestamp_ms =>
            {
                Ok(())
            }
            _ => Err(
                ConnectionReconciliationValidationErrorV1::ProtocolViolation(
                    "repeated Direct ACK conflicts with its durable receipt".to_string(),
                ),
            ),
        }
    }

    fn validate_repeated_direct_error_receipt_v1(
        &self,
        client_message_id: &str,
        rejection_reason: &str,
    ) -> Result<(), ConnectionReconciliationValidationErrorV1> {
        let scope = self
            .current_direct_outbox_scope_v1()
            .map_err(|error| match error {
                DirectSendErrorV1::Rejected(detail) => {
                    ConnectionReconciliationValidationErrorV1::ProtocolViolation(detail)
                }
                DirectSendErrorV1::StorageUncertain(detail) => {
                    ConnectionReconciliationValidationErrorV1::StorageUncertain(detail)
                }
            })?;
        let receipt = self
            .db
            .as_ref()
            .ok_or_else(|| {
                ConnectionReconciliationValidationErrorV1::StorageUncertain(
                    "SQLCipher database is unavailable during repeated Direct error validation"
                        .to_string(),
                )
            })?
            .load_direct_message_outbox_receipt_v1(&scope, client_message_id)
            .map_err(ConnectionReconciliationValidationErrorV1::StorageUncertain)?;
        match receipt.as_ref() {
            Some(DirectMessageOutboxReceiptV1::Rejected {
                rejection_reason: durable_rejection_reason,
                ..
            }) if durable_rejection_reason == rejection_reason => Ok(()),
            _ => Err(
                ConnectionReconciliationValidationErrorV1::ProtocolViolation(
                    "repeated Direct error conflicts with its durable receipt".to_string(),
                ),
            ),
        }
    }

    fn validate_connection_reconciliation_event_v1(
        &self,
        event: &ConnectionEvent,
    ) -> Result<ConnectionReconciliationV1, ConnectionReconciliationValidationErrorV1> {
        match event {
            ConnectionEvent::MessageAcked {
                message_id,
                server_timestamp,
                ref_seq,
                client_message_id,
                sender_key,
                ..
            } => {
                let correlation = self
                    .validate_message_ack_correlation_v1(
                        *ref_seq,
                        client_message_id.as_deref(),
                        message_id,
                        *server_timestamp,
                        sender_key.as_ref(),
                    )
                    .map_err(ConnectionReconciliationValidationErrorV1::ProtocolViolation)?;
                if correlation == MessageAckCorrelationV1::RepeatedDirectReceipt {
                    self.validate_repeated_direct_ack_receipt_v1(
                        client_message_id
                            .as_deref()
                            .expect("repeated Direct ACK has a validated client message id"),
                        message_id,
                        *server_timestamp,
                    )?;
                }
                Ok(ConnectionReconciliationV1::MessageAck(correlation))
            }
            ConnectionEvent::Error {
                code,
                ref_seq: Some(ref_seq),
                client_message_id,
                reason,
                ..
            } => {
                let correlation = self
                    .validate_error_correlation_v1(
                        *ref_seq,
                        *code,
                        client_message_id.as_deref(),
                        reason.as_deref(),
                    )
                    .map_err(ConnectionReconciliationValidationErrorV1::ProtocolViolation)?;
                if correlation == ErrorCorrelationV1::RepeatedDirectReceipt {
                    self.validate_repeated_direct_error_receipt_v1(
                        client_message_id
                            .as_deref()
                            .expect("repeated Direct error has a validated client message id"),
                        reason
                            .as_deref()
                            .expect("repeated Direct error has a validated stable reason"),
                    )?;
                }
                Ok(ConnectionReconciliationV1::Error(correlation))
            }
            _ => Ok(ConnectionReconciliationV1::None),
        }
    }

    fn reconcile_previous_transport_before_install_v1(&mut self) -> Result<(), String> {
        if let Err(error) = self.mark_all_pending_sequences_unknown() {
            // A transaction commit error leaves delivery-state durability
            // genuinely ambiguous. Neither the old nor the newly authenticated
            // socket may remain usable until a successful native re-unlock.
            self.revoke_after_storage_uncertain_v1();
            return Err(format!(
                "reconcile previous transport delivery state: {error}"
            ));
        }
        Ok(())
    }

    fn finalize_outgoing_message(
        &mut self,
        sequence: u64,
        client_message_id: Option<&str>,
        server_message_id: &str,
        server_timestamp: u64,
    ) -> Result<Option<String>, String> {
        let pending = self.pending_outgoing_messages.get(&sequence).cloned();
        if pending.is_none() && client_message_id.is_none() {
            // Generic, mutation and Sender-Key acknowledgements are
            // reconciled by their dedicated sequence maps below. Their wire
            // contract deliberately has no chat-message id/timestamp tuple.
            return Ok(None);
        }
        if let Some(client_message_id) = client_message_id {
            if self
                .pending_outgoing_sequence_for_client_id_v1(client_message_id)?
                .is_some_and(|authoritative_sequence| authoritative_sequence != sequence)
            {
                return Err(
                    "message ACK sequence does not match its live client message correlation"
                        .to_string(),
                );
            }
        }
        if let Some(pending) = pending.as_ref() {
            if client_message_id != Some(pending.local_message_id.as_str()) {
                return Err("message ACK client id does not match the pending send".to_string());
            }
        }
        if server_message_id.is_empty() {
            return Err("message ACK is missing the server message id".to_string());
        }
        let timestamp_ms = i64::try_from(server_timestamp / 1_000_000)
            .map_err(|_| "server message timestamp exceeds i64".to_string())?;

        // A durable Direct ACK is authoritative by client_message_id, not by
        // the ephemeral socket sequence. This also makes an identical ACK
        // after process death harmless: SQLCipher retains the compact receipt.
        if let Some(client_message_id) = client_message_id {
            let use_direct_outbox = pending
                .as_ref()
                .is_none_or(|pending| pending.durable_direct_outbox);
            if use_direct_outbox {
                let scope = self
                    .current_direct_outbox_scope_v1()
                    .map_err(|error| match error {
                        DirectSendErrorV1::Rejected(detail)
                        | DirectSendErrorV1::StorageUncertain(detail) => detail,
                    })?;
                let db = self.db.as_ref().ok_or("database not initialized")?;
                let acknowledged = if pending.is_some() {
                    db.acknowledge_direct_message_outbox_v1(
                        &scope,
                        client_message_id,
                        server_message_id,
                        timestamp_ms,
                    )?
                } else {
                    db.validate_repeated_direct_message_outbox_ack_v1(
                        &scope,
                        client_message_id,
                        server_message_id,
                        timestamp_ms,
                    )?
                };
                if acknowledged.client_message_id != client_message_id
                    || acknowledged.server_message_id != server_message_id
                    || acknowledged.server_timestamp_ms != timestamp_ms
                    || pending.as_ref().is_some_and(|pending| {
                        pending.local_message_id != acknowledged.local_message_id
                    })
                {
                    return Err(
                        "Direct outbox ACK receipt conflicts with the transport event".to_string(),
                    );
                }
                self.pending_outgoing_messages.remove(&sequence);
                if let Some(indexer) = self.indexer.as_ref() {
                    let _ = indexer.delete(&acknowledged.local_message_id);
                    if let Some(pending) = pending
                        .as_ref()
                        .filter(|pending| !pending.plaintext.is_empty())
                    {
                        let _ = indexer.index_message(
                            server_message_id,
                            &pending.conversation_id,
                            &hex::encode(pending.sender_identity_key),
                            &pending.plaintext,
                            timestamp_ms,
                        );
                    }
                }
                return Ok(Some(acknowledged.local_message_id.clone()));
            }
        }

        let Some(pending) = pending else {
            return Ok(None);
        };
        if let Some(db) = self.db.as_ref() {
            db.acknowledge_outgoing_message(
                &pending.local_message_id,
                server_message_id,
                timestamp_ms,
            )?;
        }
        self.pending_outgoing_messages.remove(&sequence);
        if let Some(indexer) = self.indexer.as_ref() {
            let _ = indexer.delete(&pending.local_message_id);
            let _ = indexer.index_message(
                server_message_id,
                &pending.conversation_id,
                &hex::encode(pending.sender_identity_key),
                &pending.plaintext,
                timestamp_ms,
            );
        }
        Ok(Some(pending.local_message_id.clone()))
    }

    fn confirm_initial_message(&mut self, sequence: u64) -> Result<(), String> {
        if !self.pending_initial_sequences.contains_key(&sequence) {
            return Ok(());
        }
        // A server ACK proves durable transport only, not that the peer can
        // derive this X3DH session. The send transition is already durable;
        // rewriting it here would create a stale-writer rollback window. Keep
        // attaching the initial metadata until an authenticated inbound DM
        // proves peer possession.
        self.pending_initial_sequences.remove(&sequence);
        Ok(())
    }

    fn confirm_peer_session_possession(
        &mut self,
        peer_identity_key: &[u8; 32],
    ) -> Result<(), String> {
        if !self.pending_initial_headers.contains_key(peer_identity_key) {
            return Ok(());
        }
        if let Some(db) = self.db.as_ref() {
            db.clear_pending_initial_header(peer_identity_key)?;
        }
        self.pending_initial_headers.remove(peer_identity_key);
        self.pending_initial_sequences
            .retain(|_, peer| peer != peer_identity_key);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_only_confirm_peer_session_possession(
        &mut self,
        peer_identity_key: &[u8; 32],
    ) -> Result<(), String> {
        self.confirm_peer_session_possession(peer_identity_key)
    }

    fn confirm_sender_key_distribution(
        &mut self,
        sequence: u64,
        ack: Option<&crate::connection::SenderKeyAckMetadataV1>,
    ) -> Result<(), String> {
        if let Some(receipt) = self
            .pending_sender_key_receipt_sequences
            .get(&sequence)
            .cloned()
        {
            let ack = ack.ok_or("Sender-Key receipt acknowledgement omitted exact metadata")?;
            if ack.conversation_id != receipt.conversation_id
                || ack.generation != receipt.generation
                || ack.target_device_id != receipt.target_device_id
                || ack.roster_version != receipt.roster_version
                || ack.membership_epoch != receipt.membership_epoch
                || ack.membership_epoch_hash != receipt.membership_epoch_hash
                || ack.envelope_commitment != receipt.envelope_commitment
            {
                return Err("Sender-Key receipt acknowledgement metadata mismatch".to_string());
            }
            self.pending_sender_key_receipt_sequences.remove(&sequence);
            self.pending_sender_key_receipt_set.remove(&receipt);
            return Ok(());
        }
        let Some(pending) = self.pending_sender_key_sequences.get(&sequence).cloned() else {
            if ack.is_some() {
                return Err("unexpected Sender-Key acknowledgement sequence".to_string());
            }
            return Ok(());
        };
        let ack = ack.ok_or("Sender-Key acknowledgement omitted exact route metadata")?;
        if ack.conversation_id != pending.conversation_id
            || ack.generation != pending.generation
            || ack.target_device_id != pending.target_device_id
            || ack.roster_version != pending.roster_version
            || ack.membership_epoch != pending.membership_epoch
            || ack.membership_epoch_hash != pending.membership_epoch_hash
            || ack.envelope_commitment != pending.envelope_commitment
        {
            return Err("Sender-Key acknowledgement route metadata mismatch".to_string());
        }
        let roster = self
            .device_rosters
            .get(&pending.conversation_id)
            .ok_or("Sender-Key acknowledgement arrived without a current roster proof")?;
        if roster.version != pending.roster_version
            || roster.commitment != pending.roster_commitment
        {
            return Err("Sender-Key acknowledgement belongs to a stale roster".to_string());
        }
        let still_waiting =
            self.pending_sender_key_sequences
                .iter()
                .any(|(pending_sequence, other)| {
                    *pending_sequence != sequence
                        && other.conversation_id == pending.conversation_id
                        && other.generation == pending.generation
                        && other.roster_version == pending.roster_version
                });
        let completed = !still_waiting
            && !self
                .failed_sender_key_distributions
                .contains(&pending.conversation_id);
        if completed {
            // Keep every recipient's exact envelope until the whole fan-out
            // succeeds. If one ACK arrives and a later ACK is lost, desktop
            // retries the full current roster and must reuse the earlier bytes.
            self.clear_sender_key_envelope_generation(
                &pending.conversation_id,
                pending.generation,
                pending.roster_version,
            )?;
        }
        self.pending_sender_key_sequences.remove(&sequence);
        if completed {
            self.sender_key_distribution_pending
                .remove(&pending.conversation_id);
            self.prepared_sender_key_generations
                .remove(&pending.conversation_id);
        }
        Ok(())
    }

    fn confirm_pending_mutation(
        &mut self,
        sequence: u64,
        _server_timestamp: u64,
    ) -> Result<Option<ConfirmedMutation>, String> {
        let Some(mutation) = self.pending_mutations.get(&sequence) else {
            return Ok(None);
        };

        if let Some(db) = self.db.as_ref() {
            match &mutation {
                ConfirmedMutation::Edit {
                    message_id,
                    new_text,
                    ..
                } => db.update_message_text(message_id, new_text)?,
                ConfirmedMutation::Delete { message_id, .. } => db.delete_message(message_id)?,
                ConfirmedMutation::Reaction {
                    message_id,
                    emoji,
                    user_id,
                    add,
                    ..
                } => {
                    if *add {
                        db.add_reaction(message_id, user_id, emoji, "You")?;
                    } else {
                        db.remove_reaction(message_id, user_id, emoji)?;
                    }
                }
            }
        }

        if let Some(indexer) = self.indexer.as_ref() {
            match &mutation {
                ConfirmedMutation::Edit {
                    message_id,
                    new_text,
                    ..
                } => {
                    let _ = indexer.update_message_body(message_id, new_text);
                }
                ConfirmedMutation::Delete { message_id, .. } => {
                    let _ = indexer.delete(message_id);
                }
                ConfirmedMutation::Reaction { .. } => {}
            }
        }

        Ok(self.pending_mutations.remove(&sequence))
    }

    fn reject_pending_sequence(&mut self, sequence: u64) -> Result<Option<String>, String> {
        if let Some(receipt) = self.pending_sender_key_receipt_sequences.remove(&sequence) {
            self.pending_sender_key_receipt_set.remove(&receipt);
        }
        self.pending_initial_sequences.remove(&sequence);
        if let Some(ConfirmedMutation::Edit { new_text, .. }) =
            self.pending_mutations.remove(&sequence).as_mut()
        {
            new_text.zeroize();
        }
        if let Some(pending) = self.pending_sender_key_sequences.remove(&sequence) {
            self.failed_sender_key_distributions
                .insert(pending.conversation_id);
        }
        let Some(pending) = self.pending_outgoing_messages.get(&sequence) else {
            return Ok(None);
        };
        if let Some(db) = self.db.as_ref() {
            db.mark_outgoing_message_failed(&pending.local_message_id)?;
        }
        let local_message_id = pending.local_message_id.clone();
        self.pending_outgoing_messages.remove(&sequence);
        Ok(Some(local_message_id))
    }

    fn reconcile_outgoing_error_v1(
        &mut self,
        sequence: u64,
        code: u32,
        client_message_id: Option<&str>,
        reason: Option<&str>,
    ) -> Result<Option<String>, String> {
        let pending = self.pending_outgoing_messages.get(&sequence).cloned();
        if let Some(client_message_id) = client_message_id {
            if self
                .pending_outgoing_sequence_for_client_id_v1(client_message_id)?
                .is_some_and(|authoritative_sequence| authoritative_sequence != sequence)
            {
                return Err(
                    "send error sequence does not match its live client message correlation"
                        .to_string(),
                );
            }
        }
        if let Some(pending) = pending.as_ref() {
            if client_message_id != Some(pending.local_message_id.as_str()) || reason.is_none() {
                return Err("send error does not match its exact client message id".to_string());
            }
        }
        if reason == Some("client_message_id_conflict") {
            return Err("server rejected a reused client message id".to_string());
        }

        if let Some(client_message_id) = client_message_id {
            let use_direct_outbox = pending
                .as_ref()
                .is_none_or(|pending| pending.durable_direct_outbox);
            if use_direct_outbox {
                if is_retryable_correlated_send_error_v1(code, reason) {
                    // Keep both the SQLCipher exact payload and its current
                    // sequence correlation until the event dispatcher closes
                    // this socket epoch below. The reconnect barrier clears
                    // the sequence while preserving the Sending row for exact
                    // replay on the next Ready lease.
                    return pending
                        .map(|pending| Some(pending.local_message_id.clone()))
                        .ok_or_else(|| {
                            "retryable send error references no current Direct outbox sequence"
                                .to_string()
                        });
                }
                let rejection_reason = reason
                    .ok_or("correlated Direct send error omitted its stable rejection reason")?;
                let scope = self
                    .current_direct_outbox_scope_v1()
                    .map_err(|error| match error {
                        DirectSendErrorV1::Rejected(detail)
                        | DirectSendErrorV1::StorageUncertain(detail) => detail,
                    })?;
                let db = self.db.as_ref().ok_or("database not initialized")?;
                let rejected = if pending.is_some() {
                    db.reject_direct_message_outbox_v1(&scope, client_message_id, rejection_reason)?
                } else {
                    db.validate_repeated_direct_message_outbox_rejection_v1(
                        &scope,
                        client_message_id,
                        rejection_reason,
                    )?
                };
                if rejected.client_message_id != client_message_id
                    || rejected.rejection_reason != rejection_reason
                    || pending.as_ref().is_some_and(|pending| {
                        pending.local_message_id != rejected.local_message_id
                    })
                {
                    return Err(
                        "Direct outbox rejection receipt conflicts with the transport event"
                            .to_string(),
                    );
                }
                self.pending_outgoing_messages.remove(&sequence);
                self.pending_initial_sequences.remove(&sequence);
                return Ok(Some(rejected.local_message_id.clone()));
            }
        }

        self.reject_pending_sequence(sequence)
    }

    #[cfg(test)]
    fn mark_pending_sequence_unknown(&mut self, sequence: u64) -> Result<Option<String>, String> {
        self.pending_initial_sequences.remove(&sequence);
        if let Some(ConfirmedMutation::Edit { new_text, .. }) =
            self.pending_mutations.remove(&sequence).as_mut()
        {
            new_text.zeroize();
        }
        if let Some(pending) = self.pending_sender_key_sequences.remove(&sequence) {
            // Retrying the exact Sender Key generation is safe and required
            // when its durable-storage ACK was lost.
            self.failed_sender_key_distributions
                .insert(pending.conversation_id);
        }
        let Some(pending) = self.pending_outgoing_messages.get(&sequence) else {
            return Ok(None);
        };
        if let Some(db) = self.db.as_ref() {
            db.mark_outgoing_message_unknown(&pending.local_message_id)?;
        }
        let local_message_id = pending.local_message_id.clone();
        self.pending_outgoing_messages.remove(&sequence);
        Ok(Some(local_message_id))
    }

    pub fn discard_failed_outgoing_message(&self, local_message_id: &str) -> Result<(), String> {
        self.require_message_conversation_available_v1(local_message_id)?;
        let db = self.db.as_ref().ok_or("database not initialized")?;
        if !db.is_discardable_outgoing_message(local_message_id)? {
            return Err("failed or unknown outgoing message not found".to_string());
        }
        if let Some(indexer) = self.indexer.as_ref() {
            indexer
                .delete(local_message_id)
                .map_err(|e| format!("remove local draft from search index: {e}"))?;
        }
        db.discard_failed_outgoing_message(local_message_id)
    }

    /// Send a text message to a conversation.
    /// Fails closed unless the conversation has an established E2E mode.
    pub async fn send_message(
        &mut self,
        conversation_id: &str,
        plaintext: &str,
        reply_to_id: Option<&str>,
    ) -> Result<u64, String> {
        self.send_message_with_attachments(conversation_id, plaintext, reply_to_id, Vec::new())
            .await
    }

    /// Send text and zero or more already-uploaded encrypted attachments.
    /// Attachment keys and private metadata are sealed into the same E2EE
    /// payload; the gateway receives only descriptor commitments.
    pub async fn send_message_with_attachments(
        &mut self,
        conversation_id: &str,
        plaintext: &str,
        reply_to_id: Option<&str>,
        attachments: Vec<crate::attachments::OutgoingAttachmentV1>,
    ) -> Result<u64, String> {
        let result = self
            .send_message_with_attachments_classified_v1(
                conversation_id,
                plaintext,
                reply_to_id,
                attachments,
            )
            .await;
        self.resolve_public_direct_send_v1(result)
    }

    async fn send_message_with_attachments_classified_v1(
        &mut self,
        conversation_id: &str,
        plaintext: &str,
        reply_to_id: Option<&str>,
        attachments: Vec<crate::attachments::OutgoingAttachmentV1>,
    ) -> Result<u64, DirectSendErrorV1> {
        self.require_direct_conversation_available_v1(conversation_id)
            .map_err(DirectSendErrorV1::rejected)?;
        if plaintext.is_empty() && attachments.is_empty() {
            return Err(DirectSendErrorV1::rejected(
                "message plaintext must not be empty",
            ));
        }
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(DirectSendErrorV1::rejected(format!(
                "message plaintext exceeds {MAX_PLAINTEXT_BYTES} bytes"
            )));
        }
        if self.connection.is_none() {
            return Err(DirectSendErrorV1::rejected("not connected"));
        }
        let (encrypted_plaintext, wire_attachments, stored_attachments) = if attachments.is_empty()
        {
            (
                Zeroizing::new(plaintext.to_string()),
                Vec::new(),
                Vec::new(),
            )
        } else {
            let (payload, wire, stored) = crate::attachments::build_outgoing_attachment_message_v1(
                conversation_id,
                plaintext,
                attachments,
            )
            .map_err(DirectSendErrorV1::rejected)?;
            (
                Zeroizing::new(String::from_utf8(payload.to_vec()).map_err(|_| {
                    DirectSendErrorV1::rejected("attachment payload is not valid protocol UTF-8")
                })?),
                wire,
                stored,
            )
        };
        let seq = self
            .connection
            .as_ref()
            .ok_or_else(|| DirectSendErrorV1::rejected("not connected"))?
            .next_seq()
            .await;

        // Encrypt first (needs mutable borrow)
        let (ciphertext, header_bytes) =
            self.encrypt_outgoing_classified_v1(conversation_id, &encrypted_plaintext)?;
        let initial_peer = (header_bytes.first() == Some(&HEADER_INITIAL_V2))
            .then(|| self.dm_conversations.get(conversation_id).copied())
            .flatten();
        let our_key = self.identity_key().map_err(DirectSendErrorV1::rejected)?;
        let local_message_id = uuid::Uuid::new_v4().to_string();
        let local_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DirectSendErrorV1::rejected("system clock is before Unix epoch"))?
            .as_millis()
            .try_into()
            .map_err(|_| DirectSendErrorV1::rejected("local message timestamp exceeds i64"))?;

        if let Some(db) = self.db.as_ref() {
            db.insert_outgoing_pending_message_with_attachments(
                &local_message_id,
                conversation_id,
                &our_key,
                plaintext,
                reply_to_id,
                &stored_attachments,
            )
            .map_err(DirectSendErrorV1::storage)?;
            match db.resolve_account_by_conversation_sender(conversation_id, &our_key) {
                Ok(Some(author_snapshot)) => {
                    db.attach_message_author(&local_message_id, &author_snapshot)
                        .map_err(|error| {
                            DirectSendErrorV1::storage(format!(
                                "persist outgoing message author attribution: {error}"
                            ))
                        })?;
                }
                Ok(None) => {
                    // Legacy unscoped conversations remain usable; their own
                    // messages are still rendered as `You`, without inventing
                    // an origin or account locator.
                }
                Err(error) => {
                    return Err(DirectSendErrorV1::storage(format!(
                        "resolve outgoing message author attribution: {error}"
                    )));
                }
            }
        }
        if !plaintext.is_empty() {
            if let Some(indexer) = self.indexer.as_ref() {
                if let Err(error) = indexer.index_message(
                    &local_message_id,
                    conversation_id,
                    &hex::encode(our_key),
                    plaintext,
                    local_timestamp,
                ) {
                    if let Some(db) = self.db.as_ref() {
                        db.mark_outgoing_message_failed(&local_message_id)
                            .map_err(DirectSendErrorV1::storage)?;
                    }
                    let _ = indexer.delete(&local_message_id);
                    return Err(DirectSendErrorV1::rejected(format!(
                        "index pending outgoing message: {error}"
                    )));
                }
            }
        }

        let roster_proof = if self.channel_conversations.contains(conversation_id) {
            let roster = self.device_rosters.get(conversation_id).ok_or_else(|| {
                DirectSendErrorV1::rejected("validated current device roster is unavailable")
            })?;
            Some(roster)
        } else {
            None
        };
        let membership_proof = roster_proof
            .filter(|roster| roster.membership_activated)
            .map(|roster| {
                let head = self
                    .membership_epoch_heads
                    .get(conversation_id)
                    .ok_or_else(|| {
                        DirectSendErrorV1::rejected(
                            "verified membership epoch is unavailable for this roster",
                        )
                    })?;
                if head.epoch != roster.membership_epoch
                    || head.hash != roster.membership_epoch_hash
                    || head.roster_version != roster.version
                    || head.roster_commitment != roster.commitment
                {
                    return Err(DirectSendErrorV1::rejected(
                        "verified membership epoch does not match this roster",
                    ));
                }
                Ok((head.epoch, head.hash))
            })
            .transpose()?;
        let direct_state = if roster_proof.is_none() {
            let peer = self.dm_conversations.get(conversation_id).ok_or_else(|| {
                DirectSendErrorV1::rejected("Direct conversation has no authenticated peer route")
            })?;
            Some(self.direct_v2_sessions.get(peer).ok_or_else(|| {
                DirectSendErrorV1::rejected("Direct v2 session is required for outgoing traffic")
            })?)
        } else {
            None
        };
        let send_msg = proto::SendMessage {
            conversation_id: conversation_id.to_string(),
            ciphertext,
            header: header_bytes,
            msg_type: if wire_attachments.is_empty() {
                proto::MessageType::Text.into()
            } else {
                proto::MessageType::File.into()
            },
            reply_to_id: reply_to_id.map(|s| s.to_string()),
            ttl_seconds: None,
            attachments: wire_attachments
                .into_iter()
                .map(|attachment| proto::EncryptedAttachment {
                    media_id: attachment.media_id,
                    encrypted_key: attachment.encrypted_key,
                    nonce: attachment.nonce,
                    size: attachment.size,
                    content_type: attachment.content_type,
                })
                .collect(),
            sealed: false,
            // Populated by the per-device roster integration. Zero/empty is
            // valid only for DMs; the gateway rejects Sender-Key traffic that
            // does not carry an exact authenticated roster proof.
            roster_version: roster_proof.map_or(0, |roster| roster.version),
            roster_commitment: roster_proof
                .map_or_else(Vec::new, |roster| roster.commitment.to_vec()),
            client_message_id: local_message_id.clone(),
            crypto_profile: membership_proof.map_or_else(
                || DIRECT_CRYPTO_PROFILE_V2.to_string(),
                |_| "sender_key_v6".to_string(),
            ),
            crypto_era: membership_proof.map_or(DIRECT_CRYPTO_ERA_V2, |_| 1),
            target_device_id: direct_state
                .map_or_else(Vec::new, |state| state.peer().device.device_id.to_vec()),
            target_binding_version: direct_state
                .map_or(0, |state| state.peer().device.binding_version),
            direct_session_id: direct_state
                .map_or_else(Vec::new, |state| state.session_id().to_vec()),
            membership_epoch: membership_proof.map_or(0, |proof| proof.0),
            membership_epoch_hash: membership_proof.map_or_else(Vec::new, |proof| proof.1.to_vec()),
        };

        let env = proto::Envelope {
            seq,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::SendMessage(send_msg)),
        };

        if let Err(error) = self
            .connection
            .as_ref()
            .ok_or_else(|| DirectSendErrorV1::rejected("not connected"))?
            .send_envelope(&env)
            .await
        {
            if let Some(db) = self.db.as_ref() {
                db.mark_outgoing_message_failed(&local_message_id)
                    .map_err(DirectSendErrorV1::storage)?;
            } else if let Some(indexer) = self.indexer.as_ref() {
                let _ = indexer.delete(&local_message_id);
            }
            return Err(DirectSendErrorV1::rejected(error));
        }
        if let Some(peer_identity_key) = initial_peer {
            self.pending_initial_sequences
                .insert(seq, peer_identity_key);
        }
        self.pending_outgoing_messages.insert(
            seq,
            PendingOutgoingMessage {
                local_message_id,
                conversation_id: conversation_id.to_string(),
                sender_identity_key: our_key,
                plaintext: plaintext.to_string(),
                durable_direct_outbox: false,
                direct_ack_deadline: None,
            },
        );

        Ok(seq)
    }

    /// Atomically accept one Direct text intent into SQLCipher before any
    /// network write. A successful result always means the native outbox owns
    /// the intent, even when the bounded transport queue could not accept it.
    pub async fn enqueue_direct_text_v1(
        &mut self,
        conversation_id: &str,
        plaintext: &str,
    ) -> Result<DirectMessageEnqueueReportV1, DirectSendErrorV1> {
        let result = self
            .enqueue_direct_text_inner_v1(conversation_id, plaintext)
            .await;
        if matches!(result, Err(DirectSendErrorV1::StorageUncertain(_))) {
            self.revoke_after_storage_uncertain_v1();
        }
        result
    }

    async fn enqueue_direct_text_inner_v1(
        &mut self,
        conversation_id: &str,
        plaintext: &str,
    ) -> Result<DirectMessageEnqueueReportV1, DirectSendErrorV1> {
        if !self.is_connected() {
            return Err(DirectSendErrorV1::rejected(
                "authenticated transport is unavailable",
            ));
        }
        let scope = self.current_direct_outbox_scope_v1()?;
        let pending_count = self
            .db
            .as_ref()
            .ok_or_else(|| DirectSendErrorV1::rejected("SQLCipher database is unavailable"))?
            .count_pending_direct_message_outbox_v1(&scope)
            .map_err(DirectSendErrorV1::storage)?;
        if pending_count >= DIRECT_MESSAGE_OUTBOX_MAX_PENDING_V1 {
            return Err(DirectSendErrorV1::rejected(
                "Direct outbox is full; reconnect and wait for pending sends",
            ));
        }
        self.require_direct_conversation_available_v1(conversation_id)
            .map_err(DirectSendErrorV1::rejected)?;
        if !Self::is_canonical_live_uuid_v1(conversation_id) {
            return Err(DirectSendErrorV1::rejected(
                "Direct conversation id is not canonical",
            ));
        }
        if plaintext.is_empty() {
            return Err(DirectSendErrorV1::rejected(
                "message plaintext must not be empty",
            ));
        }
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(DirectSendErrorV1::rejected(format!(
                "message plaintext exceeds {MAX_PLAINTEXT_BYTES} bytes"
            )));
        }
        if self.channel_conversations.contains(conversation_id) {
            return Err(DirectSendErrorV1::rejected(
                "atomic Direct text send cannot select a channel route",
            ));
        }
        let peer_identity_key = self
            .dm_conversations
            .get(conversation_id)
            .copied()
            .ok_or_else(|| {
                DirectSendErrorV1::rejected("Direct conversation has no authenticated peer route")
            })?;
        if !self.trusted_signing_keys.contains_key(&peer_identity_key) {
            return Err(DirectSendErrorV1::rejected(
                "Direct peer signing key is not pinned",
            ));
        }
        let our_identity_key = self.identity_key().map_err(DirectSendErrorV1::rejected)?;
        let local_timestamp_ms: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DirectSendErrorV1::rejected("system clock is before Unix epoch"))?
            .as_millis()
            .try_into()
            .map_err(|_| DirectSendErrorV1::rejected("local message timestamp exceeds i64"))?;

        let current_ratchet = self
            .ratchet_sessions
            .get(&peer_identity_key)
            .ok_or_else(|| DirectSendErrorV1::rejected("no ratchet session with this peer"))?;
        let persisted_ratchet = self
            .db
            .as_ref()
            .ok_or_else(|| DirectSendErrorV1::rejected("SQLCipher database is unavailable"))?
            .load_ratchet_session_with_revision_v1(&peer_identity_key)
            .map_err(DirectSendErrorV1::storage)?
            .ok_or_else(|| {
                DirectSendErrorV1::storage("Direct ratchet session is absent from SQLCipher")
            })?;
        if !current_ratchet
            .matches_serialized_v1(&persisted_ratchet.session_data)
            .map_err(DirectSendErrorV1::storage)?
        {
            return Err(DirectSendErrorV1::storage(
                "in-memory Direct ratchet differs from its SQLCipher revision",
            ));
        }

        let inner_plaintext = Zeroizing::new(Self::wrap_text_inner(plaintext));
        let prepared = self.prepare_direct_ciphertext_v1(
            &peer_identity_key,
            conversation_id,
            inner_plaintext.as_slice(),
        )?;
        if prepared.peer_identity_key != peer_identity_key {
            return Err(DirectSendErrorV1::storage(
                "prepared Direct ciphertext changed its peer binding",
            ));
        }
        let advanced_ratchet_session =
            Zeroizing::new(prepared.candidate.serialize().map_err(|error| {
                DirectSendErrorV1::storage(format!(
                    "serialize advanced Direct ratchet session: {error}"
                ))
            })?);
        let client_message_id = uuid::Uuid::new_v4().hyphenated().to_string();
        let send_message = proto::SendMessage {
            conversation_id: conversation_id.to_string(),
            ciphertext: prepared.ciphertext.clone(),
            header: prepared.header.clone(),
            msg_type: proto::MessageType::Text.into(),
            reply_to_id: None,
            ttl_seconds: None,
            attachments: Vec::new(),
            sealed: false,
            roster_version: 0,
            roster_commitment: Vec::new(),
            client_message_id: client_message_id.clone(),
            crypto_profile: self
                .direct_v2_sessions
                .get(&peer_identity_key)
                .map_or_else(String::new, |_| DIRECT_CRYPTO_PROFILE_V2.to_string()),
            crypto_era: self
                .direct_v2_sessions
                .get(&peer_identity_key)
                .map_or(0, |_| DIRECT_CRYPTO_ERA_V2),
            target_device_id: self
                .direct_v2_sessions
                .get(&peer_identity_key)
                .map_or_else(Vec::new, |state| state.peer().device.device_id.to_vec()),
            target_binding_version: self
                .direct_v2_sessions
                .get(&peer_identity_key)
                .map_or(0, |state| state.peer().device.binding_version),
            direct_session_id: self
                .direct_v2_sessions
                .get(&peer_identity_key)
                .map_or_else(Vec::new, |state| state.session_id().to_vec()),
            membership_epoch: 0,
            membership_epoch_hash: Vec::new(),
        };
        let exact_send_message_payload = send_message.encode_to_vec();
        let request_digest = send_message_request_digest_v1(&exact_send_message_payload);
        let author_snapshot = self
            .db
            .as_ref()
            .ok_or_else(|| DirectSendErrorV1::rejected("SQLCipher database is unavailable"))?
            .resolve_account_by_conversation_sender(conversation_id, &our_identity_key)
            .map_err(DirectSendErrorV1::storage)?
            .ok_or_else(|| {
                DirectSendErrorV1::storage("authenticated self is absent from the Direct directory")
            })?;
        let enqueue = DirectMessageOutboxEnqueueV1 {
            scope: scope.clone(),
            conversation_id: conversation_id.to_string(),
            client_message_id: client_message_id.clone(),
            local_message_id: client_message_id.clone(),
            request_digest,
            exact_send_message_payload: exact_send_message_payload.clone(),
            expected_ratchet_revision: persisted_ratchet.revision,
            expected_ratchet_session: persisted_ratchet.session_data.to_vec(),
            advanced_ratchet_session: advanced_ratchet_session.to_vec(),
            plaintext: plaintext.to_string(),
            reply_to_id: None,
            attachments: Vec::new(),
            author_snapshot: Some(author_snapshot),
        };
        let committed = self
            .db
            .as_ref()
            .ok_or_else(|| DirectSendErrorV1::rejected("SQLCipher database is unavailable"))?
            .enqueue_direct_message_outbox_v1(&enqueue)
            .map_err(DirectSendErrorV1::storage)?;
        if committed.client_message_id != client_message_id
            || committed.local_message_id != client_message_id
            || committed.queue_order == 0
            || committed.ratchet_revision
                != persisted_ratchet.revision.checked_add(1).ok_or_else(|| {
                    DirectSendErrorV1::storage("Direct ratchet revision is exhausted")
                })?
        {
            return Err(DirectSendErrorV1::storage(
                "SQLCipher returned an inconsistent Direct outbox commit receipt",
            ));
        }

        // Publish the already-committed candidate only after SQLCipher owns
        // the corresponding exact payload. From here on delivery is unknown;
        // only source-typed, allowlisted transport failures are retryable, and
        // no failure may roll the ratchet or local row back.
        self.ratchet_sessions
            .insert(peer_identity_key, prepared.candidate);
        if let Some(indexer) = self.indexer.as_ref() {
            let _ = indexer.index_message(
                &client_message_id,
                conversation_id,
                &hex::encode(our_identity_key),
                plaintext,
                local_timestamp_ms,
            );
        }

        #[cfg(any(test, feature = "test-utils"))]
        if std::mem::take(&mut self.test_only_epoch_invalid_after_direct_commit) {
            self.connection
                .as_ref()
                .expect("Direct outbox scope requires a live connection handle")
                .test_only_report_websocket_error_v1(
                    tokio_tungstenite::tungstenite::Error::Capacity(
                        tokio_tungstenite::tungstenite::error::CapacityError::MessageTooLong {
                            size: 2,
                            max_size: 1,
                        },
                    ),
                );
        }

        #[cfg(any(test, feature = "test-utils"))]
        if std::mem::take(&mut self.test_only_retryable_after_direct_commit) {
            self.connection
                .as_ref()
                .expect("Direct outbox scope requires a live connection handle")
                .test_only_report_websocket_error_v1(
                    tokio_tungstenite::tungstenite::Error::Protocol(
                        tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
                    ),
                );
        }

        let connection = self
            .connection
            .as_ref()
            .expect("Direct outbox scope requires a live connection handle");
        let sequence = connection.next_seq().await;
        let enqueue_result = connection
            .send_preencoded_send_message_with_seq_v1(sequence, &exact_send_message_payload)
            .await;
        let transport_enqueued = enqueue_result.is_ok();
        // The read/write task can publish a terminal concurrently with a
        // successful bounded mpsc enqueue. Preserve that typed source even in
        // the success race so native code never returns plain Accepted for an
        // already invalid socket epoch.
        let transport_stop = self.classify_direct_enqueue_result_v1(&enqueue_result);
        if transport_enqueued {
            self.pending_outgoing_messages.insert(
                sequence,
                PendingOutgoingMessage {
                    local_message_id: client_message_id,
                    conversation_id: conversation_id.to_string(),
                    sender_identity_key: our_identity_key,
                    plaintext: plaintext.to_string(),
                    durable_direct_outbox: true,
                    direct_ack_deadline: Some(next_direct_ack_deadline_v1()),
                },
            );
        }
        Ok(DirectMessageEnqueueReportV1 {
            sequence,
            transport_enqueued,
            transport_stop,
        })
    }

    /// Replay a bounded FIFO page of exact Direct payloads after a new Ready
    /// lease. The cursor is valid only for that native lease and advances only
    /// past rows already represented on the current transport.
    pub async fn replay_direct_outbox_v1(
        &mut self,
        after_queue_order: Option<u64>,
        limit: usize,
    ) -> Result<DirectOutboxReplayReportV1, DirectSendErrorV1> {
        let result = self
            .replay_direct_outbox_inner_v1(after_queue_order, limit)
            .await;
        if matches!(result, Err(DirectSendErrorV1::StorageUncertain(_))) {
            self.revoke_after_storage_uncertain_v1();
        }
        result
    }

    async fn replay_direct_outbox_inner_v1(
        &mut self,
        after_queue_order: Option<u64>,
        limit: usize,
    ) -> Result<DirectOutboxReplayReportV1, DirectSendErrorV1> {
        if limit == 0 || limit > 256 {
            return Err(DirectSendErrorV1::rejected(
                "Direct outbox replay limit is invalid",
            ));
        }
        let terminal_stop = self
            .observe_connection_terminal_stop_v1()
            .or_else(|| self.current_direct_live_stop_v1());
        match terminal_stop {
            Some(DirectLiveReplayStopV1::EpochInvalid) => {
                return Err(DirectSendErrorV1::rejected(
                    "authenticated Direct transport epoch is invalid",
                ));
            }
            Some(DirectLiveReplayStopV1::StorageUncertain) => {
                return Err(DirectSendErrorV1::storage(
                    "Direct outbox replay storage is uncertain",
                ));
            }
            Some(
                DirectLiveReplayStopV1::RetryableTransport | DirectLiveReplayStopV1::AckDeadline,
            ) if self.connection.is_none()
                || self.authenticated_user_id.is_none()
                || self.authenticated_server_origin.is_none() =>
            {
                return Ok(DirectOutboxReplayReportV1 {
                    next_queue_order: after_queue_order,
                    transport_blocked: true,
                    ..DirectOutboxReplayReportV1::default()
                });
            }
            _ => {}
        }
        let scope = self.current_direct_outbox_scope_v1()?;
        let pending_rows = self
            .db
            .as_ref()
            .ok_or_else(|| DirectSendErrorV1::rejected("SQLCipher database is unavailable"))?
            .load_pending_direct_message_outbox_after_v1(&scope, after_queue_order, limit)
            .map_err(DirectSendErrorV1::storage)?;
        let page_len = pending_rows.len();
        let our_identity_key = self.identity_key().map_err(DirectSendErrorV1::rejected)?;
        let mut report = DirectOutboxReplayReportV1 {
            next_queue_order: after_queue_order,
            ..DirectOutboxReplayReportV1::default()
        };
        if matches!(
            terminal_stop,
            Some(DirectLiveReplayStopV1::RetryableTransport | DirectLiveReplayStopV1::AckDeadline)
        ) {
            report.pending_total = self
                .db
                .as_ref()
                .ok_or_else(|| DirectSendErrorV1::rejected("SQLCipher database is unavailable"))?
                .count_pending_direct_message_outbox_v1(&scope)
                .map_err(DirectSendErrorV1::storage)?;
            report.transport_blocked = true;
            return Ok(report);
        }

        for pending in pending_rows {
            if self.stop_direct_outbox_replay_if_terminal_v1(&mut report)? {
                break;
            }
            report.visited = report
                .visited
                .checked_add(1)
                .ok_or_else(|| DirectSendErrorV1::storage("Direct replay counter overflow"))?;
            let _decoded = self.validate_pending_direct_outbox_payload_v1(&scope, &pending)?;
            if let Some(existing) = self
                .pending_outgoing_messages
                .values()
                .find(|candidate| candidate.local_message_id == pending.client_message_id)
            {
                if !existing.durable_direct_outbox
                    || existing.conversation_id != pending.conversation_id
                    || existing.sender_identity_key != our_identity_key
                {
                    return Err(DirectSendErrorV1::storage(
                        "current transport has a conflicting Direct outbox correlation",
                    ));
                }
                report.next_queue_order = Some(pending.queue_order);
                continue;
            }

            let connection = self.connection.as_ref().ok_or_else(|| {
                DirectSendErrorV1::rejected("authenticated transport is unavailable")
            })?;
            let sequence = connection.next_seq().await;
            let enqueue_result = connection
                .send_preencoded_send_message_with_seq_v1(
                    sequence,
                    &pending.exact_send_message_payload,
                )
                .await;
            if enqueue_result.is_err() {
                match self.classify_direct_enqueue_result_v1(&enqueue_result) {
                    Some(DirectLiveReplayStopV1::EpochInvalid) => {
                        return Err(DirectSendErrorV1::rejected(
                            "authenticated Direct transport epoch is invalid",
                        ));
                    }
                    Some(DirectLiveReplayStopV1::StorageUncertain) => {
                        return Err(DirectSendErrorV1::storage(
                            "Direct outbox replay storage is uncertain",
                        ));
                    }
                    Some(
                        DirectLiveReplayStopV1::RetryableTransport
                        | DirectLiveReplayStopV1::AckDeadline,
                    )
                    | None => {
                        report.transport_blocked = true;
                        break;
                    }
                }
            }
            self.pending_outgoing_messages.insert(
                sequence,
                PendingOutgoingMessage {
                    local_message_id: pending.client_message_id.clone(),
                    conversation_id: pending.conversation_id.clone(),
                    sender_identity_key: our_identity_key,
                    // Native-only copy used to repair the local search index
                    // if the ACK renames the provisional UUID.
                    plaintext: pending.plaintext.clone(),
                    durable_direct_outbox: true,
                    direct_ack_deadline: Some(next_direct_ack_deadline_v1()),
                },
            );
            #[cfg(any(test, feature = "test-utils"))]
            if std::mem::take(&mut self.test_only_epoch_invalid_after_direct_outbox_enqueue) {
                self.test_only_report_epoch_invalid_transport_v1();
            }
            report.enqueued = report
                .enqueued
                .checked_add(1)
                .ok_or_else(|| DirectSendErrorV1::storage("Direct replay counter overflow"))?;
            report.next_queue_order = Some(pending.queue_order);
            // A WebSocket task may publish a typed terminal after the bounded
            // channel accepted the exact frame. Retain the live sequence and
            // ACK deadline for those queued bytes, but never report Ready for
            // an already invalid or retry-required transport epoch.
            if self.stop_direct_outbox_replay_if_terminal_v1(&mut report)? {
                break;
            }
        }
        report.pending_total = self
            .db
            .as_ref()
            .ok_or_else(|| DirectSendErrorV1::rejected("SQLCipher database is unavailable"))?
            .count_pending_direct_message_outbox_v1(&scope)
            .map_err(DirectSendErrorV1::storage)?;
        // Close the same race for an empty page and for the final row (which
        // may already have had a process-local correlation before this turn).
        self.stop_direct_outbox_replay_if_terminal_v1(&mut report)?;
        report.reached_end = !report.transport_blocked && page_len < limit;
        Ok(report)
    }

    /// Check if we're connected to the server.
    pub fn is_connected(&self) -> bool {
        if self.current_direct_live_stop_v1().is_some() {
            return false;
        }
        self.connection
            .as_ref()
            .is_some_and(|connection| connection.events.terminal_buffer_error_v1().is_none())
    }

    /// Deterministically expire every current durable Direct ACK correlation
    /// without sleeping or changing the production timeout.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only_expire_direct_ack_deadlines_v1(&mut self) -> usize {
        self.direct_ack_expiry_grace_remaining.clear();
        let expired = Instant::now();
        let mut count = 0usize;
        for pending in self.pending_outgoing_messages.values_mut() {
            if pending.durable_direct_outbox {
                pending.direct_ack_deadline = Some(expired);
                count += 1;
            }
        }
        count
    }

    /// Cross-crate proof that sticky SQLCipher ambiguity never crosses a typed
    /// mobile boundary as retryable transport loss.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only_revoke_storage_uncertain_epoch_v1(&mut self) {
        self.revoke_after_storage_uncertain_v1();
    }

    /// Publish a deterministic post-auth protocol terminal without consuming
    /// it, so cross-crate tests can prove send/outbox policy remains typed.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only_report_epoch_invalid_transport_v1(&self) -> bool {
        let Some(connection) = self.connection.as_ref() else {
            return false;
        };
        connection.test_only_report_websocket_error_v1(
            tokio_tungstenite::tungstenite::Error::Capacity(
                tokio_tungstenite::tungstenite::error::CapacityError::MessageTooLong {
                    size: 2,
                    max_size: 1,
                },
            ),
        );
        true
    }

    /// Publish an allowlisted retryable post-auth transport loss for native
    /// cross-crate policy tests. No diagnostic text selects retryability.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only_report_retryable_transport_v1(&self) -> bool {
        let Some(connection) = self.connection.as_ref() else {
            return false;
        };
        connection.test_only_report_websocket_error_v1(
            tokio_tungstenite::tungstenite::Error::Protocol(
                tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
            ),
        );
        true
    }

    /// Deterministically publish an epoch-invalid terminal after SQLCipher has
    /// accepted the next Direct intent but before its transport enqueue.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only_epoch_invalid_after_next_direct_commit_v1(&mut self) {
        self.test_only_epoch_invalid_after_direct_commit = true;
    }

    /// Deterministically publish a retryable transport terminal after
    /// SQLCipher has accepted the next Direct intent but before enqueue.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only_retryable_after_next_direct_commit_v1(&mut self) {
        self.test_only_retryable_after_direct_commit = true;
    }

    /// Deterministically publish an epoch-invalid terminal after the next
    /// exact outbox frame enters the bounded transport queue.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only_epoch_invalid_after_next_direct_outbox_enqueue_v1(&mut self) {
        self.test_only_epoch_invalid_after_direct_outbox_enqueue = true;
    }

    /// Install an in-memory transport for cross-crate native integration tests.
    ///
    /// This method does not exist in production builds.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only_install_queued_connection(&mut self) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
        let (connection, outbound) = crate::connection::Connection::test_only_queued_connection();
        self.connection = Some(connection);
        outbound
    }

    /// Install a bounded in-memory transport whose inbound raw frames still
    /// traverse the production authenticated protobuf decoder and event FIFO.
    ///
    /// This bridge exists only for cross-crate process-recovery tests and is
    /// absent from every build that does not explicitly enable `test-utils`.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only_install_authenticated_queued_connection_v1(
        &mut self,
    ) -> crate::connection::TestOnlyAuthenticatedQueuedConnectionV1 {
        let (connection, transport) =
            crate::connection::Connection::test_only_authenticated_queued_connection_v1();
        self.connection = Some(connection);
        transport
    }

    /// Test-only equivalent of the production pre-install reconnect barrier.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only_reconcile_previous_transport_before_install_v1(
        &mut self,
    ) -> Result<(), String> {
        self.reconcile_previous_transport_before_install_v1()
    }

    /// Test-only bridge for cross-crate native guard tests. Production
    /// quarantine is still owned exclusively by authenticated live replay.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only_quarantine_direct_conversation_v1(&mut self, conversation_id: &str) -> bool {
        self.quarantine_known_direct_live_conversation_v1(conversation_id)
    }

    // ─── E2E Encryption ──────────────────────────────────

    /// Exact owner-only count endpoint for the currently initialized account.
    pub fn own_prekey_count_target(&self) -> Result<String, String> {
        self.require_crypto_runtime_active_v1()?;
        Ok(format!(
            "/v1/prekeys/{}/count",
            hex::encode(self.identity_key()?)
        ))
    }

    /// Load the exact origin/account/device publication, if one exists.
    /// A pending row must be POSTed immediately without issuing `/count`.
    pub fn own_prekey_publication(
        &self,
        canonical_server_origin: &str,
        authenticated_user_id: &str,
    ) -> Result<Option<OwnPreKeyPublication>, String> {
        self.require_own_prekey_scope(authenticated_user_id)?;
        let publication = self
            .db
            .as_ref()
            .ok_or("database not initialized")?
            .load_local_prekey_publication(
                canonical_server_origin,
                authenticated_user_id,
                &self.device_id,
            )?;
        Ok(publication.as_ref().map(OwnPreKeyPublication::from_local))
    }

    /// Validate the exact local `/count` entry, then select the upload that
    /// must complete before any authenticated Direct directory is installed.
    ///
    /// Pending bytes always win. An acknowledged batch is byte-identically
    /// reasserted while inventory is healthy; low inventory (or no prior row)
    /// creates one new immutable batch and persists its keys plus outbox in a
    /// single SQLCipher transaction before publishing anything in memory.
    pub fn prepare_own_prekey_publication_after_count(
        &mut self,
        canonical_server_origin: &str,
        authenticated_user_id: &str,
        count_response: &[u8],
    ) -> Result<OwnPreKeyPublication, String> {
        self.require_own_prekey_scope(authenticated_user_id)?;
        let count = validate_own_prekey_count_response(count_response, &self.device_id)?;
        let existing = self
            .db
            .as_ref()
            .ok_or("database not initialized")?
            .load_local_prekey_publication(
                canonical_server_origin,
                authenticated_user_id,
                &self.device_id,
            )?;
        if let Some(publication) = existing.as_ref() {
            if publication.acknowledged
                && count
                    .signed_prekey_id
                    .is_some_and(|server_id| server_id != publication.signed_prekey_id)
            {
                return Err(
                    "own prekey count signed-prekey id differs from the durable publication"
                        .to_string(),
                );
            }
            if !publication.acknowledged || count.remaining >= OWN_PREKEY_LOW_WATERMARK {
                return Ok(OwnPreKeyPublication::from_local(publication));
            }

            // Refill only the OPK inventory. Retaining the exact acknowledged
            // SPK preserves delayed initial-message decryptability and avoids
            // accumulating a fresh signed private key on every low-watermark
            // check. The server independently requires this SPK to equal its
            // current immutable row.
            let refill = self.build_prekey_refill(publication.signed_prekey_id)?;
            let request_body = canonical_own_prekey_request_body(
                &self.device_id,
                &refill.prekeys.signing_key,
                refill.prekeys.spk_id,
                &refill.prekeys.spk_public,
                &refill.prekeys.spk_signature,
                &refill.prekeys.otk_publics,
            )?;
            let next_publication = LocalPreKeyPublicationV1 {
                canonical_server_origin: canonical_server_origin.to_string(),
                user_id: authenticated_user_id.to_string(),
                device_id: self.device_id,
                signed_prekey_id: refill.prekeys.spk_id,
                one_time_prekey_count: OWN_PREKEY_BATCH_SIZE as u32,
                body_sha256: Sha256::digest(&request_body).into(),
                request_body,
                acknowledged: false,
            };
            self.db
                .as_ref()
                .ok_or("database not initialized")?
                .save_local_prekey_refill_with_publication(
                    &refill.signed_prekey,
                    &refill.one_time_prekeys,
                    &next_publication,
                )?;
            self.install_generated_prekey_refill(&refill);
            return Ok(OwnPreKeyPublication::from_local(&next_publication));
        }

        let batch = self.build_prekey_batch()?;
        let request_body = canonical_own_prekey_request_body(
            &self.device_id,
            &batch.prekeys.signing_key,
            batch.prekeys.spk_id,
            &batch.prekeys.spk_public,
            &batch.prekeys.spk_signature,
            &batch.prekeys.otk_publics,
        )?;
        let publication = LocalPreKeyPublicationV1 {
            canonical_server_origin: canonical_server_origin.to_string(),
            user_id: authenticated_user_id.to_string(),
            device_id: self.device_id,
            signed_prekey_id: batch.prekeys.spk_id,
            one_time_prekey_count: OWN_PREKEY_BATCH_SIZE as u32,
            body_sha256: Sha256::digest(&request_body).into(),
            request_body,
            acknowledged: false,
        };
        self.db
            .as_ref()
            .ok_or("database not initialized")?
            .save_local_prekeys_with_publication(&batch.local_prekeys, &publication)?;
        self.install_generated_prekey_batch(&batch);
        Ok(OwnPreKeyPublication::from_local(&publication))
    }

    /// Strictly validate a successful POST response and acknowledge only the
    /// exact current origin/account/device/SPK/body-digest outbox row.
    pub fn acknowledge_own_prekey_publication(
        &self,
        canonical_server_origin: &str,
        authenticated_user_id: &str,
        expected_signed_prekey_id: u32,
        expected_body_sha256: &[u8; 32],
        upload_response: &[u8],
    ) -> Result<OwnPreKeyAcknowledgeResult, String> {
        self.require_own_prekey_scope(authenticated_user_id)?;
        if expected_signed_prekey_id == 0 || *expected_body_sha256 == [0u8; 32] {
            return Err("own prekey acknowledgement expectation is invalid".to_string());
        }
        let validated = validate_own_prekey_upload_ack(upload_response)?;
        // Inventory is advisory and may already be lower because peers can
        // claim OPKs concurrently. Parsing it remains mandatory and bounded.
        let _advisory_remaining = validated.opk_remaining;
        self.db
            .as_ref()
            .ok_or("database not initialized")?
            .acknowledge_local_prekey_publication(
                canonical_server_origin,
                authenticated_user_id,
                &self.device_id,
                expected_signed_prekey_id,
                expected_body_sha256,
            )?;
        Ok(OwnPreKeyAcknowledgeResult::Acknowledged)
    }

    /// Generate prekeys for X3DH. Call after identity init, upload result to server.
    /// Protocol ids are durably reserved first; runtime secret maps are exposed
    /// only after the immutable key rows commit successfully.
    pub fn generate_prekeys(&mut self) -> Result<PreKeySet, String> {
        self.require_crypto_runtime_active_v1()?;
        let batch = self.build_prekey_batch()?;
        if let Some(db) = self.db.as_ref() {
            db.save_local_prekeys(&batch.local_prekeys)?;
        }
        self.install_generated_prekey_batch(&batch);
        Ok(batch.prekeys)
    }

    fn require_own_prekey_scope(&self, authenticated_user_id: &str) -> Result<(), String> {
        self.require_crypto_runtime_active_v1()?;
        if self.identity.is_none() || self.db.is_none() {
            return Err("own prekey publication requires an unlocked database".to_string());
        }
        if self.device_id == [0u8; 16] {
            return Err("own prekey publication device is invalid".to_string());
        }
        if self.authenticated_user_id.as_deref() != Some(authenticated_user_id) {
            return Err("own prekey publication user differs from authenticated self".to_string());
        }
        Ok(())
    }

    fn build_prekey_batch(&mut self) -> Result<GeneratedPreKeyBatch, String> {
        if self.identity.is_none() {
            return Err("not initialized".to_string());
        }
        let (spk_id, one_time_prekey_start_id) = self.reserve_prekey_batch_ids()?;
        let identity = self.identity.as_ref().ok_or("not initialized")?;
        let spk = x3dh::SignedPreKey::generate(identity, spk_id);
        let spk_public = *spk.public.as_bytes();
        let spk_signature = spk.signature;
        if !veil_crypto::signature::verify(
            &identity.ed25519_public_bytes(),
            &x3dh::signed_prekey_signature_message(&spk_public),
            &spk_signature,
        ) {
            return Err("generated signed prekey failed domain verification".to_string());
        }
        let mut spk_secret = spk.secret.to_bytes();
        let mut local_prekeys = Vec::with_capacity(OWN_PREKEY_BATCH_SIZE + 1);
        local_prekeys.push(LocalPreKey {
            key_type: 0,
            protocol_key_id: spk_id,
            secret_key: spk_secret,
            public_key: spk_public,
            signature: Some(spk_signature),
        });
        // `[u8; 32]` is Copy; erase the named stack copy after the durable
        // batch received its owned value.
        spk_secret.zeroize();

        let mut otk_publics = Vec::with_capacity(OWN_PREKEY_BATCH_SIZE);
        for offset in 0..OWN_PREKEY_BATCH_SIZE as u32 {
            let key_id = one_time_prekey_start_id
                .checked_add(offset)
                .ok_or_else(|| "one-time prekey id exhausted".to_string())?;
            let opk = x3dh::OneTimePreKey::generate(key_id);
            let public_key = *opk.public.as_bytes();
            let mut secret_key = opk.secret.to_bytes();
            otk_publics.push((public_key, key_id));
            local_prekeys.push(LocalPreKey {
                key_type: 1,
                protocol_key_id: key_id,
                secret_key,
                public_key,
                signature: None,
            });
            secret_key.zeroize();
        }

        Ok(GeneratedPreKeyBatch {
            prekeys: PreKeySet {
                spk_public,
                spk_id,
                spk_signature,
                signing_key: identity.ed25519_public_bytes(),
                otk_publics,
            },
            local_prekeys,
        })
    }

    fn build_prekey_refill(
        &mut self,
        signed_prekey_id: u32,
    ) -> Result<GeneratedPreKeyRefill, String> {
        let identity = self.identity.as_ref().ok_or("not initialized")?;
        let db = self.db.as_ref().ok_or("database not initialized")?;
        let signed_prekey = db
            .load_local_signed_prekey(signed_prekey_id)?
            .ok_or("acknowledged signed prekey is unavailable for refill")?;
        let derived_public =
            X25519PublicKey::from(&X25519StaticSecret::from(signed_prekey.secret_key)).to_bytes();
        if derived_public != signed_prekey.public_key {
            return Err("retained signed prekey public key differs from its secret".to_string());
        }
        let signature = signed_prekey
            .signature
            .ok_or("retained signed prekey signature is unavailable")?;
        if !veil_crypto::signature::verify(
            &identity.ed25519_public_bytes(),
            &x3dh::signed_prekey_signature_message(&signed_prekey.public_key),
            &signature,
        ) {
            return Err("retained signed prekey failed domain verification".to_string());
        }
        if self.spk_secrets.get(&signed_prekey_id).copied()
            != Some((signed_prekey.secret_key, signed_prekey.public_key))
        {
            return Err("retained signed prekey differs from the active runtime".to_string());
        }

        let reservation = db.reserve_local_one_time_prekey_batch_ids()?;
        self.otk_next_id = reservation.next_one_time_prekey_id;
        let mut otk_publics = Vec::with_capacity(OWN_PREKEY_BATCH_SIZE);
        let mut one_time_prekeys = Vec::with_capacity(OWN_PREKEY_BATCH_SIZE);
        for offset in 0..OWN_PREKEY_BATCH_SIZE as u32 {
            let key_id = reservation
                .one_time_prekey_start_id
                .checked_add(offset)
                .ok_or_else(|| "one-time prekey id exhausted".to_string())?;
            let opk = x3dh::OneTimePreKey::generate(key_id);
            let public_key = *opk.public.as_bytes();
            let mut secret_key = opk.secret.to_bytes();
            otk_publics.push((public_key, key_id));
            one_time_prekeys.push(LocalPreKey {
                key_type: 1,
                protocol_key_id: key_id,
                secret_key,
                public_key,
                signature: None,
            });
            secret_key.zeroize();
        }

        Ok(GeneratedPreKeyRefill {
            prekeys: PreKeySet {
                spk_public: signed_prekey.public_key,
                spk_id: signed_prekey.protocol_key_id,
                spk_signature: signature,
                signing_key: identity.ed25519_public_bytes(),
                otk_publics,
            },
            signed_prekey,
            one_time_prekeys,
        })
    }

    /// Reserve protocol ids before generating any private material. SQLCipher
    /// serializes database-backed reservations across independently opened
    /// clients; memory-only fixtures retain the same gap-on-failure semantics.
    fn reserve_prekey_batch_ids(&mut self) -> Result<(u32, u32), String> {
        if self.spk_next_id == 0 || self.otk_next_id == 0 {
            return Err("prekey id allocator is invalid".to_string());
        }
        if let Some(db) = self.db.as_ref() {
            let reservation = db.reserve_local_prekey_batch_ids()?;
            self.spk_next_id = reservation.next_signed_prekey_id;
            self.otk_next_id = reservation.next_one_time_prekey_id;
            return Ok((
                reservation.signed_prekey_id,
                reservation.one_time_prekey_start_id,
            ));
        }

        let signed_prekey_id = self.spk_next_id;
        let one_time_prekey_start_id = self.otk_next_id;
        let next_signed_prekey_id = signed_prekey_id
            .checked_add(1)
            .ok_or_else(|| "signed prekey id exhausted".to_string())?;
        let next_one_time_prekey_id = one_time_prekey_start_id
            .checked_add(OWN_PREKEY_BATCH_SIZE as u32)
            .ok_or_else(|| "one-time prekey id exhausted".to_string())?;
        self.spk_next_id = next_signed_prekey_id;
        self.otk_next_id = next_one_time_prekey_id;
        Ok((signed_prekey_id, one_time_prekey_start_id))
    }

    fn install_generated_prekey_batch(&mut self, batch: &GeneratedPreKeyBatch) {
        for key in &batch.local_prekeys {
            match key.key_type {
                0 => {
                    self.spk_secrets
                        .insert(key.protocol_key_id, (key.secret_key, key.public_key));
                }
                1 => {
                    self.otk_secrets.insert(key.protocol_key_id, key.secret_key);
                }
                _ => unreachable!("generated prekey batch contains only SPK and OPK rows"),
            }
        }
    }

    fn install_generated_prekey_refill(&mut self, refill: &GeneratedPreKeyRefill) {
        for key in &refill.one_time_prekeys {
            self.otk_secrets.insert(key.protocol_key_id, key.secret_key);
        }
    }

    /// Initiate X3DH with a peer's prekey bundle, create ratchet session.
    pub fn establish_session(
        &mut self,
        peer_identity_key: &[u8; 32],
        bundle: &x3dh::PreKeyBundle,
    ) -> Result<(), String> {
        let result = self.establish_session_classified_v1(peer_identity_key, bundle);
        self.resolve_public_session_establish_v1(result)
    }

    pub(crate) fn direct_v2_initiator_context(
        &self,
        conversation_id: &str,
        peer_user_id: &str,
        peer_identity_key: [u8; 32],
        peer_signing_key: [u8; 32],
        peer_device: DirectDeviceCoordinateV2,
    ) -> Result<DirectSessionContextV2, String> {
        self.require_crypto_runtime_active_v1()?;
        let canonical_server_origin = self
            .authenticated_server_origin
            .clone()
            .ok_or("Direct v2 requires an authenticated Node origin")?;
        let local_user_id = self
            .authenticated_user_id
            .clone()
            .ok_or("Direct v2 requires an authenticated account")?;
        if self.dm_conversations.get(conversation_id) != Some(&peer_identity_key)
            || self.known_user_keys.get(peer_user_id) != Some(&peer_identity_key)
            || self.trusted_signing_keys.get(&peer_identity_key) != Some(&peer_signing_key)
        {
            return Err("Direct v2 peer is outside the authenticated directory".to_string());
        }
        let identity = self.identity.as_ref().ok_or("not initialized")?;
        let device = self
            .device_identity
            .as_ref()
            .ok_or("device not initialized")?
            .binding();
        Ok(DirectSessionContextV2 {
            canonical_server_origin,
            conversation_id: conversation_id.to_string(),
            initiator: DirectParticipantCoordinateV2 {
                account: DirectAccountCoordinateV2 {
                    user_id: local_user_id,
                    identity_key: identity.x25519_public_bytes(),
                    signing_key: identity.ed25519_public_bytes(),
                },
                device: DirectDeviceCoordinateV2 {
                    device_id: device.device_id,
                    binding_version: device.version,
                    capabilities: device.capabilities,
                    status: device.status,
                    identity_key: device.device_identity_key,
                    signing_key: device.device_signing_key,
                    account_signature: device.account_signature,
                },
            },
            responder: DirectParticipantCoordinateV2 {
                account: DirectAccountCoordinateV2 {
                    user_id: peer_user_id.to_string(),
                    identity_key: peer_identity_key,
                    signing_key: peer_signing_key,
                },
                device: peer_device,
            },
        })
    }

    fn direct_v2_responder_state(
        &self,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        agreement: DirectInitialKeyAgreementV2,
        security: &DirectMessageSecurityContextV2,
    ) -> Result<DirectSessionStateV2, String> {
        self.require_crypto_runtime_active_v1()?;
        let canonical_server_origin = self
            .authenticated_server_origin
            .clone()
            .ok_or("Direct v2 requires an authenticated Node origin")?;
        let local_user_id = self
            .authenticated_user_id
            .clone()
            .ok_or("Direct v2 requires an authenticated account")?;
        if self.dm_conversations.get(conversation_id) != Some(sender_identity_key)
            || self.known_user_keys.get(&security.sender_user_id) != Some(sender_identity_key)
        {
            return Err("Direct v2 sender is outside the authenticated directory".to_string());
        }
        let sender_signing_key = self
            .trusted_signing_keys
            .get(sender_identity_key)
            .copied()
            .ok_or("Direct v2 sender signing key is not pinned")?;
        let identity = self.identity.as_ref().ok_or("not initialized")?;
        let local = self
            .device_identity
            .as_ref()
            .ok_or("device not initialized")?
            .binding();
        if security.target_device_id != local.device_id
            || security.target_binding_version != local.version
        {
            return Err("Direct v2 ciphertext targets another device epoch".to_string());
        }
        let context = DirectSessionContextV2 {
            canonical_server_origin,
            conversation_id: conversation_id.to_string(),
            initiator: DirectParticipantCoordinateV2 {
                account: DirectAccountCoordinateV2 {
                    user_id: security.sender_user_id.clone(),
                    identity_key: *sender_identity_key,
                    signing_key: sender_signing_key,
                },
                device: DirectDeviceCoordinateV2 {
                    device_id: security.sender_device_id,
                    binding_version: security.sender_binding_version,
                    capabilities: security.sender_device_capabilities,
                    status: security.sender_device_binding_status,
                    identity_key: security.sender_device_identity_key,
                    signing_key: security.sender_device_signing_key,
                    account_signature: security.sender_account_signature,
                },
            },
            responder: DirectParticipantCoordinateV2 {
                account: DirectAccountCoordinateV2 {
                    user_id: local_user_id,
                    identity_key: identity.x25519_public_bytes(),
                    signing_key: identity.ed25519_public_bytes(),
                },
                device: DirectDeviceCoordinateV2 {
                    device_id: local.device_id,
                    binding_version: local.version,
                    capabilities: local.capabilities,
                    status: local.status,
                    identity_key: local.device_identity_key,
                    signing_key: local.device_signing_key,
                    account_signature: local.account_signature,
                },
            },
        };
        let state = DirectSessionStateV2::new(context, agreement, false)?;
        if state.session_id() != security.direct_session_id {
            return Err("Direct v2 outer session commitment is invalid".to_string());
        }
        Ok(state)
    }

    pub(crate) fn direct_v2_conversation_for_peer(
        &self,
        peer_identity_key: &[u8; 32],
    ) -> Result<String, String> {
        let mut matches = self
            .dm_conversations
            .iter()
            .filter_map(|(conversation_id, peer)| {
                (peer == peer_identity_key).then_some(conversation_id.as_str())
            });
        let conversation_id = matches
            .next()
            .ok_or("Direct v2 peer has no authenticated conversation")?;
        if matches.next().is_some() {
            return Err("Direct v2 peer maps to multiple conversations".to_string());
        }
        Ok(conversation_id.to_string())
    }

    pub(crate) fn establish_session_classified_v1(
        &mut self,
        peer_identity_key: &[u8; 32],
        bundle: &x3dh::PreKeyBundle,
    ) -> Result<(), DirectSessionEstablishErrorV1> {
        if peer_identity_key != &bundle.identity_key {
            return Err(DirectSessionEstablishErrorV1::rejected(
                "peer identity key does not match prekey bundle identity",
            ));
        }
        self.require_crypto_runtime_active_v1()
            .map_err(DirectSessionEstablishErrorV1::rejected)?;
        if self.ratchet_sessions.contains_key(peer_identity_key)
            || self.pending_initial_headers.contains_key(peer_identity_key)
        {
            return Err(DirectSessionEstablishErrorV1::rejected(
                "ratchet session with this peer already exists",
            ));
        }
        if self
            .db
            .as_ref()
            .map(|db| db.load_ratchet_session_with_revision_v1(peer_identity_key))
            .transpose()
            .map_err(DirectSessionEstablishErrorV1::storage)?
            .flatten()
            .is_some()
        {
            return Err(DirectSessionEstablishErrorV1::rejected(
                "durable ratchet session with this peer already exists",
            ));
        }
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| DirectSessionEstablishErrorV1::rejected("not initialized"))?;
        let result =
            x3dh::initiate(identity, bundle).map_err(DirectSessionEstablishErrorV1::rejected)?;

        let session = RatchetSession::init_initiator(&result.shared_secret, &bundle.signed_prekey);

        // The first encrypted message must carry the X3DH metadata so the
        // responder can derive the same ratchet session before decryption.
        let pending_header = PendingInitialHeader {
            ephemeral_public: result.ephemeral_public,
            signed_prekey_id: bundle.signed_prekey_id,
            one_time_prekey_id: bundle.one_time_prekey_id,
            direct_v2_session_id: None,
        };
        if let Some(db) = self.db.as_ref() {
            let session_data = Zeroizing::new(session.serialize().map_err(|e| {
                DirectSessionEstablishErrorV1::rejected(format!(
                    "serialize initiator ratchet session: {e}"
                ))
            })?);
            let header_data = serde_json::to_vec(&pending_header).map_err(|e| {
                DirectSessionEstablishErrorV1::rejected(format!(
                    "serialize pending X3DH header: {e}"
                ))
            })?;
            db.save_initiator_session(peer_identity_key, &session_data, &header_data)
                .map_err(DirectSessionEstablishErrorV1::storage)?;
        }
        self.pending_initial_headers
            .insert(*peer_identity_key, pending_header);
        self.ratchet_sessions.insert(*peer_identity_key, session);

        Ok(())
    }

    /// Establish the sticky Direct v2 session for one exact peer device. The
    /// account-level X3DH output is re-keyed through the full origin/account/
    /// device/session transcript before it initializes Double Ratchet.
    pub(crate) fn establish_session_classified_v2(
        &mut self,
        peer_identity_key: &[u8; 32],
        bundle: &x3dh::PreKeyBundle,
        context: DirectSessionContextV2,
    ) -> Result<(), DirectSessionEstablishErrorV1> {
        if peer_identity_key != &bundle.identity_key
            || context.responder.account.identity_key != *peer_identity_key
            || context.responder.account.signing_key != bundle.signing_key
        {
            return Err(DirectSessionEstablishErrorV1::rejected(
                "Direct v2 peer coordinate differs from its prekey bundle",
            ));
        }
        self.require_crypto_runtime_active_v1()
            .map_err(DirectSessionEstablishErrorV1::rejected)?;
        if self.ratchet_sessions.contains_key(peer_identity_key)
            || self.pending_initial_headers.contains_key(peer_identity_key)
            || self.direct_v2_sessions.contains_key(peer_identity_key)
        {
            return Err(DirectSessionEstablishErrorV1::rejected(
                "ratchet session with this peer already exists",
            ));
        }
        if self
            .db
            .as_ref()
            .map(|db| db.load_ratchet_session_with_revision_v1(peer_identity_key))
            .transpose()
            .map_err(DirectSessionEstablishErrorV1::storage)?
            .flatten()
            .is_some()
        {
            return Err(DirectSessionEstablishErrorV1::rejected(
                "durable ratchet session with this peer already exists",
            ));
        }
        if self.authenticated_server_origin.as_deref()
            != Some(context.canonical_server_origin.as_str())
            || self.authenticated_user_id.as_deref()
                != Some(context.initiator.account.user_id.as_str())
            || self.dm_conversations.get(&context.conversation_id) != Some(peer_identity_key)
        {
            return Err(DirectSessionEstablishErrorV1::rejected(
                "Direct v2 context is outside the authenticated conversation epoch",
            ));
        }
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| DirectSessionEstablishErrorV1::rejected("not initialized"))?;
        let local_device = self
            .device_identity
            .as_ref()
            .ok_or_else(|| DirectSessionEstablishErrorV1::rejected("device not initialized"))?;
        let local_binding = local_device.binding();
        if context.initiator.account.identity_key != identity.x25519_public_bytes()
            || context.initiator.account.signing_key != identity.ed25519_public_bytes()
            || context.initiator.device.device_id != local_binding.device_id
            || context.initiator.device.binding_version != local_binding.version
            || context.initiator.device.capabilities != local_binding.capabilities
            || context.initiator.device.status != local_binding.status
            || context.initiator.device.identity_key != local_binding.device_identity_key
            || context.initiator.device.signing_key != local_binding.device_signing_key
            || context.initiator.device.account_signature != local_binding.account_signature
        {
            return Err(DirectSessionEstablishErrorV1::rejected(
                "Direct v2 initiator coordinate differs from this device",
            ));
        }

        let result =
            x3dh::initiate(identity, bundle).map_err(DirectSessionEstablishErrorV1::rejected)?;
        let agreement = DirectInitialKeyAgreementV2 {
            ephemeral_public: result.ephemeral_public,
            signed_prekey_id: bundle.signed_prekey_id,
            one_time_prekey_id: bundle.one_time_prekey_id,
        };
        let state = DirectSessionStateV2::new(context, agreement, true)
            .map_err(DirectSessionEstablishErrorV1::rejected)?;
        let mut session_secret = state
            .transcript()
            .derive_session_secret(&result.shared_secret, &result.associated_data)
            .map_err(DirectSessionEstablishErrorV1::rejected)?;
        let session = RatchetSession::init_initiator(&session_secret, &bundle.signed_prekey);
        session_secret.zeroize();
        let pending_header = PendingInitialHeader {
            ephemeral_public: result.ephemeral_public,
            signed_prekey_id: bundle.signed_prekey_id,
            one_time_prekey_id: bundle.one_time_prekey_id,
            direct_v2_session_id: Some(state.session_id()),
        };
        if let Some(db) = self.db.as_ref() {
            let session_data = Zeroizing::new(session.serialize().map_err(|error| {
                DirectSessionEstablishErrorV1::rejected(format!(
                    "serialize Direct v2 initiator ratchet: {error}"
                ))
            })?);
            let header_data = serde_json::to_vec(&pending_header).map_err(|error| {
                DirectSessionEstablishErrorV1::rejected(format!(
                    "serialize Direct v2 pending header: {error}"
                ))
            })?;
            let binding = state
                .to_store_blob()
                .map_err(DirectSessionEstablishErrorV1::rejected)?;
            db.save_initiator_session_v2(peer_identity_key, &session_data, &header_data, &binding)
                .map_err(DirectSessionEstablishErrorV1::storage)?;
        }
        self.pending_initial_headers
            .insert(*peer_identity_key, pending_header);
        self.direct_v2_sessions.insert(*peer_identity_key, state);
        self.ratchet_sessions.insert(*peer_identity_key, session);
        Ok(())
    }

    /// Process an initial X3DH message from a peer (responder side).
    pub fn process_initial_message(
        &mut self,
        sender_identity_key: &[u8; 32],
        ephemeral_key: &[u8; 32],
        spk_id: u32,
        opk_id: Option<u32>,
    ) -> Result<(), String> {
        let result = self.process_initial_message_classified_v1(
            sender_identity_key,
            ephemeral_key,
            spk_id,
            opk_id,
        );
        self.resolve_public_session_establish_v1(result)
    }

    fn process_initial_message_classified_v1(
        &mut self,
        sender_identity_key: &[u8; 32],
        ephemeral_key: &[u8; 32],
        spk_id: u32,
        opk_id: Option<u32>,
    ) -> Result<(), DirectSessionEstablishErrorV1> {
        self.require_crypto_runtime_active_v1()
            .map_err(DirectSessionEstablishErrorV1::rejected)?;
        if self.ratchet_sessions.contains_key(sender_identity_key) {
            return Err(DirectSessionEstablishErrorV1::rejected(
                "ratchet session with this peer already exists",
            ));
        }
        if self
            .db
            .as_ref()
            .map(|db| db.load_ratchet_session_with_revision_v1(sender_identity_key))
            .transpose()
            .map_err(DirectSessionEstablishErrorV1::storage)?
            .flatten()
            .is_some()
        {
            return Err(DirectSessionEstablishErrorV1::rejected(
                "durable ratchet session with this peer already exists",
            ));
        }
        let session = self
            .build_responder_session(sender_identity_key, ephemeral_key, spk_id, opk_id)
            .map_err(DirectSessionEstablishErrorV1::rejected)?;

        if let Some(db) = self.db.as_ref() {
            let data = Zeroizing::new(session.serialize().map_err(|e| {
                DirectSessionEstablishErrorV1::storage(format!(
                    "serialize initial ratchet session: {e}"
                ))
            })?);
            db.commit_initial_ratchet_session(sender_identity_key, &data, opk_id)
                .map_err(DirectSessionEstablishErrorV1::storage)?;
        }
        if let Some(id) = opk_id {
            if let Some(mut secret) = self.otk_secrets.remove(&id) {
                secret.zeroize();
            }
        }
        self.ratchet_sessions.insert(*sender_identity_key, session);
        Ok(())
    }

    fn build_responder_session(
        &self,
        sender_identity_key: &[u8; 32],
        ephemeral_key: &[u8; 32],
        spk_id: u32,
        opk_id: Option<u32>,
    ) -> Result<RatchetSession, String> {
        let (result, spk_secret_bytes, spk_pub) =
            self.build_responder_x3dh(sender_identity_key, ephemeral_key, spk_id, opk_id)?;
        Ok(RatchetSession::init_responder(
            &result.shared_secret,
            &spk_secret_bytes,
            &spk_pub,
        ))
    }

    fn build_responder_x3dh(
        &self,
        sender_identity_key: &[u8; 32],
        ephemeral_key: &[u8; 32],
        spk_id: u32,
        opk_id: Option<u32>,
    ) -> Result<(x3dh::X3DHResult, [u8; 32], [u8; 32]), String> {
        let identity = self.identity.as_ref().ok_or("not initialized")?;

        let (spk_secret_bytes, spk_pub) = self
            .spk_secrets
            .get(&spk_id)
            .copied()
            .ok_or_else(|| format!("unknown or expired signed prekey id {spk_id}"))?;

        // Reconstruct SignedPreKey for X3DH respond
        let spk_secret = X25519StaticSecret::from(spk_secret_bytes);
        let spk = x3dh::SignedPreKey {
            secret: spk_secret,
            public: X25519PublicKey::from(spk_pub),
            id: spk_id,
            signature: [0u8; 64], // Not needed for respond
        };

        let otk = match opk_id {
            Some(id) => {
                let secret_bytes = self.otk_secrets.get(&id).copied().ok_or_else(|| {
                    format!("unknown, expired, or already-used one-time prekey id {id}")
                })?;
                let secret = X25519StaticSecret::from(secret_bytes);
                Some(x3dh::OneTimePreKey {
                    public: X25519PublicKey::from(&secret),
                    secret,
                    id,
                })
            }
            None => None,
        };

        let result = x3dh::respond(
            identity,
            &spk,
            otk.as_ref(),
            sender_identity_key,
            ephemeral_key,
        )?;
        Ok((result, spk_secret_bytes, spk_pub))
    }

    /// Check if a ratchet session exists with a peer.
    pub fn has_session(&self, peer_identity_key: &[u8; 32]) -> bool {
        !self.direct_live_storage_uncertain && self.ratchet_sessions.contains_key(peer_identity_key)
    }

    /// Encrypt outgoing plaintext. Returns (ciphertext, wire_header).
    /// For channel conversations, encrypts with the per-group sender key.
    /// DMs require an explicit conversation/peer binding and ratchet session.
    /// Unknown conversations fail closed and can never produce plaintext.
    fn encrypt_outgoing(
        &mut self,
        conversation_id: &str,
        plaintext: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let result = self.encrypt_outgoing_classified_v1(conversation_id, plaintext);
        self.resolve_public_direct_send_v1(result)
    }

    fn encrypt_outgoing_classified_v1(
        &mut self,
        conversation_id: &str,
        plaintext: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), DirectSendErrorV1> {
        self.require_direct_conversation_available_v1(conversation_id)
            .map_err(DirectSendErrorV1::rejected)?;
        if self.channel_conversations.contains(conversation_id) {
            // Stage-5 classification is deliberately pairwise-only. Preserve
            // the established desktop Sender-Key error surface until the group
            // send transaction receives its own typed boundary.
            let channel_result = (|| -> Result<(Vec<u8>, Vec<u8>), String> {
                if self
                    .sender_key_distribution_pending
                    .contains(conversation_id)
                {
                    return Err(
                        "sender-key distribution is incomplete; channel send is blocked"
                            .to_string(),
                    );
                }
                // Creating a fresh generation is itself a distribution event.
                // It must never fall through to encryption in the same call.
                if !self.sender_keys.has_outgoing(conversation_id)
                    || self.sender_keys.needs_rotation(conversation_id)
                {
                    self.rotate_sender_key(conversation_id)?;
                    return Err(
                        "sender-key rotation requires distribution; channel send is blocked"
                            .to_string(),
                    );
                }

                let device = self
                    .device_identity
                    .as_ref()
                    .ok_or("per-device identity is required for Sender-Key v5")?;
                let ct = self.sender_keys.encrypt_signed_with_device(
                    conversation_id,
                    &device.binding().device_identity_key,
                    device.ed25519_signing_key(),
                    plaintext.as_bytes(),
                )?;
                self.persist_outgoing_sender_key(conversation_id)?;
                Ok((ct, vec![HEADER_SENDER_KEY]))
            })();
            return channel_result.map_err(DirectSendErrorV1::rejected);
        }

        // No automatic pairwise lookup yet — callers use `encrypt_for` directly
        // when they know the peer identity key.
        let peer_identity_key = self
            .dm_conversations
            .get(conversation_id)
            .copied()
            .ok_or_else(|| {
                DirectSendErrorV1::rejected(format!(
                    "E2E session unavailable: conversation {conversation_id} is not bound to a peer"
                ))
            })?;
        let inner = Self::wrap_text_inner(plaintext);
        self.encrypt_for_conversation_classified_v1(&peer_identity_key, conversation_id, &inner)
    }

    #[cfg(test)]
    pub(crate) fn test_only_encrypt_outgoing(
        &mut self,
        conversation_id: &str,
        plaintext: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.encrypt_outgoing(conversation_id, plaintext)
    }

    /// Context-free pairwise encryption is intentionally disabled: every
    /// ratchet message must authenticate its conversation and both identities.
    pub fn encrypt_for(
        &mut self,
        _peer_identity_key: &[u8; 32],
        _plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        Err(
            "context-free ratchet encryption is disabled; bind and send through a conversation"
                .to_string(),
        )
    }

    fn encrypt_for_conversation_classified_v1(
        &mut self,
        peer_identity_key: &[u8; 32],
        conversation_id: &str,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), DirectSendErrorV1> {
        let prepared =
            self.prepare_direct_ciphertext_v1(peer_identity_key, conversation_id, plaintext)?;

        // Legacy callers which are not yet using the exact-byte outbox still
        // persist before transport. The idempotent Direct send path commits
        // this same candidate together with its local row and payload instead.
        if let Some(ref db) = self.db {
            let current = self
                .ratchet_sessions
                .get(peer_identity_key)
                .ok_or_else(|| DirectSendErrorV1::rejected("ratchet session disappeared"))?;
            persist_existing_ratchet_transition_v1(
                db,
                peer_identity_key,
                current,
                &prepared.candidate,
            )
            .map_err(DirectSendErrorV1::storage)?;
        }
        self.ratchet_sessions
            .insert(*peer_identity_key, prepared.candidate);

        Ok((prepared.ciphertext, prepared.header))
    }

    fn prepare_direct_ciphertext_v1(
        &self,
        peer_identity_key: &[u8; 32],
        conversation_id: &str,
        plaintext: &[u8],
    ) -> Result<PreparedDirectCiphertextV1, DirectSendErrorV1> {
        self.require_direct_conversation_available_v1(conversation_id)
            .map_err(DirectSendErrorV1::rejected)?;
        let our_identity_key = self.identity_key().map_err(DirectSendErrorV1::rejected)?;
        let pending = self.pending_initial_headers.get(peer_identity_key).copied();
        let direct_v2 = self.direct_v2_sessions.get(peer_identity_key);
        let mut wire_prefix = Vec::with_capacity(1 + 32 + 32 + 4 + 4);
        let associated_data = if let Some(state) = direct_v2 {
            if state.context().canonical_server_origin
                != self
                    .authenticated_server_origin
                    .as_deref()
                    .ok_or_else(|| DirectSendErrorV1::rejected("Direct v2 is not authenticated"))?
                || state.context().conversation_id != conversation_id
                || state.local().account.user_id
                    != self.authenticated_user_id.as_deref().ok_or_else(|| {
                        DirectSendErrorV1::rejected("Direct v2 account is not authenticated")
                    })?
                || state.local().account.identity_key != our_identity_key
                || state.peer().account.identity_key != *peer_identity_key
                || state.local().device.device_id != self.device_id
            {
                return Err(DirectSendErrorV1::rejected(
                    "Direct v2 session is outside the authenticated device epoch",
                ));
            }
            if let Some(initial) = pending {
                if initial.direct_v2_session_id != Some(state.session_id()) {
                    return Err(DirectSendErrorV1::rejected(
                        "Direct v2 pending header has a different session commitment",
                    ));
                }
                wire_prefix.push(HEADER_INITIAL_V2);
                wire_prefix.extend_from_slice(&state.session_id());
                wire_prefix.extend_from_slice(&initial.ephemeral_public);
                wire_prefix.extend_from_slice(&initial.signed_prekey_id.to_be_bytes());
                wire_prefix.extend_from_slice(
                    &initial.one_time_prekey_id.unwrap_or(u32::MAX).to_be_bytes(),
                );
            } else {
                wire_prefix.push(HEADER_RATCHET_V2);
                wire_prefix.extend_from_slice(&state.session_id());
            }
            state
                .transcript()
                .message_associated_data(
                    &state.local().device.device_id,
                    &state.peer().device.device_id,
                    &wire_prefix,
                )
                .map_err(DirectSendErrorV1::rejected)?
        } else {
            #[cfg(not(any(test, feature = "test-utils")))]
            return Err(DirectSendErrorV1::rejected(
                "Direct v2 session is required for outgoing traffic",
            ));
            #[cfg(any(test, feature = "test-utils"))]
            {
                if pending.is_some_and(|initial| initial.direct_v2_session_id.is_some()) {
                    return Err(DirectSendErrorV1::rejected(
                        "Direct v2 pending state lost its sticky session binding",
                    ));
                }
                if let Some(initial) = pending {
                    wire_prefix.push(HEADER_INITIAL);
                    wire_prefix.extend_from_slice(&initial.ephemeral_public);
                    wire_prefix.extend_from_slice(&initial.signed_prekey_id.to_be_bytes());
                    wire_prefix.extend_from_slice(
                        &initial.one_time_prekey_id.unwrap_or(u32::MAX).to_be_bytes(),
                    );
                } else {
                    wire_prefix.push(HEADER_RATCHET);
                }
                ratchet_associated_data(
                    conversation_id,
                    &our_identity_key,
                    peer_identity_key,
                    &wire_prefix,
                )
                .map_err(DirectSendErrorV1::rejected)?
            }
        };
        let mut candidate = self
            .ratchet_sessions
            .get(peer_identity_key)
            .cloned()
            .ok_or_else(|| DirectSendErrorV1::rejected("no ratchet session with this peer"))?;

        let (ratchet_header, ciphertext) = candidate
            .encrypt_with_ad(plaintext, &associated_data)
            .map_err(DirectSendErrorV1::rejected)?;
        let rh_bytes = ratchet_header.to_bytes();

        // Every message carries the same X3DH metadata until an authenticated
        // inbound DM proves peer possession. Thus a deleted/missed first
        // offline packet does not make all subsequent ratchet packets opaque.
        let mut header = wire_prefix;
        header.extend_from_slice(&rh_bytes);

        Ok(PreparedDirectCiphertextV1 {
            peer_identity_key: *peer_identity_key,
            candidate,
            ciphertext,
            header,
        })
    }

    /// Decrypt an incoming message from a peer.
    /// Handles both initial X3DH messages and regular ratchet messages.
    /// `conversation_id` is required for sender-key (channel) messages.
    pub fn decrypt_from(
        &mut self,
        sender_identity_key: &[u8; 32],
        conversation_id: &str,
        header: &[u8],
        ciphertext: &[u8],
    ) -> Result<DecryptedPayload, String> {
        self.decrypt_from_with_security_context(
            sender_identity_key,
            conversation_id,
            header,
            ciphertext,
            None,
        )
    }

    fn validated_sender_key_route_for_message(
        &self,
        conversation_id: &str,
        sender_account_identity_key: &[u8; 32],
        ciphertext: &[u8],
        security_context: &MessageSecurityContextV1,
    ) -> Result<ValidatedSenderKeyRouteForMessageV1, String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        let (
            roster_version,
            roster_commitment,
            sender_device_id,
            target_device_id,
            sender_binding_version,
            membership_epoch,
            membership_epoch_hash,
        ) = match security_context {
            MessageSecurityContextV1::SenderKeyV5(context) => (
                context.roster_version,
                context.roster_commitment,
                context.sender_device_id,
                context.target_device_id,
                context.sender_binding_version,
                0,
                [0u8; 32],
            ),
            MessageSecurityContextV1::SenderKeyV6(context) => (
                context.roster_version,
                context.roster_commitment,
                context.sender_device_id,
                context.target_device_id,
                context.sender_binding_version,
                context.membership_epoch,
                context.membership_epoch_hash,
            ),
            MessageSecurityContextV1::DirectV2(_) => {
                return Err("Direct v2 context is not valid for Sender-Key traffic".to_string());
            }
        };
        let local = self
            .device_identity
            .as_ref()
            .ok_or("per-device identity is not initialized")?;
        if target_device_id != self.device_id {
            return Err("Sender-Key message targets another device".to_string());
        }
        let unverified = veil_crypto::sender_key::inspect_signed_sender_key_metadata(ciphertext)?;
        let local_account_identity = self.identity_key()?;
        let local_account_signing = self.signing_key()?;
        if *sender_account_identity_key == local_account_identity
            && sender_device_id == self.device_id
        {
            let roster = self
                .device_rosters
                .get(conversation_id)
                .filter(|roster| {
                    roster.version == roster_version && roster.commitment == roster_commitment
                })
                .ok_or("self-authored Sender-Key message has no exact current roster proof")?;
            self.require_live_membership_context_v1(
                conversation_id,
                roster,
                membership_epoch,
                &membership_epoch_hash,
            )?;
            let current = roster
                .eligible_devices
                .get(&self.device_id)
                .ok_or("current device is absent from its installed roster")?;
            if current.device_identity_key != local.binding().device_identity_key
                || current.device_signing_key != local.binding().device_signing_key
                || current.account_signing_key != local_account_signing
                || current.binding_version != sender_binding_version
                || unverified.sender_identity_key != local.binding().device_identity_key
                || self
                    .sender_keys
                    .outgoing_owner_identity_key(conversation_id)
                    != Some(local.binding().device_identity_key)
            {
                return Err("self-authored Sender-Key device context mismatch".to_string());
            }
            let generation = veil_crypto::sender_key::verify_signed_sender_key_envelope(
                conversation_id,
                &local.binding().device_identity_key,
                &local.binding().device_signing_key,
                ciphertext,
            )?;
            return Ok(ValidatedSenderKeyRouteForMessageV1::Verified {
                generation,
                route: Box::new(IncomingSenderKeyRouteV1 {
                    sender_account_identity_key: local_account_identity,
                    sender_device_id: self.device_id,
                    sender_device_identity_key: local.binding().device_identity_key,
                    sender_device_signing_key: local.binding().device_signing_key,
                    sender_binding_version: local.binding().version,
                    target_device_id: self.device_id,
                    target_binding_version: local.binding().version,
                    roster_version,
                    roster_commitment,
                    membership_epoch,
                    membership_epoch_hash,
                    envelope_commitment: Sha256::digest(ciphertext).into(),
                    historical_sender_binding: Some(HistoricalDeviceBindingProofV1 {
                        sender_account_signing_key: current.account_signing_key,
                        sender_device_capabilities: local.binding().capabilities,
                        sender_device_binding_status: local.binding().status,
                        sender_account_signature: local.binding().account_signature,
                        target_device_identity_key: Some(local.binding().device_identity_key),
                    }),
                }),
            });
        }
        let current_roster = self
            .device_rosters
            .get(conversation_id)
            .ok_or("current device roster is not installed")?;
        let current_target = current_roster
            .eligible_devices
            .get(&self.device_id)
            .ok_or("current device is not eligible in the installed roster")?;
        if current_target.account_identity_key != local_account_identity
            || current_target.account_signing_key != local_account_signing
            || current_target.device_identity_key != local.binding().device_identity_key
            || current_target.device_signing_key != local.binding().device_signing_key
            || current_target.binding_version != local.binding().version
            || current_target.capabilities != local.binding().capabilities
            || current_target.account_signature != local.binding().account_signature
        {
            return Err(
                "installed target roster no longer matches local device identity".to_string(),
            );
        }
        let route = self
            .db
            .as_ref()
            .ok_or("database is required for Sender-Key route verification")?
            .load_incoming_sender_key_route_v1(
                conversation_id,
                &unverified.sender_identity_key,
                unverified.generation,
            )?;
        let Some(route) = route else {
            return Ok(ValidatedSenderKeyRouteForMessageV1::MissingExactRoute {
                target_device_id,
                message_roster_version: roster_version,
                message_roster_commitment: roster_commitment,
                installed_roster_version: current_roster.version,
                installed_roster_commitment: current_roster.commitment,
            });
        };
        if let Some(proof) = route.historical_sender_binding.as_ref() {
            if proof.target_device_identity_key != Some(local.binding().device_identity_key)
                || self
                    .trusted_signing_keys
                    .get(&route.sender_account_identity_key)
                    != Some(&proof.sender_account_signing_key)
            {
                return Err("historical Sender-Key binding proof is no longer trusted".to_string());
            }
        } else if route.target_binding_version != local.binding().version {
            return Err(
                "legacy Sender-Key route cannot cross a target binding version".to_string(),
            );
        }
        if route.sender_account_identity_key != *sender_account_identity_key
            || route.sender_device_id != sender_device_id
            || route.sender_binding_version != sender_binding_version
            || route.target_device_id != target_device_id
            || route.target_device_id != self.device_id
            || route.target_binding_version == 0
            || route.target_binding_version > local.binding().version
            || route.roster_version != roster_version
            || route.roster_commitment != roster_commitment
            || route.membership_epoch != membership_epoch
            || route.membership_epoch_hash != membership_epoch_hash
        {
            return Err(
                "Sender-Key message security context does not match installed route".to_string(),
            );
        }
        if membership_epoch != 0
            && !self
                .db
                .as_ref()
                .ok_or("database is required for membership history verification")?
                .membership_epoch_matches_pin_v1(
                    conversation_id,
                    membership_epoch,
                    &membership_epoch_hash,
                )?
        {
            return Err("Sender-Key v6 message membership epoch is not durably pinned".to_string());
        }
        let generation = veil_crypto::sender_key::verify_signed_sender_key_envelope(
            conversation_id,
            &route.sender_device_identity_key,
            &route.sender_device_signing_key,
            ciphertext,
        )?;
        if generation != unverified.generation {
            return Err("Sender-Key signed generation changed during verification".to_string());
        }
        Ok(ValidatedSenderKeyRouteForMessageV1::Verified {
            generation,
            route: Box::new(route),
        })
    }

    pub fn validate_live_sender_key_security_context_v1(
        &self,
        conversation_id: &str,
        security_context: &MessageSecurityContextV1,
    ) -> Result<(), String> {
        let (roster_version, roster_commitment, membership_epoch, membership_epoch_hash) =
            match security_context {
                MessageSecurityContextV1::SenderKeyV5(context) => (
                    context.roster_version,
                    context.roster_commitment,
                    0,
                    [0u8; 32],
                ),
                MessageSecurityContextV1::SenderKeyV6(context) => (
                    context.roster_version,
                    context.roster_commitment,
                    context.membership_epoch,
                    context.membership_epoch_hash,
                ),
                MessageSecurityContextV1::DirectV2(_) => {
                    return Err("Direct v2 context is not valid for Sender-Key traffic".to_string())
                }
            };
        let roster = self
            .device_rosters
            .get(conversation_id)
            .ok_or("current device roster is not installed")?;
        if roster.version != roster_version || roster.commitment != roster_commitment {
            return Err("live Sender-Key message belongs to a stale roster".to_string());
        }
        self.require_live_membership_context_v1(
            conversation_id,
            roster,
            membership_epoch,
            &membership_epoch_hash,
        )
    }

    pub fn inspect_sender_key_message_context_v1(
        &self,
        conversation_id: &str,
        sender_account_identity_key: &[u8; 32],
        ciphertext: &[u8],
        security_context: &MessageSecurityContextV1,
    ) -> Result<SenderKeyMessageContextInspectionV1, String> {
        match self.validated_sender_key_route_for_message(
            conversation_id,
            sender_account_identity_key,
            ciphertext,
            security_context,
        )? {
            ValidatedSenderKeyRouteForMessageV1::Verified { .. } => {
                Ok(SenderKeyMessageContextInspectionV1::Verified)
            }
            ValidatedSenderKeyRouteForMessageV1::MissingExactRoute {
                target_device_id,
                message_roster_version,
                message_roster_commitment,
                installed_roster_version,
                installed_roster_commitment,
            } => Ok(SenderKeyMessageContextInspectionV1::MissingExactRoute {
                target_device_id,
                message_roster_version,
                message_roster_commitment,
                installed_roster_version,
                installed_roster_commitment,
            }),
        }
    }

    pub fn validate_sender_key_message_context_v1(
        &self,
        conversation_id: &str,
        sender_account_identity_key: &[u8; 32],
        ciphertext: &[u8],
        security_context: &MessageSecurityContextV1,
    ) -> Result<(), String> {
        match self.inspect_sender_key_message_context_v1(
            conversation_id,
            sender_account_identity_key,
            ciphertext,
            security_context,
        )? {
            SenderKeyMessageContextInspectionV1::Verified => Ok(()),
            SenderKeyMessageContextInspectionV1::MissingExactRoute { .. } => {
                Err("trusted historical Sender-Key route is unavailable".to_string())
            }
        }
    }

    pub fn decrypt_from_with_security_context(
        &mut self,
        sender_identity_key: &[u8; 32],
        conversation_id: &str,
        header: &[u8],
        ciphertext: &[u8],
        security_context: Option<&MessageSecurityContextV1>,
    ) -> Result<DecryptedPayload, String> {
        let result = self.decrypt_from_with_security_context_classified_v1(
            sender_identity_key,
            conversation_id,
            header,
            ciphertext,
            security_context,
        );
        self.resolve_public_classified_mutation_v1(result)
    }

    fn validate_direct_v2_outer_context(
        &self,
        state: &DirectSessionStateV2,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        security: &DirectMessageSecurityContextV2,
    ) -> Result<(), String> {
        let peer = state.peer();
        let local = state.local();
        if state.context().conversation_id != conversation_id
            || state.context().canonical_server_origin
                != self
                    .authenticated_server_origin
                    .as_deref()
                    .ok_or("Direct v2 runtime origin is not authenticated")?
            || local.account.user_id
                != self
                    .authenticated_user_id
                    .as_deref()
                    .ok_or("Direct v2 runtime account is not authenticated")?
            || peer.account.identity_key != *sender_identity_key
            || peer.account.user_id != security.sender_user_id
            || peer.device.device_id != security.sender_device_id
            || peer.device.binding_version != security.sender_binding_version
            || peer.device.identity_key != security.sender_device_identity_key
            || peer.device.signing_key != security.sender_device_signing_key
            || peer.device.capabilities != security.sender_device_capabilities
            || peer.device.status != security.sender_device_binding_status
            || peer.device.account_signature != security.sender_account_signature
            || local.device.device_id != security.target_device_id
            || local.device.binding_version != security.target_binding_version
            || state.session_id() != security.direct_session_id
            || self.dm_conversations.get(conversation_id) != Some(sender_identity_key)
        {
            return Err("Direct v2 outer context differs from the sticky session".to_string());
        }
        Ok(())
    }

    fn decrypt_direct_v2_classified(
        &mut self,
        sender_identity_key: &[u8; 32],
        conversation_id: &str,
        header: &[u8],
        ciphertext: &[u8],
        security_context: Option<&MessageSecurityContextV1>,
    ) -> Result<DecryptedPayload, DirectHistoryMutationError> {
        let Some(MessageSecurityContextV1::DirectV2(security)) = security_context else {
            return Err(DirectHistoryMutationError::rejected(
                "Direct v2 message is missing its exact device/session context",
            ));
        };
        let (wire_prefix_len, ratchet_offset, agreement) = match header[0] {
            HEADER_INITIAL_V2 => {
                if header.len() != 1 + 32 + 32 + 4 + 4 + 41 {
                    return Err(DirectHistoryMutationError::rejected(
                        "invalid Direct v2 initial header length",
                    ));
                }
                let mut ephemeral_public = [0u8; 32];
                ephemeral_public.copy_from_slice(&header[33..65]);
                let signed_prekey_id =
                    u32::from_be_bytes(header[65..69].try_into().expect("fixed Direct v2 SPK"));
                let one_time_prekey_raw =
                    u32::from_be_bytes(header[69..73].try_into().expect("fixed Direct v2 OPK"));
                (
                    73,
                    73,
                    Some(DirectInitialKeyAgreementV2 {
                        ephemeral_public,
                        signed_prekey_id,
                        one_time_prekey_id: (one_time_prekey_raw != u32::MAX)
                            .then_some(one_time_prekey_raw),
                    }),
                )
            }
            HEADER_RATCHET_V2 => {
                if header.len() != 1 + 32 + 41 {
                    return Err(DirectHistoryMutationError::rejected(
                        "invalid Direct v2 ratchet header length",
                    ));
                }
                (33, 33, None)
            }
            _ => {
                return Err(DirectHistoryMutationError::rejected(
                    "internal Direct v2 header dispatch mismatch",
                ));
            }
        };
        let embedded_session_id: [u8; 32] = header[1..33]
            .try_into()
            .expect("validated Direct v2 session id length");
        if embedded_session_id != security.direct_session_id {
            return Err(DirectHistoryMutationError::rejected(
                "Direct v2 header and outer session commitments disagree",
            ));
        }
        let ratchet_header = MessageHeader::from_bytes(&header[ratchet_offset..])
            .map_err(DirectHistoryMutationError::rejected)?;

        let existing_state = self.direct_v2_sessions.get(sender_identity_key).cloned();
        if let Some(state) = existing_state {
            self.validate_direct_v2_outer_context(
                &state,
                conversation_id,
                sender_identity_key,
                security,
            )
            .map_err(DirectHistoryMutationError::rejected)?;
            let current = self
                .ratchet_sessions
                .get(sender_identity_key)
                .ok_or_else(|| {
                    DirectHistoryMutationError::storage(
                        "Direct v2 sticky binding has no ratchet session",
                    )
                })?;
            let associated_data = state
                .transcript()
                .message_associated_data(
                    &state.peer().device.device_id,
                    &state.local().device.device_id,
                    &header[..wire_prefix_len],
                )
                .map_err(DirectHistoryMutationError::rejected)?;
            let mut candidate = current.clone();
            let plaintext = candidate
                .decrypt_with_ad(&ratchet_header, ciphertext, &associated_data)
                .map_err(DirectHistoryMutationError::rejected)?;
            if let Some(db) = self.db.as_ref() {
                persist_existing_ratchet_transition_v1(
                    db,
                    sender_identity_key,
                    current,
                    &candidate,
                )
                .map_err(DirectHistoryMutationError::storage)?;
            }
            self.ratchet_sessions
                .insert(*sender_identity_key, candidate);
            return self.process_ratchet_plaintext_classified_v1(sender_identity_key, plaintext);
        }

        if self.ratchet_sessions.contains_key(sender_identity_key) {
            return Err(DirectHistoryMutationError::rejected(
                "Direct v2 cannot replace an unbound legacy ratchet session",
            ));
        }
        let agreement = agreement.ok_or_else(|| {
            DirectHistoryMutationError::rejected(
                "Direct v2 ratchet header arrived before an authenticated initial packet",
            )
        })?;
        let state = self
            .direct_v2_responder_state(conversation_id, sender_identity_key, agreement, security)
            .map_err(DirectHistoryMutationError::rejected)?;
        self.validate_direct_v2_outer_context(
            &state,
            conversation_id,
            sender_identity_key,
            security,
        )
        .map_err(DirectHistoryMutationError::rejected)?;
        let (x3dh_result, spk_secret, spk_public) = self
            .build_responder_x3dh(
                sender_identity_key,
                &agreement.ephemeral_public,
                agreement.signed_prekey_id,
                agreement.one_time_prekey_id,
            )
            .map_err(DirectHistoryMutationError::rejected)?;
        let mut session_secret = state
            .transcript()
            .derive_session_secret(&x3dh_result.shared_secret, &x3dh_result.associated_data)
            .map_err(DirectHistoryMutationError::rejected)?;
        let mut candidate =
            RatchetSession::init_responder(&session_secret, &spk_secret, &spk_public);
        session_secret.zeroize();
        let associated_data = state
            .transcript()
            .message_associated_data(
                &state.peer().device.device_id,
                &state.local().device.device_id,
                &header[..wire_prefix_len],
            )
            .map_err(DirectHistoryMutationError::rejected)?;
        let plaintext = candidate
            .decrypt_with_ad(&ratchet_header, ciphertext, &associated_data)
            .map_err(DirectHistoryMutationError::rejected)?;
        if let Some(db) = self.db.as_ref() {
            let data = Zeroizing::new(candidate.serialize().map_err(|error| {
                DirectHistoryMutationError::storage(format!(
                    "serialize Direct v2 responder ratchet: {error}"
                ))
            })?);
            let binding = state
                .to_store_blob()
                .map_err(DirectHistoryMutationError::rejected)?;
            db.commit_initial_ratchet_session_v2(
                sender_identity_key,
                &data,
                agreement.one_time_prekey_id,
                &binding,
            )
            .map_err(DirectHistoryMutationError::storage)?;
        }
        if let Some(id) = agreement.one_time_prekey_id {
            if let Some(mut secret) = self.otk_secrets.remove(&id) {
                secret.zeroize();
            }
        }
        self.direct_v2_sessions.insert(*sender_identity_key, state);
        self.ratchet_sessions
            .insert(*sender_identity_key, candidate);
        self.process_ratchet_plaintext_classified_v1(sender_identity_key, plaintext)
    }

    fn decrypt_from_with_security_context_classified_v1(
        &mut self,
        sender_identity_key: &[u8; 32],
        conversation_id: &str,
        header: &[u8],
        ciphertext: &[u8],
        security_context: Option<&MessageSecurityContextV1>,
    ) -> Result<DecryptedPayload, DirectHistoryMutationError> {
        self.require_direct_conversation_available_v1(conversation_id)
            .map_err(DirectHistoryMutationError::rejected)?;
        if header.is_empty() {
            // Network messages without an authenticated E2E header are a
            // downgrade attempt (or unsupported legacy data), not plaintext.
            return Err(DirectHistoryMutationError::rejected(
                "rejected unencrypted message: missing E2E header",
            ));
        }
        if self.direct_v2_sessions.contains_key(sender_identity_key)
            && matches!(header[0], HEADER_INITIAL | HEADER_RATCHET)
        {
            return Err(DirectHistoryMutationError::rejected(
                "Direct v1 downgrade rejected for a sticky Direct v2 session",
            ));
        }
        if matches!(
            security_context,
            Some(MessageSecurityContextV1::DirectV2(_))
        ) && !matches!(header[0], HEADER_INITIAL_V2 | HEADER_RATCHET_V2)
        {
            return Err(DirectHistoryMutationError::rejected(
                "Direct v2 outer context is attached to a different wire profile",
            ));
        }

        match header[0] {
            HEADER_INITIAL_V2 | HEADER_RATCHET_V2 => self.decrypt_direct_v2_classified(
                sender_identity_key,
                conversation_id,
                header,
                ciphertext,
                security_context,
            ),
            #[cfg(any(test, feature = "test-utils"))]
            HEADER_INITIAL => {
                // Parse X3DH init header
                if header.len() != 1 + 32 + 4 + 4 + 41 {
                    return Err(DirectHistoryMutationError::rejected(format!(
                        "invalid initial header length: expected 82, got {}",
                        header.len()
                    )));
                }
                let mut ek = [0u8; 32];
                ek.copy_from_slice(&header[1..33]);
                let spk_id = u32::from_be_bytes([header[33], header[34], header[35], header[36]]);
                let opk_id_raw =
                    u32::from_be_bytes([header[37], header[38], header[39], header[40]]);
                let opk_id = if opk_id_raw == 0xFFFFFFFF {
                    None
                } else {
                    Some(opk_id_raw)
                };

                let rh = MessageHeader::from_bytes(&header[41..82])
                    .map_err(DirectHistoryMutationError::rejected)?;
                let our_identity_key = self
                    .identity_key()
                    .map_err(DirectHistoryMutationError::rejected)?;
                let associated_data = ratchet_associated_data(
                    conversation_id,
                    sender_identity_key,
                    &our_identity_key,
                    &header[..41],
                )
                .map_err(DirectHistoryMutationError::rejected)?;
                let plaintext = if self.has_session(sender_identity_key) {
                    let current =
                        self.ratchet_sessions
                            .get(sender_identity_key)
                            .ok_or_else(|| {
                                DirectHistoryMutationError::storage("session lookup failed")
                            })?;
                    let mut candidate = current.clone();
                    let plaintext = candidate
                        .decrypt_with_ad(&rh, ciphertext, &associated_data)
                        .map_err(DirectHistoryMutationError::rejected)?;
                    if let Some(db) = self.db.as_ref() {
                        persist_existing_ratchet_transition_v1(
                            db,
                            sender_identity_key,
                            current,
                            &candidate,
                        )
                        .map_err(DirectHistoryMutationError::storage)?;
                    }
                    self.ratchet_sessions
                        .insert(*sender_identity_key, candidate);
                    plaintext
                } else {
                    // Do not consume the OPK or install/persist a responder
                    // session until the first packet authenticates successfully.
                    let mut candidate = self
                        .build_responder_session(sender_identity_key, &ek, spk_id, opk_id)
                        .map_err(DirectHistoryMutationError::rejected)?;
                    let plaintext = candidate
                        .decrypt_with_ad(&rh, ciphertext, &associated_data)
                        .map_err(DirectHistoryMutationError::rejected)?;
                    if let Some(db) = self.db.as_ref() {
                        let data = Zeroizing::new(candidate.serialize().map_err(|error| {
                            DirectHistoryMutationError::storage(format!(
                                "serialize initial ratchet session: {error}"
                            ))
                        })?);
                        db.commit_initial_ratchet_session(sender_identity_key, &data, opk_id)
                            .map_err(DirectHistoryMutationError::storage)?;
                    }
                    if let Some(id) = opk_id {
                        if let Some(mut secret) = self.otk_secrets.remove(&id) {
                            secret.zeroize();
                        }
                    }
                    self.ratchet_sessions
                        .insert(*sender_identity_key, candidate);
                    plaintext
                };

                self.process_ratchet_plaintext_classified_v1(sender_identity_key, plaintext)
            }
            #[cfg(any(test, feature = "test-utils"))]
            HEADER_RATCHET => {
                if header.len() != 1 + 41 {
                    return Err(DirectHistoryMutationError::rejected(format!(
                        "invalid ratchet header length: expected 42, got {}",
                        header.len()
                    )));
                }
                let rh = MessageHeader::from_bytes(&header[1..])
                    .map_err(DirectHistoryMutationError::rejected)?;
                let our_identity_key = self
                    .identity_key()
                    .map_err(DirectHistoryMutationError::rejected)?;
                let associated_data = ratchet_associated_data(
                    conversation_id,
                    sender_identity_key,
                    &our_identity_key,
                    &header[..1],
                )
                .map_err(DirectHistoryMutationError::rejected)?;
                let current = self
                    .ratchet_sessions
                    .get(sender_identity_key)
                    .ok_or_else(|| {
                        DirectHistoryMutationError::rejected("no ratchet session with this peer")
                    })?;
                let mut candidate = current.clone();
                let plaintext = candidate
                    .decrypt_with_ad(&rh, ciphertext, &associated_data)
                    .map_err(DirectHistoryMutationError::rejected)?;

                if let Some(ref db) = self.db {
                    persist_existing_ratchet_transition_v1(
                        db,
                        sender_identity_key,
                        current,
                        &candidate,
                    )
                    .map_err(DirectHistoryMutationError::storage)?;
                }
                self.ratchet_sessions
                    .insert(*sender_identity_key, candidate);

                self.process_ratchet_plaintext_classified_v1(sender_identity_key, plaintext)
            }
            HEADER_SENDER_KEY => {
                let context = security_context.ok_or_else(|| {
                    DirectHistoryMutationError::rejected(
                        "Sender-Key v5 message is missing persisted device security context",
                    )
                })?;
                let (generation, route) = match self
                    .validated_sender_key_route_for_message(
                        conversation_id,
                        sender_identity_key,
                        ciphertext,
                        context,
                    )
                    .map_err(DirectHistoryMutationError::rejected)?
                {
                    ValidatedSenderKeyRouteForMessageV1::Verified { generation, route } => {
                        (generation, route)
                    }
                    ValidatedSenderKeyRouteForMessageV1::MissingExactRoute { .. } => {
                        return Err(DirectHistoryMutationError::rejected(
                            "trusted historical Sender-Key route is unavailable",
                        ));
                    }
                };
                self.ensure_incoming_sender_key_loaded(
                    conversation_id,
                    &route.sender_device_identity_key,
                    generation,
                )
                .map_err(DirectHistoryMutationError::rejected)?;
                let mut decrypted = self
                    .sender_keys
                    .decrypt_signed_with_metadata(
                        conversation_id,
                        &route.sender_device_identity_key,
                        &route.sender_device_signing_key,
                        ciphertext,
                    )
                    .map_err(DirectHistoryMutationError::rejected)?;
                if decrypted.generation != generation {
                    return Err(DirectHistoryMutationError::rejected(
                        "sender-key generation changed during authenticated decrypt",
                    ));
                }
                self.persist_incoming_sender_key(
                    conversation_id,
                    &route.sender_device_identity_key,
                    generation,
                )
                .map_err(DirectHistoryMutationError::storage)?;
                Ok(DecryptedPayload::Text(std::mem::take(
                    &mut *decrypted.plaintext,
                )))
            }
            _ => {
                // Unknown wire versions are never interpreted as plaintext.
                Err(DirectHistoryMutationError::rejected(format!(
                    "rejected message with unknown E2E header type {:#04x}",
                    header[0]
                )))
            }
        }
    }

    /// Direct history is pairwise text only. Keeping this path small and
    /// classified lets callers distinguish authenticated-ciphertext rejection
    /// from an uncertain SQLCipher write without parsing human-readable
    /// errors. Candidate ratchets are persisted inside the caller's receive
    /// savepoint and published to memory only after authentication succeeds.
    #[cfg(any(test, feature = "test-utils"))]
    fn decrypt_direct_history_text_classified(
        &mut self,
        sender_identity_key: &[u8; 32],
        conversation_id: &str,
        header: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DirectHistoryMutationError> {
        if header.is_empty() || ciphertext.is_empty() {
            return Err(DirectHistoryMutationError::rejected(
                "Direct history ciphertext is empty",
            ));
        }
        if self.direct_v2_sessions.contains_key(sender_identity_key) {
            return Err(DirectHistoryMutationError::rejected(
                "legacy Direct history cannot mutate a sticky Direct v2 session",
            ));
        }

        let plaintext = match header[0] {
            HEADER_INITIAL => {
                if header.len() != 1 + 32 + 4 + 4 + 41 {
                    return Err(DirectHistoryMutationError::rejected(
                        "invalid Direct history initial header length",
                    ));
                }
                let mut ephemeral_key = [0u8; 32];
                ephemeral_key.copy_from_slice(&header[1..33]);
                let signed_prekey_id =
                    u32::from_be_bytes([header[33], header[34], header[35], header[36]]);
                let one_time_prekey_raw =
                    u32::from_be_bytes([header[37], header[38], header[39], header[40]]);
                let one_time_prekey_id =
                    (one_time_prekey_raw != u32::MAX).then_some(one_time_prekey_raw);
                let ratchet_header = MessageHeader::from_bytes(&header[41..82])
                    .map_err(DirectHistoryMutationError::rejected)?;
                let local_identity = self
                    .identity_key()
                    .map_err(DirectHistoryMutationError::storage)?;
                let associated_data = ratchet_associated_data(
                    conversation_id,
                    sender_identity_key,
                    &local_identity,
                    &header[..41],
                )
                .map_err(DirectHistoryMutationError::rejected)?;

                if self.has_session(sender_identity_key) {
                    let current =
                        self.ratchet_sessions
                            .get(sender_identity_key)
                            .ok_or_else(|| {
                                DirectHistoryMutationError::storage(
                                    "Direct history ratchet session lookup failed",
                                )
                            })?;
                    let mut candidate = current.clone();
                    let plaintext = candidate
                        .decrypt_with_ad(&ratchet_header, ciphertext, &associated_data)
                        .map_err(DirectHistoryMutationError::rejected)?;
                    let db = self.db.as_ref().ok_or_else(|| {
                        DirectHistoryMutationError::storage("database not initialized")
                    })?;
                    persist_existing_ratchet_transition_v1(
                        db,
                        sender_identity_key,
                        current,
                        &candidate,
                    )
                    .map_err(DirectHistoryMutationError::storage)?;
                    self.ratchet_sessions
                        .insert(*sender_identity_key, candidate);
                    plaintext
                } else {
                    let mut candidate = self
                        .build_responder_session(
                            sender_identity_key,
                            &ephemeral_key,
                            signed_prekey_id,
                            one_time_prekey_id,
                        )
                        .map_err(DirectHistoryMutationError::rejected)?;
                    let plaintext = candidate
                        .decrypt_with_ad(&ratchet_header, ciphertext, &associated_data)
                        .map_err(DirectHistoryMutationError::rejected)?;
                    let data = Zeroizing::new(candidate.serialize().map_err(|error| {
                        DirectHistoryMutationError::storage(format!(
                            "serialize Direct history initial ratchet session: {error}"
                        ))
                    })?);
                    self.db
                        .as_ref()
                        .ok_or_else(|| {
                            DirectHistoryMutationError::storage("database not initialized")
                        })?
                        .commit_initial_ratchet_session(
                            sender_identity_key,
                            &data,
                            one_time_prekey_id,
                        )
                        .map_err(DirectHistoryMutationError::storage)?;
                    if let Some(id) = one_time_prekey_id {
                        if let Some(mut secret) = self.otk_secrets.remove(&id) {
                            secret.zeroize();
                        }
                    }
                    self.ratchet_sessions
                        .insert(*sender_identity_key, candidate);
                    plaintext
                }
            }
            HEADER_RATCHET => {
                if header.len() != 1 + 41 {
                    return Err(DirectHistoryMutationError::rejected(
                        "invalid Direct history ratchet header length",
                    ));
                }
                let ratchet_header = MessageHeader::from_bytes(&header[1..])
                    .map_err(DirectHistoryMutationError::rejected)?;
                let local_identity = self
                    .identity_key()
                    .map_err(DirectHistoryMutationError::storage)?;
                let associated_data = ratchet_associated_data(
                    conversation_id,
                    sender_identity_key,
                    &local_identity,
                    &header[..1],
                )
                .map_err(DirectHistoryMutationError::rejected)?;
                let current = self
                    .ratchet_sessions
                    .get(sender_identity_key)
                    .ok_or_else(|| {
                        DirectHistoryMutationError::rejected(
                            "no Direct history ratchet session with this peer",
                        )
                    })?;
                let mut candidate = current.clone();
                let plaintext = candidate
                    .decrypt_with_ad(&ratchet_header, ciphertext, &associated_data)
                    .map_err(DirectHistoryMutationError::rejected)?;
                let db = self.db.as_ref().ok_or_else(|| {
                    DirectHistoryMutationError::storage("database not initialized")
                })?;
                persist_existing_ratchet_transition_v1(
                    db,
                    sender_identity_key,
                    current,
                    &candidate,
                )
                .map_err(DirectHistoryMutationError::storage)?;
                self.ratchet_sessions
                    .insert(*sender_identity_key, candidate);
                plaintext
            }
            _ => {
                return Err(DirectHistoryMutationError::rejected(
                    "unsupported Direct history E2E header",
                ));
            }
        };

        let mut plaintext = Zeroizing::new(plaintext);
        if plaintext.len() > MAX_PLAINTEXT_BYTES + 1 {
            return Err(DirectHistoryMutationError::rejected(
                "Direct history plaintext exceeds the text limit",
            ));
        }
        if plaintext.first() != Some(&INNER_TEXT) {
            return Err(DirectHistoryMutationError::rejected(
                "Direct history ratchet payload is not text",
            ));
        }
        plaintext.remove(0);
        Ok(std::mem::take(&mut *plaintext))
    }

    /// Strip the inner type byte from ratchet-decrypted plaintext.
    /// `0x00` = real text (return Text), `0x01` = SKDM (process and return Control).
    /// Unprefixed/unknown payloads are rejected to prevent inner-protocol
    /// downgrade after successful ratchet decryption.
    #[cfg(test)]
    fn process_ratchet_plaintext(
        &mut self,
        sender_identity_key: &[u8; 32],
        plaintext: Vec<u8>,
    ) -> Result<DecryptedPayload, String> {
        self.process_ratchet_plaintext_classified_v1(sender_identity_key, plaintext)
            .map_err(DirectHistoryMutationError::into_detail)
    }

    fn process_ratchet_plaintext_classified_v1(
        &mut self,
        sender_identity_key: &[u8; 32],
        plaintext: Vec<u8>,
    ) -> Result<DecryptedPayload, DirectHistoryMutationError> {
        let mut plaintext = Zeroizing::new(plaintext);
        if plaintext.is_empty() {
            return Err(DirectHistoryMutationError::rejected(
                "ratchet plaintext is missing its inner type",
            ));
        }
        match plaintext[0] {
            INNER_TEXT => {
                plaintext.remove(0);
                Ok(DecryptedPayload::Text(std::mem::take(&mut *plaintext)))
            }
            INNER_SKDM => {
                let body = &plaintext[1..];
                let dist: SenderKeyDistribution =
                    serde_json::from_slice(body).map_err(|error| {
                        DirectHistoryMutationError::rejected(format!("decode SKDM: {error}"))
                    })?;
                // Only honour SKDMs whose declared sender matches the ratchet peer.
                if &dist.sender_identity_key != sender_identity_key {
                    return Err(DirectHistoryMutationError::rejected("SKDM sender mismatch"));
                }
                let group_id = dist.group_id.clone();
                self.sender_keys
                    .process_distribution(&dist)
                    .map_err(DirectHistoryMutationError::rejected)?;
                self.channel_conversations.insert(group_id.clone());
                self.sender_key_distribution_pending
                    .insert(group_id.clone());
                self.persist_incoming_sender_key(&group_id, sender_identity_key, dist.key_id)
                    .map_err(DirectHistoryMutationError::storage)?;
                Ok(DecryptedPayload::Control)
            }
            _ => {
                // A valid ratchet frame must still carry a known inner type.
                Err(DirectHistoryMutationError::rejected(format!(
                    "unknown ratchet inner type {:#04x}",
                    plaintext[0]
                )))
            }
        }
    }

    /// Mark a conversation as a channel — outgoing messages will be encrypted
    /// with a sender key, and incoming messages will look up the sender key store.
    pub fn mark_channel_conversation(&mut self, conversation_id: &str) {
        if self.direct_live_storage_uncertain
            || self
                .direct_live_blocked_conversations
                .contains(conversation_id)
        {
            return;
        }
        self.channel_conversations
            .insert(conversation_id.to_string());
        if !self.sender_keys.has_outgoing(conversation_id) {
            self.sender_key_distribution_pending
                .insert(conversation_id.to_string());
        }
    }

    pub fn is_channel_conversation(&self, conversation_id: &str) -> bool {
        !self.direct_live_storage_uncertain
            && !self
                .direct_live_blocked_conversations
                .contains(conversation_id)
            && self.channel_conversations.contains(conversation_id)
    }

    pub fn replace_authorized_conversation_senders(
        &mut self,
        conversation_id: &str,
        senders: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<(), String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        if conversation_id.is_empty() {
            return Err("authorized conversation id must not be empty".to_string());
        }
        let senders: HashSet<_> = senders.into_iter().collect();
        if senders.is_empty() {
            return Err("authenticated conversation directory has no authorized senders".into());
        }
        let roster_changed = self
            .authorized_conversation_senders
            .get(conversation_id)
            .is_some_and(|current| current != &senders);
        if roster_changed && self.channel_conversations.contains(conversation_id) {
            // Reusing a distributed generation after any add/remove would let
            // former members decrypt future traffic (and would omit new
            // members). Rotation also discards outstanding ACK mappings for
            // the old roster and keeps sends blocked until the new SKDM fanout
            // is fully acknowledged.
            if self.device_identity.is_some() {
                // The account directory is only a membership/display input in
                // per-device mode. Block the stale proof immediately; the
                // exact canonical device roster install performs the single
                // required rotation after all bindings have been verified.
                self.invalidate_device_roster_v1(conversation_id);
            } else {
                self.rotate_sender_key(conversation_id)?;
            }
        }
        // Commit the new authorization view only after cache invalidation and
        // rotation succeed. A SQLCipher failure must leave both the old roster
        // and old generation intact, with the caller receiving an error.
        self.authorized_conversation_senders
            .insert(conversation_id.to_string(), senders);
        Ok(())
    }

    pub fn clear_authorized_conversation_senders(&mut self, conversation_id: &str) {
        self.authorized_conversation_senders.remove(conversation_id);
        if self.channel_conversations.contains(conversation_id) {
            self.sender_key_distribution_pending
                .insert(conversation_id.to_string());
        }
    }

    pub fn clear_all_authorized_conversation_senders(&mut self) {
        self.authorized_conversation_senders.clear();
        self.sender_key_distribution_pending
            .extend(self.channel_conversations.iter().cloned());
    }

    pub fn is_currently_authorized_sender(
        &self,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
    ) -> bool {
        self.authorized_conversation_senders
            .get(conversation_id)
            .is_some_and(|senders| senders.contains(sender_identity_key))
    }

    pub fn require_currently_authorized_sender(
        &self,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
    ) -> Result<(), String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        if self.is_currently_authorized_sender(conversation_id, sender_identity_key) {
            Ok(())
        } else {
            Err("live sender is absent from the current authenticated conversation roster".into())
        }
    }

    /// Wrap a UTF-8 message with the inner-text type byte for pairwise channels.
    pub fn wrap_text_inner(plaintext: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + plaintext.len());
        buf.push(INNER_TEXT);
        buf.extend_from_slice(plaintext.as_bytes());
        buf
    }

    fn invalidate_sender_key_envelopes_in_memory(&mut self, conversation_id: &str) {
        self.pending_sender_key_envelopes.retain(|key, wire| {
            let keep = key.conversation_id != conversation_id;
            if !keep {
                wire.zeroize();
            }
            keep
        });
    }

    fn clear_sender_key_envelope_generation(
        &mut self,
        conversation_id: &str,
        generation: u32,
        roster_version: u64,
    ) -> Result<(), String> {
        if let Some(db) = self.db.as_ref() {
            db.delete_pending_sender_key_envelope_generation(conversation_id, generation)?;
            db.delete_pending_sender_key_device_generation_v1(
                conversation_id,
                generation,
                roster_version,
            )?;
        }
        self.pending_sender_key_envelopes.retain(|key, wire| {
            let keep = key.conversation_id != conversation_id || key.generation != generation;
            if !keep {
                wire.zeroize();
            }
            keep
        });
        Ok(())
    }

    /// Force-rotate our outgoing sender key for a channel (e.g. after a member leaves).
    pub fn rotate_sender_key(&mut self, conversation_id: &str) -> Result<(), String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        let owner_key = self
            .device_identity
            .as_ref()
            .ok_or("per-device identity is required for Sender-Key v5")?
            .binding()
            .device_identity_key;
        // Prepare the new secret state on a clone. Generation exhaustion or a
        // durable-store failure therefore leaves both the live generation and
        // the immutable retry cache untouched.
        let mut next_sender_keys = self.sender_keys.clone();
        let mut distribution = next_sender_keys.try_create_outgoing(conversation_id, &owner_key)?;
        let next_state = next_sender_keys
            .serialize_outgoing(conversation_id)
            .ok_or("cannot serialize rotated outgoing sender key")?;
        distribution.zeroize();

        if let Some(db) = self.db.as_ref() {
            db.commit_sender_key_rotation(conversation_id, &owner_key, &next_state)?;
        }

        self.sender_keys = next_sender_keys;
        self.invalidate_sender_key_envelopes_in_memory(conversation_id);
        self.pending_sender_key_sequences
            .retain(|_, pending| pending.conversation_id != conversation_id);
        self.failed_sender_key_distributions.remove(conversation_id);
        self.channel_conversations
            .insert(conversation_id.to_string());
        self.sender_key_distribution_pending
            .insert(conversation_id.to_string());
        self.prepared_sender_key_generations
            .insert(conversation_id.to_string());
        Ok(())
    }

    /// Prepare a distribution attempt without rotating an already-created
    /// generation. Retries must resend the same key until every ACK arrives;
    /// rotating per retry would keep the group permanently pending.
    /// Returns false when the current generation is already fully distributed.
    pub fn begin_sender_key_distribution(&mut self, conversation_id: &str) -> Result<bool, String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        self.channel_conversations
            .insert(conversation_id.to_string());
        if self
            .pending_sender_key_sequences
            .values()
            .any(|pending| pending.conversation_id == conversation_id)
        {
            return Err("sender-key acknowledgements are still pending".to_string());
        }

        let missing = !self.sender_keys.has_outgoing(conversation_id);
        let expired = self.sender_keys.needs_rotation(conversation_id);
        let pending = self
            .sender_key_distribution_pending
            .contains(conversation_id)
            || self
                .failed_sender_key_distributions
                .contains(conversation_id);
        if !missing && !expired && !pending {
            return Ok(false);
        }
        let fresh_generation_prepared = self
            .prepared_sender_key_generations
            .contains(conversation_id);
        if missing || expired || (pending && !fresh_generation_prepared) {
            self.rotate_sender_key(conversation_id)?;
        } else {
            self.failed_sender_key_distributions.remove(conversation_id);
            self.sender_key_distribution_pending
                .insert(conversation_id.to_string());
        }
        Ok(true)
    }

    /// Begin the post-offline-sync fanout with exactly one fresh-generation
    /// transition. Hydration may already have rotated a cold-restored key; in
    /// that case reusing the pending generation is mandatory. Warm reconnects
    /// and first-time conversations rotate here instead.
    pub fn begin_offline_sender_key_distribution(
        &mut self,
        conversation_id: &str,
        refresh: OfflineSenderKeyRefresh,
    ) -> Result<bool, String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        let already_prepared = self
            .prepared_sender_key_generations
            .contains(conversation_id);
        match refresh {
            OfflineSenderKeyRefresh::Required if !already_prepared => {
                self.rotate_sender_key(conversation_id)?;
            }
            OfflineSenderKeyRefresh::AlreadyRotated if !already_prepared => {
                return Err(
                    "offline sender-key refresh marker is stale or belongs to another session"
                        .to_string(),
                );
            }
            _ => {}
        }
        self.begin_sender_key_distribution(conversation_id)
    }

    /// Mark distribution complete only after every current non-self member has
    /// received the fresh generation successfully.
    pub fn mark_sender_key_distributed(&mut self, conversation_id: &str) -> Result<(), String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        if !self.sender_keys.has_outgoing(conversation_id) {
            return Err("cannot complete distribution without an outgoing sender key".to_string());
        }
        if self
            .pending_sender_key_sequences
            .values()
            .any(|pending| pending.conversation_id == conversation_id)
        {
            return Err("sender-key acknowledgements are still pending".to_string());
        }
        self.failed_sender_key_distributions.remove(conversation_id);
        self.sender_key_distribution_pending.remove(conversation_id);
        self.prepared_sender_key_generations.remove(conversation_id);
        Ok(())
    }

    pub fn mark_sender_key_distribution_failed(&mut self, conversation_id: &str) {
        if self.direct_live_storage_uncertain
            || self
                .direct_live_blocked_conversations
                .contains(conversation_id)
        {
            return;
        }
        self.failed_sender_key_distributions
            .insert(conversation_id.to_string());
        self.sender_key_distribution_pending
            .insert(conversation_id.to_string());
    }

    pub fn sender_key_distribution_status(&self, conversation_id: &str) -> &'static str {
        if self.direct_live_storage_uncertain {
            "revoked"
        } else if self
            .direct_live_blocked_conversations
            .contains(conversation_id)
        {
            "quarantined"
        } else if self
            .failed_sender_key_distributions
            .contains(conversation_id)
        {
            "error"
        } else if self
            .sender_key_distribution_pending
            .contains(conversation_id)
            || self
                .pending_sender_key_sequences
                .values()
                .any(|pending| pending.conversation_id == conversation_id)
        {
            "pending"
        } else if self.channel_conversations.contains(conversation_id)
            && self.sender_keys.has_outgoing(conversation_id)
        {
            "ready"
        } else {
            "checking"
        }
    }

    fn validate_cached_sender_key_device_envelope(
        &self,
        key: &PendingSenderKeyEnvelopeKey,
        target: &DeviceTargetV1,
        wire: &[u8],
    ) -> Result<(), String> {
        let metadata = veil_crypto::sender_key::inspect_skdm_metadata(wire)?;
        if metadata.group_id != key.conversation_id || metadata.generation != key.generation {
            return Err("cached SKDM scope does not match its conversation/generation".to_string());
        }
        let local = self
            .device_identity
            .as_ref()
            .ok_or("per-device identity is not initialized")?;
        if metadata.sender_identity_key != local.binding().device_identity_key
            || metadata.sender_signing_key != local.binding().device_signing_key
        {
            return Err("cached SKDM sender binding does not match this device".to_string());
        }
        if key.target_device_id != target.device_id
            || key.target_binding_version != target.binding_version
            || key.roster_version != target.roster_version
            || key.roster_commitment != target.roster_commitment
        {
            return Err("cached SKDM target/roster tuple changed".to_string());
        }
        let commitment: [u8; 32] = Sha256::digest(wire).into();
        if !bool::from(commitment.ct_eq(&key.envelope_commitment)) {
            return Err("cached SKDM envelope commitment mismatch".to_string());
        }
        Ok(())
    }

    fn prepare_sender_key_device_envelope(
        &mut self,
        target: &DeviceTargetV1,
    ) -> Result<(PendingSenderKeyEnvelopeKey, Vec<u8>), String> {
        self.require_direct_conversation_available_v1(&target.conversation_id)?;
        let conversation_id = target.conversation_id.as_str();
        let roster = self
            .device_rosters
            .get(conversation_id)
            .ok_or("validated current device roster is unavailable")?;
        let pinned_target = roster
            .eligible_devices
            .get(&target.device_id)
            .ok_or("target device is not eligible in the current roster")?;
        if pinned_target != target || target.device_id == self.device_id {
            return Err("target device tuple is stale or resolves to this device".to_string());
        }
        let (membership_epoch, membership_epoch_hash) = if roster.membership_activated {
            let head = self
                .membership_epoch_heads
                .get(conversation_id)
                .ok_or("verified membership epoch is unavailable for SKDM distribution")?;
            if head.epoch != roster.membership_epoch
                || head.hash != roster.membership_epoch_hash
                || head.roster_version != roster.version
                || head.roster_commitment != roster.commitment
            {
                return Err("verified membership epoch does not match the SKDM roster".to_string());
            }
            (head.epoch, head.hash)
        } else {
            (0, [0u8; 32])
        };
        if !self.sender_keys.has_outgoing(conversation_id) {
            self.rotate_sender_key(conversation_id)?;
        }
        let mut distribution = self.sender_keys.build_distribution(conversation_id)?;
        let local = self
            .device_identity
            .as_ref()
            .ok_or("per-device identity is not initialized")?;
        if distribution.sender_identity_key != local.binding().device_identity_key {
            distribution.zeroize();
            return Err(
                "outgoing Sender-Key generation is not device-owned; rotation required".to_string(),
            );
        }

        if let Some(db) = self.db.as_ref() {
            if let Some(cached) = db.load_pending_sender_key_device_envelope_v1(
                conversation_id,
                distribution.key_id,
                &target.device_id,
                target.binding_version,
                target.roster_version,
            )? {
                let key = PendingSenderKeyEnvelopeKey {
                    conversation_id: conversation_id.to_string(),
                    generation: distribution.key_id,
                    target_device_id: target.device_id,
                    target_binding_version: target.binding_version,
                    roster_version: target.roster_version,
                    roster_commitment: target.roster_commitment,
                    membership_epoch,
                    membership_epoch_hash,
                    envelope_commitment: cached.envelope_commitment,
                };
                if cached.target_account_identity_key != target.account_identity_key
                    || cached.target_device_identity_key != target.device_identity_key
                    || cached.sender_device_id != self.device_id
                    || cached.sender_device_identity_key != local.binding().device_identity_key
                    || cached.sender_binding_version != local.binding().version
                    || cached.roster_commitment != target.roster_commitment
                    || cached.membership_epoch != membership_epoch
                    || cached.membership_epoch_hash != membership_epoch_hash
                {
                    distribution.zeroize();
                    return Err("persisted exact-device SKDM route tuple changed".to_string());
                }
                self.validate_cached_sender_key_device_envelope(
                    &key,
                    target,
                    &cached.sealed_envelope,
                )?;
                if self
                    .pending_sender_key_envelopes
                    .get(&key)
                    .is_some_and(|in_memory| in_memory != &cached.sealed_envelope)
                {
                    return Err("SQLCipher and in-memory SKDM caches disagree".to_string());
                }
                self.pending_sender_key_envelopes
                    .insert(key.clone(), cached.sealed_envelope.clone());
                distribution.zeroize();
                return Ok((key, cached.sealed_envelope));
            }
        }

        let json = Zeroizing::new(
            serde_json::to_vec(&distribution).map_err(|e| format!("encode SKDM: {e}"))?,
        );
        let generation = distribution.key_id;
        distribution.zeroize();
        let sealed = veil_crypto::sender_key::seal_skdm_authenticated_with_device(
            &local.binding().device_identity_key,
            local.ed25519_signing_key(),
            &target.device_identity_key,
            conversation_id,
            generation,
            &json,
        )?;
        let envelope_commitment: [u8; 32] = Sha256::digest(&sealed).into();
        let key = PendingSenderKeyEnvelopeKey {
            conversation_id: conversation_id.to_string(),
            generation,
            target_device_id: target.device_id,
            target_binding_version: target.binding_version,
            roster_version: target.roster_version,
            roster_commitment: target.roster_commitment,
            membership_epoch,
            membership_epoch_hash,
            envelope_commitment,
        };
        let persisted = PendingSenderKeyDeviceEnvelopeV1 {
            conversation_id: conversation_id.to_string(),
            generation,
            target_account_identity_key: target.account_identity_key,
            target_device_id: target.device_id,
            target_device_identity_key: target.device_identity_key,
            target_binding_version: target.binding_version,
            sender_device_id: self.device_id,
            sender_device_identity_key: local.binding().device_identity_key,
            sender_binding_version: local.binding().version,
            roster_version: target.roster_version,
            roster_commitment: target.roster_commitment,
            membership_epoch,
            membership_epoch_hash,
            envelope_commitment,
            sealed_envelope: sealed,
        };
        let canonical = if let Some(db) = self.db.as_ref() {
            db.save_pending_sender_key_device_envelope_v1(&persisted)?
        } else {
            persisted.sealed_envelope
        };
        self.validate_cached_sender_key_device_envelope(&key, target, &canonical)?;
        self.pending_sender_key_envelopes
            .insert(key.clone(), canonical.clone());
        Ok((key, canonical))
    }

    #[cfg(test)]
    fn prepare_sender_key_envelope(
        &mut self,
        _conversation_id: &str,
        _peer_identity_key: &[u8; 32],
    ) -> Result<(PendingSenderKeyEnvelopeKey, Vec<u8>), String> {
        Err("legacy account-level Sender-Key test helper is disabled".to_string())
    }

    #[deprecated(note = "account-level Sender-Key distribution is disabled; use exact devices")]
    pub async fn send_sender_key_to(
        &mut self,
        _conversation_id: &str,
        _peer_identity_key: &[u8; 32],
    ) -> Result<u64, String> {
        Err("account-level Sender-Key distribution is disabled".to_string())
    }

    pub async fn send_sender_key_to_device(
        &mut self,
        target: &DeviceTargetV1,
    ) -> Result<u64, String> {
        self.require_direct_conversation_available_v1(&target.conversation_id)?;
        let (pending, sealed) = self.prepare_sender_key_device_envelope(target)?;
        let local = self
            .device_identity
            .as_ref()
            .ok_or("per-device identity is not initialized")?;
        let local_account_identity = self.identity_key()?;
        let local_account_signing = self.signing_key()?;

        let conn = self.connection.as_ref().ok_or("not connected")?;
        let seq = conn.next_seq().await;
        let env = proto::Envelope {
            seq,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::SenderKeyDist(
                proto::SenderKeyDistribution {
                    conversation_id: target.conversation_id.clone(),
                    sender_key_message: sealed,
                    generation: pending.generation,
                    target_identity_key: target.account_identity_key.to_vec(),
                    target_device_id: target.device_id.to_vec(),
                    target_device_identity_key: target.device_identity_key.to_vec(),
                    sender_device_id: self.device_id.to_vec(),
                    roster_version: target.roster_version,
                    roster_commitment: target.roster_commitment.to_vec(),
                    sender_binding_version: local.binding().version,
                    target_binding_version: target.binding_version,
                    sender_account_identity_key: local_account_identity.to_vec(),
                    sender_account_signing_key: local_account_signing.to_vec(),
                    sender_device_identity_key: local.binding().device_identity_key.to_vec(),
                    sender_device_signing_key: local.binding().device_signing_key.to_vec(),
                    sender_device_capabilities: local.binding().capabilities,
                    sender_device_binding_status: u32::from(local.binding().status),
                    sender_account_signature: local.binding().account_signature.to_vec(),
                    membership_epoch: pending.membership_epoch,
                    membership_epoch_hash: pending.membership_epoch_hash.to_vec(),
                },
            )),
        };
        conn.send_envelope(&env).await?;
        self.pending_sender_key_sequences.insert(seq, pending);
        Ok(seq)
    }

    #[deprecated(note = "account-domain SKDM processing is disabled; use exact device routes")]
    pub fn process_authenticated_sealed_skdm(
        &mut self,
        _sealed_wire: &[u8],
        _expected_sender_identity_key: &[u8; 32],
        _expected_sender_signing_key: &[u8; 32],
        _expected_group_id: &str,
        _expected_generation: u32,
    ) -> Result<(), String> {
        Err("account-domain SKDM processing is disabled".to_string())
    }

    fn install_authenticated_device_skdm(
        &mut self,
        authenticated: veil_crypto::sender_key::AuthenticatedSkdm,
        sender_account_identity_key: [u8; 32],
        route: &SenderKeyRouteV1,
    ) -> Result<PendingSenderKeyReceiptV1, String> {
        let group_id = authenticated.group_id.clone();
        let mut candidate = self.sender_keys.clone();
        candidate.process_authenticated_skdm(&authenticated)?;
        let state = candidate
            .serialize_incoming_generation(
                &group_id,
                &authenticated.sender_identity_key,
                authenticated.generation,
            )
            .ok_or("cannot serialize installed incoming Sender-Key generation")?;
        let metadata = candidate
            .incoming_generation_metadata(
                &group_id,
                &authenticated.sender_identity_key,
                authenticated.generation,
            )
            .ok_or("cannot inspect installed incoming Sender-Key generation")?;
        let db = self
            .db
            .as_ref()
            .ok_or("durable database is required before acknowledging an SKDM")?;
        db.save_incoming_sender_key_generation_with_route_v1(
            &group_id,
            &authenticated.sender_identity_key,
            authenticated.generation,
            metadata.iteration,
            metadata.revision,
            &metadata
                .distribution_commitment
                .ok_or("incoming Sender-Key distribution has no commitment")?,
            &state,
            &IncomingSenderKeyRouteV1 {
                sender_account_identity_key,
                sender_device_id: route.sender_device_id,
                sender_device_identity_key: authenticated.sender_identity_key,
                sender_device_signing_key: authenticated.sender_signing_key,
                sender_binding_version: route.sender_binding_version,
                target_device_id: route.target_device_id,
                target_binding_version: route.target_binding_version,
                roster_version: route.roster_version,
                roster_commitment: route.roster_commitment,
                membership_epoch: route.membership_epoch,
                membership_epoch_hash: route.membership_epoch_hash,
                envelope_commitment: route.envelope_commitment,
                historical_sender_binding: Some(HistoricalDeviceBindingProofV1 {
                    sender_account_signing_key: route.sender_account_signing_key,
                    sender_device_capabilities: route.sender_device_capabilities,
                    sender_device_binding_status: route.sender_device_binding_status,
                    sender_account_signature: route.sender_account_signature,
                    target_device_identity_key: Some(route.target_device_identity_key),
                }),
            },
        )?;
        self.trusted_signing_keys.insert(
            route.sender_account_identity_key,
            route.sender_account_signing_key,
        );
        self.sender_keys = candidate;
        self.channel_conversations.insert(group_id.clone());
        Ok(PendingSenderKeyReceiptV1 {
            conversation_id: group_id,
            owner_device_id: route.sender_device_id,
            target_device_id: route.target_device_id,
            generation: authenticated.generation,
            roster_version: route.roster_version,
            membership_epoch: route.membership_epoch,
            membership_epoch_hash: route.membership_epoch_hash,
            envelope_commitment: route.envelope_commitment,
        })
    }

    pub fn process_sender_key_distribution_v1(
        &mut self,
        sealed_wire: &[u8],
        route: &SenderKeyRouteV1,
    ) -> Result<PendingSenderKeyReceiptV1, String> {
        self.process_sender_key_distribution_inner_v1(
            sealed_wire,
            route,
            SenderKeyDistributionModeV1::Live,
        )
    }

    fn process_sender_key_distribution_inner_v1(
        &mut self,
        sealed_wire: &[u8],
        route: &SenderKeyRouteV1,
        mode: SenderKeyDistributionModeV1,
    ) -> Result<PendingSenderKeyReceiptV1, String> {
        self.require_direct_conversation_available_v1(&route.conversation_id)?;
        if self.dm_conversations.contains_key(&route.conversation_id) {
            return Err("sender keys are forbidden for DM conversations".to_string());
        }
        if !self.channel_conversations.contains(&route.conversation_id) {
            return Err(
                "sender-key conversation is not an authenticated group/channel".to_string(),
            );
        }
        if (route.membership_epoch == 0) != (route.membership_epoch_hash == [0u8; 32]) {
            return Err("SKDM membership coordinate is partial".to_string());
        }
        if mode == SenderKeyDistributionModeV1::Retained
            && route.membership_epoch != 0
            && !self
                .db
                .as_ref()
                .ok_or("durable database is required for retained membership validation")?
                .membership_epoch_matches_pin_v1(
                    &route.conversation_id,
                    route.membership_epoch,
                    &route.membership_epoch_hash,
                )?
        {
            return Err("retained SKDM membership epoch is not durably pinned".to_string());
        }
        let metadata = veil_crypto::sender_key::inspect_skdm_metadata(sealed_wire)?;
        let computed_envelope_commitment: [u8; 32] = Sha256::digest(sealed_wire).into();
        if metadata.group_id != route.conversation_id
            || metadata.generation != route.generation
            || computed_envelope_commitment != route.envelope_commitment
        {
            return Err("SKDM outer routing context mismatch".to_string());
        }
        let local = self
            .device_identity
            .as_ref()
            .ok_or("per-device identity is not initialized")?;
        let local_account_identity = self.identity_key()?;
        let local_account_signing = self.signing_key()?;
        if route.sender_device_id == [0u8; 16]
            || route.sender_device_id == route.target_device_id
            || route.sender_account_identity_key == [0u8; 32]
            || route.sender_account_signing_key == [0u8; 32]
            || route.sender_device_identity_key == [0u8; 32]
            || route.sender_device_signing_key == [0u8; 32]
            || HashSet::from([
                route.sender_account_identity_key,
                route.sender_account_signing_key,
                route.sender_device_identity_key,
                route.sender_device_signing_key,
            ])
            .len()
                != 4
            || route.sender_binding_version == 0
            || route.sender_binding_version > i64::MAX as u64
            || route.sender_device_capabilities > i64::MAX as u64
            || route.sender_device_capabilities & REQUIRED_DEVICE_CAPABILITIES
                != REQUIRED_DEVICE_CAPABILITIES
            || route.sender_device_binding_status != DEVICE_BINDING_STATUS_ACTIVE
            || route.sender_device_identity_key != metadata.sender_identity_key
            || route.sender_device_signing_key != metadata.sender_signing_key
        {
            return Err("invalid historical sender device binding proof".to_string());
        }
        let proof_bytes = device_binding_signing_bytes(
            &route.sender_account_identity_key,
            &route.sender_account_signing_key,
            &route.sender_device_id,
            route.sender_binding_version,
            &route.sender_device_identity_key,
            &route.sender_device_signing_key,
            route.sender_device_capabilities,
            route.sender_device_binding_status,
        );
        if !veil_crypto::signature::verify(
            &route.sender_account_signing_key,
            &proof_bytes,
            &route.sender_account_signature,
        ) {
            return Err("historical sender device account signature is invalid".to_string());
        }

        if route.target_account_identity_key != local_account_identity
            || route.target_device_id != self.device_id
            || route.target_device_identity_key != local.binding().device_identity_key
            || route.target_binding_version == 0
            || route.target_binding_version > local.binding().version
        {
            return Err("SKDM is not routed to the current authenticated device".to_string());
        }
        let current_roster = self
            .device_rosters
            .get(&route.conversation_id)
            .ok_or("current device roster is unavailable for SKDM target authorization")?;
        let current_target = current_roster
            .eligible_devices
            .get(&self.device_id)
            .ok_or("current device is not eligible in the installed roster")?;
        if current_target.account_identity_key != local_account_identity
            || current_target.account_signing_key != local_account_signing
            || current_target.device_identity_key != local.binding().device_identity_key
            || current_target.device_signing_key != local.binding().device_signing_key
            || current_target.binding_version != local.binding().version
            || current_target.capabilities != local.binding().capabilities
            || current_target.account_signature != local.binding().account_signature
        {
            return Err(
                "installed target roster no longer matches local device identity".to_string(),
            );
        }
        if mode == SenderKeyDistributionModeV1::Live {
            self.require_live_membership_context_v1(
                &route.conversation_id,
                current_roster,
                route.membership_epoch,
                &route.membership_epoch_hash,
            )?;
            if route.target_binding_version != local.binding().version
                || route.roster_version != current_roster.version
                || route.roster_commitment != current_roster.commitment
            {
                return Err("live SKDM does not match the exact current roster head".to_string());
            }
            let current_sender = current_roster
                .eligible_devices
                .get(&route.sender_device_id)
                .ok_or("live SKDM sender is not eligible in the current roster")?;
            if current_sender.account_identity_key != route.sender_account_identity_key
                || current_sender.account_signing_key != route.sender_account_signing_key
                || current_sender.device_identity_key != route.sender_device_identity_key
                || current_sender.device_signing_key != route.sender_device_signing_key
                || current_sender.binding_version != route.sender_binding_version
                || current_sender.capabilities != route.sender_device_capabilities
                || current_sender.account_signature != route.sender_account_signature
            {
                return Err(
                    "live SKDM sender binding does not match the current roster".to_string()
                );
            }
        }

        let authenticated = veil_crypto::sender_key::open_skdm_authenticated_with_device(
            local.x25519_secret(),
            &local.binding().device_identity_key,
            &metadata.sender_identity_key,
            &metadata.sender_signing_key,
            &route.conversation_id,
            route.generation,
            sealed_wire,
        )?;
        let receipt = self.install_authenticated_device_skdm(
            authenticated,
            route.sender_account_identity_key,
            route,
        )?;
        if self.pending_sender_key_receipt_set.insert(receipt.clone()) {
            self.pending_sender_key_receipts.push_back(receipt.clone());
        }
        Ok(receipt)
    }

    #[deprecated(note = "use process_sender_key_distribution_v1 with exact route metadata")]
    pub fn process_sealed_skdm(
        &mut self,
        _sealed_wire: &[u8],
        _outer_group_id: &str,
        _outer_generation: u32,
    ) -> Result<(), String> {
        Err("Sender-Key route metadata is required".to_string())
    }

    /// Send receipts only for generations already committed to SQLCipher.
    /// A transport failure leaves the FIFO intact; retained replay is also
    /// idempotent because the receipt set is keyed by the immutable route.
    pub async fn flush_sender_key_receipts_v1(&mut self) -> Result<usize, String> {
        self.require_crypto_runtime_active_v1()?;
        let mut sent = 0usize;
        while let Some(receipt) = self.pending_sender_key_receipts.front().cloned() {
            if self
                .direct_live_blocked_conversations
                .contains(&receipt.conversation_id)
            {
                self.pending_sender_key_receipts.pop_front();
                self.pending_sender_key_receipt_set.remove(&receipt);
                continue;
            }
            let conn = self.connection.as_ref().ok_or("not connected")?;
            let seq = conn.next_seq().await;
            conn.send_envelope(&proto::Envelope {
                seq,
                timestamp: 0,
                payload: Some(proto::envelope::Payload::SenderKeyReceipt(
                    proto::SenderKeyReceipt {
                        conversation_id: receipt.conversation_id.clone(),
                        owner_device_id: receipt.owner_device_id.to_vec(),
                        target_device_id: receipt.target_device_id.to_vec(),
                        generation: receipt.generation,
                        roster_version: receipt.roster_version,
                        envelope_commitment: receipt.envelope_commitment.to_vec(),
                        membership_epoch: receipt.membership_epoch,
                        membership_epoch_hash: receipt.membership_epoch_hash.to_vec(),
                    },
                )),
            })
            .await?;
            self.pending_sender_key_receipts.pop_front();
            self.pending_sender_key_receipt_sequences
                .insert(seq, receipt);
            sent += 1;
        }
        Ok(sent)
    }

    /// Drop a peer's incoming sender key (e.g. after a kick/leave WS event).
    pub fn drop_incoming_sender_key(&mut self, conversation_id: &str, sender_ik: &[u8; 32]) {
        if self.direct_live_storage_uncertain {
            return;
        }
        self.sender_keys.remove_incoming(conversation_id, sender_ik);
        // Note: per-row delete is not exposed by VeilDb today; on next save it
        // will be overwritten if the peer re-distributes.
    }

    fn persist_outgoing_sender_key(&self, conversation_id: &str) -> Result<(), String> {
        let Some(db) = self.db.as_ref() else {
            return Ok(());
        };
        let owner_key = self
            .sender_keys
            .outgoing_owner_identity_key(conversation_id)
            .ok_or("cannot persist sender-key state without an authenticated owner")?;
        let expected_owner = self
            .device_identity
            .as_ref()
            .ok_or("per-device identity is required for Sender-Key v5")?
            .binding()
            .device_identity_key;
        if owner_key != expected_owner {
            return Err("refusing to persist account-owned Sender-Key v5 state".to_string());
        }
        let data = self
            .sender_keys
            .serialize_outgoing(conversation_id)
            .ok_or_else(|| "cannot persist missing outgoing sender key".to_string())?;
        db.save_sender_key(conversation_id, &owner_key, &data, true)
    }

    fn persist_incoming_sender_key(
        &self,
        conversation_id: &str,
        sender_ik: &[u8; 32],
        generation: u32,
    ) -> Result<(), String> {
        let Some(db) = self.db.as_ref() else {
            return Ok(());
        };
        let data = self
            .sender_keys
            .serialize_incoming_generation(conversation_id, sender_ik, generation)
            .ok_or_else(|| "cannot persist missing incoming sender-key generation".to_string())?;
        let metadata = self
            .sender_keys
            .incoming_generation_metadata(conversation_id, sender_ik, generation)
            .ok_or("cannot inspect incoming sender-key generation")?;
        db.save_incoming_sender_key_generation(
            conversation_id,
            sender_ik,
            metadata.generation,
            metadata.iteration,
            metadata.revision,
            &metadata.distribution_commitment.unwrap_or([0u8; 32]),
            &data,
        )
    }

    fn hydrate_incoming_sender_key_generations(
        &mut self,
        conversation_id: &str,
    ) -> Result<(), String> {
        let sender_keys_before = self.sender_keys.clone();
        if let Err(error) = self.hydrate_incoming_sender_key_generations_inner(conversation_id) {
            self.sender_keys = sender_keys_before;
            return Err(error);
        }
        Ok(())
    }

    fn hydrate_incoming_sender_key_generations_inner(
        &mut self,
        conversation_id: &str,
    ) -> Result<(), String> {
        let (generations, legacy) = match self.db.as_ref() {
            Some(db) => (
                db.load_incoming_sender_key_generations_for_group(conversation_id)?,
                db.load_legacy_incoming_sender_keys_for_group(conversation_id)?,
            ),
            None => return Ok(()),
        };

        for row in generations {
            if self.sender_keys.has_incoming_generation(
                conversation_id,
                &row.sender_identity_key,
                row.generation,
            ) {
                continue;
            }
            let metadata = self.sender_keys.load_incoming_generation(
                conversation_id,
                &row.sender_identity_key,
                Some(row.generation),
                Some(row.distribution_commitment),
                &row.key_data,
            )?;
            if metadata.iteration != row.iteration || metadata.revision != row.state_revision {
                return Err("incoming sender-key database metadata does not match state".into());
            }
        }

        for (sender_ik, data) in legacy {
            let mut probe = SenderKeyStore::new();
            probe.load_incoming(conversation_id, &sender_ik, &data)?;
            let generation = probe
                .incoming_generations(conversation_id, &sender_ik)
                .into_iter()
                .next()
                .ok_or("legacy incoming sender-key row decoded without a generation")?;
            let metadata = probe
                .incoming_generation_metadata(conversation_id, &sender_ik, generation)
                .ok_or("cannot inspect legacy incoming sender-key state")?;
            let commitment = metadata.distribution_commitment.unwrap_or([0u8; 32]);
            if !self
                .sender_keys
                .has_incoming_generation(conversation_id, &sender_ik, generation)
            {
                self.sender_keys.load_incoming_generation(
                    conversation_id,
                    &sender_ik,
                    Some(generation),
                    Some(commitment),
                    &data,
                )?;
            }
            self.db
                .as_ref()
                .ok_or("database disappeared during sender-key migration")?
                .migrate_legacy_incoming_sender_key_generation(
                    conversation_id,
                    &sender_ik,
                    generation,
                    metadata.iteration,
                    metadata.revision,
                    &commitment,
                    &data,
                )?;
        }
        Ok(())
    }

    fn ensure_incoming_sender_key_loaded(
        &mut self,
        conversation_id: &str,
        sender_ik: &[u8; 32],
        generation: u32,
    ) -> Result<(), String> {
        if !self
            .sender_keys
            .has_incoming_generation(conversation_id, sender_ik, generation)
        {
            self.hydrate_incoming_sender_key_generations(conversation_id)?;
        }
        if self
            .sender_keys
            .has_incoming_generation(conversation_id, sender_ik, generation)
        {
            Ok(())
        } else {
            Err(format!(
                "incoming sender-key generation {generation} is unavailable after hydration"
            ))
        }
    }

    /// Hydrate sender keys (outgoing + all incoming) for a channel from the DB.
    pub fn hydrate_channel_sender_keys(
        &mut self,
        conversation_id: &str,
    ) -> Result<OfflineSenderKeyRefresh, String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        self.channel_conversations
            .insert(conversation_id.to_string());
        let account_key = self.identity_key()?;
        let expected_owner = self
            .device_identity
            .as_ref()
            .map(|device| device.binding().device_identity_key)
            .unwrap_or(account_key);
        let had_outgoing = self.sender_keys.has_outgoing(conversation_id);
        let mut restored_outgoing = false;
        let mut legacy_account_owner = self
            .sender_keys
            .outgoing_owner_identity_key(conversation_id)
            .is_some_and(|owner| owner != expected_owner);
        if let Some(db) = self.db.as_ref() {
            let rows = db.load_outgoing_sender_keys_for_group(conversation_id)?;
            for (ik, data) in rows {
                if ik != expected_owner {
                    if self.device_identity.is_some() && ik == account_key {
                        legacy_account_owner = true;
                        continue;
                    }
                    return Err(
                        "persisted outgoing sender key does not belong to this identity"
                            .to_string(),
                    );
                }
                if self.sender_keys.has_outgoing(conversation_id) {
                    let current = self
                        .sender_keys
                        .serialize_outgoing(conversation_id)
                        .ok_or("cannot inspect hydrated outgoing sender key")?;
                    if current.as_slice() != data.as_slice() {
                        return Err(
                            "in-memory and persisted outgoing sender-key states disagree"
                                .to_string(),
                        );
                    }
                } else {
                    self.sender_keys.load_outgoing(conversation_id, &data)?;
                    restored_outgoing = true;
                }
            }
        }
        self.hydrate_incoming_sender_key_generations(conversation_id)?;
        if legacy_account_owner || (!had_outgoing && restored_outgoing) {
            // The authoritative roster is not yet persisted across a native
            // session. Continuing a restored generation after an offline
            // membership/permission change could let a former member retain
            // future access. Conservatively rotate exactly once on cold
            // restore and keep sending blocked until the current roster has
            // durably received the new generation.
            self.rotate_sender_key(conversation_id)?;
            return Ok(OfflineSenderKeyRefresh::AlreadyRotated);
        }
        if self
            .prepared_sender_key_generations
            .contains(conversation_id)
        {
            return Ok(OfflineSenderKeyRefresh::AlreadyRotated);
        }
        Ok(OfflineSenderKeyRefresh::Required)
    }

    fn with_classified_receive_savepoint<T>(
        &mut self,
        rollback_label: &str,
        operation: impl FnOnce(&mut Self) -> Result<T, DirectHistoryMutationError>,
    ) -> Result<T, DirectHistoryMutationError> {
        let crypto_snapshot = self.receive_crypto_snapshot();
        self.db
            .as_ref()
            .ok_or_else(|| DirectHistoryMutationError::storage("database not initialized"))?
            .begin_receive_savepoint()
            .map_err(DirectHistoryMutationError::storage)?;

        match operation(self) {
            Ok(value) => {
                if let Err(commit_error) = self
                    .db
                    .as_ref()
                    .ok_or_else(|| DirectHistoryMutationError::storage("database not initialized"))?
                    .commit_receive_savepoint()
                {
                    let rollback_error = self
                        .db
                        .as_ref()
                        .and_then(|db| db.rollback_receive_savepoint().err());
                    self.restore_receive_crypto(crypto_snapshot);
                    let detail = rollback_error.map_or(commit_error.clone(), |rollback_error| {
                        format!(
                            "{commit_error}; {rollback_label} rollback also failed: {rollback_error}"
                        )
                    });
                    return Err(DirectHistoryMutationError::storage(detail));
                }
                Ok(value)
            }
            Err(error) => {
                let rollback_error = self
                    .db
                    .as_ref()
                    .and_then(|db| db.rollback_receive_savepoint().err());
                self.restore_receive_crypto(crypto_snapshot);
                if let Some(rollback_error) = rollback_error {
                    return Err(DirectHistoryMutationError::storage(format!(
                        "{}; {rollback_label} rollback also failed: {rollback_error}",
                        error.into_detail()
                    )));
                }
                Err(error)
            }
        }
    }

    /// Authenticate, decrypt and persist one inbound network message as a
    /// single logical transaction. Crypto helpers write their advanced state
    /// to SQLite inside the savepoint; a later FK/message/index preparation
    /// failure rolls those writes and the in-memory ratchets back together.
    ///
    /// `sender_key_mode` is the authenticated directory conversation kind,
    /// not a hint derived from the untrusted wire header.
    /// `author_snapshot` is presentation metadata resolved from that same
    /// authenticated origin. It is committed beside the plaintext row but is
    /// never consulted for decryption, authorization, or key rotation.
    // These parameters are the authenticated wire and persistence context;
    // keeping borrowed slices avoids extra plaintext/ciphertext copies.
    #[allow(clippy::too_many_arguments)]
    pub fn receive_and_persist_live_message(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        author_snapshot: Option<&AccountSnapshot>,
        author_context: Option<MessageAuthorContext>,
        sender_key_mode: bool,
        security_context: Option<&MessageSecurityContextV1>,
        fallback_conversation_name: Option<&str>,
        header: &[u8],
        ciphertext: &[u8],
        server_timestamp: Option<i64>,
        reply_to_id: Option<&str>,
        remote_metadata: Option<&RemoteMessageMetadata<'_>>,
    ) -> Result<ReceiveMessageResult, String> {
        self.receive_and_persist_live_message_with_attachments(
            message_id,
            conversation_id,
            sender_identity_key,
            author_snapshot,
            author_context,
            sender_key_mode,
            security_context,
            fallback_conversation_name,
            header,
            ciphertext,
            server_timestamp,
            reply_to_id,
            &[],
            remote_metadata,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn receive_and_persist_live_message_with_attachments(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        author_snapshot: Option<&AccountSnapshot>,
        author_context: Option<MessageAuthorContext>,
        sender_key_mode: bool,
        security_context: Option<&MessageSecurityContextV1>,
        fallback_conversation_name: Option<&str>,
        header: &[u8],
        ciphertext: &[u8],
        server_timestamp: Option<i64>,
        reply_to_id: Option<&str>,
        attachments: &[crate::attachments::WireAttachmentV1],
        remote_metadata: Option<&RemoteMessageMetadata<'_>>,
    ) -> Result<ReceiveMessageResult, String> {
        self.require_currently_authorized_sender(conversation_id, sender_identity_key)?;
        self.receive_and_persist_message_with_attachments(
            message_id,
            conversation_id,
            sender_identity_key,
            author_snapshot,
            author_context,
            sender_key_mode,
            security_context,
            fallback_conversation_name,
            header,
            ciphertext,
            server_timestamp,
            reply_to_id,
            attachments,
            remote_metadata,
        )
    }

    /// Historical/offline receive path. The desktop calls this only after an
    /// authenticated directory comparison; former members may be decrypted
    /// from durable pins without granting them live authorization.
    #[allow(clippy::too_many_arguments)]
    pub fn receive_and_persist_message(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        author_snapshot: Option<&AccountSnapshot>,
        author_context: Option<MessageAuthorContext>,
        sender_key_mode: bool,
        security_context: Option<&MessageSecurityContextV1>,
        fallback_conversation_name: Option<&str>,
        header: &[u8],
        ciphertext: &[u8],
        server_timestamp: Option<i64>,
        reply_to_id: Option<&str>,
        remote_metadata: Option<&RemoteMessageMetadata<'_>>,
    ) -> Result<ReceiveMessageResult, String> {
        self.receive_and_persist_message_with_attachments(
            message_id,
            conversation_id,
            sender_identity_key,
            author_snapshot,
            author_context,
            sender_key_mode,
            security_context,
            fallback_conversation_name,
            header,
            ciphertext,
            server_timestamp,
            reply_to_id,
            &[],
            remote_metadata,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn receive_and_persist_message_with_attachments(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        author_snapshot: Option<&AccountSnapshot>,
        author_context: Option<MessageAuthorContext>,
        sender_key_mode: bool,
        security_context: Option<&MessageSecurityContextV1>,
        fallback_conversation_name: Option<&str>,
        header: &[u8],
        ciphertext: &[u8],
        server_timestamp: Option<i64>,
        reply_to_id: Option<&str>,
        attachments: &[crate::attachments::WireAttachmentV1],
        remote_metadata: Option<&RemoteMessageMetadata<'_>>,
    ) -> Result<ReceiveMessageResult, String> {
        let result = self.receive_and_persist_message_with_attachments_classified(
            message_id,
            conversation_id,
            sender_identity_key,
            author_snapshot,
            author_context,
            sender_key_mode,
            security_context,
            fallback_conversation_name,
            header,
            ciphertext,
            server_timestamp,
            reply_to_id,
            attachments,
            remote_metadata,
            AtomicReceiveDecryptMode::General,
        );
        self.resolve_public_classified_mutation_v1(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn receive_and_persist_direct_history_message(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        author_snapshot: &AccountSnapshot,
        author_context: MessageAuthorContext,
        security_context: Option<&MessageSecurityContextV1>,
        header: &[u8],
        ciphertext: &[u8],
        server_timestamp: Option<i64>,
        reply_to_id: Option<&str>,
        remote_metadata: Option<&RemoteMessageMetadata<'_>>,
    ) -> Result<ReceiveMessageResult, DirectHistoryMutationError> {
        self.receive_and_persist_message_with_attachments_classified(
            message_id,
            conversation_id,
            sender_identity_key,
            Some(author_snapshot),
            Some(author_context),
            false,
            security_context,
            None,
            header,
            ciphertext,
            server_timestamp,
            reply_to_id,
            &[],
            remote_metadata,
            AtomicReceiveDecryptMode::DirectHistory,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn receive_and_persist_message_with_attachments_classified(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        author_snapshot: Option<&AccountSnapshot>,
        author_context: Option<MessageAuthorContext>,
        sender_key_mode: bool,
        security_context: Option<&MessageSecurityContextV1>,
        fallback_conversation_name: Option<&str>,
        header: &[u8],
        ciphertext: &[u8],
        server_timestamp: Option<i64>,
        reply_to_id: Option<&str>,
        attachments: &[crate::attachments::WireAttachmentV1],
        remote_metadata: Option<&RemoteMessageMetadata<'_>>,
        decrypt_mode: AtomicReceiveDecryptMode,
    ) -> Result<ReceiveMessageResult, DirectHistoryMutationError> {
        self.require_classified_receive_available_v1(conversation_id)?;
        if message_id.is_empty() || conversation_id.is_empty() {
            return Err(DirectHistoryMutationError::rejected(
                "inbound message and conversation ids must not be empty",
            ));
        }
        if header.is_empty() || ciphertext.is_empty() {
            return Err(DirectHistoryMutationError::rejected(
                "inbound E2E header and ciphertext must not be empty",
            ));
        }
        if author_snapshot.is_some() != author_context.is_some() {
            return Err(DirectHistoryMutationError::rejected(
                "inbound author snapshot and observation context must be paired",
            ));
        }
        self.validate_inbound_author_snapshot_classified_v1(
            conversation_id,
            sender_identity_key,
            author_snapshot,
        )?;
        if !sender_key_mode && !self.trusted_signing_keys.contains_key(sender_identity_key) {
            return Err(DirectHistoryMutationError::rejected(
                "inbound sender identity is not pinned to a signing key",
            ));
        }
        let wire_uses_sender_key = header.first() == Some(&HEADER_SENDER_KEY);
        if wire_uses_sender_key != sender_key_mode {
            return Err(DirectHistoryMutationError::rejected(
                "inbound E2E header conflicts with the pinned conversation type",
            ));
        }
        match (sender_key_mode, security_context) {
            (
                true,
                Some(
                    MessageSecurityContextV1::SenderKeyV5(_)
                    | MessageSecurityContextV1::SenderKeyV6(_),
                ),
            ) => {}
            (false, Some(MessageSecurityContextV1::DirectV2(_))) => {}
            #[cfg(any(test, feature = "test-utils"))]
            (false, None) => {}
            _ => {
                return Err(DirectHistoryMutationError::rejected(
                    "inbound message security context conflicts with the conversation type",
                ));
            }
        }
        if let Some(
            security_context @ (MessageSecurityContextV1::SenderKeyV5(_)
            | MessageSecurityContextV1::SenderKeyV6(_)),
        ) = security_context
        {
            self.validate_sender_key_message_context_v1(
                conversation_id,
                sender_identity_key,
                ciphertext,
                security_context,
            )
            .map_err(DirectHistoryMutationError::rejected)?;
        }

        let classified_result = self.with_classified_receive_savepoint("receive", |client| {
            if let Some((
                bound_conversation_id,
                bound_sender_key,
                bound_is_outgoing,
                bound_server_timestamp,
            )) = client
                .db
                .as_ref()
                .ok_or_else(|| DirectHistoryMutationError::storage("database not initialized"))?
                .get_message_binding(message_id)
                .map_err(DirectHistoryMutationError::storage)?
            {
                let timestamp_matches = match (bound_server_timestamp, server_timestamp) {
                    (Some(bound), Some(presented)) => bound == presented,
                    _ => true,
                };
                if bound_conversation_id != conversation_id
                    || bound_sender_key.as_slice() != sender_identity_key
                    || bound_is_outgoing
                    || !timestamp_matches
                {
                    return Err(DirectHistoryMutationError::rejected(
                        "inbound duplicate conflicts with its persisted message binding",
                    ));
                }
                if let (Some(author_snapshot), Some(author_context)) =
                    (author_snapshot, author_context)
                {
                    client
                        .db
                        .as_ref()
                        .ok_or_else(|| {
                            DirectHistoryMutationError::storage("database not initialized")
                        })?
                        .attach_message_author_with_context(
                            message_id,
                            author_snapshot,
                            author_context,
                        )
                        .map_err(DirectHistoryMutationError::storage)?;
                }
                return Ok(ClassifiedReceiveResultV1::Duplicate);
            }
            client
                .db
                .as_ref()
                .ok_or_else(|| DirectHistoryMutationError::storage("database not initialized"))?
                .ensure_receive_conversation(
                    conversation_id,
                    sender_key_mode,
                    sender_identity_key,
                    fallback_conversation_name,
                )
                .map_err(DirectHistoryMutationError::storage)?;

            let mut decrypted = Zeroizing::new(match decrypt_mode {
                AtomicReceiveDecryptMode::General => {
                    match client.decrypt_from_with_security_context_classified_v1(
                        sender_identity_key,
                        conversation_id,
                        header,
                        ciphertext,
                        security_context,
                    )? {
                        DecryptedPayload::Text(plaintext) => plaintext,
                        DecryptedPayload::Control => {
                            return Err(DirectHistoryMutationError::rejected(
                                "control frame is not valid on the chat message receive path",
                            ));
                        }
                    }
                }
                AtomicReceiveDecryptMode::DirectHistory => {
                    if matches!(
                        security_context,
                        Some(MessageSecurityContextV1::DirectV2(_))
                    ) {
                        match client.decrypt_from_with_security_context_classified_v1(
                            sender_identity_key,
                            conversation_id,
                            header,
                            ciphertext,
                            security_context,
                        )? {
                            DecryptedPayload::Text(plaintext) => plaintext,
                            DecryptedPayload::Control => {
                                return Err(DirectHistoryMutationError::rejected(
                                    "control frame is not valid in Direct history",
                                ));
                            }
                        }
                    } else {
                        #[cfg(any(test, feature = "test-utils"))]
                        {
                            client.decrypt_direct_history_text_classified(
                                sender_identity_key,
                                conversation_id,
                                header,
                                ciphertext,
                            )?
                        }
                        #[cfg(not(any(test, feature = "test-utils")))]
                        {
                            return Err(DirectHistoryMutationError::rejected(
                                "Direct v2 history is missing its exact device/session context",
                            ));
                        }
                    }
                }
            });
            let (plaintext, private_attachments) = if attachments.is_empty() {
                if crate::attachments::is_attachment_payload_v1(&decrypted) {
                    return Err(DirectHistoryMutationError::rejected(
                        "attachment payload has no authenticated public descriptors",
                    ));
                }
                let plaintext = match String::from_utf8(std::mem::take(&mut *decrypted)) {
                    Ok(plaintext) => plaintext,
                    Err(error) => {
                        let mut plaintext = error.into_bytes();
                        plaintext.zeroize();
                        return Err(DirectHistoryMutationError::rejected(
                            "inbound plaintext is not valid UTF-8",
                        ));
                    }
                };
                (plaintext, Vec::new())
            } else {
                let opened = crate::attachments::open_attachment_message_v1(
                    conversation_id,
                    &decrypted,
                    attachments,
                )
                .map_err(DirectHistoryMutationError::rejected)?;
                (opened.text, opened.attachments)
            };
            let plaintext = Zeroizing::new(plaintext);
            if !sender_key_mode {
                // Successful authenticated ratchet decryption is the first
                // evidence that the peer possesses this session. Clearing the
                // repeatable X3DH header participates in the same savepoint as
                // the message and ratchet-state commit.
                client
                    .confirm_peer_session_possession(sender_identity_key)
                    .map_err(DirectHistoryMutationError::storage)?;
            }
            client
                .db
                .as_ref()
                .ok_or_else(|| DirectHistoryMutationError::storage("database not initialized"))?
                .insert_message(
                    message_id,
                    conversation_id,
                    sender_identity_key,
                    &plaintext,
                    false,
                    server_timestamp,
                    reply_to_id,
                )
                .map_err(DirectHistoryMutationError::storage)?;
            client
                .db
                .as_ref()
                .ok_or_else(|| DirectHistoryMutationError::storage("database not initialized"))?
                .insert_message_attachments(message_id, &private_attachments)
                .map_err(DirectHistoryMutationError::storage)?;
            if let (Some(author_snapshot), Some(author_context)) = (author_snapshot, author_context)
            {
                client
                    .db
                    .as_ref()
                    .ok_or_else(|| DirectHistoryMutationError::storage("database not initialized"))?
                    .attach_message_author_with_context(message_id, author_snapshot, author_context)
                    .map_err(DirectHistoryMutationError::storage)?;
            }
            if let Some(metadata) = remote_metadata {
                let db = client.db.as_ref().ok_or_else(|| {
                    DirectHistoryMutationError::storage("database not initialized")
                })?;
                db.record_remote_message_state(
                    message_id,
                    conversation_id,
                    sender_identity_key,
                    metadata.revision_ms,
                    RemoteMessageStateKind::Active,
                )
                .map_err(DirectHistoryMutationError::storage)?;
                if let Some(reactions) = metadata.reactions {
                    db.replace_message_reactions(message_id, reactions)
                        .map_err(DirectHistoryMutationError::storage)?;
                }
            }
            Ok(ClassifiedReceiveResultV1::Stored { plaintext })
        })?;

        // The savepoint has committed successfully. Only now may plaintext
        // leave its zeroizing guard in the established public result shape.
        // A commit/rollback error above drops ClassifiedReceiveResultV1 and
        // wipes the String before returning StorageUncertain.
        let result = match classified_result {
            ClassifiedReceiveResultV1::Stored { mut plaintext } => ReceiveMessageResult::Stored {
                plaintext: std::mem::take(&mut *plaintext),
            },
            ClassifiedReceiveResultV1::Duplicate => ReceiveMessageResult::Duplicate,
        };

        if let ReceiveMessageResult::Stored { ref plaintext } = result {
            if let Some(ref idx) = self.indexer {
                let ts = server_timestamp.unwrap_or_else(|| {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|duration| duration.as_millis() as i64)
                        .unwrap_or(0)
                });
                let _ = idx.index_message(
                    message_id,
                    conversation_id,
                    &hex::encode(sender_identity_key),
                    plaintext,
                    ts,
                );
            }
        }
        Ok(result)
    }

    fn commit_remote_metadata_only_classified(
        &self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        metadata: &RemoteMessageMetadata<'_>,
        state: RemoteMessageStateKind,
        delete_local: bool,
    ) -> Result<(), DirectHistoryMutationError> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| DirectHistoryMutationError::storage("database not initialized"))?;
        db.begin_receive_savepoint()
            .map_err(DirectHistoryMutationError::storage)?;
        let operation = (|| -> Result<(), DirectHistoryMutationError> {
            if delete_local {
                db.delete_message_scoped(message_id, conversation_id)
                    .map_err(DirectHistoryMutationError::storage)?;
            }
            db.record_remote_message_state(
                message_id,
                conversation_id,
                sender_identity_key,
                metadata.revision_ms,
                state,
            )
            .map_err(DirectHistoryMutationError::storage)?;
            if state == RemoteMessageStateKind::Active
                && db
                    .message_exists(message_id)
                    .map_err(DirectHistoryMutationError::storage)?
            {
                if let Some(reactions) = metadata.reactions {
                    db.replace_message_reactions(message_id, reactions)
                        .map_err(DirectHistoryMutationError::storage)?;
                }
            } else {
                // Tombstones and ciphertext that is intentionally unavailable
                // must not leave reaction metadata for a message body we no
                // longer retain. The reactions table predates foreign keys, so
                // clear it explicitly rather than relying on message deletion.
                db.replace_message_reactions(message_id, &[])
                    .map_err(DirectHistoryMutationError::storage)?;
            }
            Ok(())
        })();
        match operation {
            Ok(()) => db
                .commit_receive_savepoint()
                .map_err(DirectHistoryMutationError::storage),
            Err(error) => {
                let rollback = db.rollback_receive_savepoint();
                Err(match (error, rollback) {
                    (DirectHistoryMutationError::StorageUncertain(detail), Ok(())) => {
                        DirectHistoryMutationError::storage(detail)
                    }
                    (error, Ok(())) => error,
                    (error, Err(rollback_error)) => DirectHistoryMutationError::storage(format!(
                        "{}; remote metadata rollback failed: {rollback_error}",
                        error.into_detail()
                    )),
                })
            }
        }
    }

    /// Reconcile server state that either needs no ciphertext or determines
    /// which atomic ciphertext path the caller must take next. Reaction rows
    /// are authoritative and replaced even when the content revision is equal.
    pub fn reconcile_remote_message_metadata(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        metadata: &RemoteMessageMetadata<'_>,
        state: RemoteMessageStateKind,
    ) -> Result<RemoteReconcileAction, String> {
        let result = self.reconcile_remote_message_metadata_classified(
            message_id,
            conversation_id,
            sender_identity_key,
            metadata,
            state,
        );
        self.resolve_public_classified_mutation_v1(result)
    }

    pub(crate) fn reconcile_remote_message_metadata_classified(
        &self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        metadata: &RemoteMessageMetadata<'_>,
        state: RemoteMessageStateKind,
    ) -> Result<RemoteReconcileAction, DirectHistoryMutationError> {
        self.require_classified_receive_available_v1(conversation_id)?;
        if metadata.revision_ms < 0 {
            return Err(DirectHistoryMutationError::rejected(
                "remote message revision must not be negative",
            ));
        }
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| DirectHistoryMutationError::storage("database not initialized"))?;
        let binding = db
            .get_message_binding(message_id)
            .map_err(DirectHistoryMutationError::storage)?;
        if let Some((bound_conversation, bound_sender, _, _)) = binding.as_ref() {
            if bound_conversation != conversation_id
                || bound_sender.as_slice() != sender_identity_key
            {
                return Err(DirectHistoryMutationError::rejected(
                    "remote message conflicts with its local binding",
                ));
            }
        }
        let remote = db
            .get_remote_message_state(message_id)
            .map_err(DirectHistoryMutationError::storage)?;
        if let Some(remote) = remote.as_ref() {
            if remote.conversation_id != conversation_id
                || remote.sender_key.as_slice() != sender_identity_key
            {
                return Err(DirectHistoryMutationError::rejected(
                    "remote message UUID changed scope or sender",
                ));
            }
            if metadata.revision_ms < remote.revision_ms {
                return Err(DirectHistoryMutationError::rejected(
                    "remote message revision moved backwards",
                ));
            }
        }

        match state {
            RemoteMessageStateKind::Deleted | RemoteMessageStateKind::Expired => {
                self.commit_remote_metadata_only_classified(
                    message_id,
                    conversation_id,
                    sender_identity_key,
                    metadata,
                    state,
                    true,
                )?;
                if let Some(indexer) = self.indexer.as_ref() {
                    let _ = indexer.delete(message_id);
                }
                Ok(RemoteReconcileAction::Deleted)
            }
            RemoteMessageStateKind::Unavailable => {
                self.commit_remote_metadata_only_classified(
                    message_id,
                    conversation_id,
                    sender_identity_key,
                    metadata,
                    state,
                    false,
                )?;
                Ok(RemoteReconcileAction::Unavailable)
            }
            RemoteMessageStateKind::Active => {
                if let Some((_, _, is_outgoing, _)) = binding.as_ref() {
                    if *is_outgoing {
                        self.commit_remote_metadata_only_classified(
                            message_id,
                            conversation_id,
                            sender_identity_key,
                            metadata,
                            state,
                            false,
                        )?;
                        return Ok(RemoteReconcileAction::SelfStateOnly);
                    }
                } else {
                    return Ok(RemoteReconcileAction::NeedsInitialCiphertext);
                }

                match remote {
                    Some(remote) if metadata.revision_ms == remote.revision_ms => {
                        if remote.state != RemoteMessageStateKind::Active {
                            return Err(DirectHistoryMutationError::rejected(
                                "remote message attempted same-revision resurrection",
                            ));
                        }
                        self.commit_remote_metadata_only_classified(
                            message_id,
                            conversation_id,
                            sender_identity_key,
                            metadata,
                            state,
                            false,
                        )?;
                        Ok(RemoteReconcileAction::Unchanged)
                    }
                    Some(_) => Ok(RemoteReconcileAction::NeedsEncryptedEdit),
                    None => {
                        let created_ms = binding.and_then(|(_, _, _, timestamp)| timestamp);
                        if created_ms.is_some_and(|created| metadata.revision_ms > created) {
                            Ok(RemoteReconcileAction::NeedsEncryptedEdit)
                        } else {
                            self.commit_remote_metadata_only_classified(
                                message_id,
                                conversation_id,
                                sender_identity_key,
                                metadata,
                                state,
                                false,
                            )?;
                            Ok(RemoteReconcileAction::Unchanged)
                        }
                    }
                }
            }
        }
    }

    /// Transactional counterpart for encrypted live/offline edits. The
    /// receive ratchet, plaintext update, revision and reactions commit or
    /// roll back together.
    #[allow(clippy::too_many_arguments)]
    pub fn receive_and_persist_live_edit(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        author_snapshot: Option<&AccountSnapshot>,
        author_context: Option<MessageAuthorContext>,
        sender_key_mode: bool,
        security_context: Option<&MessageSecurityContextV1>,
        header: &[u8],
        ciphertext: &[u8],
        remote_metadata: Option<&RemoteMessageMetadata<'_>>,
    ) -> Result<String, String> {
        self.require_currently_authorized_sender(conversation_id, sender_identity_key)?;
        self.receive_and_persist_edit(
            message_id,
            conversation_id,
            sender_identity_key,
            author_snapshot,
            author_context,
            sender_key_mode,
            security_context,
            header,
            ciphertext,
            remote_metadata,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn receive_and_persist_edit(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        author_snapshot: Option<&AccountSnapshot>,
        author_context: Option<MessageAuthorContext>,
        sender_key_mode: bool,
        security_context: Option<&MessageSecurityContextV1>,
        header: &[u8],
        ciphertext: &[u8],
        remote_metadata: Option<&RemoteMessageMetadata<'_>>,
    ) -> Result<String, String> {
        let result = self.receive_and_persist_edit_classified(
            message_id,
            conversation_id,
            sender_identity_key,
            author_snapshot,
            author_context,
            sender_key_mode,
            security_context,
            header,
            ciphertext,
            remote_metadata,
        );
        let mut plaintext = self.resolve_public_classified_mutation_v1(result)?;
        let plaintext = std::mem::take(&mut *plaintext);
        if let Some(indexer) = self.indexer.as_ref() {
            let _ = indexer.update_message_body(message_id, &plaintext);
        }
        Ok(plaintext)
    }

    #[allow(clippy::too_many_arguments)]
    fn receive_and_persist_edit_classified(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        author_snapshot: Option<&AccountSnapshot>,
        author_context: Option<MessageAuthorContext>,
        sender_key_mode: bool,
        security_context: Option<&MessageSecurityContextV1>,
        header: &[u8],
        ciphertext: &[u8],
        remote_metadata: Option<&RemoteMessageMetadata<'_>>,
    ) -> Result<Zeroizing<String>, DirectHistoryMutationError> {
        self.require_classified_receive_available_v1(conversation_id)?;
        if sender_key_mode || self.channel_conversations.contains(conversation_id) {
            return Err(DirectHistoryMutationError::rejected(
                "encrypted group/channel edits are disabled until an exact device edit protocol exists"
            ));
        }
        if author_snapshot.is_some() != author_context.is_some() {
            return Err(DirectHistoryMutationError::rejected(
                "edit author snapshot and observation context must be paired",
            ));
        }
        self.validate_inbound_author_snapshot_classified_v1(
            conversation_id,
            sender_identity_key,
            author_snapshot,
        )?;
        if !self.trusted_signing_keys.contains_key(sender_identity_key) {
            return Err(DirectHistoryMutationError::rejected(
                "edit sender identity is not pinned to a signing key",
            ));
        }
        if header.is_empty()
            || ciphertext.is_empty()
            || (header.first() == Some(&HEADER_SENDER_KEY)) != sender_key_mode
        {
            return Err(DirectHistoryMutationError::rejected(
                "edit E2E header conflicts with the conversation type",
            ));
        }

        self.with_classified_receive_savepoint("edit", |client| {
            client
                .db
                .as_ref()
                .ok_or_else(|| DirectHistoryMutationError::storage("database not initialized"))?
                .ensure_receive_conversation(
                    conversation_id,
                    sender_key_mode,
                    sender_identity_key,
                    None,
                )
                .map_err(DirectHistoryMutationError::storage)?;
            let plaintext = match client.decrypt_from_with_security_context_classified_v1(
                sender_identity_key,
                conversation_id,
                header,
                ciphertext,
                security_context,
            )? {
                DecryptedPayload::Text(plaintext) => plaintext,
                DecryptedPayload::Control => {
                    return Err(DirectHistoryMutationError::rejected(
                        "control frame is not valid in a Direct edit",
                    ));
                }
            };
            let plaintext = match String::from_utf8(plaintext) {
                Ok(plaintext) => Zeroizing::new(plaintext),
                Err(error) => {
                    let mut plaintext = error.into_bytes();
                    plaintext.zeroize();
                    return Err(DirectHistoryMutationError::rejected(
                        "edited plaintext is not valid UTF-8",
                    ));
                }
            };
            if !sender_key_mode {
                client
                    .confirm_peer_session_possession(sender_identity_key)
                    .map_err(DirectHistoryMutationError::storage)?;
            }
            let db = client
                .db
                .as_ref()
                .ok_or_else(|| DirectHistoryMutationError::storage("database not initialized"))?;
            db.update_incoming_message_text_scoped(
                message_id,
                conversation_id,
                sender_identity_key,
                &plaintext,
            )
            .map_err(DirectHistoryMutationError::storage)?;
            if let (Some(author_snapshot), Some(author_context)) = (author_snapshot, author_context)
            {
                db.attach_message_author_with_context(message_id, author_snapshot, author_context)
                    .map_err(DirectHistoryMutationError::storage)?;
            }
            if let Some(metadata) = remote_metadata {
                db.record_remote_message_state(
                    message_id,
                    conversation_id,
                    sender_identity_key,
                    metadata.revision_ms,
                    RemoteMessageStateKind::Active,
                )
                .map_err(DirectHistoryMutationError::storage)?;
                if let Some(reactions) = metadata.reactions {
                    db.replace_message_reactions(message_id, reactions)
                        .map_err(DirectHistoryMutationError::storage)?;
                }
            }
            Ok(plaintext)
        })
    }

    /// Persist a received message to the local DB.
    pub fn persist_incoming_message(
        &self,
        message_id: &str,
        conversation_id: &str,
        sender_key: &[u8],
        plaintext: &str,
        server_timestamp: Option<i64>,
        reply_to_id: Option<&str>,
    ) -> Result<(), String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        let db = self.db.as_ref().ok_or("database not initialized")?;
        db.insert_message(
            message_id,
            conversation_id,
            sender_key,
            plaintext,
            false,
            server_timestamp,
            reply_to_id,
        )?;
        if let Some(ref idx) = self.indexer {
            let ts = server_timestamp.unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0)
            });
            let _ = idx.index_message(
                message_id,
                conversation_id,
                &hex::encode(sender_key),
                plaintext,
                ts,
            );
        }
        Ok(())
    }

    /// Send an edit_message to the server.
    pub async fn edit_message(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        new_text: &str,
    ) -> Result<u64, String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        if self.channel_conversations.contains(conversation_id) {
            return Err(
                "group/channel edits are disabled until an exact device edit protocol exists"
                    .to_string(),
            );
        }
        if new_text.is_empty() {
            return Err("edited plaintext must not be empty".to_string());
        }
        if new_text.len() > MAX_PLAINTEXT_BYTES {
            return Err(format!(
                "edited plaintext exceeds {MAX_PLAINTEXT_BYTES} bytes"
            ));
        }
        let (ciphertext, header_bytes) = self.encrypt_outgoing(conversation_id, new_text)?;
        let initial_peer = (header_bytes.first() == Some(&HEADER_INITIAL_V2))
            .then(|| self.dm_conversations.get(conversation_id).copied())
            .flatten();

        let conn = self.connection.as_ref().ok_or("not connected")?;
        let seq = conn.next_seq().await;

        let edit_msg = proto::EditMessage {
            message_id: message_id.to_string(),
            conversation_id: conversation_id.to_string(),
            new_ciphertext: ciphertext,
            new_header: header_bytes,
        };

        let env = proto::Envelope {
            seq,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::EditMessage(edit_msg)),
        };

        conn.send_envelope(&env).await?;
        self.pending_mutations.insert(
            seq,
            ConfirmedMutation::Edit {
                message_id: message_id.to_string(),
                conversation_id: conversation_id.to_string(),
                new_text: new_text.to_string(),
            },
        );
        if let Some(peer_identity_key) = initial_peer {
            self.pending_initial_sequences
                .insert(seq, peer_identity_key);
        }

        Ok(seq)
    }

    /// Send a delete_message to the server.
    pub async fn delete_message(
        &mut self,
        message_id: &str,
        conversation_id: &str,
    ) -> Result<u64, String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        let conn = self.connection.as_ref().ok_or("not connected")?;
        let seq = conn.next_seq().await;

        let del_msg = proto::DeleteMessage {
            message_id: message_id.to_string(),
            conversation_id: conversation_id.to_string(),
        };

        let env = proto::Envelope {
            seq,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::DeleteMessage(del_msg)),
        };

        conn.send_envelope(&env).await?;
        self.pending_mutations.insert(
            seq,
            ConfirmedMutation::Delete {
                message_id: message_id.to_string(),
                conversation_id: conversation_id.to_string(),
            },
        );

        Ok(seq)
    }

    /// Send a typing indicator to a conversation.
    pub async fn send_typing(
        &mut self,
        conversation_id: &str,
        started: bool,
    ) -> Result<(), String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        let conn = self.connection.as_ref().ok_or("not connected")?;
        let identity_key = self
            .identity
            .as_ref()
            .ok_or("no identity")?
            .x25519_public_bytes()
            .to_vec();

        let env = proto::Envelope {
            seq: conn.next_seq().await,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::TypingEvent(proto::TypingEvent {
                conversation_id: conversation_id.to_string(),
                identity_key,
                started,
            })),
        };
        conn.send_envelope(&env).await
    }

    /// Send a reaction (add or remove) to the server.
    pub async fn send_reaction(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        emoji: &str,
        add: bool,
    ) -> Result<(), String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        let user_id = self.authenticated_user_id()?.to_string();
        let conn = self.connection.as_ref().ok_or("not connected")?;
        let seq = conn.next_seq().await;
        let env = proto::Envelope {
            seq,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::ReactionUpdate(
                proto::ReactionUpdate {
                    message_id: message_id.to_string(),
                    conversation_id: conversation_id.to_string(),
                    emoji: emoji.to_string(),
                    add,
                },
            )),
        };
        conn.send_envelope(&env).await?;
        self.pending_mutations.insert(
            seq,
            ConfirmedMutation::Reaction {
                message_id: message_id.to_string(),
                conversation_id: conversation_id.to_string(),
                emoji: emoji.to_string(),
                user_id,
                add,
            },
        );
        Ok(())
    }

    /// Add a reaction to local DB.
    pub fn add_local_reaction(
        &self,
        message_id: &str,
        user_id: &str,
        emoji: &str,
        username: &str,
    ) -> Result<(), String> {
        self.require_message_conversation_available_v1(message_id)?;
        self.db
            .as_ref()
            .ok_or("database not initialized")?
            .add_reaction(message_id, user_id, emoji, username)
    }

    /// Remove a reaction from local DB.
    pub fn remove_local_reaction(
        &self,
        message_id: &str,
        user_id: &str,
        emoji: &str,
    ) -> Result<(), String> {
        self.require_message_conversation_available_v1(message_id)?;
        self.db
            .as_ref()
            .ok_or("database not initialized")?
            .remove_reaction(message_id, user_id, emoji)
    }

    /// Get reactions for a message from local DB.
    pub fn get_local_reactions(
        &self,
        message_id: &str,
    ) -> Result<Vec<(String, String, String)>, String> {
        self.require_message_conversation_available_v1(message_id)?;
        self.db
            .as_ref()
            .ok_or("database not initialized")?
            .get_reactions(message_id)
    }

    /// Update a message in local DB (for incoming edits).
    pub fn update_local_message(&self, message_id: &str, new_text: &str) -> Result<(), String> {
        self.require_message_conversation_available_v1(message_id)?;
        self.db
            .as_ref()
            .ok_or("database not initialized")?
            .update_message_text(message_id, new_text)?;
        if let Some(ref idx) = self.indexer {
            // Preserve the original search recency and authoritative metadata;
            // an edit outside the retained slice must not be reinserted as new.
            idx.update_message_body(message_id, new_text)
                .map_err(|error| format!("update local search projection: {error}"))?;
        }
        Ok(())
    }

    /// Delete a message from local DB (for incoming deletes).
    pub fn delete_local_message(
        &self,
        message_id: &str,
        conversation_id: &str,
    ) -> Result<(), String> {
        self.require_direct_conversation_available_v1(conversation_id)?;
        self.db
            .as_ref()
            .ok_or("database not initialized")?
            .delete_message_scoped(message_id, conversation_id)?;
        if let Some(ref idx) = self.indexer {
            let _ = idx.delete(message_id);
        }
        Ok(())
    }

    /// Persist a conversation to the local DB.
    pub fn persist_conversation(
        &mut self,
        id: &str,
        conv_type: u8,
        name: Option<&str>,
        peer_key: Option<&[u8]>,
    ) -> Result<(), String> {
        self.require_direct_conversation_available_v1(id)?;
        if conv_type == 0 {
            if let Some(peer) = peer_key.and_then(|key| <[u8; 32]>::try_from(key).ok()) {
                self.dm_conversations.insert(id.to_string(), peer);
            }
        }
        let db = self.db.as_ref().ok_or("database not initialized")?;
        db.insert_conversation(id, conv_type, name, peer_key, None)
    }

    // ── Friends & Presence ────────────────────────────────

    /// Send a friend request to a user by user ID.
    pub async fn send_friend_request(
        &self,
        target_user_id: &str,
        message: Option<&str>,
    ) -> Result<(), String> {
        if !Self::is_canonical_live_uuid_v1(target_user_id)
            || message.is_some_and(|message| message.len() > 1_024)
        {
            return Err("invalid friend request".to_string());
        }
        let conn = self.connection.as_ref().ok_or("not connected")?;
        let seq = conn.next_seq().await;
        conn.send_envelope(&proto::Envelope {
            seq,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::FriendRequest(
                proto::FriendRequest {
                    target_user_id: target_user_id.to_string(),
                    message: message.map(|s| s.to_string()),
                },
            )),
        })
        .await
    }

    /// Respond to a friend request (accept or reject).
    pub async fn respond_friend_request(
        &self,
        request_id: &str,
        accept: bool,
    ) -> Result<(), String> {
        if !Self::is_canonical_live_uuid_v1(request_id) {
            return Err("invalid friend request response".to_string());
        }
        let conn = self.connection.as_ref().ok_or("not connected")?;
        let seq = conn.next_seq().await;
        conn.send_envelope(&proto::Envelope {
            seq,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::FriendRespond(
                proto::FriendRespond {
                    request_id: request_id.to_string(),
                    accept,
                },
            )),
        })
        .await
    }

    /// Remove a friend.
    pub async fn remove_friend(&self, user_id: &str) -> Result<(), String> {
        if !Self::is_canonical_live_uuid_v1(user_id) {
            return Err("invalid friend id".to_string());
        }
        let conn = self.connection.as_ref().ok_or("not connected")?;
        let seq = conn.next_seq().await;
        conn.send_envelope(&proto::Envelope {
            seq,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::FriendRemove(
                proto::FriendRemove {
                    user_id: user_id.to_string(),
                },
            )),
        })
        .await
    }

    /// Request the full friend list from the server.
    pub async fn request_friend_list(&self) -> Result<(), String> {
        let conn = self.connection.as_ref().ok_or("not connected")?;
        let seq = conn.next_seq().await;
        conn.send_envelope(&proto::Envelope {
            seq,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::FriendListRequest(
                proto::FriendListRequest {},
            )),
        })
        .await
    }

    /// Send presence update to the server.
    pub async fn send_presence(
        &self,
        status: i32,
        status_text: Option<&str>,
    ) -> Result<(), String> {
        let conn = self.connection.as_ref().ok_or("not connected")?;
        let seq = conn.next_seq().await;
        conn.send_envelope(&proto::Envelope {
            seq,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::PresenceUpdate(
                proto::PresenceUpdate {
                    identity_key: Vec::new(), // Server fills this
                    status,
                    status_text: status_text.map(|s| s.to_string()),
                    last_seen: None,
                },
            )),
        })
        .await
    }
}

impl Default for VeilClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VeilClient {
    fn drop(&mut self) {
        // Abort detached WS tasks before erasing the state they could feed.
        self.connection.take();
        self.zeroize_prekey_secrets();
        for pending in self.pending_outgoing_messages.values_mut() {
            pending.plaintext.zeroize();
        }
        for mutation in self.pending_mutations.values_mut() {
            if let ConfirmedMutation::Edit { new_text, .. } = mutation {
                new_text.zeroize();
            }
        }
        for wire in self.pending_sender_key_envelopes.values_mut() {
            wire.zeroize();
        }
        self.pending_sender_key_envelopes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_identity_qr_v1_is_canonical_bounded_and_exact() {
        let fingerprint_hex = "ab".repeat(32);
        let payload = direct_identity_qr_payload_v1(&fingerprint_hex).unwrap();
        assert_eq!(
            payload,
            format!("veil-identity:account-v2:{fingerprint_hex}")
        );
        assert_eq!(payload.len(), 89);
        assert_eq!(
            direct_identity_qr_fingerprint_v1(&payload).unwrap(),
            [0xab; 32]
        );

        assert!(direct_identity_qr_payload_v1(&"AB".repeat(32)).is_err());
        assert!(direct_identity_qr_payload_v1(&"ab".repeat(31)).is_err());
        for malformed in [
            format!("veil-identity:account-v1:{fingerprint_hex}"),
            format!("veil-identity:account-v2:{}", "AB".repeat(32)),
            format!("veil-identity:account-v2:{fingerprint_hex}\n"),
            format!("veil-identity:account-v2:{fingerprint_hex}\0"),
            format!("veіl-identity:account-v2:{fingerprint_hex}"),
            format!("veil-identity:account-v2:{}", "ab".repeat(31)),
        ] {
            assert!(direct_identity_qr_fingerprint_v1(&malformed).is_err());
        }
    }

    #[test]
    fn mobile_connect_preserves_typed_connection_stop_reasons() {
        for (connection_stop, mobile_stop) in [
            (
                ConnectionConnectStopV1::RetryableTransport,
                MobileConnectStopV1::RetryableTransport,
            ),
            (
                ConnectionConnectStopV1::AuthenticationRejected,
                MobileConnectStopV1::AuthenticationRejected,
            ),
            (
                ConnectionConnectStopV1::RegistrationClosed,
                MobileConnectStopV1::RegistrationClosed,
            ),
            (
                ConnectionConnectStopV1::InviteInvalid,
                MobileConnectStopV1::InviteInvalid,
            ),
            (
                ConnectionConnectStopV1::EpochInvalid,
                MobileConnectStopV1::EpochInvalid,
            ),
        ] {
            let mapped = MobileConnectErrorV1::from_connection(ConnectionConnectErrorV1 {
                stop: connection_stop,
                detail: "private diagnostic".to_string(),
            });
            assert_eq!(mapped.stop, mobile_stop);
            assert_eq!(mapped.detail, "private diagnostic");
        }
    }

    #[tokio::test]
    async fn metadata_access_pass_boundary_is_exact_before_networking() {
        let mut client = VeilClient::new();

        let classified = client
            .connect_with_client_metadata_and_access_pass_classified_v1(
                "wss://chat.example.test/ws",
                "veil-android",
                "veil-android",
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(classified.stop, MobileConnectStopV1::EpochInvalid);
        assert_eq!(classified.detail, "not initialized");

        assert_eq!(
            client
                .connect_with_client_metadata_and_access_pass(
                    "wss://chat.example.test/ws",
                    "veil-android",
                    "veil-android",
                    None,
                )
                .await
                .unwrap_err(),
            "not initialized"
        );

        let valid = [0x42; 32];
        assert_eq!(
            client
                .connect_with_client_metadata_and_access_pass(
                    "wss://chat.example.test/ws",
                    "veil-android",
                    "veil-android",
                    Some(&valid),
                )
                .await
                .unwrap_err(),
            "not initialized"
        );

        for invalid in [vec![0x42; 31], vec![0x42; 33]] {
            let classified = client
                .connect_with_client_metadata_and_access_pass_classified_v1(
                    "wss://chat.example.test/ws",
                    "veil-android",
                    "veil-android",
                    Some(&invalid),
                )
                .await
                .unwrap_err();
            assert_eq!(classified.stop, MobileConnectStopV1::EpochInvalid);
            assert_eq!(
                classified.detail,
                "node access pass must contain exactly 32 bytes"
            );
            assert_eq!(
                client
                    .connect_with_client_metadata_and_access_pass(
                        "wss://chat.example.test/ws",
                        "veil-android",
                        "veil-android",
                        Some(&invalid),
                    )
                    .await
                    .unwrap_err(),
                "node access pass must contain exactly 32 bytes"
            );
        }

        client.revoke_storage_uncertain_epoch_v1();
        let classified = client
            .connect_with_client_metadata_and_access_pass_classified_v1(
                "wss://chat.example.test/ws",
                "veil-android",
                "veil-android",
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(classified.stop, MobileConnectStopV1::StorageUncertain);
    }

    fn test_roster_commitment(candidate: &DeviceRosterCandidateV1) -> [u8; 32] {
        let conversation = uuid::Uuid::parse_str(&candidate.conversation_id).unwrap();
        let mut grouped: BTreeMap<[u8; 16], Vec<&DeviceRosterEntryV1>> = candidate
            .member_user_ids
            .iter()
            .copied()
            .map(|member| (member, Vec::new()))
            .collect();
        for device in &candidate.devices {
            grouped.get_mut(&device.user_id).unwrap().push(device);
        }
        let mut canonical = Vec::new();
        canonical.extend_from_slice(DEVICE_ROSTER_COMMITMENT_DOMAIN);
        canonical.extend_from_slice(conversation.as_bytes());
        canonical.extend_from_slice(&candidate.required_capabilities.to_be_bytes());
        canonical.extend_from_slice(&(grouped.len() as u32).to_be_bytes());
        for (member, devices) in &mut grouped {
            canonical.extend_from_slice(member);
            devices.sort_by_key(|device| device.device_id);
            canonical.extend_from_slice(&(devices.len() as u32).to_be_bytes());
            for device in devices {
                canonical.extend_from_slice(&device.device_id);
                match device.binding.as_ref() {
                    Some(binding) => {
                        canonical.push(binding.status);
                        canonical.extend_from_slice(&binding.version.to_be_bytes());
                        canonical.extend_from_slice(&binding.capabilities.to_be_bytes());
                        canonical.extend_from_slice(&binding.device_identity_key);
                        canonical.extend_from_slice(&binding.device_signing_key);
                        canonical.extend_from_slice(&binding.account_signature);
                    }
                    None => {
                        canonical.push(4);
                        canonical.extend_from_slice(&[0u8; 8 + 8 + 32 + 32 + 64]);
                    }
                }
            }
        }
        Sha256::digest(canonical).into()
    }

    fn roster_entry(
        user_id: [u8; 16],
        account: &IdentityKeyPair,
        binding: &crate::device_identity::DeviceBindingPublicV1,
    ) -> DeviceRosterEntryV1 {
        DeviceRosterEntryV1 {
            user_id,
            account_identity_key: account.x25519_public_bytes(),
            account_signing_key: account.ed25519_public_bytes(),
            device_id: binding.device_id,
            binding: Some(DeviceBindingCandidateV1 {
                device_id: binding.device_id,
                device_identity_key: binding.device_identity_key,
                device_signing_key: binding.device_signing_key,
                version: binding.version,
                capabilities: binding.capabilities,
                status: binding.status,
                account_signature: binding.account_signature,
            }),
        }
    }

    fn candidate_with_commitment(
        conversation_id: &str,
        version: u64,
        entries: Vec<DeviceRosterEntryV1>,
    ) -> DeviceRosterCandidateV1 {
        let mut members: Vec<[u8; 16]> = entries.iter().map(|entry| entry.user_id).collect();
        members.sort();
        members.dedup();
        let mut candidate = DeviceRosterCandidateV1 {
            conversation_id: conversation_id.to_string(),
            roster_version: version,
            roster_commitment: [0u8; 32],
            required_capabilities: REQUIRED_DEVICE_CAPABILITIES,
            ready: true,
            member_user_ids: members,
            devices: entries,
            crypto_profile: "sender_key_v5".to_string(),
            membership_activated: false,
            membership_ready: true,
            membership_epoch: 0,
            membership_epoch_hash: [0u8; 32],
        };
        candidate.roster_commitment = test_roster_commitment(&candidate);
        candidate
    }

    fn memory_client_with_device(
        account: IdentityKeyPair,
        user_id: uuid::Uuid,
        device_id: [u8; 16],
        db_key: [u8; 32],
    ) -> VeilClient {
        let stored = DeviceIdentityV1::generate_stored(&account, device_id).unwrap();
        let device = DeviceIdentityV1::from_stored(&account, stored).unwrap();
        let mut client = VeilClient::from_identity(account);
        client.device_id = device_id;
        client.device_identity = Some(device);
        client.db = Some(VeilDb::open_memory(&db_key).unwrap());
        client.authenticated_user_id = Some(user_id.hyphenated().to_string());
        client
    }

    const PREKEY_TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const PREKEY_ORIGIN_A: &str = "https://prekeys-a.example.test:443";
    const PREKEY_ORIGIN_B: &str = "https://prekeys-b.example.test:443";
    const PREKEY_USER: &str = "00000000-0000-0000-0000-0000000000a1";

    fn file_publication_client(path: &Path, origin: &str) -> VeilClient {
        let mut client = VeilClient::new();
        client
            .init_with_mnemonic(PREKEY_TEST_MNEMONIC, path)
            .unwrap();
        client.authenticated_user_id = Some(PREKEY_USER.to_string());
        client
            .db()
            .unwrap()
            .bind_authenticated_self(
                origin,
                PREKEY_USER,
                &client.identity_key().unwrap(),
                &client.signing_key().unwrap(),
            )
            .unwrap();
        client
    }

    fn memory_publication_client(origin: &str) -> VeilClient {
        let account = IdentityKeyPair::from_mnemonic(PREKEY_TEST_MNEMONIC).unwrap();
        let device_id = [0xA5; 16];
        let stored = DeviceIdentityV1::generate_stored(&account, device_id).unwrap();
        let db = VeilDb::open_memory(&[0x73; 32]).unwrap();
        db.create_device_identity_v1(&stored).unwrap();
        db.bind_authenticated_self(
            origin,
            PREKEY_USER,
            &account.x25519_public_bytes(),
            &account.ed25519_public_bytes(),
        )
        .unwrap();
        let device_identity = DeviceIdentityV1::from_stored(&account, stored).unwrap();
        let mut client = VeilClient::from_identity(account);
        client.device_id = device_id;
        client.device_identity = Some(device_identity);
        client.db = Some(db);
        client.authenticated_user_id = Some(PREKEY_USER.to_string());
        client
    }

    fn own_prekey_count_response(
        device_id: [u8; 16],
        remaining: u32,
        signed_prekey_id: Option<u32>,
    ) -> Vec<u8> {
        let mut device = serde_json::json!({
            "device_id": hex::encode(device_id),
            "remaining": remaining,
        });
        if let Some(signed_prekey_id) = signed_prekey_id {
            device["signed_prekey_id"] = serde_json::json!(signed_prekey_id);
        }
        serde_json::to_vec(&serde_json::json!({"devices": [device]})).unwrap()
    }

    fn own_prekey_opk_ids(publication: &OwnPreKeyPublication) -> Vec<u32> {
        serde_json::from_slice::<serde_json::Value>(&publication.request_body).unwrap()
            ["one_time_prekeys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["key_id"].as_u64().unwrap() as u32)
            .collect()
    }

    fn remove_test_database(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let _ = std::fs::remove_file(path.with_extension("db-journal"));
    }

    fn clone_local_device_at_version(client: &VeilClient, version: u64) -> DeviceIdentityV1 {
        let account = client.identity.as_ref().unwrap();
        let current = client.device_identity.as_ref().unwrap();
        let binding = current.binding();
        let account_identity_key = account.x25519_public_bytes();
        let account_signing_key = account.ed25519_public_bytes();
        let signature = veil_crypto::signature::sign(
            account,
            &device_binding_signing_bytes(
                &account_identity_key,
                &account_signing_key,
                &binding.device_id,
                version,
                &binding.device_identity_key,
                &binding.device_signing_key,
                binding.capabilities,
                binding.status,
            ),
        );
        DeviceIdentityV1::from_stored(
            account,
            veil_store::db::LocalDeviceIdentityV1 {
                device_id: binding.device_id,
                version,
                x25519_secret: current.x25519_secret().to_bytes(),
                ed25519_secret: current.ed25519_signing_key().to_bytes(),
                device_identity_key: binding.device_identity_key,
                device_signing_key: binding.device_signing_key,
                capabilities: binding.capabilities,
                status: binding.status,
                account_identity_key,
                account_signing_key,
                account_signature: signature,
            },
        )
        .unwrap()
    }

    fn route_for_test(
        sender: &VeilClient,
        target: &DeviceTargetV1,
        key: &PendingSenderKeyEnvelopeKey,
    ) -> SenderKeyRouteV1 {
        let local = sender.device_identity.as_ref().unwrap().binding();
        SenderKeyRouteV1 {
            conversation_id: target.conversation_id.clone(),
            generation: key.generation,
            target_account_identity_key: target.account_identity_key,
            target_device_id: target.device_id,
            target_device_identity_key: target.device_identity_key,
            sender_device_id: sender.device_id,
            sender_account_identity_key: sender.identity_key().unwrap(),
            sender_account_signing_key: sender.signing_key().unwrap(),
            sender_device_identity_key: local.device_identity_key,
            sender_device_signing_key: local.device_signing_key,
            sender_device_capabilities: local.capabilities,
            sender_device_binding_status: local.status,
            sender_account_signature: local.account_signature,
            roster_version: target.roster_version,
            roster_commitment: target.roster_commitment,
            membership_epoch: key.membership_epoch,
            membership_epoch_hash: key.membership_epoch_hash,
            sender_binding_version: local.version,
            target_binding_version: target.binding_version,
            envelope_commitment: key.envelope_commitment,
        }
    }

    fn pending_sender_key(
        client: &VeilClient,
        conversation_id: &str,
        target_identity_key: [u8; 32],
    ) -> PendingSenderKeyEnvelopeKey {
        let distribution = client
            .sender_keys
            .build_distribution(conversation_id)
            .unwrap();
        PendingSenderKeyEnvelopeKey {
            conversation_id: conversation_id.to_string(),
            generation: distribution.key_id,
            target_device_id: target_identity_key[..16].try_into().unwrap(),
            target_binding_version: 1,
            roster_version: 1,
            roster_commitment: [0xA1; 32],
            membership_epoch: 0,
            membership_epoch_hash: [0u8; 32],
            envelope_commitment: [0xB2; 32],
        }
    }

    #[test]
    fn generated_device_id_is_never_the_legacy_zero_value() {
        assert_ne!(VeilClient::new().device_id, [0u8; 16]);
    }

    #[test]
    fn own_prekey_publication_retries_exact_bytes_and_keeps_ids_monotonic() {
        let path = std::env::temp_dir().join(format!(
            "veil-client-own-prekeys-{}.db",
            uuid::Uuid::new_v4()
        ));
        let first_device_id;
        let first_publication;
        {
            let mut client = file_publication_client(&path, PREKEY_ORIGIN_A);
            first_device_id = client.device_id();
            assert_eq!(
                client.own_prekey_count_target().unwrap(),
                format!(
                    "/v1/prekeys/{}/count",
                    hex::encode(client.identity_key().unwrap())
                )
            );
            first_publication = client
                .prepare_own_prekey_publication_after_count(
                    PREKEY_ORIGIN_A,
                    PREKEY_USER,
                    &own_prekey_count_response(first_device_id, 0, None),
                )
                .unwrap();
            assert!(!first_publication.acknowledged);
            assert_eq!(first_publication.signed_prekey_id, 1);
            assert_eq!(
                own_prekey_opk_ids(&first_publication),
                (1..=20).collect::<Vec<_>>()
            );
            let loaded = client
                .own_prekey_publication(PREKEY_ORIGIN_A, PREKEY_USER)
                .unwrap()
                .unwrap();
            assert_eq!(loaded.request_body, first_publication.request_body);
            assert_eq!(loaded.body_sha256, first_publication.body_sha256);
            // Simulate a lost HTTP response: no ACK is installed before drop.
        }

        {
            let mut client = file_publication_client(&path, PREKEY_ORIGIN_A);
            assert_eq!(client.device_id(), first_device_id);
            let pending = client
                .own_prekey_publication(PREKEY_ORIGIN_A, PREKEY_USER)
                .unwrap()
                .unwrap();
            assert!(!pending.acknowledged);
            assert_eq!(pending.request_body, first_publication.request_body);
            assert_eq!(pending.body_sha256, first_publication.body_sha256);

            // Even an accidentally issued count cannot replace pending bytes.
            let selected = client
                .prepare_own_prekey_publication_after_count(
                    PREKEY_ORIGIN_A,
                    PREKEY_USER,
                    &own_prekey_count_response(first_device_id, 100, Some(999)),
                )
                .unwrap();
            assert_eq!(selected.request_body, first_publication.request_body);
            assert_eq!(
                selected.signed_prekey_id,
                first_publication.signed_prekey_id
            );

            assert_eq!(
                client
                    .acknowledge_own_prekey_publication(
                        PREKEY_ORIGIN_A,
                        PREKEY_USER,
                        first_publication.signed_prekey_id,
                        &first_publication.body_sha256,
                        br#"{"stored":21,"opk_remaining":19}"#,
                    )
                    .unwrap(),
                OwnPreKeyAcknowledgeResult::Acknowledged
            );
            let acknowledged = client
                .own_prekey_publication(PREKEY_ORIGIN_A, PREKEY_USER)
                .unwrap()
                .unwrap();
            assert!(acknowledged.acknowledged);

            // Healthy inventory still performs the mandatory POST, but it
            // reasserts the exact acknowledged body rather than rotating.
            let healthy = client
                .prepare_own_prekey_publication_after_count(
                    PREKEY_ORIGIN_A,
                    PREKEY_USER,
                    &own_prekey_count_response(
                        first_device_id,
                        OWN_PREKEY_LOW_WATERMARK,
                        Some(first_publication.signed_prekey_id),
                    ),
                )
                .unwrap();
            assert!(healthy.acknowledged);
            assert_eq!(healthy.request_body, first_publication.request_body);

            // Below the low-water mark, retain the acknowledged SPK and
            // allocate only fresh monotonic OPKs.
            let second = client
                .prepare_own_prekey_publication_after_count(
                    PREKEY_ORIGIN_A,
                    PREKEY_USER,
                    &own_prekey_count_response(
                        first_device_id,
                        OWN_PREKEY_LOW_WATERMARK - 1,
                        Some(first_publication.signed_prekey_id),
                    ),
                )
                .unwrap();
            assert!(!second.acknowledged);
            assert_eq!(second.signed_prekey_id, first_publication.signed_prekey_id);
            assert_eq!(own_prekey_opk_ids(&second), (21..=40).collect::<Vec<_>>());
            assert_ne!(second.request_body, first_publication.request_body);
            assert_eq!(client.spk_next_id, 2);
            assert_eq!(client.otk_next_id, 41);
            assert_eq!(client.spk_secrets.len(), 1);

            let mut wrong_digest = second.body_sha256;
            wrong_digest[0] ^= 1;
            assert!(client
                .acknowledge_own_prekey_publication(
                    PREKEY_ORIGIN_A,
                    PREKEY_USER,
                    second.signed_prekey_id,
                    &wrong_digest,
                    br#"{"stored":21,"opk_remaining":20}"#,
                )
                .is_err());
            assert!(
                !client
                    .own_prekey_publication(PREKEY_ORIGIN_A, PREKEY_USER)
                    .unwrap()
                    .unwrap()
                    .acknowledged
            );
            assert_eq!(
                client
                    .acknowledge_own_prekey_publication(
                        PREKEY_ORIGIN_A,
                        PREKEY_USER,
                        second.signed_prekey_id,
                        &second.body_sha256,
                        br#"{"stored":21,"opk_remaining":0}"#,
                    )
                    .unwrap(),
                OwnPreKeyAcknowledgeResult::Acknowledged
            );
            assert!(client
                .prepare_own_prekey_publication_after_count(
                    PREKEY_ORIGIN_A,
                    PREKEY_USER,
                    &own_prekey_count_response(
                        first_device_id,
                        OWN_PREKEY_LOW_WATERMARK,
                        Some(second.signed_prekey_id + 1),
                    ),
                )
                .is_err());

            // A second origin gets a distinct batch; it cannot overwrite the
            // exact publication retained for the first self-hosted node.
            client
                .db()
                .unwrap()
                .bind_authenticated_self(
                    PREKEY_ORIGIN_B,
                    PREKEY_USER,
                    &client.identity_key().unwrap(),
                    &client.signing_key().unwrap(),
                )
                .unwrap();
            let third = client
                .prepare_own_prekey_publication_after_count(
                    PREKEY_ORIGIN_B,
                    PREKEY_USER,
                    &own_prekey_count_response(first_device_id, 0, None),
                )
                .unwrap();
            assert_eq!(
                third.signed_prekey_id,
                first_publication.signed_prekey_id + 1
            );
            assert_eq!(own_prekey_opk_ids(&third), (41..=60).collect::<Vec<_>>());
            assert_ne!(third.request_body, second.request_body);
            assert_eq!(client.spk_secrets.len(), 2);
            assert_eq!(
                client
                    .own_prekey_publication(PREKEY_ORIGIN_A, PREKEY_USER)
                    .unwrap()
                    .unwrap()
                    .request_body,
                second.request_body
            );
        }
        remove_test_database(&path);
    }

    #[test]
    fn own_prekey_reservation_skips_ids_inserted_after_client_open() {
        let mut client = memory_publication_client(PREKEY_ORIGIN_A);
        client
            .db()
            .unwrap()
            .save_local_prekeys(&[
                LocalPreKey {
                    key_type: 0,
                    protocol_key_id: 1,
                    secret_key: [0x11; 32],
                    public_key: [0x22; 32],
                    signature: Some([0x33; 64]),
                },
                LocalPreKey {
                    key_type: 1,
                    protocol_key_id: 7,
                    secret_key: [0x44; 32],
                    public_key: [0x55; 32],
                    signature: None,
                },
            ])
            .unwrap();
        let device_id = client.device_id();

        let publication = client
            .prepare_own_prekey_publication_after_count(
                PREKEY_ORIGIN_A,
                PREKEY_USER,
                &own_prekey_count_response(device_id, 0, None),
            )
            .unwrap();
        assert_eq!(publication.signed_prekey_id, 2);
        assert_eq!(
            own_prekey_opk_ids(&publication),
            (8..=27).collect::<Vec<_>>()
        );
        assert_eq!(client.spk_next_id, 3);
        assert_eq!(client.otk_next_id, 28);
        assert_eq!(client.spk_secrets.len(), 1);
        assert_eq!(client.otk_secrets.len(), OWN_PREKEY_BATCH_SIZE);
        assert_eq!(
            client
                .own_prekey_publication(PREKEY_ORIGIN_A, PREKEY_USER)
                .unwrap()
                .unwrap()
                .request_body,
            publication.request_body,
        );
    }

    #[test]
    fn generate_prekeys_publishes_runtime_state_only_after_db_commit() {
        let mut client = memory_publication_client(PREKEY_ORIGIN_A);
        client
            .db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER reject_test_prekeys BEFORE INSERT ON local_prekeys
                 BEGIN SELECT RAISE(ABORT, 'test prekey persistence failure'); END;",
            )
            .unwrap();
        assert!(client.generate_prekeys().is_err());
        // Reservation committed before the failed key write. The gap is
        // deliberate and prevents a retry from assigning new material to the
        // ambiguous protocol ids.
        assert_eq!(client.spk_next_id, 2);
        assert_eq!(client.otk_next_id, 21);
        assert!(client.spk_secrets.is_empty());
        assert!(client.otk_secrets.is_empty());

        client
            .db()
            .unwrap()
            .conn()
            .execute_batch("DROP TRIGGER reject_test_prekeys")
            .unwrap();
        let generated = client.generate_prekeys().unwrap();
        assert_eq!(generated.spk_id, 2);
        assert_eq!(generated.otk_publics.first().unwrap().1, 21);
        assert_eq!(generated.otk_publics.last().unwrap().1, 40);
        assert_eq!(client.spk_next_id, 3);
        assert_eq!(client.otk_next_id, 41);
        assert_eq!(
            client
                .db()
                .unwrap()
                .synchronize_local_prekey_allocator()
                .unwrap(),
            (3, 41),
        );
    }

    #[test]
    fn user_identity_binding_is_fill_once_and_idempotent() {
        let mut client = VeilClient::new();
        let identity_key = [0x11; 32];

        assert!(client.remember_user_identity("", identity_key).is_err());
        assert!(client.remember_user_identity("user-1", [0u8; 32]).is_err());
        client
            .remember_user_identity("user-1", identity_key)
            .unwrap();
        client
            .remember_user_identity("user-1", identity_key)
            .unwrap();

        assert_eq!(client.known_user_identity("user-1"), Some(identity_key));
    }

    #[test]
    fn user_identity_binding_rejects_conflicting_overwrite() {
        let mut client = VeilClient::new();
        let original = [0x21; 32];
        client.remember_user_identity("user-1", original).unwrap();

        assert!(client.remember_user_identity("user-1", [0x22; 32]).is_err());
        assert_eq!(client.known_user_identity("user-1"), Some(original));
    }

    #[test]
    fn clearing_user_identities_permits_clean_next_origin_namespace() {
        let mut client = VeilClient::new();
        client
            .remember_user_identity("shared-user-id", [0x31; 32])
            .unwrap();

        client.clear_known_user_identities();
        assert_eq!(client.known_user_identity("shared-user-id"), None);

        let next_origin_identity = [0x32; 32];
        client
            .remember_user_identity("shared-user-id", next_origin_identity)
            .unwrap();
        assert_eq!(
            client.known_user_identity("shared-user-id"),
            Some(next_origin_identity)
        );

        client
            .bind_dm_conversation("origin-a-dm", [0x33; 32])
            .unwrap();
        client.mark_channel_conversation("origin-a-channel");
        client.clear_server_scoped_conversation_routing();
        assert!(client.dm_conversations.is_empty());
        assert!(!client.is_channel_conversation("origin-a-channel"));
    }

    #[test]
    fn conflicting_durable_dm_binding_never_changes_the_live_peer() {
        let original_peer = [0x41; 32];
        let replacement_peer = [0x42; 32];
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        client.db = Some(VeilDb::open_memory(&[0x43; 32]).unwrap());
        client
            .db()
            .unwrap()
            .upsert_directory_conversation(
                "dm-binding",
                ConversationType::DM as u8,
                "https://binding.test:443",
                Some("Peer"),
                Some("00000000-0000-0000-0000-000000000041"),
                Some(original_peer.as_slice()),
                None,
                "2026-07-12T00:00:00Z",
            )
            .unwrap();

        assert!(client
            .bind_dm_conversation("dm-binding", replacement_peer)
            .is_err());
        assert!(!client.dm_conversations.contains_key("dm-binding"));

        client
            .bind_dm_conversation("dm-binding", original_peer)
            .unwrap();
        assert!(client
            .bind_dm_conversation("dm-binding", replacement_peer)
            .is_err());
        assert_eq!(
            client.dm_conversations.get("dm-binding"),
            Some(&original_peer)
        );
    }

    #[test]
    fn unscoped_durable_dm_binding_is_never_published_live() {
        let peer = [0x44; 32];
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        client.db = Some(VeilDb::open_memory(&[0x45; 32]).unwrap());
        client
            .db()
            .unwrap()
            .insert_conversation(
                "legacy-dm-binding",
                ConversationType::DM as u8,
                Some("Legacy peer"),
                Some(&peer),
                None,
            )
            .unwrap();

        assert!(client
            .bind_dm_conversation("legacy-dm-binding", peer)
            .is_err());
        assert!(!client.dm_conversations.contains_key("legacy-dm-binding"));
    }

    #[test]
    fn shared_peer_key_across_origins_is_not_routed_through_one_ratchet_namespace() {
        let peer = [0x46; 32];
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        client.db = Some(VeilDb::open_memory(&[0x47; 32]).unwrap());
        for (conversation_id, origin, peer_user_id) in [
            (
                "dm-origin-a",
                "https://origin-a.test:443",
                "00000000-0000-0000-0000-000000000048",
            ),
            (
                "dm-origin-b",
                "https://origin-b.test:443",
                "00000000-0000-0000-0000-000000000049",
            ),
        ] {
            client
                .db()
                .unwrap()
                .upsert_directory_conversation(
                    conversation_id,
                    ConversationType::DM as u8,
                    origin,
                    Some("Peer"),
                    Some(peer_user_id),
                    Some(peer.as_slice()),
                    None,
                    "2026-07-12T00:00:00Z",
                )
                .unwrap();
        }

        assert!(client
            .bind_dm_conversation("dm-origin-a", peer)
            .unwrap_err()
            .contains("origin-scoped ratchet storage"));
        assert!(client.dm_conversations.is_empty());
    }

    #[test]
    fn roster_commitment_matches_the_go_cross_language_vector() {
        let binding = |device: u8, status: u8, version: u64, key: u8| DeviceRosterEntryV1 {
            user_id: [0u8; 16],
            account_identity_key: [0x90; 32],
            account_signing_key: [0x91; 32],
            device_id: [device; 16],
            binding: Some(DeviceBindingCandidateV1 {
                device_id: [device; 16],
                device_identity_key: [key; 32],
                device_signing_key: [key + 1; 32],
                version,
                capabilities: 3,
                status,
                account_signature: [key + 2; 64],
            }),
        };
        let user_one = *uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
            .unwrap()
            .as_bytes();
        let user_two = *uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002")
            .unwrap()
            .as_bytes();
        let mut excluded = binding(0x30, 2, 7, 0x31);
        excluded.user_id = user_one;
        let mut active = binding(0x20, 1, 2, 0x21);
        active.user_id = user_two;
        let legacy = DeviceRosterEntryV1 {
            user_id: user_two,
            account_identity_key: [0x92; 32],
            account_signing_key: [0x93; 32],
            device_id: [0x10; 16],
            binding: None,
        };
        let candidate = DeviceRosterCandidateV1 {
            conversation_id: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
            roster_version: 1,
            roster_commitment: [0u8; 32],
            required_capabilities: 3,
            ready: false,
            member_user_ids: vec![user_two, user_one],
            devices: vec![active, legacy, excluded],
            crypto_profile: "sender_key_v5".to_string(),
            membership_activated: false,
            membership_ready: true,
            membership_epoch: 0,
            membership_epoch_hash: [0u8; 32],
        };
        assert_eq!(
            hex::encode(test_roster_commitment(&candidate)),
            "d2a757a44fb7f4fc28a17d92d6d874b4301bc0a17b71ae929ca1b65684923902"
        );
    }

    #[test]
    fn per_device_binding_is_independent_and_stable_across_restart() {
        let mnemonic = generate_mnemonic().to_string();
        let path =
            std::env::temp_dir().join(format!("veil-device-binding-{}.db", uuid::Uuid::new_v4()));
        let first_binding = {
            let mut client = VeilClient::new();
            client.init_with_mnemonic(&mnemonic, &path).unwrap();
            let binding = client.device_identity.as_ref().unwrap().binding().clone();
            assert_eq!(binding.device_id, client.device_id());
            assert_ne!(binding.device_identity_key, client.identity_key().unwrap());
            assert_ne!(binding.device_signing_key, client.signing_key().unwrap());
            binding
        };
        let second_binding = {
            let mut restored = VeilClient::new();
            restored.init_with_mnemonic(&mnemonic, &path).unwrap();
            restored.device_identity.as_ref().unwrap().binding().clone()
        };
        assert_eq!(second_binding, first_binding);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn membership_epoch_activation_is_automatic_and_blocks_live_v5_downgrade() {
        let origin = "https://membership.example.test:443";
        let local_user = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000111").unwrap();
        let conversation = "00000000-0000-4000-8000-000000000abc";
        let mut client = memory_client_with_device(
            IdentityKeyPair::generate(),
            local_user,
            [0x31; 16],
            [0x79; 32],
        );
        client.authenticated_server_origin = Some(origin.to_string());
        client.mark_channel_conversation(conversation);
        let local_entry = roster_entry(
            *local_user.as_bytes(),
            client.identity.as_ref().unwrap(),
            client.device_identity.as_ref().unwrap().binding(),
        );
        let legacy = candidate_with_commitment(conversation, 1, vec![local_entry]);
        client.install_device_roster_v1(legacy.clone()).unwrap();

        let local_binding = client.device_identity.as_ref().unwrap().binding().clone();
        let v5 = MessageSecurityContextV1::SenderKeyV5(SenderKeyMessageSecurityContextV1 {
            roster_version: legacy.roster_version,
            roster_commitment: legacy.roster_commitment,
            sender_device_id: local_binding.device_id,
            target_device_id: local_binding.device_id,
            sender_binding_version: local_binding.version,
        });
        client
            .validate_live_sender_key_security_context_v1(conversation, &v5)
            .unwrap();

        let owner = MembershipPolicySignerV1 {
            account_id: *local_user.as_bytes(),
            account_signing_key: client.signing_key().unwrap(),
        };
        let prepared = client
            .prepare_membership_epoch_bootstrap_v1(
                conversation,
                veil_crypto::membership::MEMBERSHIP_CONVERSATION_KIND_GROUP_V1,
                legacy.roster_version,
                legacy.roster_commitment,
                owner,
            )
            .unwrap();
        assert_ne!(prepared.epoch.mutation_nonce, [0u8; 32]);
        assert!(client
            .prepare_membership_epoch_bootstrap_v1(
                &conversation.to_ascii_uppercase(),
                veil_crypto::membership::MEMBERSHIP_CONVERSATION_KIND_GROUP_V1,
                legacy.roster_version,
                legacy.roster_commitment,
                owner,
            )
            .unwrap_err()
            .contains("not canonical"));

        let mut activated = legacy;
        activated.crypto_profile = "sender_key_v6".to_string();
        activated.membership_activated = true;
        activated.membership_epoch = prepared.epoch.epoch;
        activated.membership_epoch_hash = prepared.epoch_hash;
        client.install_device_roster_v1(activated.clone()).unwrap();
        client
            .install_membership_epoch_chain_v1(MembershipEpochChainCandidateV1 {
                canonical_origin: origin.to_string(),
                conversation_id: conversation.to_string(),
                head_epoch: prepared.epoch.epoch,
                head_hash: prepared.epoch_hash,
                records: vec![MembershipEpochRecordCandidateV1 {
                    epoch: prepared.epoch.clone(),
                    epoch_hash: prepared.epoch_hash,
                    signatures: prepared.signatures.clone(),
                    bootstrap_owner: Some(owner),
                }],
            })
            .unwrap();

        let v6 = MessageSecurityContextV1::SenderKeyV6(SenderKeyMessageSecurityContextV6 {
            roster_version: activated.roster_version,
            roster_commitment: activated.roster_commitment,
            sender_device_id: local_binding.device_id,
            target_device_id: local_binding.device_id,
            sender_binding_version: local_binding.version,
            membership_epoch: prepared.epoch.epoch,
            membership_epoch_hash: prepared.epoch_hash,
        });
        client
            .validate_live_sender_key_security_context_v1(conversation, &v6)
            .unwrap();
        assert!(client
            .validate_live_sender_key_security_context_v1(conversation, &v5)
            .unwrap_err()
            .contains("membership epoch"));
        let mut stale = v6;
        let MessageSecurityContextV1::SenderKeyV6(stale_context) = &mut stale else {
            unreachable!();
        };
        stale_context.membership_epoch_hash[0] ^= 1;
        assert!(client
            .validate_live_sender_key_security_context_v1(conversation, &stale)
            .is_err());

        let next = client
            .prepare_membership_epoch_transition_v1(
                &prepared.epoch,
                activated.roster_version + 1,
                [0xA1; 32],
            )
            .unwrap();
        assert_eq!(next.epoch.epoch, 2);
        assert_eq!(next.epoch.predecessor_hash, prepared.epoch_hash);
        assert_eq!(next.epoch.successor_policy, prepared.epoch.successor_policy);
    }

    #[test]
    fn sender_key_v6_roundtrip_keeps_legacy_history_but_never_reuses_v5_generation() {
        let origin = "https://membership-roundtrip.example.test:443";
        let sender_user = uuid::Uuid::from_bytes([0x41; 16]);
        let recipient_user = uuid::Uuid::from_bytes([0x42; 16]);
        let conversation = "00000000-0000-4000-8000-000000000abd";
        let mut sender = memory_client_with_device(
            IdentityKeyPair::generate(),
            sender_user,
            [0x43; 16],
            [0x44; 32],
        );
        let mut recipient = memory_client_with_device(
            IdentityKeyPair::generate(),
            recipient_user,
            [0x45; 16],
            [0x46; 32],
        );
        for client in [&mut sender, &mut recipient] {
            client.authenticated_server_origin = Some(origin.to_string());
            client.mark_channel_conversation(conversation);
        }
        let entries = vec![
            roster_entry(
                *sender_user.as_bytes(),
                sender.identity.as_ref().unwrap(),
                sender.device_identity.as_ref().unwrap().binding(),
            ),
            roster_entry(
                *recipient_user.as_bytes(),
                recipient.identity.as_ref().unwrap(),
                recipient.device_identity.as_ref().unwrap().binding(),
            ),
        ];
        let legacy = candidate_with_commitment(conversation, 1, entries);
        sender.install_device_roster_v1(legacy.clone()).unwrap();
        recipient.install_device_roster_v1(legacy.clone()).unwrap();
        let legacy_target = sender
            .sender_key_device_targets(conversation)
            .unwrap()
            .into_iter()
            .find(|target| target.device_id == recipient.device_id)
            .unwrap();
        let (legacy_key, legacy_wire) = sender
            .prepare_sender_key_device_envelope(&legacy_target)
            .unwrap();
        let legacy_route = route_for_test(&sender, &legacy_target, &legacy_key);
        recipient
            .process_sender_key_distribution_v1(&legacy_wire, &legacy_route)
            .unwrap();
        sender.mark_sender_key_distributed(conversation).unwrap();
        let (legacy_ciphertext, legacy_header) = sender
            .encrypt_outgoing(conversation, "legacy history")
            .unwrap();
        let legacy_context =
            MessageSecurityContextV1::SenderKeyV5(SenderKeyMessageSecurityContextV1 {
                roster_version: legacy_route.roster_version,
                roster_commitment: legacy_route.roster_commitment,
                sender_device_id: legacy_route.sender_device_id,
                target_device_id: legacy_route.target_device_id,
                sender_binding_version: legacy_route.sender_binding_version,
            });

        let owner = MembershipPolicySignerV1 {
            account_id: *sender_user.as_bytes(),
            account_signing_key: sender.signing_key().unwrap(),
        };
        let prepared = sender
            .prepare_membership_epoch_bootstrap_v1(
                conversation,
                veil_crypto::membership::MEMBERSHIP_CONVERSATION_KIND_GROUP_V1,
                legacy.roster_version,
                legacy.roster_commitment,
                owner,
            )
            .unwrap();
        let mut activated = legacy;
        activated.crypto_profile = "sender_key_v6".to_string();
        activated.membership_activated = true;
        activated.membership_epoch = 1;
        activated.membership_epoch_hash = prepared.epoch_hash;
        let chain = MembershipEpochChainCandidateV1 {
            canonical_origin: origin.to_string(),
            conversation_id: conversation.to_string(),
            head_epoch: 1,
            head_hash: prepared.epoch_hash,
            records: vec![MembershipEpochRecordCandidateV1 {
                epoch: prepared.epoch,
                epoch_hash: prepared.epoch_hash,
                signatures: prepared.signatures,
                bootstrap_owner: Some(owner),
            }],
        };
        for client in [&mut sender, &mut recipient] {
            client.install_device_roster_v1(activated.clone()).unwrap();
            client
                .install_membership_epoch_chain_v1(chain.clone())
                .unwrap();
        }

        assert!(recipient
            .validate_live_sender_key_security_context_v1(conversation, &legacy_context)
            .unwrap_err()
            .contains("membership epoch"));
        match recipient
            .decrypt_from_with_security_context(
                &legacy_route.sender_account_identity_key,
                conversation,
                &legacy_header,
                &legacy_ciphertext,
                Some(&legacy_context),
            )
            .unwrap()
        {
            DecryptedPayload::Text(text) => assert_eq!(text, b"legacy history"),
            DecryptedPayload::Control => panic!("legacy history decoded as control"),
        }

        let v6_target = sender
            .sender_key_device_targets(conversation)
            .unwrap()
            .into_iter()
            .find(|target| target.device_id == recipient.device_id)
            .unwrap();
        let (v6_key, v6_wire) = sender
            .prepare_sender_key_device_envelope(&v6_target)
            .unwrap();
        assert!(v6_key.generation > legacy_key.generation);
        assert_eq!(v6_key.membership_epoch, 1);
        assert_eq!(v6_key.membership_epoch_hash, prepared.epoch_hash);
        let v6_route = route_for_test(&sender, &v6_target, &v6_key);
        recipient
            .process_sender_key_distribution_v1(&v6_wire, &v6_route)
            .unwrap();
        sender.mark_sender_key_distributed(conversation).unwrap();
        let (v6_ciphertext, v6_header) = sender
            .encrypt_outgoing(conversation, "epoch protected")
            .unwrap();
        let v6_context = MessageSecurityContextV1::SenderKeyV6(SenderKeyMessageSecurityContextV6 {
            roster_version: v6_route.roster_version,
            roster_commitment: v6_route.roster_commitment,
            sender_device_id: v6_route.sender_device_id,
            target_device_id: v6_route.target_device_id,
            sender_binding_version: v6_route.sender_binding_version,
            membership_epoch: v6_route.membership_epoch,
            membership_epoch_hash: v6_route.membership_epoch_hash,
        });
        recipient
            .validate_live_sender_key_security_context_v1(conversation, &v6_context)
            .unwrap();
        match recipient
            .decrypt_from_with_security_context(
                &v6_route.sender_account_identity_key,
                conversation,
                &v6_header,
                &v6_ciphertext,
                Some(&v6_context),
            )
            .unwrap()
        {
            DecryptedPayload::Text(text) => assert_eq!(text, b"epoch protected"),
            DecryptedPayload::Control => panic!("Sender-Key v6 text decoded as control"),
        }
    }

    #[test]
    fn validated_roster_targets_own_other_devices_and_invalidates_stale_runtime_proof() {
        let local_user = uuid::Uuid::from_bytes([0x11; 16]);
        let remote_user = uuid::Uuid::from_bytes([0x22; 16]);
        let mut client = memory_client_with_device(
            IdentityKeyPair::generate(),
            local_user,
            [0x31; 16],
            [0x71; 32],
        );
        let conversation = "00000000-0000-0000-0000-000000000301";
        client.mark_channel_conversation(conversation);

        let local_account = client.identity.as_ref().unwrap();
        let local_entry = roster_entry(
            *local_user.as_bytes(),
            local_account,
            client.device_identity.as_ref().unwrap().binding(),
        );
        let second_stored = DeviceIdentityV1::generate_stored(local_account, [0x32; 16]).unwrap();
        let second_device = DeviceIdentityV1::from_stored(local_account, second_stored).unwrap();
        let second_entry = roster_entry(
            *local_user.as_bytes(),
            local_account,
            second_device.binding(),
        );
        let remote_account = IdentityKeyPair::generate();
        let remote_stored = DeviceIdentityV1::generate_stored(&remote_account, [0x41; 16]).unwrap();
        let remote_device = DeviceIdentityV1::from_stored(&remote_account, remote_stored).unwrap();
        let remote_entry = roster_entry(
            *remote_user.as_bytes(),
            &remote_account,
            remote_device.binding(),
        );
        let candidate = candidate_with_commitment(
            conversation,
            1,
            vec![remote_entry, second_entry, local_entry],
        );
        client.install_device_roster_v1(candidate.clone()).unwrap();
        let targets = client.sender_key_device_targets(conversation).unwrap();
        assert_eq!(targets.len(), 2);
        assert!(targets.iter().any(|target| target.device_id == [0x32; 16]));
        assert!(targets.iter().any(|target| target.device_id == [0x41; 16]));
        assert!(!targets.iter().any(|target| target.device_id == [0x31; 16]));
        assert_eq!(
            client.sender_keys.outgoing_owner_identity_key(conversation),
            Some(
                client
                    .device_identity
                    .as_ref()
                    .unwrap()
                    .binding()
                    .device_identity_key
            )
        );
        let mut pending = Vec::new();
        for (offset, target) in targets.iter().enumerate() {
            let (key, first) = client.prepare_sender_key_device_envelope(target).unwrap();
            let (_, retry) = client.prepare_sender_key_device_envelope(target).unwrap();
            assert_eq!(retry, first);
            let stored = client
                .db()
                .unwrap()
                .load_pending_sender_key_device_envelope_v1(
                    conversation,
                    key.generation,
                    &target.device_id,
                    target.binding_version,
                    target.roster_version,
                )
                .unwrap()
                .unwrap();
            assert_eq!(stored.sealed_envelope, first);
            let sequence = 800 + offset as u64;
            client
                .pending_sender_key_sequences
                .insert(sequence, key.clone());
            pending.push((sequence, key));
        }
        let (first_sequence, first_key) = &pending[0];
        let mut wrong_ack = crate::connection::SenderKeyAckMetadataV1 {
            target_device_id: first_key.target_device_id,
            conversation_id: conversation.to_string(),
            generation: first_key.generation,
            roster_version: first_key.roster_version,
            membership_epoch: first_key.membership_epoch,
            membership_epoch_hash: first_key.membership_epoch_hash,
            envelope_commitment: first_key.envelope_commitment,
        };
        wrong_ack.envelope_commitment[0] ^= 1;
        assert!(client
            .confirm_sender_key_distribution(*first_sequence, Some(&wrong_ack))
            .is_err());
        let exact_ack = crate::connection::SenderKeyAckMetadataV1 {
            envelope_commitment: first_key.envelope_commitment,
            ..wrong_ack
        };
        client
            .confirm_sender_key_distribution(*first_sequence, Some(&exact_ack))
            .unwrap();
        assert_eq!(
            client.sender_key_distribution_status(conversation),
            "pending"
        );
        let (last_sequence, last_key) = &pending[1];
        client
            .confirm_sender_key_distribution(
                *last_sequence,
                Some(&crate::connection::SenderKeyAckMetadataV1 {
                    target_device_id: last_key.target_device_id,
                    conversation_id: conversation.to_string(),
                    generation: last_key.generation,
                    roster_version: last_key.roster_version,
                    membership_epoch: last_key.membership_epoch,
                    membership_epoch_hash: last_key.membership_epoch_hash,
                    envelope_commitment: last_key.envelope_commitment,
                }),
            )
            .unwrap();
        assert_eq!(client.sender_key_distribution_status(conversation), "ready");
        let account = client.identity.as_ref().unwrap();
        assert!(client
            .sender_keys
            .encrypt_signed(conversation, account, b"account substitution")
            .unwrap_err()
            .contains("does not own"));

        let mut not_ready = candidate;
        not_ready.ready = false;
        assert!(client.install_device_roster_v1(not_ready).is_err());
        assert!(client.sender_key_device_targets(conversation).is_err());
        assert!(client.encrypt_outgoing(conversation, "blocked").is_err());
    }

    #[test]
    fn changed_roster_rotates_even_when_old_generation_is_still_prepared_and_zero_targets_complete()
    {
        let local_user = uuid::Uuid::from_bytes([0x51; 16]);
        let removed_user = uuid::Uuid::from_bytes([0x52; 16]);
        let mut client = memory_client_with_device(
            IdentityKeyPair::generate(),
            local_user,
            [0x61; 16],
            [0x72; 32],
        );
        let conversation = "00000000-0000-0000-0000-000000000302";
        client.mark_channel_conversation(conversation);
        let local_entry = roster_entry(
            *local_user.as_bytes(),
            client.identity.as_ref().unwrap(),
            client.device_identity.as_ref().unwrap().binding(),
        );
        let removed_account = IdentityKeyPair::generate();
        let removed_stored =
            DeviceIdentityV1::generate_stored(&removed_account, [0x62; 16]).unwrap();
        let removed_device =
            DeviceIdentityV1::from_stored(&removed_account, removed_stored).unwrap();
        let removed_entry = roster_entry(
            *removed_user.as_bytes(),
            &removed_account,
            removed_device.binding(),
        );
        client
            .install_device_roster_v1(candidate_with_commitment(
                conversation,
                1,
                vec![local_entry.clone(), removed_entry],
            ))
            .unwrap();
        let first_generation = client
            .sender_keys
            .build_distribution(conversation)
            .unwrap()
            .key_id;
        assert!(client
            .prepared_sender_key_generations
            .contains(conversation));

        let single_device_roster = candidate_with_commitment(conversation, 2, vec![local_entry]);
        client
            .install_device_roster_v1(single_device_roster.clone())
            .unwrap();
        let second_generation = client
            .sender_keys
            .build_distribution(conversation)
            .unwrap()
            .key_id;
        assert_eq!(second_generation, first_generation + 1);
        assert!(client
            .sender_key_device_targets(conversation)
            .unwrap()
            .is_empty());
        assert_eq!(client.sender_key_distribution_status(conversation), "ready");
        assert!(client
            .encrypt_outgoing(conversation, "single device")
            .is_ok());

        let device_identity_key = client
            .device_identity
            .as_ref()
            .unwrap()
            .binding()
            .device_identity_key;
        let signing = ed25519_dalek::SigningKey::from_bytes(
            &client
                .device_identity
                .as_ref()
                .unwrap()
                .ed25519_signing_key()
                .to_bytes(),
        );
        while !client.sender_keys.needs_rotation(conversation) {
            client
                .sender_keys
                .encrypt_signed_with_device(conversation, &device_identity_key, &signing, b"expire")
                .unwrap();
        }
        let expired_generation = client
            .sender_keys
            .build_distribution(conversation)
            .unwrap()
            .key_id;
        assert!(!client
            .install_device_roster_v1(single_device_roster)
            .unwrap());
        assert_eq!(
            client
                .sender_keys
                .build_distribution(conversation)
                .unwrap()
                .key_id,
            expired_generation + 1,
        );
        assert_eq!(client.sender_key_distribution_status(conversation), "ready");
        assert!(client
            .encrypt_outgoing(conversation, "fresh single device")
            .is_ok());
    }

    #[test]
    fn retained_first_seen_tofu_conflict_rolls_back_key_route_and_receipt() {
        let sender_user = uuid::Uuid::from_bytes([0x91; 16]);
        let recipient_user = uuid::Uuid::from_bytes([0x92; 16]);
        let mut sender = memory_client_with_device(
            IdentityKeyPair::generate(),
            sender_user,
            [0x93; 16],
            [0x94; 32],
        );
        let mut recipient = memory_client_with_device(
            IdentityKeyPair::generate(),
            recipient_user,
            [0x95; 16],
            [0x96; 32],
        );
        let conversation = "00000000-0000-0000-0000-000000000304";
        let roster = candidate_with_commitment(
            conversation,
            1,
            vec![
                roster_entry(
                    *sender_user.as_bytes(),
                    sender.identity.as_ref().unwrap(),
                    sender.device_identity.as_ref().unwrap().binding(),
                ),
                roster_entry(
                    *recipient_user.as_bytes(),
                    recipient.identity.as_ref().unwrap(),
                    recipient.device_identity.as_ref().unwrap().binding(),
                ),
            ],
        );
        sender.mark_channel_conversation(conversation);
        recipient.mark_channel_conversation(conversation);
        sender.install_device_roster_v1(roster.clone()).unwrap();
        recipient.install_device_roster_v1(roster).unwrap();
        let target = sender
            .sender_key_device_targets(conversation)
            .unwrap()
            .into_iter()
            .find(|target| target.device_id == recipient.device_id)
            .unwrap();
        let (pending, sealed) = sender.prepare_sender_key_device_envelope(&target).unwrap();
        let route = route_for_test(&sender, &target, &pending);
        let sender_account_identity = sender.identity_key().unwrap();
        recipient
            .pin_peer_signing_key(sender_account_identity, [0xFF; 32])
            .unwrap();

        let error = recipient
            .process_sender_key_distribution_inner_v1(
                &sealed,
                &route,
                SenderKeyDistributionModeV1::Retained,
            )
            .unwrap_err();
        assert!(error.contains("trusted signing key changed"));
        assert!(!recipient.sender_keys.has_incoming_generation(
            conversation,
            &route.sender_device_identity_key,
            route.generation,
        ));
        assert!(recipient
            .db()
            .unwrap()
            .load_incoming_sender_key_generations_for_group(conversation)
            .unwrap()
            .is_empty());
        assert!(recipient.pending_sender_key_receipts.is_empty());
    }

    #[test]
    fn retained_failure_is_isolated_to_its_conversation() {
        let sender_user = uuid::Uuid::from_bytes([0xA1; 16]);
        let recipient_user = uuid::Uuid::from_bytes([0xA2; 16]);
        let mut sender = memory_client_with_device(
            IdentityKeyPair::generate(),
            sender_user,
            [0xA3; 16],
            [0xA4; 32],
        );
        let mut recipient = memory_client_with_device(
            IdentityKeyPair::generate(),
            recipient_user,
            [0xA5; 16],
            [0xA6; 32],
        );
        let valid_conversation = "00000000-0000-0000-0000-000000000305";
        let blocked_conversation = "00000000-0000-0000-0000-000000000306";
        let roster = candidate_with_commitment(
            valid_conversation,
            1,
            vec![
                roster_entry(
                    *sender_user.as_bytes(),
                    sender.identity.as_ref().unwrap(),
                    sender.device_identity.as_ref().unwrap().binding(),
                ),
                roster_entry(
                    *recipient_user.as_bytes(),
                    recipient.identity.as_ref().unwrap(),
                    recipient.device_identity.as_ref().unwrap().binding(),
                ),
            ],
        );
        sender.mark_channel_conversation(valid_conversation);
        recipient.mark_channel_conversation(valid_conversation);
        recipient.mark_channel_conversation(blocked_conversation);
        sender.install_device_roster_v1(roster.clone()).unwrap();
        recipient.install_device_roster_v1(roster).unwrap();
        let target = sender
            .sender_key_device_targets(valid_conversation)
            .unwrap()
            .into_iter()
            .find(|target| target.device_id == recipient.device_id)
            .unwrap();
        let (pending, sealed) = sender.prepare_sender_key_device_envelope(&target).unwrap();
        let valid_route = route_for_test(&sender, &target, &pending);
        let mut bad_route = valid_route.clone();
        bad_route.conversation_id = blocked_conversation.to_string();
        let outgoing_generation_before = recipient
            .sender_keys
            .build_distribution(valid_conversation)
            .unwrap()
            .key_id;

        let report = recipient
            .process_retained_sender_key_events_v1(vec![
                ConnectionEvent::SenderKeyDist {
                    sender_key_message: sealed.clone(),
                    route: bad_route.clone(),
                },
                ConnectionEvent::SenderKeyDist {
                    sender_key_message: sealed.clone(),
                    route: bad_route,
                },
                ConnectionEvent::SenderKeyDist {
                    sender_key_message: sealed,
                    route: valid_route.clone(),
                },
            ])
            .unwrap();
        assert_eq!(report.processed, 1);
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].conversation_id, blocked_conversation);
        assert!(report.diagnostics[0]
            .reason
            .contains("outer routing context"));
        assert!(recipient.sender_keys.has_incoming_generation(
            valid_conversation,
            &valid_route.sender_device_identity_key,
            valid_route.generation,
        ));
        assert!(!recipient.sender_keys.has_incoming_generation(
            blocked_conversation,
            &valid_route.sender_device_identity_key,
            valid_route.generation,
        ));
        assert_eq!(recipient.pending_sender_key_receipts.len(), 1);
        assert_eq!(
            recipient
                .sender_keys
                .build_distribution(valid_conversation)
                .unwrap()
                .key_id,
            outgoing_generation_before,
        );
    }

    #[test]
    fn retained_conversation_batch_rolls_back_an_earlier_success_before_diagnosing() {
        let sender_a_user = uuid::Uuid::from_bytes([0xB1; 16]);
        let sender_b_user = uuid::Uuid::from_bytes([0xB2; 16]);
        let recipient_user = uuid::Uuid::from_bytes([0xB3; 16]);
        let mut sender_a = memory_client_with_device(
            IdentityKeyPair::generate(),
            sender_a_user,
            [0xB4; 16],
            [0xB5; 32],
        );
        let mut sender_b = memory_client_with_device(
            IdentityKeyPair::generate(),
            sender_b_user,
            [0xB6; 16],
            [0xB7; 32],
        );
        let mut recipient = memory_client_with_device(
            IdentityKeyPair::generate(),
            recipient_user,
            [0xB8; 16],
            [0xB9; 32],
        );
        let conversation_a = "00000000-0000-0000-0000-000000000307";
        let conversation_b = "00000000-0000-0000-0000-000000000308";

        let recipient_entry = || {
            roster_entry(
                *recipient_user.as_bytes(),
                recipient.identity.as_ref().unwrap(),
                recipient.device_identity.as_ref().unwrap().binding(),
            )
        };
        let roster_a = candidate_with_commitment(
            conversation_a,
            1,
            vec![
                roster_entry(
                    *sender_a_user.as_bytes(),
                    sender_a.identity.as_ref().unwrap(),
                    sender_a.device_identity.as_ref().unwrap().binding(),
                ),
                recipient_entry(),
            ],
        );
        let roster_b = candidate_with_commitment(
            conversation_b,
            1,
            vec![
                roster_entry(
                    *sender_b_user.as_bytes(),
                    sender_b.identity.as_ref().unwrap(),
                    sender_b.device_identity.as_ref().unwrap().binding(),
                ),
                recipient_entry(),
            ],
        );
        for conversation in [conversation_a, conversation_b] {
            recipient.mark_channel_conversation(conversation);
        }
        sender_a.mark_channel_conversation(conversation_a);
        sender_b.mark_channel_conversation(conversation_b);
        sender_a.install_device_roster_v1(roster_a.clone()).unwrap();
        recipient.install_device_roster_v1(roster_a).unwrap();
        sender_b.install_device_roster_v1(roster_b.clone()).unwrap();
        recipient.install_device_roster_v1(roster_b).unwrap();

        let target_a = sender_a
            .sender_key_device_targets(conversation_a)
            .unwrap()
            .into_iter()
            .find(|target| target.device_id == recipient.device_id)
            .unwrap();
        let target_b = sender_b
            .sender_key_device_targets(conversation_b)
            .unwrap()
            .into_iter()
            .find(|target| target.device_id == recipient.device_id)
            .unwrap();
        let (pending_a, sealed_a) = sender_a
            .prepare_sender_key_device_envelope(&target_a)
            .unwrap();
        let (pending_b, sealed_b) = sender_b
            .prepare_sender_key_device_envelope(&target_b)
            .unwrap();
        let route_a = route_for_test(&sender_a, &target_a, &pending_a);
        let route_b = route_for_test(&sender_b, &target_b, &pending_b);
        let mut conflicting_a = route_a.clone();
        conflicting_a.sender_account_signature[0] ^= 1;

        let report = recipient
            .process_retained_sender_key_events_v1(vec![
                ConnectionEvent::SenderKeyDist {
                    sender_key_message: sealed_a.clone(),
                    route: route_a.clone(),
                },
                ConnectionEvent::SenderKeyDist {
                    sender_key_message: sealed_b,
                    route: route_b.clone(),
                },
                ConnectionEvent::SenderKeyDist {
                    sender_key_message: sealed_a,
                    route: conflicting_a,
                },
            ])
            .unwrap();
        assert_eq!(report.processed, 1);
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].conversation_id, conversation_a);
        assert!(!recipient.sender_keys.has_incoming_generation(
            conversation_a,
            &route_a.sender_device_identity_key,
            route_a.generation,
        ));
        assert!(recipient.sender_keys.has_incoming_generation(
            conversation_b,
            &route_b.sender_device_identity_key,
            route_b.generation,
        ));
        assert!(recipient
            .db()
            .unwrap()
            .load_incoming_sender_key_generations_for_group(conversation_a)
            .unwrap()
            .is_empty());
        assert!(recipient
            .db()
            .unwrap()
            .load_incoming_sender_key_route_v1(
                conversation_a,
                &route_a.sender_device_identity_key,
                route_a.generation,
            )
            .unwrap()
            .is_none());
        assert!(!recipient.peer_signing_key_is_pinned(
            &route_a.sender_account_identity_key,
            &route_a.sender_account_signing_key,
        ));
        assert!(recipient.peer_signing_key_is_pinned(
            &route_b.sender_account_identity_key,
            &route_b.sender_account_signing_key,
        ));
        assert_eq!(recipient.pending_sender_key_receipts.len(), 1);
        assert_eq!(
            recipient.pending_sender_key_receipts[0].conversation_id,
            conversation_b
        );
    }

    #[test]
    fn live_sender_key_generation_cap_blocks_only_the_affected_conversation() {
        let sender_user = uuid::Uuid::from_bytes([0xC1; 16]);
        let recipient_user = uuid::Uuid::from_bytes([0xC2; 16]);
        let mut sender = memory_client_with_device(
            IdentityKeyPair::generate(),
            sender_user,
            [0xC3; 16],
            [0xC4; 32],
        );
        let mut recipient = memory_client_with_device(
            IdentityKeyPair::generate(),
            recipient_user,
            [0xC5; 16],
            [0xC6; 32],
        );
        let bounded = "00000000-0000-0000-0000-000000000309";
        let independent = "00000000-0000-0000-0000-000000000310";
        for conversation in [bounded, independent] {
            let entries = vec![
                roster_entry(
                    *sender_user.as_bytes(),
                    sender.identity.as_ref().unwrap(),
                    sender.device_identity.as_ref().unwrap().binding(),
                ),
                roster_entry(
                    *recipient_user.as_bytes(),
                    recipient.identity.as_ref().unwrap(),
                    recipient.device_identity.as_ref().unwrap().binding(),
                ),
            ];
            let roster = candidate_with_commitment(conversation, 1, entries);
            sender.mark_channel_conversation(conversation);
            recipient.mark_channel_conversation(conversation);
            sender.install_device_roster_v1(roster.clone()).unwrap();
            recipient.install_device_roster_v1(roster).unwrap();
        }
        let bounded_target = sender
            .sender_key_device_targets(bounded)
            .unwrap()
            .into_iter()
            .find(|target| target.device_id == recipient.device_id)
            .unwrap();
        for accepted in 0..veil_crypto::sender_key::MAX_RETAINED_GENERATIONS_PER_SENDER {
            let (pending, sealed) = sender
                .prepare_sender_key_device_envelope(&bounded_target)
                .unwrap();
            let route = route_for_test(&sender, &bounded_target, &pending);
            recipient
                .process_sender_key_distribution_v1(&sealed, &route)
                .unwrap();
            assert_eq!(pending.generation as usize, accepted + 1);
            sender.rotate_sender_key(bounded).unwrap();
        }
        let (overflow_pending, overflow_sealed) = sender
            .prepare_sender_key_device_envelope(&bounded_target)
            .unwrap();
        let overflow_route = route_for_test(&sender, &bounded_target, &overflow_pending);
        assert!(recipient
            .process_sender_key_distribution_v1(&overflow_sealed, &overflow_route)
            .unwrap_err()
            .contains("retention limit"));
        assert_eq!(
            recipient
                .db()
                .unwrap()
                .load_incoming_sender_key_generations_for_group(bounded)
                .unwrap()
                .len(),
            veil_crypto::sender_key::MAX_RETAINED_GENERATIONS_PER_SENDER,
        );
        assert_eq!(
            recipient.pending_sender_key_receipts.len(),
            veil_crypto::sender_key::MAX_RETAINED_GENERATIONS_PER_SENDER,
        );

        let independent_target = sender
            .sender_key_device_targets(independent)
            .unwrap()
            .into_iter()
            .find(|target| target.device_id == recipient.device_id)
            .unwrap();
        let (pending, sealed) = sender
            .prepare_sender_key_device_envelope(&independent_target)
            .unwrap();
        let route = route_for_test(&sender, &independent_target, &pending);
        recipient
            .process_sender_key_distribution_v1(&sealed, &route)
            .unwrap();
        assert!(recipient.sender_keys.has_incoming_generation(
            independent,
            &route.sender_device_identity_key,
            route.generation,
        ));
        assert_eq!(
            recipient.pending_sender_key_receipts.len(),
            veil_crypto::sender_key::MAX_RETAINED_GENERATIONS_PER_SENDER + 1,
        );
    }

    #[test]
    fn hydration_rejects_oversized_generation_history_without_partial_heap_state() {
        let user = uuid::Uuid::from_bytes([0xD1; 16]);
        let mut client =
            memory_client_with_device(IdentityKeyPair::generate(), user, [0xD2; 16], [0xD3; 32]);
        let bounded = "00000000-0000-0000-0000-000000000311";
        let independent = "00000000-0000-0000-0000-000000000312";
        let sender = [0xD4; 32];
        let mut source = SenderKeyStore::new();
        for generation in
            1..=veil_crypto::sender_key::MAX_RETAINED_GENERATIONS_PER_SENDER as u32 + 1
        {
            source
                .create_outgoing_at_generation(bounded, &sender, generation)
                .unwrap();
            let data = source.serialize_outgoing(bounded).unwrap();
            client
                .db()
                .unwrap()
                .conn()
                .execute(
                    "INSERT INTO sender_key_incoming_generations
                        (group_id, sender_identity_key, generation, iteration,
                         state_revision, distribution_commitment, key_data)
                     VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6)",
                    rusqlite::params![
                        bounded,
                        sender.as_slice(),
                        i64::from(generation),
                        0u64.to_be_bytes().as_slice(),
                        [0u8; 32].as_slice(),
                        data.as_slice(),
                    ],
                )
                .unwrap();
        }
        assert!(client
            .hydrate_channel_sender_keys(bounded)
            .unwrap_err()
            .contains("retention limit"));
        assert!(client
            .sender_keys
            .incoming_generations(bounded, &sender)
            .is_empty());

        source
            .create_outgoing_at_generation(independent, &sender, 1)
            .unwrap();
        let independent_data = source.serialize_outgoing(independent).unwrap();
        client
            .db()
            .unwrap()
            .save_incoming_sender_key_generation(
                independent,
                &sender,
                1,
                0,
                0,
                &[0u8; 32],
                &independent_data,
            )
            .unwrap();
        assert_eq!(
            client.hydrate_channel_sender_keys(independent).unwrap(),
            OfflineSenderKeyRefresh::Required,
        );
        assert!(client
            .sender_keys
            .has_incoming_generation(independent, &sender, 1));
    }

    #[test]
    fn exact_device_skdm_restores_and_decrypts_two_generations_after_restart() {
        let sender_mnemonic = generate_mnemonic().to_string();
        let recipient_mnemonic = generate_mnemonic().to_string();
        let sender_path =
            std::env::temp_dir().join(format!("veil-device-sender-{}.db", uuid::Uuid::new_v4()));
        let recipient_path =
            std::env::temp_dir().join(format!("veil-device-recipient-{}.db", uuid::Uuid::new_v4()));
        let sender_user = uuid::Uuid::from_bytes([0x71; 16]);
        let recipient_user = uuid::Uuid::from_bytes([0x72; 16]);
        let conversation = "00000000-0000-0000-0000-000000000303";

        let mut sender = VeilClient::new();
        sender
            .init_with_mnemonic(&sender_mnemonic, &sender_path)
            .unwrap();
        sender.authenticated_user_id = Some(sender_user.hyphenated().to_string());
        let mut recipient = VeilClient::new();
        recipient
            .init_with_mnemonic(&recipient_mnemonic, &recipient_path)
            .unwrap();
        recipient.authenticated_user_id = Some(recipient_user.hyphenated().to_string());
        recipient.device_identity = Some(clone_local_device_at_version(&recipient, 2));
        let sender_account_key = sender.identity_key().unwrap();
        let sender_account_signing_key = sender.signing_key().unwrap();
        let sender_entry = roster_entry(
            *sender_user.as_bytes(),
            sender.identity.as_ref().unwrap(),
            sender.device_identity.as_ref().unwrap().binding(),
        );
        let recipient_entry = roster_entry(
            *recipient_user.as_bytes(),
            recipient.identity.as_ref().unwrap(),
            recipient.device_identity.as_ref().unwrap().binding(),
        );
        let candidate =
            candidate_with_commitment(conversation, 1, vec![recipient_entry, sender_entry]);
        sender.mark_channel_conversation(conversation);
        recipient.mark_channel_conversation(conversation);
        sender.install_device_roster_v1(candidate.clone()).unwrap();
        recipient
            .install_device_roster_v1(candidate.clone())
            .unwrap();

        let recipient_target = sender
            .sender_key_device_targets(conversation)
            .unwrap()
            .into_iter()
            .find(|target| target.user_id == *recipient_user.as_bytes())
            .unwrap();
        let (key_one, sealed_one) = sender
            .prepare_sender_key_device_envelope(&recipient_target)
            .unwrap();
        let mut route_one = route_for_test(&sender, &recipient_target, &key_one);
        // A retained generation may have been published under an older roster
        // while the immutable sender device binding is still present now.
        route_one.roster_version = 77;
        route_one.roster_commitment = [0x77; 32];
        route_one.target_binding_version = 1;
        assert!(recipient
            .process_sender_key_distribution_v1(&sealed_one, &route_one)
            .unwrap_err()
            .contains("exact current roster"));
        let mut future_target = route_one.clone();
        future_target.target_binding_version = 3;
        assert!(recipient
            .process_sender_key_distribution_inner_v1(
                &sealed_one,
                &future_target,
                SenderKeyDistributionModeV1::Retained,
            )
            .is_err());
        let mut substituted_target_key = route_one.clone();
        substituted_target_key.target_device_identity_key[0] ^= 1;
        assert!(recipient
            .process_sender_key_distribution_inner_v1(
                &sealed_one,
                &substituted_target_key,
                SenderKeyDistributionModeV1::Retained,
            )
            .is_err());
        let mut bad_sender_proof = route_one.clone();
        bad_sender_proof.sender_account_signature[0] ^= 1;
        assert!(recipient
            .process_sender_key_distribution_inner_v1(
                &sealed_one,
                &bad_sender_proof,
                SenderKeyDistributionModeV1::Retained,
            )
            .is_err());
        let receipt_one = recipient
            .process_sender_key_distribution_inner_v1(
                &sealed_one,
                &route_one,
                SenderKeyDistributionModeV1::Retained,
            )
            .unwrap();
        assert_eq!(receipt_one.envelope_commitment, key_one.envelope_commitment);
        assert!(
            recipient.peer_signing_key_is_pinned(&sender_account_key, &sender_account_signing_key,)
        );
        sender.mark_sender_key_distributed(conversation).unwrap();
        let (ciphertext_one, header_one) = sender
            .encrypt_outgoing(conversation, "generation one")
            .unwrap();

        sender.rotate_sender_key(conversation).unwrap();
        let (key_two, sealed_two) = sender
            .prepare_sender_key_device_envelope(&recipient_target)
            .unwrap();
        assert_eq!(key_two.generation, key_one.generation + 1);
        let route_two = route_for_test(&sender, &recipient_target, &key_two);
        recipient
            .process_sender_key_distribution_v1(&sealed_two, &route_two)
            .unwrap();
        assert_eq!(recipient.pending_sender_key_receipts.len(), 2);
        let acked_receipt = recipient.pending_sender_key_receipts.pop_front().unwrap();
        recipient
            .pending_sender_key_receipt_sequences
            .insert(901, acked_receipt.clone());
        recipient
            .confirm_sender_key_distribution(
                901,
                Some(&crate::connection::SenderKeyAckMetadataV1 {
                    target_device_id: acked_receipt.target_device_id,
                    conversation_id: acked_receipt.conversation_id.clone(),
                    generation: acked_receipt.generation,
                    roster_version: acked_receipt.roster_version,
                    membership_epoch: acked_receipt.membership_epoch,
                    membership_epoch_hash: acked_receipt.membership_epoch_hash,
                    envelope_commitment: acked_receipt.envelope_commitment,
                }),
            )
            .unwrap();
        assert!(!recipient
            .pending_sender_key_receipt_sequences
            .contains_key(&901));
        let lost_ack_receipt = recipient.pending_sender_key_receipts.pop_front().unwrap();
        recipient
            .pending_sender_key_receipt_sequences
            .insert(902, lost_ack_receipt.clone());
        recipient.mark_all_pending_sequences_unknown().unwrap();
        assert!(recipient.pending_sender_key_receipt_sequences.is_empty());
        assert!(!recipient
            .pending_sender_key_receipt_set
            .contains(&lost_ack_receipt));
        sender.mark_sender_key_distributed(conversation).unwrap();
        let (ciphertext_two, header_two) = sender
            .encrypt_outgoing(conversation, "generation two")
            .unwrap();
        drop(recipient);

        let mut restored = VeilClient::new();
        restored
            .init_with_mnemonic(&recipient_mnemonic, &recipient_path)
            .unwrap();
        restored.authenticated_user_id = Some(recipient_user.hyphenated().to_string());
        restored.device_identity = Some(clone_local_device_at_version(&restored, 2));
        restored.mark_channel_conversation(conversation);
        assert_eq!(
            restored.hydrate_channel_sender_keys(conversation).unwrap(),
            OfflineSenderKeyRefresh::AlreadyRotated
        );
        restored.install_device_roster_v1(candidate).unwrap();
        let context = |route: &SenderKeyRouteV1| {
            MessageSecurityContextV1::SenderKeyV5(SenderKeyMessageSecurityContextV1 {
                roster_version: route.roster_version,
                roster_commitment: route.roster_commitment,
                sender_device_id: route.sender_device_id,
                target_device_id: route.target_device_id,
                sender_binding_version: route.sender_binding_version,
            })
        };
        let context_two = context(&route_two);
        let context_one = context(&route_one);
        match restored
            .decrypt_from_with_security_context(
                &sender_account_key,
                conversation,
                &header_two,
                &ciphertext_two,
                Some(&context_two),
            )
            .unwrap()
        {
            DecryptedPayload::Text(text) => assert_eq!(text, b"generation two"),
            DecryptedPayload::Control => panic!("generation two decoded as control"),
        }
        match restored
            .decrypt_from_with_security_context(
                &sender_account_key,
                conversation,
                &header_one,
                &ciphertext_one,
                Some(&context_one),
            )
            .unwrap()
        {
            DecryptedPayload::Text(text) => assert_eq!(text, b"generation one"),
            DecryptedPayload::Control => panic!("generation one decoded as control"),
        }

        drop(restored);
        for path in [&sender_path, &recipient_path] {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(path.with_extension("db-wal"));
            let _ = std::fs::remove_file(path.with_extension("db-shm"));
        }
    }

    #[test]
    fn missing_exact_route_is_never_an_admission_decision() {
        let sender_user = uuid::Uuid::from_bytes([0x81; 16]);
        let recipient_user = uuid::Uuid::from_bytes([0x82; 16]);
        let mut sender = memory_client_with_device(
            IdentityKeyPair::generate(),
            sender_user,
            [0x83; 16],
            [0x84; 32],
        );
        let mut recipient = memory_client_with_device(
            IdentityKeyPair::generate(),
            recipient_user,
            [0x85; 16],
            [0x86; 32],
        );
        let conversation = "00000000-0000-0000-0000-000000000314";
        let sender_entry = roster_entry(
            *sender_user.as_bytes(),
            sender.identity.as_ref().unwrap(),
            sender.device_identity.as_ref().unwrap().binding(),
        );
        let recipient_entry = roster_entry(
            *recipient_user.as_bytes(),
            recipient.identity.as_ref().unwrap(),
            recipient.device_identity.as_ref().unwrap().binding(),
        );

        let historical_roster =
            candidate_with_commitment(conversation, 1, vec![sender_entry.clone()]);
        sender.mark_channel_conversation(conversation);
        sender
            .install_device_roster_v1(historical_roster.clone())
            .unwrap();
        let (historical_ciphertext, historical_header) = sender
            .encrypt_outgoing(conversation, "before target admission")
            .unwrap();
        assert_eq!(historical_header, [HEADER_SENDER_KEY]);

        let current_roster =
            candidate_with_commitment(conversation, 2, vec![sender_entry, recipient_entry]);
        sender
            .install_device_roster_v1(current_roster.clone())
            .unwrap();
        recipient.mark_channel_conversation(conversation);
        recipient
            .install_device_roster_v1(current_roster.clone())
            .unwrap();

        let sender_binding_version = sender.device_identity.as_ref().unwrap().binding().version;
        let sender_device_identity_key = sender
            .device_identity
            .as_ref()
            .unwrap()
            .binding()
            .device_identity_key;
        let recipient_target = sender
            .sender_key_device_targets(conversation)
            .unwrap()
            .into_iter()
            .find(|target| target.device_id == recipient.device_id)
            .unwrap();
        let (fresh_key, fresh_envelope) = sender
            .prepare_sender_key_device_envelope(&recipient_target)
            .unwrap();
        let fresh_route = route_for_test(&sender, &recipient_target, &fresh_key);
        recipient
            .process_sender_key_distribution_v1(&fresh_envelope, &fresh_route)
            .unwrap();
        sender.mark_sender_key_distributed(conversation).unwrap();
        let (fresh_ciphertext, fresh_header) = sender
            .encrypt_outgoing(conversation, "after exact-device distribution")
            .unwrap();
        let fresh_context =
            MessageSecurityContextV1::SenderKeyV5(SenderKeyMessageSecurityContextV1 {
                roster_version: fresh_route.roster_version,
                roster_commitment: fresh_route.roster_commitment,
                sender_device_id: fresh_route.sender_device_id,
                target_device_id: fresh_route.target_device_id,
                sender_binding_version: fresh_route.sender_binding_version,
            });
        let historical_context =
            MessageSecurityContextV1::SenderKeyV5(SenderKeyMessageSecurityContextV1 {
                roster_version: historical_roster.roster_version,
                roster_commitment: historical_roster.roster_commitment,
                sender_device_id: sender.device_id,
                target_device_id: recipient.device_id,
                sender_binding_version,
            });
        assert_eq!(
            recipient
                .inspect_sender_key_message_context_v1(
                    conversation,
                    &sender.identity_key().unwrap(),
                    &historical_ciphertext,
                    &historical_context,
                )
                .unwrap(),
            SenderKeyMessageContextInspectionV1::MissingExactRoute {
                target_device_id: recipient.device_id,
                message_roster_version: historical_roster.roster_version,
                message_roster_commitment: historical_roster.roster_commitment,
                installed_roster_version: current_roster.roster_version,
                installed_roster_commitment: current_roster.roster_commitment,
            }
        );
        assert!(recipient
            .decrypt_from_with_security_context(
                &sender.identity_key().unwrap(),
                conversation,
                &historical_header,
                &historical_ciphertext,
                Some(&historical_context),
            )
            .unwrap_err()
            .contains("historical Sender-Key route is unavailable"));
        assert!(recipient
            .validate_sender_key_message_context_v1(
                conversation,
                &sender.identity_key().unwrap(),
                &historical_ciphertext,
                &historical_context,
            )
            .unwrap_err()
            .contains("historical Sender-Key route is unavailable"));

        let incoming_before = recipient
            .sender_keys
            .incoming_generations(conversation, &sender_device_identity_key);
        assert_eq!(incoming_before, vec![fresh_key.generation]);
        let fresh_metadata_before = recipient
            .sender_keys
            .incoming_generation_metadata(
                conversation,
                &sender_device_identity_key,
                fresh_key.generation,
            )
            .unwrap();
        let ratchet_sessions_before = recipient.ratchet_sessions.len();
        let pending_receipts_before = recipient.pending_sender_key_receipts.len();
        let outgoing_generation_before = recipient
            .sender_keys
            .build_distribution(conversation)
            .unwrap()
            .key_id;
        let persisted_before = recipient
            .db()
            .unwrap()
            .load_incoming_sender_key_generations_for_group(conversation)
            .unwrap();
        assert_eq!(persisted_before.len(), 1);
        let persisted_before = (
            persisted_before[0].sender_identity_key,
            persisted_before[0].generation,
            persisted_before[0].iteration,
            persisted_before[0].state_revision,
            persisted_before[0].distribution_commitment,
            Sha256::digest(persisted_before[0].key_data.as_slice()),
        );
        assert!(recipient
            .receive_and_persist_message(
                "pre-admission-message",
                conversation,
                &sender.identity_key().unwrap(),
                None,
                None,
                true,
                Some(&historical_context),
                Some("Pre-admission history"),
                &historical_header,
                &historical_ciphertext,
                Some(1),
                None,
                None,
            )
            .unwrap_err()
            .contains("historical Sender-Key route is unavailable"));
        let unavailable_metadata = RemoteMessageMetadata {
            revision_ms: 1,
            reactions: None,
        };
        assert_eq!(
            recipient
                .reconcile_remote_message_metadata(
                    "pre-admission-message",
                    conversation,
                    &sender.identity_key().unwrap(),
                    &unavailable_metadata,
                    RemoteMessageStateKind::Unavailable,
                )
                .unwrap(),
            RemoteReconcileAction::Unavailable
        );
        assert_eq!(
            recipient
                .sender_keys
                .incoming_generations(conversation, &sender_device_identity_key),
            incoming_before
        );
        assert_eq!(
            recipient
                .sender_keys
                .incoming_generation_metadata(
                    conversation,
                    &sender_device_identity_key,
                    fresh_key.generation,
                )
                .unwrap(),
            fresh_metadata_before
        );
        assert_eq!(recipient.ratchet_sessions.len(), ratchet_sessions_before);
        assert_eq!(
            recipient.pending_sender_key_receipts.len(),
            pending_receipts_before
        );
        assert_eq!(
            recipient
                .sender_keys
                .build_distribution(conversation)
                .unwrap()
                .key_id,
            outgoing_generation_before
        );
        let persisted_after = recipient
            .db()
            .unwrap()
            .load_incoming_sender_key_generations_for_group(conversation)
            .unwrap();
        assert_eq!(persisted_after.len(), 1);
        assert_eq!(
            (
                persisted_after[0].sender_identity_key,
                persisted_after[0].generation,
                persisted_after[0].iteration,
                persisted_after[0].state_revision,
                persisted_after[0].distribution_commitment,
                Sha256::digest(persisted_after[0].key_data.as_slice()),
            ),
            persisted_before
        );
        assert!(!recipient
            .db()
            .unwrap()
            .message_exists("pre-admission-message")
            .unwrap());
        assert_eq!(
            recipient
                .db()
                .unwrap()
                .get_remote_message_state("pre-admission-message")
                .unwrap()
                .unwrap()
                .state,
            RemoteMessageStateKind::Unavailable
        );

        let current_epoch_without_route =
            MessageSecurityContextV1::SenderKeyV5(SenderKeyMessageSecurityContextV1 {
                roster_version: current_roster.roster_version,
                roster_commitment: current_roster.roster_commitment,
                sender_device_id: sender.device_id,
                target_device_id: recipient.device_id,
                sender_binding_version,
            });
        assert!(matches!(
            recipient
                .inspect_sender_key_message_context_v1(
                    conversation,
                    &sender.identity_key().unwrap(),
                    &historical_ciphertext,
                    &current_epoch_without_route,
                )
                .unwrap(),
            SenderKeyMessageContextInspectionV1::MissingExactRoute {
                message_roster_version: 2,
                ..
            }
        ));
        assert!(recipient
            .inspect_sender_key_message_context_v1(
                conversation,
                &sender.identity_key().unwrap(),
                &historical_ciphertext[..historical_ciphertext.len() - 1],
                &historical_context,
            )
            .is_err());

        assert_eq!(
            recipient
                .inspect_sender_key_message_context_v1(
                    conversation,
                    &sender.identity_key().unwrap(),
                    &fresh_ciphertext,
                    &fresh_context,
                )
                .unwrap(),
            SenderKeyMessageContextInspectionV1::Verified
        );
        recipient
            .validate_sender_key_message_context_v1(
                conversation,
                &sender.identity_key().unwrap(),
                &fresh_ciphertext,
                &fresh_context,
            )
            .unwrap();

        let conflicting_context =
            MessageSecurityContextV1::SenderKeyV5(SenderKeyMessageSecurityContextV1 {
                roster_version: fresh_route.roster_version,
                roster_commitment: fresh_route.roster_commitment,
                sender_device_id: [0x99; 16],
                target_device_id: fresh_route.target_device_id,
                sender_binding_version: fresh_route.sender_binding_version,
            });
        assert!(recipient
            .inspect_sender_key_message_context_v1(
                conversation,
                &sender.identity_key().unwrap(),
                &fresh_ciphertext,
                &conflicting_context,
            )
            .is_err());

        let mut wrong_account_identity = sender.identity_key().unwrap();
        wrong_account_identity[0] ^= 0x80;
        assert!(recipient
            .inspect_sender_key_message_context_v1(
                conversation,
                &wrong_account_identity,
                &fresh_ciphertext,
                &fresh_context,
            )
            .is_err());

        let group_len = u16::from_be_bytes([fresh_ciphertext[1], fresh_ciphertext[2]]) as usize;
        let sender_identity_offset = 3 + group_len;
        let inner_offset = sender_identity_offset + 32 + 4;
        let mut mutated_sender_identity = fresh_ciphertext.clone();
        mutated_sender_identity[sender_identity_offset] ^= 0x01;
        let mut mutated_generation = fresh_ciphertext.clone();
        mutated_generation[inner_offset + 1] ^= 0x01;
        let mut mutated_signature = fresh_ciphertext.clone();
        let signature_byte = mutated_signature
            .last_mut()
            .expect("signed Sender-Key message has a signature");
        *signature_byte ^= 0x01;
        for mutated in [
            &mutated_sender_identity,
            &mutated_generation,
            &mutated_signature,
        ] {
            assert!(recipient
                .validate_sender_key_message_context_v1(
                    conversation,
                    &sender.identity_key().unwrap(),
                    mutated,
                    &fresh_context,
                )
                .is_err());
        }
        let fresh_metadata = RemoteMessageMetadata {
            revision_ms: 2,
            reactions: None,
        };
        assert_eq!(
            recipient
                .receive_and_persist_message(
                    "fresh-routed-message",
                    conversation,
                    &sender.identity_key().unwrap(),
                    None,
                    None,
                    true,
                    Some(&fresh_context),
                    Some("Current secure channel"),
                    &fresh_header,
                    &fresh_ciphertext,
                    Some(2),
                    None,
                    Some(&fresh_metadata),
                )
                .unwrap(),
            ReceiveMessageResult::Stored {
                plaintext: "after exact-device distribution".to_string()
            }
        );
        let fresh_metadata_after = recipient
            .sender_keys
            .incoming_generation_metadata(
                conversation,
                &sender_device_identity_key,
                fresh_key.generation,
            )
            .unwrap();
        assert_eq!(
            fresh_metadata_after.iteration,
            fresh_metadata_before.iteration + 1
        );
        assert_eq!(recipient.ratchet_sessions.len(), ratchet_sessions_before);
        assert_eq!(
            recipient.pending_sender_key_receipts.len(),
            pending_receipts_before
        );
        assert!(recipient
            .db()
            .unwrap()
            .message_exists("fresh-routed-message")
            .unwrap());
        assert_eq!(
            recipient
                .db()
                .unwrap()
                .get_remote_message_state("fresh-routed-message")
                .unwrap()
                .unwrap()
                .state,
            RemoteMessageStateKind::Active
        );
        let offline_refresh = recipient.hydrate_channel_sender_keys(conversation).unwrap();
        assert!(recipient
            .begin_offline_sender_key_distribution(conversation, offline_refresh)
            .unwrap());
        assert_eq!(
            recipient.sender_key_distribution_status(conversation),
            "pending"
        );
        let distributed_generation = recipient
            .sender_keys
            .build_distribution(conversation)
            .unwrap()
            .key_id;
        match offline_refresh {
            OfflineSenderKeyRefresh::Required => {
                assert_ne!(distributed_generation, outgoing_generation_before)
            }
            OfflineSenderKeyRefresh::AlreadyRotated => {
                assert_eq!(distributed_generation, outgoing_generation_before)
            }
        }
    }

    #[test]
    fn corrupted_persisted_device_secret_blocks_restart() {
        let mnemonic = generate_mnemonic().to_string();
        let path =
            std::env::temp_dir().join(format!("veil-device-corrupt-{}.db", uuid::Uuid::new_v4()));
        {
            let mut client = VeilClient::new();
            client.init_with_mnemonic(&mnemonic, &path).unwrap();
        }

        let db_key = Zeroizing::new(kdf::derive_db_key(&mnemonic).unwrap());
        let conn = rusqlite::Connection::open(&path).unwrap();
        let key_pragma = Zeroizing::new(format!(
            "PRAGMA key = \"x'{}'\";",
            hex::encode(db_key.as_slice())
        ));
        conn.execute_batch(&key_pragma).unwrap();
        conn.execute(
            "UPDATE device_identity_v1 SET x25519_secret = ?1 WHERE singleton = 1",
            // Canonical but unrelated scalar: this exercises derived-public
            // verification rather than only the canonical-encoding guard.
            rusqlite::params![[0x40u8; 32].as_slice()],
        )
        .unwrap();
        drop(conn);

        let mut restored = VeilClient::new();
        let error = restored.init_with_mnemonic(&mnemonic, &path).unwrap_err();
        assert!(error.contains("secret/public key mismatch"));
        drop(restored);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[tokio::test]
    async fn account_only_client_cannot_attempt_bound_websocket_auth() {
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        assert!(client
            .connect("ws://127.0.0.1:1/ws")
            .await
            .unwrap_err()
            .contains("per-device identity is missing"));
    }

    #[test]
    fn first_post_barrier_skdm_stays_live_fifo_and_requires_exact_current_roster() {
        let sender_user = uuid::Uuid::from_bytes([0xE1; 16]);
        let recipient_user = uuid::Uuid::from_bytes([0xE2; 16]);
        let mut sender = memory_client_with_device(
            IdentityKeyPair::generate(),
            sender_user,
            [0xE3; 16],
            [0xE4; 32],
        );
        let mut recipient = memory_client_with_device(
            IdentityKeyPair::generate(),
            recipient_user,
            [0xE5; 16],
            [0xE6; 32],
        );
        let conversation = "00000000-0000-0000-0000-000000000313";
        let roster = candidate_with_commitment(
            conversation,
            1,
            vec![
                roster_entry(
                    *sender_user.as_bytes(),
                    sender.identity.as_ref().unwrap(),
                    sender.device_identity.as_ref().unwrap().binding(),
                ),
                roster_entry(
                    *recipient_user.as_bytes(),
                    recipient.identity.as_ref().unwrap(),
                    recipient.device_identity.as_ref().unwrap().binding(),
                ),
            ],
        );
        sender.mark_channel_conversation(conversation);
        recipient.mark_channel_conversation(conversation);
        sender.install_device_roster_v1(roster.clone()).unwrap();
        recipient.install_device_roster_v1(roster).unwrap();
        let target = sender
            .sender_key_device_targets(conversation)
            .unwrap()
            .into_iter()
            .find(|target| target.device_id == recipient.device_id)
            .unwrap();
        let (pending, sealed) = sender.prepare_sender_key_device_envelope(&target).unwrap();
        let mut stale_route = route_for_test(&sender, &target, &pending);
        stale_route.roster_version += 1;
        stale_route.roster_commitment[0] ^= 1;
        let next_live = ConnectionEvent::MessageReceived {
            message_id: "next-live-message".to_string(),
            conversation_id: conversation.to_string(),
            sender_identity_key: sender.identity_key().unwrap().to_vec(),
            sender_username: "Sender".to_string(),
            ciphertext: vec![4],
            header: vec![HEADER_SENDER_KEY],
            server_timestamp: 1,
            reply_to_id: None,
            msg_type: Some(0),
            ttl_seconds: None,
            sealed: Some(false),
            attachments: Vec::new(),
            security_context: None,
        };
        let live_budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        let report = recipient
            .process_retained_and_defer_live_events_v1(
                Vec::new(),
                vec![
                    live_budget
                        .try_wrap(ConnectionEvent::SenderKeyDist {
                            sender_key_message: sealed.clone(),
                            route: stale_route.clone(),
                        })
                        .unwrap(),
                    live_budget.try_wrap(next_live).unwrap(),
                ],
            )
            .unwrap();
        assert_eq!(report, RetainedSenderKeyProcessReportV1::default());
        let first = recipient
            .deferred_connection_events
            .pop_front()
            .unwrap()
            .into_event();
        match first {
            ConnectionEvent::SenderKeyDist {
                sender_key_message,
                route,
            } => assert!(recipient
                .process_sender_key_distribution_v1(&sender_key_message, &route)
                .unwrap_err()
                .contains("exact current roster")),
            _ => panic!("first post-barrier event was reordered"),
        }
        assert!(matches!(
            recipient
                .deferred_connection_events
                .pop_front()
                .map(BudgetedConnectionEventV1::into_event),
            Some(ConnectionEvent::MessageReceived { message_id, .. })
                if message_id == "next-live-message"
        ));
        assert!(recipient.pending_sender_key_receipts.is_empty());
    }

    #[tokio::test]
    async fn live_overflow_is_atomic_before_any_retained_sender_key_side_effect() {
        let sender_user = uuid::Uuid::from_bytes([0xD1; 16]);
        let recipient_user = uuid::Uuid::from_bytes([0xD2; 16]);
        let mut sender = memory_client_with_device(
            IdentityKeyPair::generate(),
            sender_user,
            [0xD3; 16],
            [0xD4; 32],
        );
        let mut recipient = memory_client_with_device(
            IdentityKeyPair::generate(),
            recipient_user,
            [0xD5; 16],
            [0xD6; 32],
        );
        let conversation = "00000000-0000-0000-0000-000000000314";
        let roster = candidate_with_commitment(
            conversation,
            1,
            vec![
                roster_entry(
                    *sender_user.as_bytes(),
                    sender.identity.as_ref().unwrap(),
                    sender.device_identity.as_ref().unwrap().binding(),
                ),
                roster_entry(
                    *recipient_user.as_bytes(),
                    recipient.identity.as_ref().unwrap(),
                    recipient.device_identity.as_ref().unwrap().binding(),
                ),
            ],
        );
        sender.mark_channel_conversation(conversation);
        recipient.mark_channel_conversation(conversation);
        sender.install_device_roster_v1(roster.clone()).unwrap();
        recipient.install_device_roster_v1(roster).unwrap();
        let target = sender
            .sender_key_device_targets(conversation)
            .unwrap()
            .into_iter()
            .find(|target| target.device_id == recipient.device_id)
            .unwrap();
        let (pending, sealed) = sender.prepare_sender_key_device_envelope(&target).unwrap();
        let route = route_for_test(&sender, &target, &pending);

        let test_budget =
            crate::connection::ConnectionEventBudgetV1::with_limits(2, 64 * 1024 * 1024);
        let retained = test_budget
            .try_wrap(ConnectionEvent::SenderKeyDist {
                sender_key_message: sealed,
                route,
            })
            .unwrap();
        let mut oversized_reason = String::with_capacity(LIVE_EVENT_RETAINED_BYTES + 1);
        oversized_reason.push('x');
        let live = test_budget
            .try_wrap(ConnectionEvent::Error {
                code: 500,
                message: oversized_reason,
                ref_seq: None,
                client_message_id: None,
                reason: None,
                local_message_id: None,
                conversation_id: None,
                stale_roster_context: false,
            })
            .unwrap();

        let error = recipient
            .process_retained_and_defer_live_events_v1(vec![retained], vec![live])
            .unwrap_err();
        assert!(error.contains("retained-size limit"));
        assert!(!recipient.sender_keys.has_incoming_generation(
            conversation,
            &sender.identity_key().unwrap(),
            pending.generation,
        ));
        assert!(recipient.pending_sender_key_receipts.is_empty());
        assert!(recipient
            .poll_event()
            .await
            .unwrap_err()
            .contains("retained-size limit"));
    }

    #[test]
    fn deferred_fifo_epoch_reset_drops_stale_events_and_sticky_failure() {
        let budget =
            crate::connection::ConnectionEventBudgetV1::with_limits(2, LIVE_EVENT_RETAINED_BYTES);
        let event = |id: &str| ConnectionEvent::FriendRemoved {
            user_id: id.to_string(),
        };
        let first = budget.try_wrap(event("first")).unwrap();
        let second = budget.try_wrap(event("second")).unwrap();
        let mut queue = DeferredConnectionEventQueueV1::default();
        queue.try_extend(vec![first, second]).unwrap();
        assert!(matches!(
            queue.pop_front().map(BudgetedConnectionEventV1::into_event),
            Some(ConnectionEvent::FriendRemoved { user_id }) if user_id == "first"
        ));
        assert!(matches!(
            queue.pop_front().map(BudgetedConnectionEventV1::into_event),
            Some(ConnectionEvent::FriendRemoved { user_id }) if user_id == "second"
        ));

        let anomaly = budget
            .try_wrap(ConnectionEvent::Authenticated {
                user_id: "unexpected".to_string(),
            })
            .unwrap();
        assert!(matches!(
            queue.try_extend(vec![anomaly]),
            Err(ConnectionEventBufferErrorV1::AuthenticationEpochAnomaly { .. })
        ));
        assert!(queue.failure().is_some());

        // Successful reconnect calls this exact reset before installing its
        // new Connection, so neither stale FIFO data nor a prior sticky error
        // can cross the epoch boundary.
        queue.reset_for_new_epoch();
        assert!(queue.failure().is_none());
        queue
            .try_extend(vec![budget.try_wrap(event("new epoch")).unwrap()])
            .unwrap();
        assert!(matches!(
            queue.pop_front().map(BudgetedConnectionEventV1::into_event),
            Some(ConnectionEvent::FriendRemoved { user_id }) if user_id == "new epoch"
        ));
    }

    #[tokio::test]
    async fn fallback_receive_preserves_racing_typed_terminal_failure() {
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        let terminal_error = ConnectionEventBufferErrorV1::RetainedSizeLimitExceeded {
            limit: LIVE_EVENT_RETAINED_BYTES,
            event_bytes: LIVE_EVENT_RETAINED_BYTES + 1,
        };
        let racing_terminal =
            BudgetedConnectionEventV1::terminal_failure_for_test(terminal_error.clone());

        // Models a terminal published after poll_event's precheck but before
        // its fallback receiver call. Metadata must survive that exact path.
        let error = client
            .resolve_budgeted_connection_event_v1(Some(racing_terminal))
            .unwrap_err();
        assert!(error.contains("retained-size limit"));
        assert_eq!(
            client.deferred_connection_events.failure(),
            Some(terminal_error)
        );
        assert!(client
            .poll_event()
            .await
            .unwrap_err()
            .contains("retained-size limit"));
    }

    const DIRECT_LIVE_TEST_ORIGIN: &str = "https://live-replay.example.test:443";

    struct DirectOutboxClientFixture {
        client: VeilClient,
        outbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
        conversation_id: String,
        peer_identity_key: [u8; 32],
        peer_signing_key: [u8; 32],
        self_user_id: String,
        peer_user_id: String,
    }

    impl DirectOutboxClientFixture {
        fn new() -> Self {
            Self::new_with_identity_and_db(
                IdentityKeyPair::generate(),
                VeilDb::open_memory(&[0xD8; 32]).unwrap(),
            )
        }

        fn new_with_identity_and_db(self_identity: IdentityKeyPair, db: VeilDb) -> Self {
            let self_identity_key = self_identity.x25519_public_bytes();
            let self_signing_key = self_identity.ed25519_public_bytes();
            let self_user_id =
                uuid::Uuid::from_u128(0x7100_0000_0000_0000_0000_0000_0000_0001).to_string();
            let peer_user_id =
                uuid::Uuid::from_u128(0x7200_0000_0000_0000_0000_0000_0000_0002).to_string();
            let conversation_id =
                uuid::Uuid::from_u128(0x7300_0000_0000_0000_0000_0000_0000_0003).to_string();
            let device_id = [0xD7; 16];
            let stored_device =
                DeviceIdentityV1::generate_stored(&self_identity, device_id).unwrap();
            db.create_device_identity_v1(&stored_device).unwrap();
            let device_identity = DeviceIdentityV1::from_stored(
                &self_identity,
                db.load_device_identity_v1().unwrap().unwrap(),
            )
            .unwrap();
            db.bind_authenticated_self(
                DIRECT_LIVE_TEST_ORIGIN,
                &self_user_id,
                &self_identity_key,
                &self_signing_key,
            )
            .unwrap();

            let peer_identity = IdentityKeyPair::generate();
            let peer_identity_key = peer_identity.x25519_public_bytes();
            let peer_signing_key = peer_identity.ed25519_public_bytes();
            let snapshots = [
                AccountSnapshot {
                    locator: veil_store::models::ProfileLocator {
                        canonical_server_origin: DIRECT_LIVE_TEST_ORIGIN.to_string(),
                        user_id: self_user_id.clone(),
                        identity_key: self_identity_key,
                    },
                    signing_key: self_signing_key,
                    username: Some("Outbox Self".to_string()),
                    display_name: None,
                    profile_version: Some(1),
                    profile_origin: DIRECT_LIVE_TEST_ORIGIN.to_string(),
                    source: veil_store::models::AccountSnapshotSource::AuthenticatedConversationDirectory,
                    observed_at: "2026-07-19T00:00:00Z".to_string(),
                },
                AccountSnapshot {
                    locator: veil_store::models::ProfileLocator {
                        canonical_server_origin: DIRECT_LIVE_TEST_ORIGIN.to_string(),
                        user_id: peer_user_id.clone(),
                        identity_key: peer_identity_key,
                    },
                    signing_key: peer_signing_key,
                    username: Some("Outbox Peer".to_string()),
                    display_name: None,
                    profile_version: Some(1),
                    profile_origin: DIRECT_LIVE_TEST_ORIGIN.to_string(),
                    source: veil_store::models::AccountSnapshotSource::AuthenticatedConversationDirectory,
                    observed_at: "2026-07-19T00:00:00Z".to_string(),
                },
            ];
            db.upsert_identity_directory(&snapshots).unwrap();
            db.upsert_directory_conversation(
                &conversation_id,
                ConversationType::DM as u8,
                DIRECT_LIVE_TEST_ORIGIN,
                Some("Outbox Peer"),
                Some(&peer_user_id),
                Some(&peer_identity_key),
                None,
                "2026-07-19T00:00:00Z",
            )
            .unwrap();

            let mut client = VeilClient::from_identity(self_identity);
            client.device_id = device_id;
            client.device_identity = Some(device_identity);
            client.db = Some(db);
            client.authenticated_user_id = Some(self_user_id.clone());
            client.authenticated_server_origin = Some(DIRECT_LIVE_TEST_ORIGIN.to_string());
            client
                .remember_user_identity(&self_user_id, self_identity_key)
                .unwrap();
            client
                .remember_user_identity(&peer_user_id, peer_identity_key)
                .unwrap();
            client
                .pin_peer_signing_key(peer_identity_key, peer_signing_key)
                .unwrap();
            client
                .replace_authorized_conversation_senders(
                    &conversation_id,
                    [self_identity_key, peer_identity_key],
                )
                .unwrap();
            client
                .bind_dm_conversation(&conversation_id, peer_identity_key)
                .unwrap();

            let peer_device_id = [0xE7; 16];
            let peer_stored_device =
                DeviceIdentityV1::generate_stored(&peer_identity, peer_device_id).unwrap();
            let peer_device =
                DeviceIdentityV1::from_stored(&peer_identity, peer_stored_device).unwrap();
            let peer_binding = peer_device.binding().clone();
            let mut peer = VeilClient::from_identity(peer_identity);
            peer.device_id = peer_device_id;
            peer.device_identity = Some(peer_device);
            let peer_prekeys = peer.generate_prekeys().unwrap();
            let (one_time_prekey, one_time_prekey_id) = peer_prekeys.otk_publics[0];
            let direct_context = client
                .direct_v2_initiator_context(
                    &conversation_id,
                    &peer_user_id,
                    peer_identity_key,
                    peer_signing_key,
                    DirectDeviceCoordinateV2 {
                        device_id: peer_binding.device_id,
                        binding_version: peer_binding.version,
                        capabilities: peer_binding.capabilities,
                        status: peer_binding.status,
                        identity_key: peer_binding.device_identity_key,
                        signing_key: peer_binding.device_signing_key,
                        account_signature: peer_binding.account_signature,
                    },
                )
                .unwrap();
            client
                .establish_session_classified_v2(
                    &peer_identity_key,
                    &x3dh::PreKeyBundle {
                        identity_key: peer_identity_key,
                        signing_key: peer_signing_key,
                        signed_prekey: peer_prekeys.spk_public,
                        signed_prekey_signature: peer_prekeys.spk_signature,
                        signed_prekey_id: peer_prekeys.spk_id,
                        one_time_prekey: Some(one_time_prekey),
                        one_time_prekey_id: Some(one_time_prekey_id),
                    },
                    direct_context,
                )
                .unwrap();
            let outbound = client.test_only_install_queued_connection();
            Self {
                client,
                outbound,
                conversation_id,
                peer_identity_key,
                peer_signing_key,
                self_user_id,
                peer_user_id,
            }
        }

        fn decode_send(wire: &[u8]) -> (u64, proto::SendMessage) {
            let envelope = <proto::Envelope as prost::Message>::decode(wire).unwrap();
            let Some(proto::envelope::Payload::SendMessage(send)) = envelope.payload else {
                panic!("expected SendMessage envelope")
            };
            (envelope.seq, send)
        }
    }

    #[tokio::test]
    async fn atomic_direct_outbox_replays_exact_payload_and_ack_is_restart_idempotent() {
        let mut fixture = DirectOutboxClientFixture::new();
        let enqueue = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "atomic exact retry")
            .await
            .unwrap();
        assert!(enqueue.transport_enqueued);
        let first_wire = fixture.outbound.recv().await.unwrap();
        let (first_sequence, first_send) = DirectOutboxClientFixture::decode_send(&first_wire);
        assert_eq!(first_sequence, enqueue.sequence);
        assert!(VeilClient::is_canonical_live_uuid_v1(
            &first_send.client_message_id
        ));
        let exact_payload = first_send.encode_to_vec();
        let scope = fixture.client.current_direct_outbox_scope_v1().unwrap();
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&scope)
                .unwrap(),
            1
        );
        assert!(fixture
            .client
            .ratchet_sessions
            .get(&fixture.peer_identity_key)
            .unwrap()
            .matches_serialized_v1(
                &fixture
                    .client
                    .db()
                    .unwrap()
                    .load_ratchet_session_with_revision_v1(&fixture.peer_identity_key)
                    .unwrap()
                    .unwrap()
                    .session_data
            )
            .unwrap());

        fixture.client.mark_all_pending_sequences_unknown().unwrap();
        assert!(fixture.client.pending_outgoing_messages.is_empty());
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .get_messages(&fixture.conversation_id, 10)
                .unwrap()[0]
                .status,
            veil_store::models::MessageStatus::Sending
        );
        fixture.outbound = fixture.client.test_only_install_queued_connection();
        let replay = fixture
            .client
            .replay_direct_outbox_v1(None, 10)
            .await
            .unwrap();
        assert_eq!(replay.visited, 1);
        assert_eq!(replay.enqueued, 1);
        assert_eq!(replay.pending_total, 1);
        assert!(replay.next_queue_order.is_some());
        assert!(replay.reached_end);
        assert!(!replay.transport_blocked);
        let replay_wire = fixture.outbound.recv().await.unwrap();
        let (replay_sequence, replay_send) = DirectOutboxClientFixture::decode_send(&replay_wire);
        assert!(replay_sequence > 0);
        assert_eq!(replay_send.encode_to_vec(), exact_payload);

        let server_message_id =
            uuid::Uuid::from_u128(0x7400_0000_0000_0000_0000_0000_0000_0004).to_string();
        let server_timestamp = 1_700_000_000_123_000_000u64;
        assert!(fixture
            .client
            .finalize_outgoing_message(
                replay_sequence + 1,
                Some(&first_send.client_message_id),
                &server_message_id,
                server_timestamp,
            )
            .unwrap_err()
            .contains("sequence does not match"));
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&scope)
                .unwrap(),
            1
        );
        assert_eq!(
            fixture
                .client
                .finalize_outgoing_message(
                    replay_sequence,
                    Some(&first_send.client_message_id),
                    &server_message_id,
                    server_timestamp,
                )
                .unwrap()
                .as_deref(),
            Some(first_send.client_message_id.as_str())
        );
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&scope)
                .unwrap(),
            0
        );
        let sent = fixture
            .client
            .db()
            .unwrap()
            .get_messages(&fixture.conversation_id, 10)
            .unwrap();
        assert_eq!(sent[0].id, server_message_id);
        assert_eq!(sent[0].status, veil_store::models::MessageStatus::Sent);
        assert_eq!(
            fixture
                .client
                .finalize_outgoing_message(
                    replay_sequence + 100,
                    Some(&first_send.client_message_id),
                    &server_message_id,
                    server_timestamp,
                )
                .unwrap()
                .as_deref(),
            Some(first_send.client_message_id.as_str())
        );
        fixture
            .client
            .db()
            .unwrap()
            .conn()
            .execute(
                "DELETE FROM messages WHERE id = ?1",
                rusqlite::params![server_message_id],
            )
            .unwrap();
        fixture
            .client
            .db()
            .unwrap()
            .conn()
            .execute(
                "DELETE FROM conversations WHERE id = ?1",
                rusqlite::params![fixture.conversation_id],
            )
            .unwrap();
        assert_eq!(
            fixture
                .client
                .finalize_outgoing_message(
                    replay_sequence + 101,
                    Some(&first_send.client_message_id),
                    &server_message_id,
                    server_timestamp,
                )
                .unwrap()
                .as_deref(),
            Some(first_send.client_message_id.as_str())
        );
        let compact: (i64, bool) = fixture
            .client
            .db()
            .unwrap()
            .conn()
            .query_row(
                "SELECT state, exact_send_message_payload IS NULL
                 FROM direct_message_outbox_v1 WHERE client_message_id = ?1",
                rusqlite::params![first_send.client_message_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(compact, (1, true));
    }

    #[tokio::test]
    async fn successful_outbox_enqueue_racing_protocol_terminal_never_reports_ready() {
        let mut fixture = DirectOutboxClientFixture::new();
        fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "replay terminal race")
            .await
            .unwrap();
        let first_wire = fixture.outbound.recv().await.unwrap();
        fixture.client.mark_all_pending_sequences_unknown().unwrap();
        fixture.outbound = fixture.client.test_only_install_queued_connection();
        fixture
            .client
            .test_only_epoch_invalid_after_next_direct_outbox_enqueue_v1();

        let error = fixture
            .client
            .replay_direct_outbox_v1(None, 10)
            .await
            .unwrap_err();
        assert!(matches!(error, DirectSendErrorV1::Rejected(_)));
        assert_eq!(
            fixture.client.direct_live_stop,
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );
        assert!(!fixture.client.direct_live_storage_uncertain);
        assert_eq!(fixture.client.pending_outgoing_messages.len(), 1);
        let replay_wire = fixture.outbound.recv().await.unwrap();
        assert_eq!(
            replay_wire, first_wire,
            "the terminal race must not change exact replay bytes"
        );
    }

    #[tokio::test]
    async fn expired_direct_ack_deadline_revokes_transport_and_replays_exact_outbox() {
        let mut fixture = DirectOutboxClientFixture::new();
        let queued = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "deadline exact retry")
            .await
            .unwrap();
        assert!(queued.transport_enqueued);
        let first_wire = fixture.outbound.recv().await.unwrap();
        let (_, first_send) = DirectOutboxClientFixture::decode_send(&first_wire);
        let exact_payload = first_send.encode_to_vec();
        let scope = fixture.client.current_direct_outbox_scope_v1().unwrap();

        assert_eq!(fixture.client.test_only_expire_direct_ack_deadlines_v1(), 1);
        let error = fixture
            .client
            .replay_direct_live_events_v1()
            .await
            .unwrap_err();
        assert_eq!(error.stop, DirectLiveReplayStopV1::AckDeadline);
        assert_eq!(error.report, DirectLiveReplayReportV1::default());
        assert_eq!(
            fixture.client.direct_live_stop,
            Some(DirectLiveReplayStopV1::AckDeadline)
        );
        assert!(fixture.client.connection.is_none());
        assert!(fixture.client.authenticated_user_id.is_none());
        assert!(fixture.client.authenticated_server_origin.is_none());
        assert!(fixture.client.pending_outgoing_messages.is_empty());
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&scope)
                .unwrap(),
            1
        );
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .get_messages(&fixture.conversation_id, 10)
                .unwrap()[0]
                .status,
            veil_store::models::MessageStatus::Sending
        );

        // Model the successful authenticated reconnect boundary. Only the new
        // socket correlation/deadline changes; SQLCipher supplies the exact
        // previously committed SendMessage bytes.
        fixture
            .client
            .deferred_connection_events
            .reset_for_new_epoch();
        fixture.client.direct_live_stop = None;
        fixture.client.authenticated_user_id = Some(fixture.self_user_id.clone());
        fixture.client.authenticated_server_origin = Some(DIRECT_LIVE_TEST_ORIGIN.to_string());
        fixture.outbound = fixture.client.test_only_install_queued_connection();
        let replay = fixture
            .client
            .replay_direct_outbox_v1(None, 10)
            .await
            .unwrap();
        assert_eq!(replay.enqueued, 1);
        assert!(replay.reached_end);
        let replay_wire = fixture.outbound.recv().await.unwrap();
        let (_, replay_send) = DirectOutboxClientFixture::decode_send(&replay_wire);
        assert_eq!(replay_send.encode_to_vec(), exact_payload);
        assert_eq!(fixture.client.test_only_expire_direct_ack_deadlines_v1(), 1);
    }

    #[tokio::test]
    async fn queued_direct_ack_wins_over_an_expired_monotonic_deadline() {
        let mut fixture = DirectOutboxClientFixture::new();
        let queued = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "queued ACK wins")
            .await
            .unwrap();
        let wire = fixture.outbound.recv().await.unwrap();
        let (_, send) = DirectOutboxClientFixture::decode_send(&wire);
        let scope = fixture.client.current_direct_outbox_scope_v1().unwrap();
        assert_eq!(fixture.client.test_only_expire_direct_ack_deadlines_v1(), 1);

        let server_message_id =
            uuid::Uuid::from_u128(0x7400_0000_0000_0000_0000_0000_0000_00A1).to_string();
        let budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        fixture
            .client
            .deferred_connection_events
            .try_extend(vec![budget
                .try_wrap(ConnectionEvent::MessageAcked {
                    message_id: server_message_id.clone(),
                    server_timestamp: 1_700_000_001_234_000_000,
                    ref_seq: queued.sequence,
                    client_message_id: Some(send.client_message_id),
                    local_message_id: None,
                    mutation: None,
                    sender_key: None,
                })
                .unwrap()])
            .unwrap();

        let report = fixture.client.replay_direct_live_events_v1().await.unwrap();
        assert_eq!(report.consumed, 1);
        assert!(report.quiescent);
        assert_eq!(fixture.client.direct_live_stop, None);
        assert!(fixture.client.connection.is_some());
        assert!(fixture.client.pending_outgoing_messages.is_empty());
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&scope)
                .unwrap(),
            0
        );
        let messages = fixture
            .client
            .db()
            .unwrap()
            .get_messages(&fixture.conversation_id, 10)
            .unwrap();
        assert_eq!(messages[0].id, server_message_id);
        assert_eq!(messages[0].status, veil_store::models::MessageStatus::Sent);
    }

    #[tokio::test]
    async fn queued_direct_ack_beyond_one_batch_wins_the_finite_expiry_snapshot() {
        let mut fixture = DirectOutboxClientFixture::new();
        let queued = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "deep queued ACK wins")
            .await
            .unwrap();
        let wire = fixture.outbound.recv().await.unwrap();
        let (_, send) = DirectOutboxClientFixture::decode_send(&wire);
        assert_eq!(fixture.client.test_only_expire_direct_ack_deadlines_v1(), 1);

        let budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        let mut events = (0..DIRECT_LIVE_REPLAY_MAX_BATCH_V1)
            .map(|index| {
                budget
                    .try_wrap(ConnectionEvent::TypingEvent {
                        conversation_id: format!("queued-before-ack-{index}"),
                        identity_key: vec![0xA5; 32],
                        started: true,
                    })
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let server_message_id =
            uuid::Uuid::from_u128(0x7400_0000_0000_0000_0000_0000_0000_00A2).to_string();
        events.push(
            budget
                .try_wrap(ConnectionEvent::MessageAcked {
                    message_id: server_message_id.clone(),
                    server_timestamp: 1_700_000_001_235_000_000,
                    ref_seq: queued.sequence,
                    client_message_id: Some(send.client_message_id),
                    local_message_id: None,
                    mutation: None,
                    sender_key: None,
                })
                .unwrap(),
        );
        fixture
            .client
            .deferred_connection_events
            .try_extend(events)
            .unwrap();

        let first = fixture.client.replay_direct_live_events_v1().await.unwrap();
        assert_eq!(first.consumed, DIRECT_LIVE_REPLAY_MAX_BATCH_V1);
        assert!(!first.quiescent);
        assert_eq!(
            fixture
                .client
                .direct_ack_expiry_grace_remaining
                .get(&queued.sequence)
                .copied(),
            Some(1)
        );

        let second = fixture.client.replay_direct_live_events_v1().await.unwrap();
        assert_eq!(second.consumed, 1);
        assert!(second.quiescent);
        assert!(fixture.client.pending_outgoing_messages.is_empty());
        assert!(fixture.client.direct_ack_expiry_grace_remaining.is_empty());
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .get_messages(&fixture.conversation_id, 10)
                .unwrap()[0]
                .id,
            server_message_id
        );
    }

    #[tokio::test]
    async fn staggered_direct_deadlines_keep_independent_fifo_snapshots() {
        let mut fixture = DirectOutboxClientFixture::new();
        let first = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "first staggered deadline")
            .await
            .unwrap();
        let (_, first_send) =
            DirectOutboxClientFixture::decode_send(&fixture.outbound.recv().await.unwrap());
        let second = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "second staggered deadline")
            .await
            .unwrap();
        let (_, second_send) =
            DirectOutboxClientFixture::decode_send(&fixture.outbound.recv().await.unwrap());
        let now = Instant::now();
        fixture
            .client
            .pending_outgoing_messages
            .get_mut(&first.sequence)
            .unwrap()
            .direct_ack_deadline = Some(now);
        fixture
            .client
            .pending_outgoing_messages
            .get_mut(&second.sequence)
            .unwrap()
            .direct_ack_deadline = Some(now.checked_add(Duration::from_secs(60)).unwrap());

        let budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        let first_server_id =
            uuid::Uuid::from_u128(0x7400_0000_0000_0000_0000_0000_0000_00c1).to_string();
        fixture
            .client
            .deferred_connection_events
            .try_extend(vec![budget
                .try_wrap(ConnectionEvent::MessageAcked {
                    message_id: first_server_id,
                    server_timestamp: 1_700_000_001_250_000_000,
                    ref_seq: first.sequence,
                    client_message_id: Some(first_send.client_message_id),
                    local_message_id: None,
                    mutation: None,
                    sender_key: None,
                })
                .unwrap()])
            .unwrap();
        fixture.client.refresh_direct_ack_expiry_grace_v1(now);
        assert_eq!(
            fixture
                .client
                .direct_ack_expiry_grace_remaining
                .get(&first.sequence),
            Some(&1)
        );

        assert!(matches!(
            fixture.client.poll_event().await.unwrap(),
            Some(ConnectionEvent::MessageAcked { .. })
        ));
        fixture
            .client
            .pending_outgoing_messages
            .get_mut(&second.sequence)
            .unwrap()
            .direct_ack_deadline = Some(now);
        let second_server_id =
            uuid::Uuid::from_u128(0x7400_0000_0000_0000_0000_0000_0000_00c2).to_string();
        fixture
            .client
            .deferred_connection_events
            .try_extend(vec![budget
                .try_wrap(ConnectionEvent::MessageAcked {
                    message_id: second_server_id,
                    server_timestamp: 1_700_000_001_251_000_000,
                    ref_seq: second.sequence,
                    client_message_id: Some(second_send.client_message_id),
                    local_message_id: None,
                    mutation: None,
                    sender_key: None,
                })
                .unwrap()])
            .unwrap();
        fixture.client.consume_direct_ack_expiry_grace_event_v1(now);
        assert_eq!(
            fixture
                .client
                .direct_ack_expiry_grace_remaining
                .get(&second.sequence),
            Some(&1),
            "the second correlation must snapshot its own queued ACK"
        );
        assert!(!fixture.client.has_exhausted_direct_ack_expiry_grace_v1());

        assert!(matches!(
            fixture.client.poll_event().await.unwrap(),
            Some(ConnectionEvent::MessageAcked { .. })
        ));
        fixture.client.consume_direct_ack_expiry_grace_event_v1(now);
        assert!(fixture.client.pending_outgoing_messages.is_empty());
        assert!(fixture.client.direct_ack_expiry_grace_remaining.is_empty());
        assert_eq!(fixture.client.direct_live_stop, None);
    }

    #[tokio::test]
    async fn ack_queued_after_empty_poll_at_deadline_gets_a_frozen_fifo_turn() {
        let mut fixture = DirectOutboxClientFixture::new();
        let queued = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "empty-poll deadline race")
            .await
            .unwrap();
        let (_, send) =
            DirectOutboxClientFixture::decode_send(&fixture.outbound.recv().await.unwrap());
        let before_expiry = Instant::now();
        fixture
            .client
            .pending_outgoing_messages
            .get_mut(&queued.sequence)
            .unwrap()
            .direct_ack_deadline =
            Some(before_expiry.checked_add(Duration::from_secs(60)).unwrap());
        fixture
            .client
            .refresh_direct_ack_expiry_grace_v1(before_expiry);
        assert!(fixture.client.direct_ack_expiry_grace_remaining.is_empty());
        assert!(fixture.client.poll_event().await.unwrap().is_none());

        let observed_expiry = Instant::now();
        fixture
            .client
            .pending_outgoing_messages
            .get_mut(&queued.sequence)
            .unwrap()
            .direct_ack_deadline = Some(observed_expiry);
        let budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        fixture
            .client
            .deferred_connection_events
            .try_extend(vec![budget
                .try_wrap(ConnectionEvent::MessageAcked {
                    message_id: uuid::Uuid::from_u128(0x7400_0000_0000_0000_0000_0000_0000_00c3)
                        .to_string(),
                    server_timestamp: 1_700_000_001_254_000_000,
                    ref_seq: queued.sequence,
                    client_message_id: Some(send.client_message_id),
                    local_message_id: None,
                    mutation: None,
                    sender_key: None,
                })
                .unwrap()])
            .unwrap();
        assert_eq!(
            fixture
                .client
                .classify_direct_live_empty_poll_v1(observed_expiry),
            DirectLiveEmptyPollV1::ContinueFrozenFifo
        );
        assert_eq!(
            fixture
                .client
                .direct_ack_expiry_grace_remaining
                .get(&queued.sequence),
            Some(&1)
        );

        let report = fixture.client.replay_direct_live_events_v1().await.unwrap();
        assert_eq!(report.consumed, 1);
        assert!(report.quiescent);
        assert!(fixture.client.pending_outgoing_messages.is_empty());
        assert_eq!(fixture.client.direct_live_stop, None);
    }

    #[tokio::test]
    async fn post_expiry_unrelated_traffic_cannot_replenish_the_fifo_grace() {
        let mut fixture = DirectOutboxClientFixture::new();
        let queued = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "bounded deadline grace")
            .await
            .unwrap();
        fixture.outbound.recv().await.unwrap();
        assert_eq!(fixture.client.test_only_expire_direct_ack_deadlines_v1(), 1);

        let budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        let initial_count = DIRECT_LIVE_REPLAY_MAX_BATCH_V1 + 1;
        let initial = (0..initial_count)
            .map(|index| {
                budget
                    .try_wrap(ConnectionEvent::TypingEvent {
                        conversation_id: format!("expiry-snapshot-{index}"),
                        identity_key: vec![0xB6; 32],
                        started: true,
                    })
                    .unwrap()
            })
            .collect();
        fixture
            .client
            .deferred_connection_events
            .try_extend(initial)
            .unwrap();

        let refill_budget = budget.clone();
        let first = fixture
            .client
            .replay_direct_live_events_inner_v1(move |client, consumed| {
                client
                    .deferred_connection_events
                    .try_extend(vec![refill_budget
                        .try_wrap(ConnectionEvent::TypingEvent {
                            conversation_id: format!("arrived-after-expiry-{consumed}"),
                            identity_key: vec![0xC7; 32],
                            started: false,
                        })
                        .unwrap()])
                    .unwrap();
            })
            .await
            .unwrap();
        assert_eq!(first.consumed, DIRECT_LIVE_REPLAY_MAX_BATCH_V1);
        assert_eq!(
            fixture
                .client
                .direct_ack_expiry_grace_remaining
                .get(&queued.sequence)
                .copied(),
            Some(1)
        );

        let error = fixture
            .client
            .replay_direct_live_events_inner_v1(|client, consumed| {
                client
                    .deferred_connection_events
                    .try_extend(vec![budget
                        .try_wrap(ConnectionEvent::TypingEvent {
                            conversation_id: format!("second-refill-{consumed}"),
                            identity_key: vec![0xD8; 32],
                            started: false,
                        })
                        .unwrap()])
                    .unwrap();
            })
            .await
            .unwrap_err();
        assert_eq!(error.stop, DirectLiveReplayStopV1::AckDeadline);
        assert_eq!(error.report.consumed, 1);
        assert!(fixture.client.connection.is_none());
        assert!(fixture.client.pending_outgoing_messages.is_empty());
    }

    #[tokio::test]
    async fn direct_ack_correlation_mismatch_is_epoch_invalid_not_storage_uncertain() {
        let mut fixture = DirectOutboxClientFixture::new();
        let queued = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "mismatch remains durable")
            .await
            .unwrap();
        let wire = fixture.outbound.recv().await.unwrap();
        let (_, send) = DirectOutboxClientFixture::decode_send(&wire);
        let scope = fixture.client.current_direct_outbox_scope_v1().unwrap();
        let budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        fixture
            .client
            .deferred_connection_events
            .try_extend(vec![budget
                .try_wrap(ConnectionEvent::MessageAcked {
                    message_id: uuid::Uuid::new_v4().hyphenated().to_string(),
                    server_timestamp: 1_700_000_001_236_000_000,
                    ref_seq: queued.sequence + 1,
                    client_message_id: Some(send.client_message_id),
                    local_message_id: None,
                    mutation: None,
                    sender_key: None,
                })
                .unwrap()])
            .unwrap();

        let detail = fixture.client.poll_event().await.unwrap_err();
        assert!(detail.contains("sequence does not match"));
        assert_eq!(
            fixture.client.direct_live_stop,
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );
        assert!(!fixture.client.direct_live_storage_uncertain);
        assert!(fixture.client.db().is_some());
        assert!(fixture.client.identity.is_some());
        assert!(fixture.client.connection.is_none());
        assert!(fixture.client.pending_outgoing_messages.is_empty());
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&scope)
                .unwrap(),
            1
        );
        assert_eq!(
            fixture
                .client
                .replay_direct_live_events_v1()
                .await
                .unwrap_err()
                .stop,
            DirectLiveReplayStopV1::EpochInvalid
        );
    }

    #[tokio::test]
    async fn sub_millisecond_direct_ack_is_epoch_invalid_before_sqlcipher_mutation() {
        let mut fixture = DirectOutboxClientFixture::new();
        let queued = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "timestamp remains pending")
            .await
            .unwrap();
        let (_, send) =
            DirectOutboxClientFixture::decode_send(&fixture.outbound.recv().await.unwrap());
        let scope = fixture.client.current_direct_outbox_scope_v1().unwrap();
        let budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        fixture
            .client
            .deferred_connection_events
            .try_extend(vec![budget
                .try_wrap(ConnectionEvent::MessageAcked {
                    message_id: uuid::Uuid::from_u128(0x7400_0000_0000_0000_0000_0000_0000_00d1)
                        .to_string(),
                    server_timestamp: 1,
                    ref_seq: queued.sequence,
                    client_message_id: Some(send.client_message_id),
                    local_message_id: None,
                    mutation: None,
                    sender_key: None,
                })
                .unwrap()])
            .unwrap();

        let detail = fixture.client.poll_event().await.unwrap_err();
        assert!(detail.contains("durable millisecond contract"));
        assert_eq!(
            fixture.client.direct_live_stop,
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );
        assert!(!fixture.client.direct_live_storage_uncertain);
        assert!(fixture.client.db().is_some());
        assert!(fixture.client.identity.is_some());
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&scope)
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn chat_shaped_ack_must_match_the_pending_mutation_target() {
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let baseline = fixture.peers[peer].next_event("mutation target remains unchanged");
        let message_id = match &baseline {
            ConnectionEvent::MessageReceived { message_id, .. } => message_id.clone(),
            _ => unreachable!(),
        };
        fixture.enqueue(vec![baseline]);
        fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap();
        let sequence = 0xD2;
        fixture.receiver.pending_mutations.insert(
            sequence,
            ConfirmedMutation::Edit {
                message_id: message_id.clone(),
                conversation_id: fixture.peers[peer].conversation_id.clone(),
                new_text: "must not be selected by another message id".to_string(),
            },
        );
        fixture.enqueue(vec![ConnectionEvent::MessageAcked {
            message_id: uuid::Uuid::from_u128(0x7400_0000_0000_0000_0000_0000_0000_00d2)
                .to_string(),
            server_timestamp: 1_700_000_001_252_000_000,
            ref_seq: sequence,
            client_message_id: None,
            local_message_id: None,
            mutation: None,
            sender_key: None,
        }]);

        let detail = fixture.receiver.poll_event().await.unwrap_err();
        assert!(detail.contains("mutation ACK message id does not match"));
        assert_eq!(
            fixture.receiver.direct_live_stop,
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );
        assert!(!fixture.receiver.direct_live_storage_uncertain);
        let persisted = fixture
            .receiver
            .db()
            .unwrap()
            .get_messages(&fixture.peers[peer].conversation_id, 10)
            .unwrap();
        assert!(persisted.iter().any(|message| {
            message.id == message_id && message.plaintext == "mutation target remains unchanged"
        }));
    }

    #[tokio::test]
    async fn exact_chat_shaped_mutation_ack_commits_the_pending_edit() {
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let baseline = fixture.peers[peer].next_event("positive mutation target");
        let message_id = match &baseline {
            ConnectionEvent::MessageReceived { message_id, .. } => message_id.clone(),
            _ => unreachable!(),
        };
        fixture.enqueue(vec![baseline]);
        fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap();
        let sequence = 0xD4;
        fixture.receiver.pending_mutations.insert(
            sequence,
            ConfirmedMutation::Edit {
                message_id: message_id.clone(),
                conversation_id: fixture.peers[peer].conversation_id.clone(),
                new_text: "exact mutation ACK committed".to_string(),
            },
        );
        fixture.enqueue(vec![ConnectionEvent::MessageAcked {
            message_id: message_id.clone(),
            server_timestamp: 1_700_000_001_253_000_000,
            ref_seq: sequence,
            client_message_id: None,
            local_message_id: None,
            mutation: None,
            sender_key: None,
        }]);

        assert!(matches!(
            fixture.receiver.poll_event().await.unwrap(),
            Some(ConnectionEvent::MessageAcked {
                mutation: Some(ConfirmedMutation::Edit { .. }),
                ..
            })
        ));
        assert!(fixture.receiver.pending_mutations.is_empty());
        assert_eq!(fixture.receiver.direct_live_stop, None);
        let persisted = fixture
            .receiver
            .db()
            .unwrap()
            .get_messages(&fixture.peers[peer].conversation_id, 10)
            .unwrap();
        assert!(persisted.iter().any(|message| {
            message.id == message_id && message.plaintext == "exact mutation ACK committed"
        }));
    }

    #[tokio::test]
    async fn out_of_contract_correlated_error_is_epoch_invalid_before_rejection() {
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let baseline = fixture.peers[peer].next_event("error target remains unchanged");
        let message_id = match &baseline {
            ConnectionEvent::MessageReceived { message_id, .. } => message_id.clone(),
            _ => unreachable!(),
        };
        fixture.enqueue(vec![baseline]);
        fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap();
        let sequence = 0xD3;
        fixture.receiver.pending_mutations.insert(
            sequence,
            ConfirmedMutation::Delete {
                message_id: message_id.clone(),
                conversation_id: fixture.peers[peer].conversation_id.clone(),
            },
        );
        fixture.enqueue(vec![ConnectionEvent::Error {
            code: 600,
            message: "out-of-contract status".to_string(),
            ref_seq: Some(sequence),
            client_message_id: None,
            reason: Some("unknown_status".to_string()),
            local_message_id: None,
            conversation_id: None,
            stale_roster_context: false,
        }]);

        let detail = fixture.receiver.poll_event().await.unwrap_err();
        assert!(detail.contains("outside the HTTP error contract"));
        assert_eq!(
            fixture.receiver.direct_live_stop,
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );
        assert!(!fixture.receiver.direct_live_storage_uncertain);
        assert!(fixture
            .receiver
            .db()
            .unwrap()
            .get_messages(&fixture.peers[peer].conversation_id, 10)
            .unwrap()
            .iter()
            .any(|message| message.id == message_id));
    }

    #[tokio::test]
    async fn repeated_direct_ack_cannot_confirm_a_new_mutation_by_stale_sequence() {
        let mut fixture = DirectOutboxClientFixture::new();
        let queued = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "original durable Direct text")
            .await
            .unwrap();
        let wire = fixture.outbound.recv().await.unwrap();
        let (_, send) = DirectOutboxClientFixture::decode_send(&wire);
        let server_message_id =
            uuid::Uuid::from_u128(0x7400_0000_0000_0000_0000_0000_0000_00a1).to_string();
        let server_timestamp = 1_700_000_001_240_000_000u64;
        let budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        fixture
            .client
            .deferred_connection_events
            .try_extend(vec![budget
                .try_wrap(ConnectionEvent::MessageAcked {
                    message_id: server_message_id.clone(),
                    server_timestamp,
                    ref_seq: queued.sequence,
                    client_message_id: Some(send.client_message_id.clone()),
                    local_message_id: None,
                    mutation: None,
                    sender_key: None,
                })
                .unwrap()])
            .unwrap();
        assert!(matches!(
            fixture.client.poll_event().await.unwrap(),
            Some(ConnectionEvent::MessageAcked { .. })
        ));

        let mutation_sequence = queued.sequence.checked_add(0x100).unwrap();
        fixture.client.pending_mutations.insert(
            mutation_sequence,
            ConfirmedMutation::Edit {
                message_id: server_message_id.clone(),
                conversation_id: fixture.conversation_id.clone(),
                new_text: "stale ACK must not persist this edit".to_string(),
            },
        );
        fixture
            .client
            .deferred_connection_events
            .try_extend(vec![budget
                .try_wrap(ConnectionEvent::MessageAcked {
                    message_id: server_message_id.clone(),
                    server_timestamp,
                    ref_seq: mutation_sequence,
                    client_message_id: Some(send.client_message_id),
                    local_message_id: None,
                    mutation: None,
                    sender_key: None,
                })
                .unwrap()])
            .unwrap();

        let detail = fixture.client.poll_event().await.unwrap_err();
        assert!(detail.contains("collides with a non-message live correlation"));
        assert_eq!(
            fixture.client.direct_live_stop,
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );
        assert!(!fixture.client.direct_live_storage_uncertain);
        let persisted = fixture
            .client
            .db()
            .unwrap()
            .get_messages(&fixture.conversation_id, 10)
            .unwrap();
        assert!(persisted.iter().any(|message| {
            message.id == server_message_id && message.plaintext == "original durable Direct text"
        }));
    }

    #[tokio::test]
    async fn repeated_direct_error_cannot_alias_a_new_command_sequence() {
        let mut fixture = DirectOutboxClientFixture::new();
        let queued = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "definitely rejected Direct text")
            .await
            .unwrap();
        let wire = fixture.outbound.recv().await.unwrap();
        let (_, send) = DirectOutboxClientFixture::decode_send(&wire);
        let budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        let rejection = || ConnectionEvent::Error {
            code: 400,
            message: "invalid Direct payload".to_string(),
            ref_seq: Some(queued.sequence),
            client_message_id: Some(send.client_message_id.clone()),
            reason: Some("invalid_message".to_string()),
            local_message_id: None,
            conversation_id: None,
            stale_roster_context: false,
        };
        fixture
            .client
            .deferred_connection_events
            .try_extend(vec![budget.try_wrap(rejection()).unwrap()])
            .unwrap();
        assert!(matches!(
            fixture.client.poll_event().await.unwrap(),
            Some(ConnectionEvent::Error { .. })
        ));

        let mutation_sequence = queued.sequence.checked_add(0x200).unwrap();
        fixture.client.pending_mutations.insert(
            mutation_sequence,
            ConfirmedMutation::Edit {
                message_id: send.client_message_id.clone(),
                conversation_id: fixture.conversation_id.clone(),
                new_text: "stale error must not select this edit".to_string(),
            },
        );
        let mut repeated = rejection();
        let ConnectionEvent::Error {
            ref mut ref_seq, ..
        } = repeated
        else {
            unreachable!()
        };
        *ref_seq = Some(mutation_sequence);
        fixture
            .client
            .deferred_connection_events
            .try_extend(vec![budget.try_wrap(repeated).unwrap()])
            .unwrap();

        let detail = fixture.client.poll_event().await.unwrap_err();
        assert!(detail.contains("collides with a non-message live correlation"));
        assert_eq!(
            fixture.client.direct_live_stop,
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );
        assert!(!fixture.client.direct_live_storage_uncertain);
        let persisted = fixture
            .client
            .db()
            .unwrap()
            .get_messages(&fixture.conversation_id, 10)
            .unwrap();
        assert!(persisted.iter().any(|message| {
            message.id == send.client_message_id
                && message.plaintext == "definitely rejected Direct text"
                && message.status == veil_store::models::MessageStatus::Failed
        }));
    }

    #[tokio::test]
    async fn unknown_repeated_direct_ack_is_epoch_invalid_not_storage_uncertain() {
        let mut fixture = DirectOutboxClientFixture::new();
        let queued = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "unrelated durable intent")
            .await
            .unwrap();
        fixture.outbound.recv().await.unwrap();
        let scope = fixture.client.current_direct_outbox_scope_v1().unwrap();
        let budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        fixture
            .client
            .deferred_connection_events
            .try_extend(vec![budget
                .try_wrap(ConnectionEvent::MessageAcked {
                    message_id: uuid::Uuid::from_u128(0x7400_0000_0000_0000_0000_0000_0000_00b1)
                        .to_string(),
                    server_timestamp: 1_700_000_001_241_000_000,
                    ref_seq: queued.sequence.checked_add(0x300).unwrap(),
                    client_message_id: Some(
                        uuid::Uuid::from_u128(0x7400_0000_0000_0000_0000_0000_0000_00b2)
                            .to_string(),
                    ),
                    local_message_id: None,
                    mutation: None,
                    sender_key: None,
                })
                .unwrap()])
            .unwrap();

        let detail = fixture.client.poll_event().await.unwrap_err();
        assert!(detail.contains("conflicts with its durable receipt"));
        assert_eq!(
            fixture.client.direct_live_stop,
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );
        assert!(!fixture.client.direct_live_storage_uncertain);
        assert!(fixture.client.db().is_some());
        assert!(fixture.client.identity.is_some());
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&scope)
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn unknown_repeated_direct_error_is_epoch_invalid_not_storage_uncertain() {
        let mut fixture = DirectOutboxClientFixture::new();
        let queued = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "second unrelated durable intent")
            .await
            .unwrap();
        fixture.outbound.recv().await.unwrap();
        let scope = fixture.client.current_direct_outbox_scope_v1().unwrap();
        let budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        fixture
            .client
            .deferred_connection_events
            .try_extend(vec![budget
                .try_wrap(ConnectionEvent::Error {
                    code: 400,
                    message: "unknown rejection receipt".to_string(),
                    ref_seq: Some(queued.sequence.checked_add(0x400).unwrap()),
                    client_message_id: Some(
                        uuid::Uuid::from_u128(0x7400_0000_0000_0000_0000_0000_0000_00b3)
                            .to_string(),
                    ),
                    reason: Some("invalid_message".to_string()),
                    local_message_id: None,
                    conversation_id: None,
                    stale_roster_context: false,
                })
                .unwrap()])
            .unwrap();

        let detail = fixture.client.poll_event().await.unwrap_err();
        assert!(detail.contains("conflicts with its durable receipt"));
        assert_eq!(
            fixture.client.direct_live_stop,
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );
        assert!(!fixture.client.direct_live_storage_uncertain);
        assert!(fixture.client.db().is_some());
        assert!(fixture.client.identity.is_some());
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&scope)
                .unwrap(),
            1
        );
    }

    #[test]
    fn storage_uncertainty_dominates_transport_and_protocol_stops() {
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        client.record_direct_live_stop_v1(DirectLiveReplayStopV1::RetryableTransport);
        client.record_direct_live_stop_v1(DirectLiveReplayStopV1::EpochInvalid);
        client.revoke_after_storage_uncertain_v1();
        client.record_direct_live_stop_v1(DirectLiveReplayStopV1::RetryableTransport);
        assert_eq!(
            client.current_direct_live_stop_v1(),
            Some(DirectLiveReplayStopV1::StorageUncertain)
        );
        assert!(client.direct_live_storage_uncertain);
    }

    #[test]
    fn correlated_send_retry_allowlist_has_finite_status_boundaries() {
        for (code, reason, expected) in [
            (499, Some("client_error"), false),
            (500, Some("internal_error"), true),
            (599, Some("server_error"), true),
            (600, Some("unknown"), false),
            (u32::MAX, Some("unknown"), false),
            (429, Some("rate_limited"), true),
            (401, Some("not_authenticated"), true),
            (401, Some("other"), false),
        ] {
            assert_eq!(
                is_retryable_correlated_send_error_v1(code, reason),
                expected,
                "unexpected retry classification for code {code}"
            );
        }
    }

    #[tokio::test]
    async fn direct_enqueue_queue_errors_preserve_typed_retry_policy() {
        let mut timeout = DirectOutboxClientFixture::new();
        assert_eq!(
            timeout
                .client
                .classify_direct_enqueue_result_v1(&Err(ConnectionSendErrorV1::QueueTimeout,)),
            Some(DirectLiveReplayStopV1::RetryableTransport)
        );

        let mut rejected = DirectOutboxClientFixture::new();
        assert_eq!(
            rejected.client.classify_direct_enqueue_result_v1(&Err(
                ConnectionSendErrorV1::Rejected("invalid exact envelope".to_string()),
            )),
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );

        let mut untyped_closed = DirectOutboxClientFixture::new();
        assert_eq!(
            untyped_closed
                .client
                .classify_direct_enqueue_result_v1(&Err(ConnectionSendErrorV1::QueueClosed)),
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );

        let mut source_typed_closed = DirectOutboxClientFixture::new();
        source_typed_closed
            .client
            .connection
            .as_ref()
            .unwrap()
            .test_only_report_websocket_error_v1(tokio_tungstenite::tungstenite::Error::Protocol(
                tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
            ));
        assert_eq!(
            source_typed_closed
                .client
                .classify_direct_enqueue_result_v1(&Err(ConnectionSendErrorV1::QueueClosed)),
            Some(DirectLiveReplayStopV1::RetryableTransport)
        );

        let mut protocol_closed = DirectOutboxClientFixture::new();
        assert!(protocol_closed
            .client
            .test_only_report_epoch_invalid_transport_v1());
        assert_eq!(
            protocol_closed
                .client
                .classify_direct_enqueue_result_v1(&Err(ConnectionSendErrorV1::QueueClosed)),
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );
    }

    #[tokio::test]
    async fn ack_deadline_delivery_reconciliation_failure_escalates_to_storage_uncertain() {
        let mut fixture = DirectOutboxClientFixture::new();
        fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "durable deadline intent")
            .await
            .unwrap();
        fixture.outbound.recv().await.unwrap();

        // Add one legacy correlation so transport-loss reconciliation must
        // execute a fallible SQLCipher status transition in the same batch.
        let legacy_id = uuid::Uuid::new_v4().to_string();
        let self_identity_key = fixture.client.identity_key().unwrap();
        fixture
            .client
            .db()
            .unwrap()
            .insert_outgoing_pending_message(
                &legacy_id,
                &fixture.conversation_id,
                &self_identity_key,
                "legacy correlation",
                None,
            )
            .unwrap();
        fixture.client.pending_outgoing_messages.insert(
            0xA11,
            PendingOutgoingMessage {
                local_message_id: legacy_id,
                conversation_id: fixture.conversation_id.clone(),
                sender_identity_key: self_identity_key,
                plaintext: "legacy correlation".to_string(),
                durable_direct_outbox: false,
                direct_ack_deadline: None,
            },
        );
        fixture
            .client
            .db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER reject_deadline_delivery_state
                 BEFORE UPDATE OF status ON messages
                 BEGIN SELECT RAISE(FAIL, 'forced ACK deadline reconciliation failure'); END;",
            )
            .unwrap();

        assert_eq!(fixture.client.test_only_expire_direct_ack_deadlines_v1(), 1);
        let error = fixture
            .client
            .replay_direct_live_events_v1()
            .await
            .unwrap_err();
        assert_eq!(error.stop, DirectLiveReplayStopV1::StorageUncertain);
        assert!(fixture.client.direct_live_storage_uncertain);
        assert_eq!(
            fixture.client.direct_live_stop,
            Some(DirectLiveReplayStopV1::StorageUncertain)
        );
        assert!(fixture.client.connection.is_none());
        assert!(fixture.client.db().is_none());
        assert!(fixture.client.identity.is_none());
        assert!(fixture.client.pending_outgoing_messages.is_empty());
    }

    #[tokio::test]
    async fn direct_outbox_error_keeps_retryable_bytes_and_compacts_definite_rejection() {
        let mut retryable = DirectOutboxClientFixture::new();
        let queued = retryable
            .client
            .enqueue_direct_text_v1(&retryable.conversation_id, "retry after reconnect")
            .await
            .unwrap();
        let wire = retryable.outbound.recv().await.unwrap();
        let (_, send) = DirectOutboxClientFixture::decode_send(&wire);
        for (code, reason) in [
            (500, "internal_error"),
            (429, "rate_limited"),
            (401, "not_authenticated"),
        ] {
            assert_eq!(
                retryable
                    .client
                    .reconcile_outgoing_error_v1(
                        queued.sequence,
                        code,
                        Some(&send.client_message_id),
                        Some(reason),
                    )
                    .unwrap()
                    .as_deref(),
                Some(send.client_message_id.as_str())
            );
        }
        assert!(retryable
            .client
            .pending_outgoing_messages
            .contains_key(&queued.sequence));
        let retry_scope = retryable.client.current_direct_outbox_scope_v1().unwrap();
        assert_eq!(
            retryable
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&retry_scope)
                .unwrap(),
            1
        );
        let budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        let retryable_event = budget
            .try_wrap(ConnectionEvent::Error {
                code: 429,
                message: "retry later".to_string(),
                ref_seq: Some(queued.sequence),
                client_message_id: Some(send.client_message_id.clone()),
                reason: Some("rate_limited".to_string()),
                local_message_id: None,
                conversation_id: None,
                stale_roster_context: false,
            })
            .unwrap();
        retryable
            .client
            .deferred_connection_events
            .try_extend(vec![retryable_event])
            .unwrap();
        assert!(matches!(
            retryable.client.poll_event().await.unwrap(),
            Some(ConnectionEvent::Error {
                local_message_id: Some(ref local_message_id),
                ..
            }) if local_message_id == &send.client_message_id
        ));
        assert!(retryable.client.connection.is_none());
        assert!(retryable.client.authenticated_user_id.is_none());
        assert!(retryable.client.authenticated_server_origin.is_none());
        assert!(retryable.client.pending_outgoing_messages.is_empty());
        assert_eq!(
            retryable.client.direct_live_stop,
            Some(DirectLiveReplayStopV1::RetryableTransport)
        );
        assert_eq!(
            retryable
                .client
                .replay_direct_live_events_v1()
                .await
                .unwrap_err()
                .stop,
            DirectLiveReplayStopV1::RetryableTransport
        );
        assert_eq!(
            retryable
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&retry_scope)
                .unwrap(),
            1
        );
        assert_eq!(
            retryable
                .client
                .db()
                .unwrap()
                .get_messages(&retryable.conversation_id, 10)
                .unwrap()[0]
                .status,
            veil_store::models::MessageStatus::Sending
        );

        let mut rejected = DirectOutboxClientFixture::new();
        let queued = rejected
            .client
            .enqueue_direct_text_v1(&rejected.conversation_id, "definite rejection")
            .await
            .unwrap();
        let wire = rejected.outbound.recv().await.unwrap();
        let (_, send) = DirectOutboxClientFixture::decode_send(&wire);
        let reject_scope = rejected.client.current_direct_outbox_scope_v1().unwrap();
        assert!(rejected
            .client
            .reconcile_outgoing_error_v1(
                queued.sequence + 1,
                400,
                Some(&send.client_message_id),
                Some("invalid_message"),
            )
            .unwrap_err()
            .contains("sequence does not match"));
        assert_eq!(
            rejected
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&reject_scope)
                .unwrap(),
            1
        );
        assert_eq!(
            rejected
                .client
                .reconcile_outgoing_error_v1(
                    queued.sequence,
                    400,
                    Some(&send.client_message_id),
                    Some("invalid_message"),
                )
                .unwrap()
                .as_deref(),
            Some(send.client_message_id.as_str())
        );
        assert_eq!(
            rejected
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&reject_scope)
                .unwrap(),
            0
        );
        assert_eq!(
            rejected
                .client
                .db()
                .unwrap()
                .get_messages(&rejected.conversation_id, 10)
                .unwrap()[0]
                .status,
            veil_store::models::MessageStatus::Failed
        );
        let compact: (i64, bool, String) = rejected
            .client
            .db()
            .unwrap()
            .conn()
            .query_row(
                "SELECT state, exact_send_message_payload IS NULL, rejection_reason
                 FROM direct_message_outbox_v1 WHERE client_message_id = ?1",
                rusqlite::params![send.client_message_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(compact, (2, true, "invalid_message".to_string()));
    }

    #[tokio::test]
    async fn direct_outbox_owns_commit_when_transport_is_closed_and_requires_live_correlation() {
        let mut fixture = DirectOutboxClientFixture::new();
        fixture.outbound.close();
        let queued = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "committed before wire")
            .await
            .unwrap();
        assert!(!queued.transport_enqueued);
        assert_eq!(
            queued.transport_stop,
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );
        assert!(queued.sequence > 0);
        assert!(!fixture.client.is_connected());
        assert!(fixture.client.pending_outgoing_messages.is_empty());
        let scope = fixture.client.current_direct_outbox_scope_v1().unwrap();
        let pending = fixture
            .client
            .db()
            .unwrap()
            .load_pending_direct_message_outbox_v1(&scope, 10)
            .unwrap();
        assert_eq!(pending.len(), 1);
        let send =
            proto::SendMessage::decode(pending[0].exact_send_message_payload.as_slice()).unwrap();
        let server_message_id =
            uuid::Uuid::from_u128(0x7500_0000_0000_0000_0000_0000_0000_0005).to_string();
        let server_timestamp = 1_700_000_000_456_000_000u64;
        assert!(fixture
            .client
            .finalize_outgoing_message(
                queued.sequence,
                Some(&send.client_message_id),
                &server_message_id,
                server_timestamp,
            )
            .unwrap_err()
            .contains("current transport sequence correlation"));
        assert!(fixture
            .client
            .reconcile_outgoing_error_v1(
                queued.sequence,
                400,
                Some(&send.client_message_id),
                Some("invalid_message"),
            )
            .unwrap_err()
            .contains("current transport sequence correlation"));
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .count_pending_direct_message_outbox_v1(&scope)
                .unwrap(),
            1
        );
        assert_eq!(
            fixture
                .client
                .db()
                .unwrap()
                .get_messages(&fixture.conversation_id, 10)
                .unwrap()[0]
                .status,
            veil_store::models::MessageStatus::Sending
        );
        assert!(fixture
            .client
            .ratchet_sessions
            .get(&fixture.peer_identity_key)
            .unwrap()
            .matches_serialized_v1(
                &fixture
                    .client
                    .db()
                    .unwrap()
                    .load_ratchet_session_with_revision_v1(&fixture.peer_identity_key)
                    .unwrap()
                    .unwrap()
                    .session_data
            )
            .unwrap());
        // Model a newly authenticated socket epoch. Production connect resets
        // the typed stop only after its full pre-install reconciliation.
        fixture.client.direct_live_stop = None;
        fixture.outbound = fixture.client.test_only_install_queued_connection();
        let replay = fixture
            .client
            .replay_direct_outbox_v1(None, 10)
            .await
            .unwrap();
        assert_eq!(replay.enqueued, 1);
        let replay_wire = fixture.outbound.recv().await.unwrap();
        let (_, replay_send) = DirectOutboxClientFixture::decode_send(&replay_wire);
        assert_eq!(
            replay_send.encode_to_vec(),
            pending[0].exact_send_message_payload
        );
    }

    #[tokio::test]
    async fn direct_outbox_survives_real_sqlcipher_process_reopen_before_first_wire() {
        let mnemonic = generate_mnemonic().to_string();
        let path = std::env::temp_dir().join(format!(
            "veil-direct-outbox-reopen-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db_key = Zeroizing::new(kdf::derive_db_key(&mnemonic).unwrap());
        let identity = IdentityKeyPair::from_mnemonic(&mnemonic).unwrap();
        let db = VeilDb::open(&path, &db_key).unwrap();
        let mut fixture = DirectOutboxClientFixture::new_with_identity_and_db(identity, db);
        fixture.outbound.close();
        let queued = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "survive real reopen")
            .await
            .unwrap();
        assert!(!queued.transport_enqueued);
        let scope = fixture.client.current_direct_outbox_scope_v1().unwrap();
        let pending = fixture
            .client
            .db()
            .unwrap()
            .load_pending_direct_message_outbox_v1(&scope, 1)
            .unwrap();
        let exact_payload = pending[0].exact_send_message_payload.clone();
        let client_message_id = pending[0].client_message_id.clone();
        let conversation_id = fixture.conversation_id.clone();
        let peer_identity_key = fixture.peer_identity_key;
        let peer_signing_key = fixture.peer_signing_key;
        let self_user_id = fixture.self_user_id.clone();
        let peer_user_id = fixture.peer_user_id.clone();
        drop(pending);
        drop(fixture);

        let mut restored = VeilClient::new();
        restored.init_with_mnemonic(&mnemonic, &path).unwrap();
        restored
            .test_only_restore_authenticated_user_from_durable_binding(
                DIRECT_LIVE_TEST_ORIGIN,
                &self_user_id,
            )
            .unwrap();
        let self_identity_key = restored.identity_key().unwrap();
        restored
            .remember_user_identity(&self_user_id, self_identity_key)
            .unwrap();
        restored
            .remember_user_identity(&peer_user_id, peer_identity_key)
            .unwrap();
        restored
            .pin_peer_signing_key(peer_identity_key, peer_signing_key)
            .unwrap();
        restored
            .replace_authorized_conversation_senders(
                &conversation_id,
                [self_identity_key, peer_identity_key],
            )
            .unwrap();
        restored
            .bind_dm_conversation(&conversation_id, peer_identity_key)
            .unwrap();
        let mut outbound = restored.test_only_install_queued_connection();
        let replay = restored.replay_direct_outbox_v1(None, 10).await.unwrap();
        assert_eq!(replay.enqueued, 1);
        assert_eq!(replay.pending_total, 1);
        let wire = outbound.recv().await.unwrap();
        let (_, send) = DirectOutboxClientFixture::decode_send(&wire);
        assert_eq!(send.client_message_id, client_message_id);
        assert_eq!(send.encode_to_vec(), exact_payload);
        assert_eq!(
            restored
                .db()
                .unwrap()
                .get_messages(&conversation_id, 10)
                .unwrap()[0]
                .status,
            veil_store::models::MessageStatus::Sending
        );

        drop(outbound);
        drop(restored);
        for candidate in [
            path.clone(),
            std::path::PathBuf::from(format!("{}-wal", path.display())),
            std::path::PathBuf::from(format!("{}-shm", path.display())),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }

    #[tokio::test]
    async fn direct_outbox_cursor_is_fifo_deduplicated_and_stops_before_blocked_row() {
        let mut fixture = DirectOutboxClientFixture::new();
        let first = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "fifo first")
            .await
            .unwrap();
        let first_wire = fixture.outbound.recv().await.unwrap();
        let (_, first_send) = DirectOutboxClientFixture::decode_send(&first_wire);
        let second = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "fifo second")
            .await
            .unwrap();
        let second_wire = fixture.outbound.recv().await.unwrap();
        let (_, second_send) = DirectOutboxClientFixture::decode_send(&second_wire);
        assert_ne!(first.sequence, second.sequence);
        assert_ne!(first_send.client_message_id, second_send.client_message_id);

        let first_skip = fixture
            .client
            .replay_direct_outbox_v1(None, 1)
            .await
            .unwrap();
        assert_eq!(first_skip.visited, 1);
        assert_eq!(first_skip.enqueued, 0);
        assert!(!first_skip.reached_end);
        assert!(!first_skip.transport_blocked);
        assert!(fixture.outbound.try_recv().is_err());
        let first_cursor = first_skip.next_queue_order.unwrap();
        let second_skip = fixture
            .client
            .replay_direct_outbox_v1(Some(first_cursor), 1)
            .await
            .unwrap();
        assert_eq!(second_skip.visited, 1);
        assert_eq!(second_skip.enqueued, 0);
        let second_cursor = second_skip.next_queue_order.unwrap();
        assert!(second_cursor > first_cursor);
        assert!(fixture.outbound.try_recv().is_err());

        fixture.client.mark_all_pending_sequences_unknown().unwrap();
        fixture.outbound = fixture.client.test_only_install_queued_connection();
        let first_page = fixture
            .client
            .replay_direct_outbox_v1(None, 1)
            .await
            .unwrap();
        assert_eq!(first_page.enqueued, 1);
        assert_eq!(first_page.next_queue_order, Some(first_cursor));
        assert!(!first_page.reached_end);
        let wire = fixture.outbound.recv().await.unwrap();
        let (_, replayed_first) = DirectOutboxClientFixture::decode_send(&wire);
        assert_eq!(
            replayed_first.client_message_id,
            first_send.client_message_id
        );
        let second_page = fixture
            .client
            .replay_direct_outbox_v1(Some(first_cursor), 1)
            .await
            .unwrap();
        assert_eq!(second_page.enqueued, 1);
        assert_eq!(second_page.next_queue_order, Some(second_cursor));
        assert!(!second_page.reached_end);
        let wire = fixture.outbound.recv().await.unwrap();
        let (_, replayed_second) = DirectOutboxClientFixture::decode_send(&wire);
        assert_eq!(
            replayed_second.client_message_id,
            second_send.client_message_id
        );
        let end = fixture
            .client
            .replay_direct_outbox_v1(Some(second_cursor), 1)
            .await
            .unwrap();
        assert_eq!(end.visited, 0);
        assert_eq!(end.enqueued, 0);
        assert_eq!(end.next_queue_order, Some(second_cursor));
        assert!(end.reached_end);

        fixture.client.mark_all_pending_sequences_unknown().unwrap();
        fixture.outbound = fixture.client.test_only_install_queued_connection();
        fixture.outbound.close();
        let error = fixture
            .client
            .replay_direct_outbox_v1(None, 1)
            .await
            .unwrap_err();
        assert!(matches!(error, DirectSendErrorV1::Rejected(_)));
        assert_eq!(
            fixture.client.direct_live_stop,
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );
    }

    #[tokio::test]
    async fn direct_outbox_capacity_is_a_definite_rejection_not_a_runtime_revoke() {
        let mut fixture = DirectOutboxClientFixture::new();
        let scope = fixture.client.current_direct_outbox_scope_v1().unwrap();
        let ratchet_before = Zeroizing::new(
            serde_json::to_vec(
                fixture
                    .client
                    .ratchet_sessions
                    .get(&fixture.peer_identity_key)
                    .unwrap(),
            )
            .unwrap(),
        );
        let peer_user_id =
            uuid::Uuid::from_u128(0x7700_0000_0000_0000_0000_0000_0000_0007).to_string();
        let tx = fixture
            .client
            .db()
            .unwrap()
            .conn()
            .unchecked_transaction()
            .unwrap();
        for index in 0..DIRECT_MESSAGE_OUTBOX_MAX_PENDING_V1 {
            let client_message_id =
                uuid::Uuid::from_u128(0x7800_0000_0000_0000_0000_0000_0000_0000 + index as u128)
                    .to_string();
            tx.execute(
                "INSERT INTO direct_message_outbox_v1
                   (canonical_server_origin, user_id, device_id, conversation_id,
                    peer_user_id, peer_identity_key, peer_signing_key,
                    client_message_id, local_message_id, request_digest,
                    exact_send_message_payload, ratchet_revision, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11, 0)",
                rusqlite::params![
                    &scope.canonical_server_origin,
                    &scope.user_id,
                    scope.device_id.as_slice(),
                    &fixture.conversation_id,
                    &peer_user_id,
                    [0x51u8; 32].as_slice(),
                    [0x52u8; 32].as_slice(),
                    &client_message_id,
                    [0x53u8; 32].as_slice(),
                    [0x01u8].as_slice(),
                    i64::try_from(index + 1).unwrap(),
                ],
            )
            .unwrap();
        }
        tx.commit().unwrap();

        let error = fixture
            .client
            .enqueue_direct_text_v1(&fixture.conversation_id, "must not advance ratchet")
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            DirectSendErrorV1::Rejected(ref detail) if detail.contains("outbox is full")
        ));
        assert!(!fixture.client.direct_live_storage_uncertain);
        assert!(fixture.client.connection.is_some());
        assert!(fixture.client.pending_outgoing_messages.is_empty());
        assert!(fixture
            .client
            .ratchet_sessions
            .get(&fixture.peer_identity_key)
            .unwrap()
            .matches_serialized_v1(&ratchet_before)
            .unwrap());
    }

    struct DirectLivePeerFixture {
        sender: VeilClient,
        sender_identity_key: [u8; 32],
        sender_user_id: String,
        receiver_identity_key: [u8; 32],
        receiver_device_id: [u8; 16],
        receiver_binding_version: u64,
        conversation_id: String,
        username: String,
        next_message: u128,
    }

    impl DirectLivePeerFixture {
        fn next_event(&mut self, text: &str) -> ConnectionEvent {
            let (ciphertext, header) = self
                .sender
                .encrypt_outgoing(&self.conversation_id, text)
                .unwrap();
            if header.first() == Some(&HEADER_INITIAL_V2) {
                self.sender
                    .test_only_confirm_peer_session_possession(&self.receiver_identity_key)
                    .unwrap();
            }
            let sender_binding = self
                .sender
                .device_identity
                .as_ref()
                .unwrap()
                .binding()
                .clone();
            let direct_session_id = self
                .sender
                .direct_v2_sessions
                .get(&self.receiver_identity_key)
                .unwrap()
                .session_id();
            self.next_message += 1;
            ConnectionEvent::MessageReceived {
                message_id: uuid::Uuid::from_u128(self.next_message).to_string(),
                conversation_id: self.conversation_id.clone(),
                sender_identity_key: self.sender_identity_key.to_vec(),
                sender_username: self.username.clone(),
                ciphertext,
                header,
                server_timestamp: 1_700_000_000_000_000_000
                    + (self.next_message as u64 & 0x0000_ffff_ffff_ffff),
                reply_to_id: None,
                msg_type: Some(proto::MessageType::Text as i32),
                ttl_seconds: None,
                sealed: Some(false),
                attachments: Vec::new(),
                security_context: Some(MessageSecurityContextV1::DirectV2(
                    DirectMessageSecurityContextV2 {
                        sender_user_id: self.sender_user_id.clone(),
                        sender_device_id: sender_binding.device_id,
                        sender_binding_version: sender_binding.version,
                        sender_device_identity_key: sender_binding.device_identity_key,
                        sender_device_signing_key: sender_binding.device_signing_key,
                        sender_device_capabilities: sender_binding.capabilities,
                        sender_device_binding_status: sender_binding.status,
                        sender_account_signature: sender_binding.account_signature,
                        target_device_id: self.receiver_device_id,
                        target_binding_version: self.receiver_binding_version,
                        direct_session_id,
                    },
                )),
            }
        }
    }

    struct DirectLiveReplayFixture {
        receiver: VeilClient,
        receiver_identity_key: [u8; 32],
        receiver_signing_key: [u8; 32],
        peers: Vec<DirectLivePeerFixture>,
    }

    impl DirectLiveReplayFixture {
        fn new() -> Self {
            Self::new_with_db(VeilDb::open_memory(&[0x91; 32]).unwrap())
        }

        fn new_with_db(db: VeilDb) -> Self {
            Self::new_with_identity_and_db(IdentityKeyPair::generate(), db)
        }

        fn new_with_identity_and_db(receiver_identity: IdentityKeyPair, db: VeilDb) -> Self {
            let receiver_identity_key = receiver_identity.x25519_public_bytes();
            let receiver_signing_key = receiver_identity.ed25519_public_bytes();
            let receiver_user_id =
                uuid::Uuid::from_u128(0x1000_0000_0000_0000_0000_0000_0000_0001).to_string();
            let receiver_device_id = [0x91; 16];
            let receiver_stored_device =
                DeviceIdentityV1::generate_stored(&receiver_identity, receiver_device_id).unwrap();
            db.create_device_identity_v1(&receiver_stored_device)
                .unwrap();
            let receiver_device =
                DeviceIdentityV1::from_stored(&receiver_identity, receiver_stored_device).unwrap();
            let mut receiver = VeilClient::from_identity(receiver_identity);
            receiver.device_id = receiver_device_id;
            receiver.device_identity = Some(receiver_device);
            db.bind_authenticated_self(
                DIRECT_LIVE_TEST_ORIGIN,
                &receiver_user_id,
                &receiver_identity_key,
                &receiver_signing_key,
            )
            .unwrap();
            let self_account = AccountSnapshot {
                locator: veil_store::models::ProfileLocator {
                    canonical_server_origin: DIRECT_LIVE_TEST_ORIGIN.to_string(),
                    user_id: receiver_user_id.clone(),
                    identity_key: receiver_identity_key,
                },
                signing_key: receiver_signing_key,
                username: Some("Receiver".to_string()),
                display_name: Some("Replay Receiver".to_string()),
                profile_version: Some(1),
                profile_origin: DIRECT_LIVE_TEST_ORIGIN.to_string(),
                source:
                    veil_store::models::AccountSnapshotSource::AuthenticatedConversationDirectory,
                observed_at: "2026-07-18T00:00:00Z".to_string(),
            };
            db.upsert_identity_directory(std::slice::from_ref(&self_account))
                .unwrap();
            receiver.db = Some(db);
            receiver.authenticated_user_id = Some(receiver_user_id.clone());
            receiver.authenticated_server_origin = Some(DIRECT_LIVE_TEST_ORIGIN.to_string());
            receiver
                .remember_user_identity(&receiver_user_id, receiver_identity_key)
                .unwrap();
            receiver
                .pin_peer_signing_key(receiver_identity_key, receiver_signing_key)
                .unwrap();
            Self {
                receiver,
                receiver_identity_key,
                receiver_signing_key,
                peers: Vec::new(),
            }
        }

        fn add_peer(&mut self) -> usize {
            let index = self.peers.len() as u128 + 1;
            let sender_identity = IdentityKeyPair::generate();
            let sender_identity_key = sender_identity.x25519_public_bytes();
            let sender_signing_key = sender_identity.ed25519_public_bytes();
            let sender_user_uuid =
                uuid::Uuid::from_u128(0x2000_0000_0000_0000_0000_0000_0000_0000 + index);
            let sender_user_id = sender_user_uuid.to_string();
            let conversation_id =
                uuid::Uuid::from_u128(0x3000_0000_0000_0000_0000_0000_0000_0000 + index)
                    .to_string();
            let username = format!("Sender{index}");
            let author = AccountSnapshot {
                locator: veil_store::models::ProfileLocator {
                    canonical_server_origin: DIRECT_LIVE_TEST_ORIGIN.to_string(),
                    user_id: sender_user_id.clone(),
                    identity_key: sender_identity_key,
                },
                signing_key: sender_signing_key,
                username: Some(username.clone()),
                display_name: Some(format!("Replay Sender {index}")),
                profile_version: Some(1),
                profile_origin: DIRECT_LIVE_TEST_ORIGIN.to_string(),
                source:
                    veil_store::models::AccountSnapshotSource::AuthenticatedConversationDirectory,
                observed_at: "2026-07-18T00:00:00Z".to_string(),
            };
            let db = self.receiver.db().unwrap();
            db.upsert_identity_directory(std::slice::from_ref(&author))
                .unwrap();
            db.upsert_directory_conversation(
                &conversation_id,
                0,
                DIRECT_LIVE_TEST_ORIGIN,
                Some(&username),
                Some(&sender_user_id),
                Some(&sender_identity_key),
                None,
                "2026-07-18T00:00:00Z",
            )
            .unwrap();
            self.receiver
                .remember_user_identity(&sender_user_id, sender_identity_key)
                .unwrap();
            self.receiver
                .pin_peer_signing_key(sender_identity_key, sender_signing_key)
                .unwrap();
            self.receiver
                .replace_authorized_conversation_senders(
                    &conversation_id,
                    [self.receiver_identity_key, sender_identity_key],
                )
                .unwrap();
            self.receiver
                .bind_dm_conversation(&conversation_id, sender_identity_key)
                .unwrap();

            let prekeys = self.receiver.generate_prekeys().unwrap();
            let (one_time_prekey, one_time_prekey_id) = prekeys.otk_publics[0];
            let sender_device_marker = u8::try_from(0xA0u128 + index).unwrap();
            let sender_device_id = [sender_device_marker; 16];
            let sender_stored_device =
                DeviceIdentityV1::generate_stored(&sender_identity, sender_device_id).unwrap();
            let sender_device =
                DeviceIdentityV1::from_stored(&sender_identity, sender_stored_device).unwrap();
            let mut sender = VeilClient::from_identity(sender_identity);
            sender.device_id = sender_device_id;
            sender.device_identity = Some(sender_device);
            sender.authenticated_user_id = Some(sender_user_uuid.to_string());
            sender.authenticated_server_origin = Some(DIRECT_LIVE_TEST_ORIGIN.to_string());
            sender
                .remember_user_identity(
                    self.receiver
                        .authenticated_user_id
                        .as_deref()
                        .expect("receiver is authenticated"),
                    self.receiver_identity_key,
                )
                .unwrap();
            sender
                .pin_peer_signing_key(self.receiver_identity_key, self.receiver_signing_key)
                .unwrap();
            sender
                .bind_dm_conversation(&conversation_id, self.receiver_identity_key)
                .unwrap();
            let receiver_binding = self
                .receiver
                .device_identity
                .as_ref()
                .unwrap()
                .binding()
                .clone();
            let direct_context = sender
                .direct_v2_initiator_context(
                    &conversation_id,
                    self.receiver.authenticated_user_id.as_deref().unwrap(),
                    self.receiver_identity_key,
                    self.receiver_signing_key,
                    DirectDeviceCoordinateV2 {
                        device_id: receiver_binding.device_id,
                        binding_version: receiver_binding.version,
                        capabilities: receiver_binding.capabilities,
                        status: receiver_binding.status,
                        identity_key: receiver_binding.device_identity_key,
                        signing_key: receiver_binding.device_signing_key,
                        account_signature: receiver_binding.account_signature,
                    },
                )
                .unwrap();
            sender
                .establish_session_classified_v2(
                    &self.receiver_identity_key,
                    &x3dh::PreKeyBundle {
                        identity_key: self.receiver_identity_key,
                        signing_key: self.receiver_signing_key,
                        signed_prekey: prekeys.spk_public,
                        signed_prekey_signature: prekeys.spk_signature,
                        signed_prekey_id: prekeys.spk_id,
                        one_time_prekey: Some(one_time_prekey),
                        one_time_prekey_id: Some(one_time_prekey_id),
                    },
                    direct_context,
                )
                .unwrap();
            self.peers.push(DirectLivePeerFixture {
                sender,
                sender_identity_key,
                sender_user_id,
                receiver_identity_key: self.receiver_identity_key,
                receiver_device_id: receiver_binding.device_id,
                receiver_binding_version: receiver_binding.version,
                conversation_id,
                username,
                next_message: 0x4000_0000_0000_0000_0000_0000_0000_0000 + (index << 32),
            });
            self.peers.len() - 1
        }

        fn enqueue(&mut self, events: Vec<ConnectionEvent>) {
            let budget = crate::connection::ConnectionEventBudgetV1::with_limits(
                LIVE_EVENT_QUEUE_CAPACITY,
                LIVE_EVENT_RETAINED_BYTES,
            );
            let events = events
                .into_iter()
                .map(|event| budget.try_wrap(event).unwrap())
                .collect();
            self.receiver
                .deferred_connection_events
                .try_extend(events)
                .unwrap();
        }
    }

    fn restore_single_peer_direct_replay_runtime(
        client: &mut VeilClient,
        receiver_identity_key: [u8; 32],
        peer_identity_key: [u8; 32],
        conversation_id: &str,
    ) {
        let receiver_user_id =
            uuid::Uuid::from_u128(0x1000_0000_0000_0000_0000_0000_0000_0001).to_string();
        let peer_user_id =
            uuid::Uuid::from_u128(0x2000_0000_0000_0000_0000_0000_0000_0001).to_string();
        client.authenticated_user_id = Some(receiver_user_id.clone());
        client.authenticated_server_origin = Some(DIRECT_LIVE_TEST_ORIGIN.to_string());
        client
            .remember_user_identity(&receiver_user_id, receiver_identity_key)
            .unwrap();
        client
            .remember_user_identity(&peer_user_id, peer_identity_key)
            .unwrap();
        client
            .replace_authorized_conversation_senders(
                conversation_id,
                [receiver_identity_key, peer_identity_key],
            )
            .unwrap();
        client
            .bind_dm_conversation(conversation_id, peer_identity_key)
            .unwrap();
    }

    fn runtime_ratchet_fingerprint_v1(
        client: &VeilClient,
        peer_identity_key: &[u8; 32],
    ) -> Option<[u8; 32]> {
        client
            .ratchet_sessions
            .get(peer_identity_key)
            .map(|ratchet| {
                let serialized = Zeroizing::new(serde_json::to_vec(ratchet).unwrap());
                Sha256::digest(serialized.as_slice()).into()
            })
    }

    fn durable_ratchet_fingerprint_v1(
        db: &VeilDb,
        peer_identity_key: &[u8; 32],
    ) -> Option<[u8; 32]> {
        db.load_ratchet_session(peer_identity_key)
            .unwrap()
            .map(|serialized| {
                let serialized = Zeroizing::new(serialized);
                Sha256::digest(serialized.as_slice()).into()
            })
    }

    fn runtime_otk_fingerprint_v1(client: &VeilClient) -> [u8; 32] {
        let mut ids: Vec<_> = client.otk_secrets.keys().copied().collect();
        ids.sort_unstable();
        let mut digest = Sha256::new();
        for id in ids {
            digest.update(id.to_be_bytes());
            digest.update(client.otk_secrets[&id]);
        }
        digest.finalize().into()
    }

    type DurablePreKeyPublicFingerprintV1 = (u8, u32, [u8; 32], Option<[u8; 64]>);

    fn durable_prekey_public_fingerprint_v1(db: &VeilDb) -> Vec<DurablePreKeyPublicFingerprintV1> {
        db.load_local_prekeys()
            .unwrap()
            .into_iter()
            .map(|prekey| {
                (
                    prekey.key_type,
                    prekey.protocol_key_id,
                    prekey.public_key,
                    prekey.signature,
                )
            })
            .collect()
    }

    fn direct_message_projection_fingerprint_v1(db: &VeilDb, conversation_id: &str) -> [u8; 32] {
        let serialized = Zeroizing::new(
            serde_json::to_vec(&db.get_messages(conversation_id, 100).unwrap()).unwrap(),
        );
        Sha256::digest(serialized.as_slice()).into()
    }

    #[test]
    fn websocket_url_maps_to_exact_canonical_authenticated_origin() {
        for (websocket, expected) in [
            (
                "wss://Chat.Example.Test/ws?transport=websocket",
                "https://chat.example.test:443",
            ),
            ("wss://example.test:8443/ws", "https://example.test:8443"),
            ("ws://127.0.0.1:8080/ws", "http://127.0.0.1:8080"),
            ("ws://[::1]:9090/ws", "http://[::1]:9090"),
            (
                "wss://bücher.example/ws",
                "https://xn--bcher-kva.example:443",
            ),
        ] {
            assert_eq!(
                canonical_server_origin_from_websocket_url_v1(websocket).unwrap(),
                expected
            );
        }

        for rejected in [
            "ws://example.test/ws",
            "wss://user@example.test/ws",
            "wss://example.test/ws#fragment",
            "https://example.test/ws",
            "wss:///",
        ] {
            assert!(
                canonical_server_origin_from_websocket_url_v1(rejected).is_err(),
                "unexpectedly accepted {rejected}"
            );
        }
    }

    #[tokio::test]
    async fn direct_live_replay_is_exactly_duplicate_safe_and_reports_quiescence() {
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let event = fixture.peers[peer].next_event("store exactly once");
        fixture.enqueue(vec![event.clone()]);

        assert_eq!(
            fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap(),
            DirectLiveReplayReportV1 {
                consumed: 1,
                stored: 1,
                visible_mutations: 1,
                quiescent: true,
                ..DirectLiveReplayReportV1::default()
            }
        );

        let ConnectionEvent::MessageReceived {
            message_id,
            conversation_id,
            sender_identity_key,
            ciphertext,
            header,
            server_timestamp,
            reply_to_id,
            ..
        } = &event
        else {
            unreachable!()
        };
        let sender_identity_key: [u8; 32] = sender_identity_key.as_slice().try_into().unwrap();
        let author = fixture
            .receiver
            .db()
            .unwrap()
            .resolve_account_by_conversation_sender(conversation_id, &sender_identity_key)
            .unwrap()
            .unwrap();
        let rest_timestamp_ms = i64::try_from(*server_timestamp / 1_000_000).unwrap();
        assert_eq!(
            fixture
                .receiver
                .receive_and_persist_direct_history_message(
                    message_id,
                    conversation_id,
                    &sender_identity_key,
                    &author,
                    MessageAuthorContext::DirectoryMemberAtObservation,
                    None,
                    header,
                    ciphertext,
                    Some(rest_timestamp_ms),
                    reply_to_id.as_deref(),
                    None,
                )
                .unwrap(),
            ReceiveMessageResult::Duplicate
        );
        assert_eq!(
            fixture
                .receiver
                .db()
                .unwrap()
                .get_messages(conversation_id, 10)
                .unwrap()[0]
                .server_timestamp,
            Some(rest_timestamp_ms)
        );

        fixture.enqueue(vec![event]);
        assert_eq!(
            fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap(),
            DirectLiveReplayReportV1 {
                consumed: 1,
                duplicates: 1,
                visible_mutations: 1,
                quiescent: true,
                ..DirectLiveReplayReportV1::default()
            }
        );
        assert_eq!(
            fixture
                .receiver
                .db()
                .unwrap()
                .get_messages(&fixture.peers[peer].conversation_id, 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn skipped_keys_survive_reopen_and_stale_receive_cannot_roll_back_ratchet() {
        let mnemonic = generate_mnemonic().to_string();
        let path = std::env::temp_dir().join(format!(
            "veil-skipped-key-reopen-{}.db",
            uuid::Uuid::new_v4()
        ));
        remove_test_database(&path);
        let db_key = Zeroizing::new(kdf::derive_db_key(&mnemonic).unwrap());
        let receiver_identity = IdentityKeyPair::from_mnemonic(&mnemonic).unwrap();
        let db = VeilDb::open(&path, &db_key).unwrap();
        let mut fixture = DirectLiveReplayFixture::new_with_identity_and_db(receiver_identity, db);
        let peer = fixture.add_peer();
        let receiver_identity_key = fixture.receiver_identity_key;
        let receiver_signing_key = fixture.receiver_signing_key;
        let peer_identity_key = fixture.peers[peer].sender_identity_key;
        let conversation_id = fixture.peers[peer].conversation_id.clone();

        let initial = fixture.peers[peer].next_event("initial");
        fixture.enqueue(vec![initial]);
        assert_eq!(
            fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap()
                .stored,
            1
        );

        let late_one = fixture.peers[peer].next_event("late-one");
        let late_two = fixture.peers[peer].next_event("late-two");
        let late_three = fixture.peers[peer].next_event("late-three");

        let mut stale = VeilClient::new();
        stale.init_with_mnemonic(&mnemonic, &path).unwrap();
        restore_single_peer_direct_replay_runtime(
            &mut stale,
            receiver_identity_key,
            peer_identity_key,
            &conversation_id,
        );
        let mut stale_general = VeilClient::new();
        stale_general.init_with_mnemonic(&mnemonic, &path).unwrap();
        restore_single_peer_direct_replay_runtime(
            &mut stale_general,
            receiver_identity_key,
            peer_identity_key,
            &conversation_id,
        );
        let stale_before = stale
            .ratchet_sessions
            .get(&peer_identity_key)
            .unwrap()
            .serialize()
            .unwrap();

        fixture.enqueue(vec![late_three]);
        assert_eq!(
            fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap()
                .stored,
            1
        );
        let durable_after_gap = fixture
            .receiver
            .db()
            .unwrap()
            .load_ratchet_session_with_revision_v1(&peer_identity_key)
            .unwrap()
            .unwrap();
        let gap_revision = durable_after_gap.revision;
        assert_eq!(durable_after_gap.revision, 1);
        assert!(!fixture
            .receiver
            .ratchet_sessions
            .get(&peer_identity_key)
            .unwrap()
            .matches_serialized_v1(&stale_before)
            .unwrap());

        // Emulate a valid historical writer which emitted the two skipped-key
        // members in the opposite order. Startup must validate and hydrate it,
        // never eagerly rewrite it or advance the revision merely to
        // canonicalize JSON.
        let serialized =
            Zeroizing::new(String::from_utf8(durable_after_gap.session_data.to_vec()).unwrap());
        let marker = "\"skipped_keys\":{";
        let body_start = serialized.find(marker).unwrap() + marker.len();
        let body_end = body_start + serialized[body_start..].find('}').unwrap();
        let mut skipped_entries: Vec<_> = serialized[body_start..body_end].split(',').collect();
        assert_eq!(skipped_entries.len(), 2);
        skipped_entries.reverse();
        let mut legacy_order = Zeroizing::new(String::with_capacity(serialized.len()));
        legacy_order.push_str(&serialized[..body_start]);
        for (index, entry) in skipped_entries.into_iter().enumerate() {
            if index != 0 {
                legacy_order.push(',');
            }
            legacy_order.push_str(entry);
        }
        legacy_order.push_str(&serialized[body_end..]);
        assert_ne!(
            legacy_order.as_bytes(),
            durable_after_gap.session_data.as_slice()
        );
        RatchetSession::deserialize(legacy_order.as_bytes()).unwrap();
        assert_eq!(
            fixture
                .receiver
                .db()
                .unwrap()
                .conn()
                .execute(
                    "UPDATE ratchet_sessions SET session_data = ?1
                     WHERE peer_identity_key = ?2 AND revision = ?3",
                    rusqlite::params![
                        legacy_order.as_bytes(),
                        peer_identity_key.as_slice(),
                        i64::try_from(durable_after_gap.revision).unwrap(),
                    ],
                )
                .unwrap(),
            1
        );

        let mut stale_fixture = DirectLiveReplayFixture {
            receiver: stale,
            receiver_identity_key,
            receiver_signing_key,
            peers: Vec::new(),
        };
        stale_fixture.enqueue(vec![late_one.clone()]);
        let stale_error = stale_fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap_err();
        assert_eq!(stale_error.stop, DirectLiveReplayStopV1::StorageUncertain);
        assert!(stale_fixture.receiver.direct_live_storage_uncertain);
        assert!(stale_fixture.receiver.db().is_none());

        let ConnectionEvent::MessageReceived {
            message_id,
            conversation_id: late_two_conversation,
            sender_identity_key,
            ciphertext,
            header,
            reply_to_id,
            ..
        } = &late_two
        else {
            unreachable!();
        };
        let sender_identity_key: [u8; 32] = sender_identity_key.as_slice().try_into().unwrap();
        assert!(stale_general
            .receive_and_persist_message(
                message_id,
                late_two_conversation,
                &sender_identity_key,
                None,
                None,
                false,
                None,
                None,
                header,
                ciphertext,
                None,
                reply_to_id.as_deref(),
                None,
            )
            .is_err());
        assert!(stale_general.direct_live_storage_uncertain);
        assert!(stale_general.db().is_none());
        assert!(stale_general.identity.is_none());
        assert!(stale_general.ratchet_sessions.is_empty());
        assert_eq!(
            fixture
                .receiver
                .db()
                .unwrap()
                .get_messages(&conversation_id, 10)
                .unwrap()
                .len(),
            2
        );
        let durable_after_stale = fixture
            .receiver
            .db()
            .unwrap()
            .load_ratchet_session_with_revision_v1(&peer_identity_key)
            .unwrap()
            .unwrap();
        assert_eq!(durable_after_stale.session_data, legacy_order.as_bytes());
        assert_eq!(durable_after_stale.revision, durable_after_gap.revision);

        drop(durable_after_stale);
        drop(durable_after_gap);
        drop(stale_general);
        drop(stale_fixture);
        drop(fixture);

        let mut reopened = VeilClient::new();
        reopened.init_with_mnemonic(&mnemonic, &path).unwrap();
        restore_single_peer_direct_replay_runtime(
            &mut reopened,
            receiver_identity_key,
            peer_identity_key,
            &conversation_id,
        );
        let hydrated_without_migration = reopened
            .db()
            .unwrap()
            .load_ratchet_session_with_revision_v1(&peer_identity_key)
            .unwrap()
            .unwrap();
        assert_eq!(
            hydrated_without_migration.session_data,
            legacy_order.as_bytes()
        );
        assert_eq!(hydrated_without_migration.revision, gap_revision);
        drop(hydrated_without_migration);
        let mut reopened_fixture = DirectLiveReplayFixture {
            receiver: reopened,
            receiver_identity_key,
            receiver_signing_key,
            peers: Vec::new(),
        };
        reopened_fixture.enqueue(vec![late_one, late_two]);
        assert_eq!(
            reopened_fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap()
                .stored,
            2
        );
        let durable_final = reopened_fixture
            .receiver
            .db()
            .unwrap()
            .load_ratchet_session_with_revision_v1(&peer_identity_key)
            .unwrap()
            .unwrap();
        assert_eq!(durable_final.revision, 3);
        assert!(reopened_fixture
            .receiver
            .ratchet_sessions
            .get(&peer_identity_key)
            .unwrap()
            .matches_serialized_v1(&durable_final.session_data)
            .unwrap());
        assert_eq!(
            reopened_fixture
                .receiver
                .db()
                .unwrap()
                .get_messages(&conversation_id, 10)
                .unwrap()
                .len(),
            4
        );

        drop(durable_final);
        drop(reopened_fixture);
        remove_test_database(&path);
    }

    #[tokio::test]
    async fn direct_live_duplicate_repairs_legacy_author_and_signals_projection_refresh() {
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let event = fixture.peers[peer].next_event("legacy author repair");
        let (message_id, conversation_id) = match &event {
            ConnectionEvent::MessageReceived {
                message_id,
                conversation_id,
                ..
            } => (message_id.clone(), conversation_id.clone()),
            _ => unreachable!(),
        };
        fixture.enqueue(vec![event.clone()]);
        fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap();
        fixture
            .receiver
            .db()
            .unwrap()
            .conn()
            .execute(
                "DELETE FROM message_author_snapshots_v1 WHERE message_id = ?1",
                rusqlite::params![message_id],
            )
            .unwrap();
        assert!(fixture
            .receiver
            .db()
            .unwrap()
            .get_messages(&conversation_id, 10)
            .unwrap()[0]
            .author
            .is_none());
        let ratchet_before =
            duplicate_ratchet_state(&fixture.receiver, &fixture.peers[peer].sender_identity_key);

        fixture.enqueue(vec![event]);
        assert_eq!(
            fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap(),
            DirectLiveReplayReportV1 {
                consumed: 1,
                duplicates: 1,
                visible_mutations: 1,
                quiescent: true,
                ..DirectLiveReplayReportV1::default()
            }
        );
        assert_eq!(
            duplicate_ratchet_state(&fixture.receiver, &fixture.peers[peer].sender_identity_key),
            ratchet_before
        );
        assert!(fixture
            .receiver
            .db()
            .unwrap()
            .get_messages(&conversation_id, 10)
            .unwrap()[0]
            .author
            .is_some());
    }

    #[tokio::test]
    async fn direct_live_ack_and_error_reconcile_sqlcipher_without_leaking_identifiers() {
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let conversation_id = fixture.peers[peer].conversation_id.clone();
        let ack_local_id = uuid::Uuid::new_v4().to_string();
        let failed_local_id = uuid::Uuid::new_v4().to_string();
        let server_message_id = uuid::Uuid::new_v4().to_string();
        let ack_sequence = 0xA1;
        let failed_sequence = 0xA2;
        let ack_timestamp_ns = 1_700_000_123_456_000_000u64;
        for (sequence, local_id, plaintext) in [
            (ack_sequence, ack_local_id.as_str(), "acknowledged"),
            (failed_sequence, failed_local_id.as_str(), "failed"),
        ] {
            fixture
                .receiver
                .db()
                .unwrap()
                .insert_outgoing_pending_message(
                    local_id,
                    &conversation_id,
                    &fixture.receiver_identity_key,
                    plaintext,
                    None,
                )
                .unwrap();
            fixture.receiver.pending_outgoing_messages.insert(
                sequence,
                PendingOutgoingMessage {
                    local_message_id: local_id.to_string(),
                    conversation_id: conversation_id.clone(),
                    sender_identity_key: fixture.receiver_identity_key,
                    plaintext: plaintext.to_string(),
                    durable_direct_outbox: false,
                    direct_ack_deadline: None,
                },
            );
        }
        fixture.enqueue(vec![
            ConnectionEvent::MessageAcked {
                message_id: server_message_id.clone(),
                server_timestamp: ack_timestamp_ns,
                ref_seq: ack_sequence,
                client_message_id: Some(ack_local_id.clone()),
                local_message_id: None,
                mutation: None,
                sender_key: None,
            },
            ConnectionEvent::Error {
                code: 500,
                message: "rejected".to_string(),
                ref_seq: Some(failed_sequence),
                client_message_id: Some(failed_local_id.clone()),
                reason: Some("internal_error".to_string()),
                local_message_id: None,
                conversation_id: None,
                stale_roster_context: false,
            },
        ]);

        let report = fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap();
        assert_eq!(
            report,
            DirectLiveReplayReportV1 {
                consumed: 2,
                ignored: 2,
                visible_mutations: 2,
                quiescent: true,
                ..DirectLiveReplayReportV1::default()
            }
        );
        let aggregate_debug = format!("{report:?}");
        assert!(!aggregate_debug.contains(&ack_local_id));
        assert!(!aggregate_debug.contains(&failed_local_id));
        assert!(!aggregate_debug.contains(&server_message_id));
        assert!(fixture.receiver.pending_outgoing_messages.is_empty());

        let messages = fixture
            .receiver
            .db()
            .unwrap()
            .get_messages(&conversation_id, 10)
            .unwrap();
        assert_eq!(messages.len(), 2);
        assert!(messages.iter().all(|message| message.id != ack_local_id));
        let acknowledged = messages
            .iter()
            .find(|message| message.id == server_message_id)
            .unwrap();
        assert_eq!(acknowledged.status, veil_store::models::MessageStatus::Sent);
        assert_eq!(
            acknowledged.server_timestamp,
            Some(i64::try_from(ack_timestamp_ns / 1_000_000).unwrap())
        );
        let failed = messages
            .iter()
            .find(|message| message.id == failed_local_id)
            .unwrap();
        assert_eq!(failed.status, veil_store::models::MessageStatus::Failed);
        assert_eq!(failed.server_timestamp, None);
    }

    #[tokio::test]
    async fn generic_poll_storage_reconciliation_revokes_the_native_epoch() {
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let baseline = fixture.peers[peer].next_event("message to edit");
        let message_id = match &baseline {
            ConnectionEvent::MessageReceived { message_id, .. } => message_id.clone(),
            _ => unreachable!(),
        };
        fixture.enqueue(vec![baseline]);
        fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap();
        fixture.receiver.pending_mutations.insert(
            0xB1,
            ConfirmedMutation::Edit {
                message_id: message_id.clone(),
                conversation_id: fixture.peers[peer].conversation_id.clone(),
                new_text: "sensitive pending edit".to_string(),
            },
        );
        fixture
            .receiver
            .db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER reject_poll_edit
                 BEFORE UPDATE OF plaintext ON messages
                 BEGIN SELECT RAISE(FAIL, 'forced poll reconciliation failure'); END;",
            )
            .unwrap();
        fixture.enqueue(vec![ConnectionEvent::MessageAcked {
            message_id: message_id.clone(),
            server_timestamp: 1_700_000_000_000_000_000,
            ref_seq: 0xB1,
            client_message_id: None,
            local_message_id: None,
            mutation: None,
            sender_key: None,
        }]);

        let error = fixture.receiver.poll_event().await.unwrap_err();
        assert!(error.contains("forced poll reconciliation failure"));
        assert!(fixture.receiver.direct_live_storage_uncertain);
        assert!(fixture.receiver.connection.is_none());
        assert!(fixture.receiver.authenticated_user_id.is_none());
        assert!(fixture.receiver.authenticated_server_origin.is_none());
        assert!(fixture.receiver.pending_mutations.is_empty());
        assert!(fixture.receiver.db().is_none());
        assert!(fixture.receiver.identity.is_none());
        assert_eq!(
            fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap_err()
                .stop,
            DirectLiveReplayStopV1::StorageUncertain
        );
    }

    #[tokio::test]
    async fn initial_ack_does_not_rewrite_ratchet_and_confirms_edit_once() {
        let path =
            std::env::temp_dir().join(format!("veil-ack-late-failure-{}.db", uuid::Uuid::new_v4()));
        remove_test_database(&path);
        let db_key = [0x94; 32];
        let mut fixture =
            DirectLiveReplayFixture::new_with_db(VeilDb::open(&path, &db_key).unwrap());
        let peer = fixture.add_peer();
        let conversation_id = fixture.peers[peer].conversation_id.clone();
        let peer_identity_key = fixture.peers[peer].sender_identity_key;
        let baseline = fixture.peers[peer].next_event("original durable text");
        let message_id = match &baseline {
            ConnectionEvent::MessageReceived { message_id, .. } => message_id.clone(),
            _ => unreachable!(),
        };
        fixture.enqueue(vec![baseline]);
        fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap();

        let ratchet_before_ack = fixture
            .receiver
            .db()
            .unwrap()
            .load_ratchet_session_with_revision_v1(&peer_identity_key)
            .unwrap()
            .unwrap();
        // One sequence deliberately overlaps a plaintext-bearing edit and an
        // initial-session acknowledgement. ACK must not rewrite the already
        // durable ratchet; only the pending edit confirmation may commit.
        let sequence = 0xB2;
        fixture.receiver.pending_mutations.insert(
            sequence,
            ConfirmedMutation::Edit {
                message_id: message_id.clone(),
                conversation_id: conversation_id.clone(),
                new_text: "sensitive edit that must never escape".to_string(),
            },
        );
        fixture
            .receiver
            .pending_initial_sequences
            .insert(sequence, peer_identity_key);
        fixture
            .receiver
            .db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER reject_ack_ratchet
                 BEFORE UPDATE ON ratchet_sessions
                 BEGIN SELECT RAISE(FAIL, 'ACK attempted a ratchet rewrite'); END;",
            )
            .unwrap();
        fixture.enqueue(vec![ConnectionEvent::MessageAcked {
            message_id: message_id.clone(),
            server_timestamp: 1_700_000_000_000_000_000,
            ref_seq: sequence,
            client_message_id: None,
            local_message_id: None,
            mutation: None,
            sender_key: None,
        }]);

        let event = fixture.receiver.poll_event().await.unwrap().unwrap();
        assert!(matches!(
            event,
            ConnectionEvent::MessageAcked {
                mutation: Some(ConfirmedMutation::Edit { ref new_text, .. }),
                ..
            } if new_text == "sensitive edit that must never escape"
        ));
        assert!(!fixture.receiver.direct_live_storage_uncertain);
        assert!(fixture.receiver.pending_mutations.is_empty());
        assert!(!fixture
            .receiver
            .pending_initial_sequences
            .contains_key(&sequence));
        assert!(fixture.receiver.db().is_some());

        let ratchet_after_ack = fixture
            .receiver
            .db()
            .unwrap()
            .load_ratchet_session_with_revision_v1(&peer_identity_key)
            .unwrap()
            .unwrap();
        assert_eq!(ratchet_after_ack.revision, ratchet_before_ack.revision);
        assert_eq!(
            ratchet_after_ack.session_data,
            ratchet_before_ack.session_data
        );

        // The trigger above is a test-only tripwire, not part of the durable
        // schema. Remove it before reopen so the exact ratchet schema gate can
        // distinguish a clean database from an unknown/future trigger.
        fixture
            .receiver
            .db()
            .unwrap()
            .conn()
            .execute_batch("DROP TRIGGER reject_ack_ratchet;")
            .unwrap();

        drop(ratchet_after_ack);
        drop(ratchet_before_ack);
        drop(fixture);
        let reopened = VeilDb::open(&path, &db_key).unwrap();
        let messages = reopened.get_messages(&conversation_id, 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, message_id);
        assert_eq!(
            messages[0].plaintext,
            "sensitive edit that must never escape"
        );
        drop(reopened);
        remove_test_database(&path);
    }

    fn assert_failed_initialization_epoch_is_scrubbed_v1(
        client: &VeilClient,
        peer_identity_key: &[u8; 32],
    ) {
        assert!(client.direct_live_storage_uncertain);
        assert!(client.connection.is_none());
        assert!(client.authenticated_user_id.is_none());
        assert!(client.authenticated_server_origin.is_none());
        assert!(client.deferred_connection_events.events.is_empty());
        assert!(client.db().is_none());
        assert!(client.indexer().is_none());
        assert!(client.identity.is_none());
        assert!(client.device_identity.is_none());
        assert!(client.ratchet_sessions.is_empty());
        assert!(!client.has_session(peer_identity_key));
        assert!(client.spk_secrets.is_empty());
        assert!(client.otk_secrets.is_empty());
        assert_eq!(client.spk_next_id, 1);
        assert_eq!(client.otk_next_id, 1);
        assert!(client.pending_initial_headers.is_empty());
        assert!(client.pending_initial_sequences.is_empty());
        assert!(client.pending_outgoing_messages.is_empty());
        assert!(client.pending_mutations.is_empty());
        assert!(client.dm_conversations.is_empty());
        assert!(client.known_user_keys.is_empty());
        assert!(client.trusted_signing_keys.is_empty());
        assert!(client.channel_conversations.is_empty());
        assert!(client.authorized_conversation_senders.is_empty());
        assert!(client.device_rosters.is_empty());
        assert!(client.last_invalidated_device_rosters.is_empty());
        assert!(client.device_roster_rotation_pending.is_empty());
        assert!(client.sender_key_distribution_pending.is_empty());
        assert!(client.prepared_sender_key_generations.is_empty());
        assert!(client.pending_sender_key_sequences.is_empty());
        assert!(client.pending_sender_key_envelopes.is_empty());
        assert!(client.pending_sender_key_receipts.is_empty());
        assert!(client.pending_sender_key_receipt_set.is_empty());
        assert!(client.pending_sender_key_receipt_sequences.is_empty());
        assert!(client.failed_sender_key_distributions.is_empty());
        assert!(client.direct_live_blocked_conversations.is_empty());
        assert!(!client.sender_keys.has_outgoing("scrubbed-sender-key-probe"));
        assert!(!client
            .sender_keys
            .has_incoming("scrubbed-sender-key-probe", peer_identity_key));
    }

    #[tokio::test]
    async fn direct_send_sqlcipher_failures_revoke_before_a_retry_can_reuse_the_epoch() {
        for fault in ["ratchet", "pending"] {
            let mut fixture = DirectLiveReplayFixture::new();
            let peer = fixture.add_peer();
            let peer_identity_key = fixture.peers[peer].sender_identity_key;
            let conversation_id = fixture.peers[peer].conversation_id.clone();
            let initial = fixture.peers[peer].next_event("establish responder session");
            fixture.enqueue(vec![initial]);
            fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap();
            assert!(fixture.receiver.has_session(&peer_identity_key));

            let trigger = match fault {
                "ratchet" => {
                    "CREATE TRIGGER reject_direct_send_ratchet
                     BEFORE UPDATE ON ratchet_sessions
                     BEGIN SELECT RAISE(ABORT, 'forced Direct send ratchet failure'); END;"
                }
                "pending" => {
                    "CREATE TRIGGER reject_direct_send_pending
                     BEFORE INSERT ON messages
                     BEGIN SELECT RAISE(ABORT, 'forced Direct send pending failure'); END;"
                }
                _ => unreachable!(),
            };
            fixture
                .receiver
                .db()
                .unwrap()
                .conn()
                .execute_batch(trigger)
                .unwrap();
            let (connection, mut outbound) =
                crate::connection::Connection::test_only_queued_connection();
            fixture.receiver.connection = Some(connection);

            let error = fixture
                .receiver
                .send_message(&conversation_id, "must not become retryable", None)
                .await
                .unwrap_err();
            assert!(error.contains(&format!("forced Direct send {fault} failure")));
            assert_failed_initialization_epoch_is_scrubbed_v1(
                &fixture.receiver,
                &peer_identity_key,
            );
            assert!(outbound.try_recv().is_err());
        }

        // A closed bounded transport queue is a definite local rejection: no
        // envelope was accepted. If the compensating SQLCipher status update
        // succeeds, the ratchet may safely skip its consumed key and the epoch
        // must remain usable instead of being over-classified as uncertain.
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let peer_identity_key = fixture.peers[peer].sender_identity_key;
        let conversation_id = fixture.peers[peer].conversation_id.clone();
        let initial = fixture.peers[peer].next_event("establish responder session");
        fixture.enqueue(vec![initial]);
        fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap();
        let (connection, outbound) = crate::connection::Connection::test_only_queued_connection();
        drop(outbound);
        fixture.receiver.connection = Some(connection);

        let error = fixture
            .receiver
            .send_message(&conversation_id, "definitely not queued", None)
            .await
            .unwrap_err();
        assert!(error.contains("send failed"));
        assert!(!fixture.receiver.direct_live_storage_uncertain);
        assert!(fixture.receiver.db().is_some());
        assert!(fixture.receiver.has_session(&peer_identity_key));
        let messages = fixture
            .receiver
            .db()
            .unwrap()
            .get_messages(&conversation_id, 10)
            .unwrap();
        let rejected = messages
            .iter()
            .find(|message| message.is_outgoing && message.plaintext == "definitely not queued")
            .expect("definitely rejected outgoing row is durable");
        assert_eq!(rejected.status, veil_store::models::MessageStatus::Failed);
    }

    #[test]
    fn failed_initialization_scrubs_partial_fresh_and_revoked_epochs() {
        let mnemonic = generate_mnemonic().to_string();
        let corrupt_path = std::env::temp_dir().join(format!(
            "veil-init-partial-corrupt-{}.db",
            uuid::Uuid::new_v4()
        ));
        let recovered_path = std::env::temp_dir().join(format!(
            "veil-init-partial-recovered-{}.db",
            uuid::Uuid::new_v4()
        ));
        remove_test_database(&corrupt_path);
        remove_test_database(&recovered_path);

        let peer_identity = IdentityKeyPair::generate();
        let peer_identity_key = peer_identity.x25519_public_bytes();
        let peer_signing_key = peer_identity.ed25519_public_bytes();
        let mut peer = VeilClient::from_identity(peer_identity);
        let peer_prekeys = peer.generate_prekeys().unwrap();
        let (one_time_prekey, one_time_prekey_id) = peer_prekeys.otk_publics[0];
        let bundle = x3dh::PreKeyBundle {
            identity_key: peer_identity_key,
            signing_key: peer_signing_key,
            signed_prekey: peer_prekeys.spk_public,
            signed_prekey_signature: peer_prekeys.spk_signature,
            signed_prekey_id: peer_prekeys.spk_id,
            one_time_prekey: Some(one_time_prekey),
            one_time_prekey_id: Some(one_time_prekey_id),
        };

        let mut seeded = VeilClient::new();
        seeded.init_with_mnemonic(&mnemonic, &corrupt_path).unwrap();
        seeded.generate_prekeys().unwrap();
        seeded
            .establish_session(&peer_identity_key, &bundle)
            .unwrap();
        seeded
            .db()
            .unwrap()
            .upsert_directory_conversation(
                "late-corrupt-init",
                ConversationType::DM as u8,
                "https://init-corrupt.test:443",
                Some("Peer"),
                Some("00000000-0000-0000-0000-000000000047"),
                Some(peer_identity_key.as_slice()),
                None,
                "2026-07-18T00:00:00Z",
            )
            .unwrap();
        let changed = seeded
            .db()
            .unwrap()
            .conn()
            .execute(
                "UPDATE pending_initial_headers SET header_data = ?1
                 WHERE peer_identity_key = ?2",
                rusqlite::params![b"{".as_slice(), peer_identity_key.as_slice()],
            )
            .unwrap();
        assert_eq!(changed, 1);
        assert!(!seeded
            .db()
            .unwrap()
            .load_local_prekeys()
            .unwrap()
            .is_empty());
        assert!(seeded
            .db()
            .unwrap()
            .load_ratchet_session(&peer_identity_key)
            .unwrap()
            .is_some());
        drop(seeded);

        let mut recovering = VeilClient::new();
        let original_device_id = recovering.device_id();
        let first_error = recovering
            .init_with_mnemonic(&mnemonic, &corrupt_path)
            .unwrap_err();
        assert!(first_error.contains("decode pending X3DH header"));
        assert_eq!(recovering.device_id(), original_device_id);
        assert_failed_initialization_epoch_is_scrubbed_v1(&recovering, &peer_identity_key);

        // The same corrupt late load is also safe when entered as an explicit
        // sticky-revoke recovery attempt.
        let second_error = recovering
            .init_with_mnemonic(&mnemonic, &corrupt_path)
            .unwrap_err();
        assert!(second_error.contains("decode pending X3DH header"));
        assert_eq!(recovering.device_id(), original_device_id);
        assert_failed_initialization_epoch_is_scrubbed_v1(&recovering, &peer_identity_key);

        recovering
            .init_with_mnemonic(&mnemonic, &recovered_path)
            .unwrap();
        assert!(!recovering.direct_live_storage_uncertain);
        assert!(recovering.db().is_some());
        assert!(recovering.identity.is_some());
        assert!(recovering.device_identity.is_some());

        drop(recovering);
        remove_test_database(&corrupt_path);
        remove_test_database(&recovered_path);
    }

    #[test]
    fn initialization_rejects_corrupt_local_prekey_keypairs_and_signatures() {
        for (variant, mutation) in [
            (
                "signed-public",
                "UPDATE local_prekeys SET public_key = zeroblob(32) WHERE key_type = 0",
            ),
            (
                "signed-signature",
                "UPDATE local_prekeys SET signature = zeroblob(64) WHERE key_type = 0",
            ),
            (
                "one-time-public",
                "UPDATE local_prekeys SET public_key = zeroblob(32) WHERE key_type = 1",
            ),
            (
                "one-time-signature",
                "UPDATE local_prekeys SET signature = zeroblob(64) WHERE key_type = 1",
            ),
        ] {
            let mnemonic = generate_mnemonic().to_string();
            let path = std::env::temp_dir().join(format!(
                "veil-corrupt-local-prekey-{variant}-{}.db",
                uuid::Uuid::new_v4()
            ));
            remove_test_database(&path);
            {
                let mut seeded = VeilClient::new();
                seeded.init_with_mnemonic(&mnemonic, &path).unwrap();
                seeded.generate_prekeys().unwrap();
                seeded.db().unwrap().conn().execute(mutation, []).unwrap();
            }

            let mut recovering = VeilClient::new();
            let error = recovering.init_with_mnemonic(&mnemonic, &path).unwrap_err();
            assert!(
                error.contains("public key differs from its secret")
                    || error.contains("failed domain verification")
                    || error.contains("unexpectedly contains a signature"),
                "variant={variant} error={error}"
            );
            assert!(recovering.identity.is_none());
            assert!(recovering.device_identity.is_none());
            assert!(recovering.db().is_none());
            assert!(recovering.spk_secrets.is_empty());
            assert!(recovering.otk_secrets.is_empty());
            remove_test_database(&path);
        }
    }

    #[tokio::test]
    async fn active_reinitialization_is_rejected_without_epoch_mutation() {
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let conversation_id = fixture.peers[peer].conversation_id.clone();
        let peer_identity_key = fixture.peers[peer].sender_identity_key;
        let baseline = fixture.peers[peer].next_event("baseline");
        fixture.enqueue(vec![baseline]);
        fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap();
        let queued = fixture.peers[peer].next_event("queued after reject");
        fixture.enqueue(vec![queued]);

        let identity_before = fixture.receiver.identity_key().unwrap();
        let signing_before = fixture.receiver.signing_key().unwrap();
        let device_id_before = fixture.receiver.device_id();
        let auth_before = fixture.receiver.authenticated_user_id.clone();
        let origin_before = fixture.receiver.authenticated_server_origin.clone();
        let ratchet_before =
            runtime_ratchet_fingerprint_v1(&fixture.receiver, &peer_identity_key).unwrap();
        let db_changes_before = fixture.receiver.db().unwrap().conn().changes();
        let queued_before = fixture.receiver.deferred_connection_events.events.len();
        let transport_before = fixture.receiver.connection.is_some();
        let replacement_path = std::env::temp_dir().join(format!(
            "veil-active-reinit-rejected-{}.db",
            uuid::Uuid::new_v4()
        ));
        remove_test_database(&replacement_path);
        let replacement_mnemonic = generate_mnemonic().to_string();

        let error = fixture
            .receiver
            .init_with_mnemonic(&replacement_mnemonic, &replacement_path)
            .unwrap_err();
        assert!(error.contains("already initialized"));
        assert!(!fixture.receiver.direct_live_storage_uncertain);
        assert_eq!(fixture.receiver.identity_key().unwrap(), identity_before);
        assert_eq!(fixture.receiver.signing_key().unwrap(), signing_before);
        assert_eq!(fixture.receiver.device_id(), device_id_before);
        assert_eq!(fixture.receiver.authenticated_user_id, auth_before);
        assert_eq!(fixture.receiver.authenticated_server_origin, origin_before);
        assert_eq!(
            runtime_ratchet_fingerprint_v1(&fixture.receiver, &peer_identity_key),
            Some(ratchet_before)
        );
        assert_eq!(
            fixture.receiver.db().unwrap().conn().changes(),
            db_changes_before
        );
        assert_eq!(
            fixture.receiver.deferred_connection_events.events.len(),
            queued_before
        );
        assert_eq!(fixture.receiver.connection.is_some(), transport_before);
        assert!(!replacement_path.exists());

        let report = fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap();
        assert_eq!(report.stored, 1);
        let messages = fixture
            .receiver
            .direct_messages_projection_v1(&conversation_id, 10)
            .unwrap();
        assert_eq!(messages.len(), 2);
        remove_test_database(&replacement_path);
    }

    #[test]
    fn connect_preinstall_reconciliation_failure_revokes_the_old_epoch() {
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let conversation_id = fixture.peers[peer].conversation_id.clone();
        let local_message_id = uuid::Uuid::new_v4().to_string();
        fixture
            .receiver
            .db()
            .unwrap()
            .insert_outgoing_pending_message(
                &local_message_id,
                &conversation_id,
                &fixture.receiver_identity_key,
                "ambiguous reconnect draft",
                None,
            )
            .unwrap();
        fixture.receiver.pending_outgoing_messages.insert(
            0xB2,
            PendingOutgoingMessage {
                local_message_id,
                conversation_id,
                sender_identity_key: fixture.receiver_identity_key,
                plaintext: "ambiguous reconnect draft".to_string(),
                durable_direct_outbox: false,
                direct_ack_deadline: None,
            },
        );
        fixture
            .receiver
            .db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER reject_reconnect_delivery_state
                 BEFORE UPDATE OF status ON messages
                 BEGIN SELECT RAISE(FAIL, 'forced reconnect reconciliation failure'); END;",
            )
            .unwrap();

        let error = fixture
            .receiver
            .reconcile_previous_transport_before_install_v1()
            .unwrap_err();
        assert!(error.contains("forced reconnect reconciliation failure"));
        assert!(fixture.receiver.direct_live_storage_uncertain);
        assert!(fixture.receiver.connection.is_none());
        assert!(fixture.receiver.authenticated_user_id.is_none());
        assert!(fixture.receiver.authenticated_server_origin.is_none());
        assert!(fixture.receiver.pending_outgoing_messages.is_empty());
        assert!(fixture.receiver.db().is_none());
        assert!(fixture.receiver.identity.is_none());
    }

    #[tokio::test]
    async fn direct_live_terminal_between_events_preempts_the_next_poll() {
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let first = fixture.peers[peer].next_event("first");
        let second = fixture.peers[peer].next_event("must be preempted");
        fixture.enqueue(vec![first, second]);

        let error = fixture
            .receiver
            .replay_direct_live_events_inner_v1(|client, consumed| {
                if consumed == 1 {
                    client
                        .deferred_connection_events
                        .fail(ConnectionEventBufferErrorV1::TransportEpochEnded);
                }
            })
            .await
            .unwrap_err();
        assert_eq!(error.stop, DirectLiveReplayStopV1::RetryableTransport);
        assert_eq!(
            error.report,
            DirectLiveReplayReportV1 {
                consumed: 1,
                stored: 1,
                visible_mutations: 1,
                ..DirectLiveReplayReportV1::default()
            }
        );
        assert_eq!(
            fixture
                .receiver
                .db()
                .unwrap()
                .get_messages(&fixture.peers[peer].conversation_id, 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn direct_live_buffer_and_protocol_failures_are_epoch_invalid() {
        for failure in [
            ConnectionEventBufferErrorV1::EventCountLimitExceeded { limit: 1 },
            ConnectionEventBufferErrorV1::ProtocolViolation {
                envelope: "test authenticated envelope",
            },
        ] {
            let mut fixture = DirectLiveReplayFixture::new();
            fixture
                .receiver
                .deferred_connection_events
                .fail(failure.clone());

            let error = fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap_err();
            assert_eq!(error.stop, DirectLiveReplayStopV1::EpochInvalid);
            assert_eq!(error.report, DirectLiveReplayReportV1::default());
            assert_eq!(
                fixture
                    .receiver
                    .replay_direct_live_events_v1()
                    .await
                    .unwrap_err()
                    .stop,
                DirectLiveReplayStopV1::EpochInvalid
            );
        }
    }

    #[tokio::test]
    async fn post_auth_websocket_protocol_terminal_never_becomes_retryable_in_api() {
        let mut fixture = DirectLiveReplayFixture::new();
        let _outbound = fixture.receiver.test_only_install_queued_connection();
        fixture
            .receiver
            .connection
            .as_ref()
            .unwrap()
            .test_only_report_websocket_error_v1(tokio_tungstenite::tungstenite::Error::Capacity(
                tokio_tungstenite::tungstenite::error::CapacityError::MessageTooLong {
                    size: 2,
                    max_size: 1,
                },
            ));

        let error = fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap_err();
        assert_eq!(error.stop, DirectLiveReplayStopV1::EpochInvalid);
        assert_ne!(error.stop, DirectLiveReplayStopV1::RetryableTransport);
        assert!(!fixture.receiver.direct_live_storage_uncertain);
        assert_eq!(
            fixture.receiver.direct_live_stop,
            Some(DirectLiveReplayStopV1::EpochInvalid)
        );
        assert!(fixture.receiver.connection.is_none());
    }

    #[tokio::test]
    async fn already_reported_protocol_terminal_rejects_direct_intent_before_sqlcipher_commit() {
        let mut fixture = DirectOutboxClientFixture::new();
        assert!(fixture.client.test_only_report_epoch_invalid_transport_v1());
        assert!(!fixture.client.is_connected());

        assert!(matches!(
            fixture
                .client
                .enqueue_direct_text_v1(&fixture.conversation_id, "must not be accepted")
                .await,
            Err(DirectSendErrorV1::Rejected(_))
        ));
        let pending_count: i64 = fixture
            .client
            .db()
            .unwrap()
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM direct_message_outbox_v1 WHERE state = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_count, 0);
        assert!(fixture.client.pending_outgoing_messages.is_empty());
    }

    #[tokio::test]
    async fn direct_live_replay_stops_at_sixty_four_without_claiming_quiescence() {
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let events = (0..(DIRECT_LIVE_REPLAY_MAX_BATCH_V1 + 1))
            .map(|index| fixture.peers[peer].next_event(&format!("message {index}")))
            .collect();
        fixture.enqueue(events);

        assert_eq!(
            fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap(),
            DirectLiveReplayReportV1 {
                consumed: DIRECT_LIVE_REPLAY_MAX_BATCH_V1,
                stored: DIRECT_LIVE_REPLAY_MAX_BATCH_V1,
                visible_mutations: DIRECT_LIVE_REPLAY_MAX_BATCH_V1,
                quiescent: false,
                ..DirectLiveReplayReportV1::default()
            }
        );
        assert_eq!(
            fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap(),
            DirectLiveReplayReportV1 {
                consumed: 1,
                stored: 1,
                visible_mutations: 1,
                quiescent: true,
                ..DirectLiveReplayReportV1::default()
            }
        );
    }

    #[tokio::test]
    async fn direct_live_poison_blocks_only_its_conversation() {
        let mut fixture = DirectLiveReplayFixture::new();
        let poisoned_peer = fixture.add_peer();
        let healthy_peer = fixture.add_peer();
        let mut poison = fixture.peers[poisoned_peer].next_event("poisoned");
        if let ConnectionEvent::MessageReceived { ciphertext, .. } = &mut poison {
            let last = ciphertext.last_mut().unwrap();
            *last ^= 0x80;
        }
        let healthy = fixture.peers[healthy_peer].next_event("healthy");
        fixture.enqueue(vec![poison, healthy]);

        assert_eq!(
            fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap(),
            DirectLiveReplayReportV1 {
                consumed: 2,
                stored: 1,
                ignored: 1,
                newly_blocked: 1,
                visible_mutations: 1,
                quiescent: true,
                ..DirectLiveReplayReportV1::default()
            }
        );
        assert!(fixture
            .receiver
            .direct_live_blocked_conversations
            .contains(&fixture.peers[poisoned_peer].conversation_id));
        assert!(!fixture
            .receiver
            .direct_live_blocked_conversations
            .contains(&fixture.peers[healthy_peer].conversation_id));
        assert_eq!(
            fixture
                .receiver
                .direct_conversation_availability_v1(&fixture.peers[poisoned_peer].conversation_id),
            DirectConversationAvailabilityV1::Quarantined
        );
        assert_eq!(
            fixture
                .receiver
                .direct_conversation_availability_v1(&fixture.peers[healthy_peer].conversation_id),
            DirectConversationAvailabilityV1::Available
        );
        assert!(fixture
            .receiver
            .direct_messages_projection_v1(&fixture.peers[poisoned_peer].conversation_id, 10)
            .unwrap_err()
            .contains("quarantined"));
        assert_eq!(
            fixture
                .receiver
                .direct_messages_projection_v1(&fixture.peers[healthy_peer].conversation_id, 10)
                .unwrap()
                .len(),
            1
        );
        let blocked_send = fixture
            .receiver
            .test_only_encrypt_outgoing(
                &fixture.peers[poisoned_peer].conversation_id,
                "must not encrypt",
            )
            .unwrap_err();
        assert!(blocked_send.contains("quarantined"));

        let quarantined = fixture.peers[poisoned_peer].next_event("still blocked");
        let ConnectionEvent::MessageReceived {
            conversation_id,
            sender_identity_key,
            header,
            ciphertext,
            ..
        } = &quarantined
        else {
            unreachable!()
        };
        let blocked_sender: [u8; 32] = sender_identity_key.as_slice().try_into().unwrap();
        let blocked_receive = fixture
            .receiver
            .decrypt_from(&blocked_sender, conversation_id, header, ciphertext)
            .unwrap_err();
        assert!(blocked_receive.contains("quarantined"));
        let blocked_projection = fixture
            .receiver
            .persist_incoming_message(
                &uuid::Uuid::new_v4().to_string(),
                conversation_id,
                &blocked_sender,
                "must not project",
                Some(1),
                None,
            )
            .unwrap_err();
        assert!(blocked_projection.contains("quarantined"));
        let still_healthy = fixture.peers[healthy_peer].next_event("still healthy");
        fixture.enqueue(vec![quarantined, still_healthy]);
        let report = fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap();
        assert_eq!(report.stored, 1);
        assert_eq!(report.ignored, 1);
        assert_eq!(report.newly_blocked, 0);
        assert!(report.quiescent);

        let blocked_id = fixture.peers[poisoned_peer].conversation_id.clone();
        fixture.receiver.clear_server_scoped_conversation_routing();
        assert_eq!(
            fixture
                .receiver
                .direct_conversation_availability_v1(&blocked_id),
            DirectConversationAvailabilityV1::Quarantined
        );
        fixture.receiver.mark_channel_conversation(&blocked_id);
        assert!(!fixture.receiver.is_channel_conversation(&blocked_id));
        assert!(fixture
            .receiver
            .begin_sender_key_distribution(&blocked_id)
            .unwrap_err()
            .contains("quarantined"));
        assert_eq!(
            fixture.receiver.sender_key_distribution_status(&blocked_id),
            "quarantined"
        );
    }

    #[tokio::test]
    async fn repeated_unsupported_direct_mutations_stay_conversation_scoped() {
        let mut fixture = DirectLiveReplayFixture::new();
        let blocked_peer = fixture.add_peer();
        let healthy_peer = fixture.add_peer();
        let blocked_conversation = fixture.peers[blocked_peer].conversation_id.clone();
        let blocked_identity = fixture.peers[blocked_peer].sender_identity_key.to_vec();
        let edit = |message_suffix: u128| ConnectionEvent::MessageEdited {
            message_id: uuid::Uuid::from_u128(
                0x7000_0000_0000_0000_0000_0000_0000_0000 + message_suffix,
            )
            .to_string(),
            conversation_id: blocked_conversation.clone(),
            sender_identity_key: blocked_identity.clone(),
            ciphertext: vec![1],
            header: vec![HEADER_RATCHET],
            edit_timestamp: 1_700_000_000_000_000_000 + message_suffix as u64,
            security_context: None,
        };
        let healthy = fixture.peers[healthy_peer].next_event("healthy after blocked mutations");
        fixture.enqueue(vec![edit(1), edit(2), healthy]);

        assert_eq!(
            fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap(),
            DirectLiveReplayReportV1 {
                consumed: 3,
                stored: 1,
                ignored: 2,
                newly_blocked: 1,
                visible_mutations: 1,
                quiescent: true,
                ..DirectLiveReplayReportV1::default()
            }
        );
    }

    #[tokio::test]
    async fn direct_live_storage_uncertainty_is_a_sticky_global_stop() {
        let path = std::env::temp_dir().join(format!(
            "veil-direct-live-storage-{}.db",
            uuid::Uuid::new_v4()
        ));
        remove_test_database(&path);
        let db_key = [0x91; 32];
        let mut fixture =
            DirectLiveReplayFixture::new_with_db(VeilDb::open(&path, &db_key).unwrap());
        let peer = fixture.add_peer();
        let conversation_id = fixture.peers[peer].conversation_id.clone();
        let sender_identity_key = fixture.peers[peer].sender_identity_key;
        let durable_prekeys_before = fixture
            .receiver
            .db()
            .unwrap()
            .load_local_prekeys()
            .unwrap()
            .len();
        let durable_ratchet_before =
            durable_ratchet_fingerprint_v1(fixture.receiver.db().unwrap(), &sender_identity_key);
        fixture.receiver.pending_outgoing_messages.insert(
            700,
            PendingOutgoingMessage {
                local_message_id: uuid::Uuid::new_v4().to_string(),
                conversation_id: conversation_id.clone(),
                sender_identity_key: fixture.receiver_identity_key,
                plaintext: "pending plaintext must be erased".to_string(),
                durable_direct_outbox: false,
                direct_ack_deadline: None,
            },
        );
        fixture.receiver.pending_mutations.insert(
            701,
            ConfirmedMutation::Edit {
                message_id: uuid::Uuid::new_v4().to_string(),
                conversation_id: conversation_id.clone(),
                new_text: "pending edit must be erased".to_string(),
            },
        );
        fixture
            .receiver
            .db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER reject_direct_live_message
                 BEFORE INSERT ON messages
                 BEGIN SELECT RAISE(FAIL, 'forced Direct live write failure'); END;",
            )
            .unwrap();
        let event = fixture.peers[peer].next_event("must roll back");
        let receive_probe = event.clone();
        fixture.enqueue(vec![event]);

        let error = fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap_err();
        assert_eq!(error.stop, DirectLiveReplayStopV1::StorageUncertain);
        assert_eq!(error.report.consumed, 1);
        assert_eq!(error.report.stored, 0);
        assert!(fixture.receiver.direct_live_storage_uncertain);
        assert!(fixture.receiver.connection.is_none());
        assert!(fixture.receiver.authenticated_user_id.is_none());
        assert!(fixture.receiver.authenticated_server_origin.is_none());
        assert!(fixture
            .receiver
            .deferred_connection_events
            .events
            .is_empty());
        assert!(fixture.receiver.pending_outgoing_messages.is_empty());
        assert!(fixture.receiver.pending_mutations.is_empty());
        assert!(fixture.receiver.pending_initial_headers.is_empty());
        assert!(fixture.receiver.pending_sender_key_envelopes.is_empty());
        assert!(fixture.receiver.ratchet_sessions.is_empty());
        assert!(fixture.receiver.spk_secrets.is_empty());
        assert!(fixture.receiver.otk_secrets.is_empty());
        assert!(fixture.receiver.db().is_none());
        assert!(fixture.receiver.identity.is_none());
        assert!(fixture.receiver.device_identity.is_none());
        assert_eq!(
            fixture
                .receiver
                .direct_conversation_availability_v1(&conversation_id),
            DirectConversationAvailabilityV1::RuntimeRevoked
        );

        let send_error = fixture
            .receiver
            .send_message(&conversation_id, "denied", None)
            .await
            .unwrap_err();
        assert!(send_error.contains("revoked"));
        let ConnectionEvent::MessageReceived {
            sender_identity_key,
            header,
            ciphertext,
            ..
        } = receive_probe
        else {
            unreachable!()
        };
        let sender_identity_key: [u8; 32] = sender_identity_key.try_into().unwrap();
        let receive_error = fixture
            .receiver
            .decrypt_from(&sender_identity_key, &conversation_id, &header, &ciphertext)
            .unwrap_err();
        assert!(receive_error.contains("revoked"));
        assert!(fixture
            .receiver
            .poll_event()
            .await
            .unwrap_err()
            .contains("revoked"));

        // The failed handle was dropped by revoke. Remove the external fault
        // with a separately opened SQLCipher handle; the old runtime must stay
        // revoked even after the original storage cause no longer exists.
        let inspection_db = VeilDb::open(&path, &db_key).unwrap();
        inspection_db
            .conn()
            .execute_batch("DROP TRIGGER reject_direct_live_message")
            .unwrap();
        assert!(inspection_db
            .get_messages(&conversation_id, 10)
            .unwrap()
            .is_empty());
        assert_eq!(
            inspection_db.load_local_prekeys().unwrap().len(),
            durable_prekeys_before
        );
        assert_eq!(
            durable_ratchet_fingerprint_v1(&inspection_db, &sender_identity_key),
            durable_ratchet_before
        );

        let sticky = fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap_err();
        assert_eq!(sticky.stop, DirectLiveReplayStopV1::StorageUncertain);
        assert_eq!(sticky.report, DirectLiveReplayReportV1::default());

        let failed_reinit_path = std::env::temp_dir().join(format!(
            "veil-direct-live-failed-reinit-{}.db",
            uuid::Uuid::new_v4()
        ));
        assert!(fixture
            .receiver
            .init_with_mnemonic("not a valid mnemonic", &failed_reinit_path)
            .is_err());
        assert!(fixture.receiver.direct_live_storage_uncertain);

        let recovered_path = std::env::temp_dir().join(format!(
            "veil-direct-live-reinit-{}.db",
            uuid::Uuid::new_v4()
        ));
        let mnemonic = fixture.receiver.generate_mnemonic();
        fixture
            .receiver
            .init_with_mnemonic(&mnemonic, &recovered_path)
            .unwrap();
        assert!(!fixture.receiver.direct_live_storage_uncertain);
        assert!(fixture.receiver.db().is_some());
        assert_eq!(
            fixture
                .receiver
                .direct_conversation_availability_v1(&conversation_id),
            DirectConversationAvailabilityV1::NotDirect
        );

        drop(inspection_db);
        drop(fixture);
        remove_test_database(&path);
        remove_test_database(&failed_reinit_path);
        remove_test_database(&recovered_path);
    }

    #[tokio::test]
    async fn direct_live_durable_scope_mismatch_matrix_revokes_before_decrypt() {
        for variant in 0..6 {
            let path = std::env::temp_dir().join(format!(
                "veil-direct-live-scope-{variant}-{}.db",
                uuid::Uuid::new_v4()
            ));
            remove_test_database(&path);
            let db_key = [0x92; 32];
            let mut fixture =
                DirectLiveReplayFixture::new_with_db(VeilDb::open(&path, &db_key).unwrap());
            let peer = fixture.add_peer();
            let conversation_id = fixture.peers[peer].conversation_id.clone();
            let sender_identity_key = fixture.peers[peer].sender_identity_key;
            let event = fixture.peers[peer].next_event("must fail durable scope");

            match variant {
                0 => {
                    fixture.receiver.authenticated_server_origin =
                        Some("https://other.example.test:443".to_string());
                }
                1 => {
                    fixture.receiver.authenticated_user_id = Some(uuid::Uuid::new_v4().to_string());
                }
                2 => {
                    let replacement = IdentityKeyPair::generate().x25519_public_bytes();
                    fixture
                        .receiver
                        .db()
                        .unwrap()
                        .conn()
                        .execute(
                            "UPDATE authenticated_self_bindings_v1
                             SET identity_key = ?1
                             WHERE canonical_server_origin = ?2",
                            rusqlite::params![replacement.as_slice(), DIRECT_LIVE_TEST_ORIGIN],
                        )
                        .unwrap();
                }
                3 => {
                    let replacement = IdentityKeyPair::generate().ed25519_public_bytes();
                    fixture
                        .receiver
                        .db()
                        .unwrap()
                        .conn()
                        .execute(
                            "UPDATE authenticated_self_bindings_v1
                             SET signing_key = ?1
                             WHERE canonical_server_origin = ?2",
                            rusqlite::params![replacement.as_slice(), DIRECT_LIVE_TEST_ORIGIN],
                        )
                        .unwrap();
                }
                4 => {
                    fixture
                        .receiver
                        .db()
                        .unwrap()
                        .conn()
                        .execute(
                            "UPDATE conversations SET peer_user_id = ?1 WHERE id = ?2",
                            rusqlite::params![uuid::Uuid::new_v4().to_string(), conversation_id],
                        )
                        .unwrap();
                }
                5 => {
                    let replacement = IdentityKeyPair::generate().x25519_public_bytes();
                    fixture
                        .receiver
                        .db()
                        .unwrap()
                        .conn()
                        .execute(
                            "UPDATE conversations SET peer_identity_key = ?1 WHERE id = ?2",
                            rusqlite::params![replacement.as_slice(), conversation_id],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }

            let runtime_ratchet_before =
                runtime_ratchet_fingerprint_v1(&fixture.receiver, &sender_identity_key);
            let runtime_otk_before = runtime_otk_fingerprint_v1(&fixture.receiver);
            let durable_ratchet_before = durable_ratchet_fingerprint_v1(
                fixture.receiver.db().unwrap(),
                &sender_identity_key,
            );
            let durable_prekeys_before =
                durable_prekey_public_fingerprint_v1(fixture.receiver.db().unwrap());
            fixture.enqueue(vec![event]);

            let error = fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap_err();
            assert_eq!(
                error.stop,
                DirectLiveReplayStopV1::StorageUncertain,
                "scope mismatch variant {variant}"
            );
            assert_eq!(error.report.consumed, 1, "scope mismatch variant {variant}");
            assert!(!error.report.quiescent, "scope mismatch variant {variant}");
            assert!(fixture.receiver.direct_live_storage_uncertain);
            assert!(fixture.receiver.db().is_none());
            assert!(fixture.receiver.identity.is_none());
            assert!(fixture.receiver.ratchet_sessions.is_empty());
            assert!(fixture.receiver.otk_secrets.is_empty());
            assert_eq!(runtime_ratchet_before, None);
            assert_ne!(runtime_otk_before, [0u8; 32]);

            let inspection_db = VeilDb::open(&path, &db_key).unwrap();
            assert!(inspection_db
                .get_messages(&conversation_id, 10)
                .unwrap()
                .is_empty());
            assert_eq!(
                durable_ratchet_fingerprint_v1(&inspection_db, &sender_identity_key),
                durable_ratchet_before
            );
            assert_eq!(
                durable_prekey_public_fingerprint_v1(&inspection_db),
                durable_prekeys_before
            );
            drop(inspection_db);
            drop(fixture);
            remove_test_database(&path);
        }
    }

    #[tokio::test]
    async fn direct_live_authorization_mismatch_matrix_quarantines_before_decrypt() {
        for variant in 0..3 {
            let mut fixture = DirectLiveReplayFixture::new();
            let blocked_peer = fixture.add_peer();
            let healthy_peer = fixture.add_peer();
            let conversation_id = fixture.peers[blocked_peer].conversation_id.clone();
            let sender_identity_key = fixture.peers[blocked_peer].sender_identity_key;
            let event = fixture.peers[blocked_peer].next_event("must be quarantined");

            match variant {
                0 => {
                    let replacement = IdentityKeyPair::generate().ed25519_public_bytes();
                    fixture
                        .receiver
                        .db()
                        .unwrap()
                        .conn()
                        .execute(
                            "UPDATE identity_directory_v1
                             SET signing_key = ?1
                             WHERE canonical_server_origin = ?2 AND identity_key = ?3",
                            rusqlite::params![
                                replacement.as_slice(),
                                DIRECT_LIVE_TEST_ORIGIN,
                                sender_identity_key.as_slice()
                            ],
                        )
                        .unwrap();
                }
                1 => {
                    fixture
                        .receiver
                        .db()
                        .unwrap()
                        .conn()
                        .execute(
                            "UPDATE identity_directory_v1
                             SET source = 1
                             WHERE canonical_server_origin = ?1 AND identity_key = ?2",
                            rusqlite::params![
                                DIRECT_LIVE_TEST_ORIGIN,
                                sender_identity_key.as_slice()
                            ],
                        )
                        .unwrap();
                }
                2 => fixture
                    .receiver
                    .clear_authorized_conversation_senders(&conversation_id),
                _ => unreachable!(),
            }

            let runtime_ratchet_before =
                runtime_ratchet_fingerprint_v1(&fixture.receiver, &sender_identity_key);
            let runtime_otk_before = runtime_otk_fingerprint_v1(&fixture.receiver);
            let durable_ratchet_before = durable_ratchet_fingerprint_v1(
                fixture.receiver.db().unwrap(),
                &sender_identity_key,
            );
            let durable_prekeys_before =
                durable_prekey_public_fingerprint_v1(fixture.receiver.db().unwrap());
            let sql_changes_before: i64 = fixture
                .receiver
                .db()
                .unwrap()
                .conn()
                .query_row("SELECT total_changes()", [], |row| row.get(0))
                .unwrap();
            fixture.enqueue(vec![event]);

            assert_eq!(
                fixture
                    .receiver
                    .replay_direct_live_events_v1()
                    .await
                    .unwrap(),
                DirectLiveReplayReportV1 {
                    consumed: 1,
                    ignored: 1,
                    newly_blocked: 1,
                    quiescent: true,
                    ..DirectLiveReplayReportV1::default()
                },
                "authorization mismatch variant {variant}"
            );
            assert_eq!(
                fixture
                    .receiver
                    .direct_conversation_availability_v1(&conversation_id),
                DirectConversationAvailabilityV1::Quarantined
            );
            assert_eq!(
                runtime_ratchet_fingerprint_v1(&fixture.receiver, &sender_identity_key),
                runtime_ratchet_before
            );
            assert_eq!(
                runtime_otk_fingerprint_v1(&fixture.receiver),
                runtime_otk_before
            );
            assert_eq!(
                durable_ratchet_fingerprint_v1(
                    fixture.receiver.db().unwrap(),
                    &sender_identity_key
                ),
                durable_ratchet_before
            );
            assert_eq!(
                durable_prekey_public_fingerprint_v1(fixture.receiver.db().unwrap()),
                durable_prekeys_before
            );
            assert_eq!(
                fixture
                    .receiver
                    .db()
                    .unwrap()
                    .conn()
                    .query_row("SELECT total_changes()", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                sql_changes_before
            );
            assert!(fixture
                .receiver
                .db()
                .unwrap()
                .get_messages(&conversation_id, 10)
                .unwrap()
                .is_empty());

            let healthy_event = fixture.peers[healthy_peer].next_event("healthy continuation");
            let healthy_conversation = fixture.peers[healthy_peer].conversation_id.clone();
            fixture.enqueue(vec![healthy_event]);
            let healthy_report = fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap();
            assert_eq!(healthy_report.stored, 1);
            assert_eq!(
                fixture
                    .receiver
                    .direct_conversation_availability_v1(&healthy_conversation),
                DirectConversationAvailabilityV1::Available
            );
        }
    }

    #[tokio::test]
    async fn direct_live_future_policy_is_quarantined_before_decrypt() {
        for mutation in 0..7 {
            let mut fixture = DirectLiveReplayFixture::new();
            let peer = fixture.add_peer();
            let mut event = fixture.peers[peer].next_event("unsupported");
            let ConnectionEvent::MessageReceived {
                msg_type,
                ttl_seconds,
                sealed,
                attachments,
                header,
                message_id,
                reply_to_id,
                ..
            } = &mut event
            else {
                unreachable!()
            };
            match mutation {
                0 => *msg_type = Some(i32::MAX),
                1 => *ttl_seconds = Some(30),
                2 => *sealed = Some(true),
                3 => attachments.push(crate::attachments::WireAttachmentV1 {
                    media_id: uuid::Uuid::from_u128(0x5000).to_string(),
                    encrypted_key: vec![1; 32],
                    nonce: vec![2; 24],
                    size: 1,
                    content_type: "application/octet-stream".to_string(),
                }),
                4 => header[0] = HEADER_SENDER_KEY,
                5 => *msg_type = None,
                6 => *reply_to_id = Some(message_id.clone()),
                _ => unreachable!(),
            }
            fixture.enqueue(vec![event]);
            let report = fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap();
            assert_eq!(report.stored, 0);
            assert_eq!(report.ignored, 1);
            assert_eq!(report.newly_blocked, 1);
            assert!(report.quiescent);
            assert!(fixture
                .receiver
                .db()
                .unwrap()
                .get_messages(&fixture.peers[peer].conversation_id, 10)
                .unwrap()
                .is_empty());
        }
    }

    #[tokio::test]
    async fn direct_live_unknown_route_poison_cannot_be_reported_quiescent() {
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let mut unknown = fixture.peers[peer].next_event("unknown route");
        if let ConnectionEvent::MessageReceived {
            conversation_id, ..
        } = &mut unknown
        {
            *conversation_id =
                uuid::Uuid::from_u128(0x6000_0000_0000_0000_0000_0000_0000_0001).to_string();
        }
        let otherwise_valid = fixture.peers[peer].next_event("must be preempted");
        fixture.enqueue(vec![unknown, otherwise_valid]);

        let error = fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap_err();
        assert_eq!(error.stop, DirectLiveReplayStopV1::EpochInvalid);
        assert_eq!(error.report.consumed, 1);
        assert!(!error.report.quiescent);
        assert_eq!(error.report.stored, 0);
        assert_eq!(
            fixture.receiver.deferred_connection_events.failure(),
            Some(ConnectionEventBufferErrorV1::ProtocolViolation {
                envelope: "Direct live route"
            })
        );
        let sticky = fixture
            .receiver
            .replay_direct_live_events_v1()
            .await
            .unwrap_err();
        assert_eq!(sticky.stop, DirectLiveReplayStopV1::EpochInvalid);
        assert_eq!(sticky.report, DirectLiveReplayReportV1::default());
    }

    #[tokio::test]
    async fn direct_live_known_non_direct_does_not_advance_ratchet_or_sqlcipher() {
        let mut fixture = DirectLiveReplayFixture::new();
        let peer = fixture.add_peer();
        let direct_conversation_id = fixture.peers[peer].conversation_id.clone();
        let baseline = fixture.peers[peer].next_event("establish Direct receive state");
        fixture.enqueue(vec![baseline]);
        assert_eq!(
            fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap()
                .stored,
            1
        );
        let channel_id =
            uuid::Uuid::from_u128(0x6000_0000_0000_0000_0000_0000_0000_0002).to_string();
        fixture.receiver.mark_channel_conversation(&channel_id);
        let mut channel_event = fixture.peers[peer].next_event("known channel");
        if let ConnectionEvent::MessageReceived {
            conversation_id, ..
        } = &mut channel_event
        {
            *conversation_id = channel_id.clone();
        }
        let sender_identity_key = fixture.peers[peer].sender_identity_key;
        let ratchet_before =
            runtime_ratchet_fingerprint_v1(&fixture.receiver, &sender_identity_key);
        let otk_before = runtime_otk_fingerprint_v1(&fixture.receiver);
        let durable_ratchet_before =
            durable_ratchet_fingerprint_v1(fixture.receiver.db().unwrap(), &sender_identity_key);
        let durable_prekeys_before =
            durable_prekey_public_fingerprint_v1(fixture.receiver.db().unwrap());
        let sql_changes_before: i64 = fixture
            .receiver
            .db()
            .unwrap()
            .conn()
            .query_row("SELECT total_changes()", [], |row| row.get(0))
            .unwrap();
        let direct_messages_before = direct_message_projection_fingerprint_v1(
            fixture.receiver.db().unwrap(),
            &direct_conversation_id,
        );
        fixture.enqueue(vec![channel_event]);

        assert_eq!(
            fixture
                .receiver
                .replay_direct_live_events_v1()
                .await
                .unwrap(),
            DirectLiveReplayReportV1 {
                consumed: 1,
                ignored: 1,
                quiescent: true,
                ..DirectLiveReplayReportV1::default()
            }
        );
        assert_eq!(
            runtime_ratchet_fingerprint_v1(&fixture.receiver, &sender_identity_key),
            ratchet_before
        );
        assert_eq!(runtime_otk_fingerprint_v1(&fixture.receiver), otk_before);
        assert_eq!(
            durable_ratchet_fingerprint_v1(fixture.receiver.db().unwrap(), &sender_identity_key),
            durable_ratchet_before
        );
        assert_eq!(
            durable_prekey_public_fingerprint_v1(fixture.receiver.db().unwrap()),
            durable_prekeys_before
        );
        assert_eq!(
            fixture
                .receiver
                .db()
                .unwrap()
                .conn()
                .query_row("SELECT total_changes()", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            sql_changes_before
        );
        assert!(fixture
            .receiver
            .db()
            .unwrap()
            .get_messages(&channel_id, 10)
            .unwrap()
            .is_empty());
        assert_eq!(
            direct_message_projection_fingerprint_v1(
                fixture.receiver.db().unwrap(),
                &direct_conversation_id
            ),
            direct_messages_before
        );
    }

    #[test]
    fn dm_encryption_fails_closed_without_binding_or_session() {
        let peer = IdentityKeyPair::generate().x25519_public_bytes();
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());

        let err = client.encrypt_outgoing("unknown", "secret").unwrap_err();
        assert!(err.contains("not bound to a peer"));

        client.bind_dm_conversation("dm-1", peer).unwrap();
        let err = client.encrypt_outgoing("dm-1", "secret").unwrap_err();
        assert!(err.contains("no ratchet session"));
    }

    #[test]
    fn network_decryption_rejects_plaintext_and_unknown_headers() {
        let sender = [7u8; 32];
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());

        let missing = client
            .decrypt_from(&sender, "dm-1", &[], b"server-visible secret")
            .unwrap_err();
        assert!(missing.contains("missing E2E header"));

        let unknown = client
            .decrypt_from(&sender, "dm-1", &[0xff], b"server-visible secret")
            .unwrap_err();
        assert!(unknown.contains("unknown E2E header type"));

        assert!(client
            .process_ratchet_plaintext(&sender, Vec::new())
            .is_err());
        assert!(client
            .process_ratchet_plaintext(&sender, b"legacy unprefixed".to_vec())
            .is_err());
        match client
            .process_ratchet_plaintext(&sender, VeilClient::wrap_text_inner(""))
            .unwrap()
        {
            DecryptedPayload::Text(text) => assert!(text.is_empty()),
            DecryptedPayload::Control => panic!("empty text decoded as control"),
        }
    }

    fn test_peer_prekey_bundle() -> ([u8; 32], x3dh::PreKeyBundle) {
        let peer_identity = IdentityKeyPair::generate();
        let peer_identity_key = peer_identity.x25519_public_bytes();
        let peer_signing_key = peer_identity.ed25519_public_bytes();
        let mut peer = VeilClient::from_identity(peer_identity);
        let peer_prekeys = peer.generate_prekeys().unwrap();
        let (one_time_prekey, one_time_prekey_id) = peer_prekeys.otk_publics[0];
        (
            peer_identity_key,
            x3dh::PreKeyBundle {
                identity_key: peer_identity_key,
                signing_key: peer_signing_key,
                signed_prekey: peer_prekeys.spk_public,
                signed_prekey_signature: peer_prekeys.spk_signature,
                signed_prekey_id: peer_prekeys.spk_id,
                one_time_prekey: Some(one_time_prekey),
                one_time_prekey_id: Some(one_time_prekey_id),
            },
        )
    }

    #[test]
    fn establish_session_rejects_peer_bundle_identity_mismatch_without_mutation() {
        let mnemonic = generate_mnemonic().to_string();
        let path = std::env::temp_dir().join(format!(
            "veil-establish-session-identity-mismatch-{}.db",
            uuid::Uuid::new_v4()
        ));
        remove_test_database(&path);

        let mut client = VeilClient::new();
        client.init_with_mnemonic(&mnemonic, &path).unwrap();
        let local_identity_before = client.identity_key().unwrap();
        let (bundle_identity_key, bundle) = test_peer_prekey_bundle();
        let requested_peer_identity_key = IdentityKeyPair::generate().x25519_public_bytes();
        assert_ne!(requested_peer_identity_key, bundle_identity_key);
        assert!(client.ratchet_sessions.is_empty());
        assert!(client.pending_initial_headers.is_empty());
        assert!(client
            .db()
            .unwrap()
            .load_pending_initial_headers()
            .unwrap()
            .is_empty());

        let error = client
            .establish_session(&requested_peer_identity_key, &bundle)
            .unwrap_err();

        assert_eq!(
            error,
            "peer identity key does not match prekey bundle identity"
        );
        assert_eq!(client.identity_key().unwrap(), local_identity_before);
        assert!(!client.has_session(&requested_peer_identity_key));
        assert!(!client.has_session(&bundle_identity_key));
        assert!(client.ratchet_sessions.is_empty());
        assert!(client.pending_initial_headers.is_empty());
        assert!(client.pending_initial_sequences.is_empty());
        assert!(client
            .db()
            .unwrap()
            .load_ratchet_session(&requested_peer_identity_key)
            .unwrap()
            .is_none());
        assert!(client
            .db()
            .unwrap()
            .load_ratchet_session(&bundle_identity_key)
            .unwrap()
            .is_none());
        assert!(client
            .db()
            .unwrap()
            .load_pending_initial_headers()
            .unwrap()
            .is_empty());
        drop(client);

        let mut reopened = VeilClient::new();
        reopened.init_with_mnemonic(&mnemonic, &path).unwrap();
        assert!(!reopened.has_session(&requested_peer_identity_key));
        assert!(!reopened.has_session(&bundle_identity_key));
        assert!(reopened.pending_initial_headers.is_empty());
        assert!(reopened
            .db()
            .unwrap()
            .load_pending_initial_headers()
            .unwrap()
            .is_empty());
        drop(reopened);
        remove_test_database(&path);
    }

    #[test]
    fn establish_session_matching_peer_persists_only_the_exact_session() {
        let mnemonic = generate_mnemonic().to_string();
        let path = std::env::temp_dir().join(format!(
            "veil-establish-session-identity-match-{}.db",
            uuid::Uuid::new_v4()
        ));
        remove_test_database(&path);

        let mut client = VeilClient::new();
        client.init_with_mnemonic(&mnemonic, &path).unwrap();
        let (peer_identity_key, bundle) = test_peer_prekey_bundle();
        assert_eq!(peer_identity_key, bundle.identity_key);

        client
            .establish_session(&peer_identity_key, &bundle)
            .unwrap();

        assert!(client.has_session(&peer_identity_key));
        assert_eq!(client.ratchet_sessions.len(), 1);
        assert_eq!(client.pending_initial_headers.len(), 1);
        assert!(client
            .pending_initial_headers
            .contains_key(&peer_identity_key));
        let persisted_session = client
            .db()
            .unwrap()
            .load_ratchet_session(&peer_identity_key)
            .unwrap()
            .expect("matching peer session must be durable");
        let persisted_headers = client.db().unwrap().load_pending_initial_headers().unwrap();
        assert_eq!(persisted_headers.len(), 1);
        assert_eq!(persisted_headers[0].0, peer_identity_key);
        drop(client);

        let mut reopened = VeilClient::new();
        reopened.init_with_mnemonic(&mnemonic, &path).unwrap();
        assert!(reopened.has_session(&peer_identity_key));
        assert_eq!(reopened.ratchet_sessions.len(), 1);
        assert_eq!(reopened.pending_initial_headers.len(), 1);
        assert!(reopened
            .pending_initial_headers
            .contains_key(&peer_identity_key));
        assert_eq!(
            reopened
                .db()
                .unwrap()
                .load_ratchet_session(&peer_identity_key)
                .unwrap()
                .as_deref(),
            Some(persisted_session.as_slice())
        );
        assert_eq!(
            reopened
                .db()
                .unwrap()
                .load_pending_initial_headers()
                .unwrap(),
            persisted_headers
        );
        drop(reopened);
        remove_test_database(&path);
    }

    #[test]
    fn legacy_process_initial_refuses_existing_runtime_and_durable_sessions() {
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        let peer = IdentityKeyPair::generate().x25519_public_bytes();
        let existing = RatchetSession::init_initiator(&[0x61; 32], &peer);
        let existing_bytes = existing.serialize().unwrap();
        client.ratchet_sessions.insert(peer, existing);

        let error = client
            .process_initial_message(&peer, &[0x62; 32], 1, None)
            .unwrap_err();
        assert!(error.contains("already exists"));
        assert!(!client.direct_live_storage_uncertain);
        assert!(client
            .ratchet_sessions
            .get(&peer)
            .unwrap()
            .matches_serialized_v1(&existing_bytes)
            .unwrap());

        let durable_peer = IdentityKeyPair::generate().x25519_public_bytes();
        let db = VeilDb::open_memory(&[0x63; 32]).unwrap();
        db.commit_initial_ratchet_session(&durable_peer, &existing_bytes, None)
            .unwrap();
        client.db = Some(db);
        let error = client
            .process_initial_message(&durable_peer, &[0x64; 32], 2, None)
            .unwrap_err();
        assert!(error.contains("durable ratchet session"));
        assert!(!client.direct_live_storage_uncertain);
        assert!(!client.ratchet_sessions.contains_key(&durable_peer));
        let durable = client
            .db()
            .unwrap()
            .load_ratchet_session_with_revision_v1(&durable_peer)
            .unwrap()
            .unwrap();
        assert_eq!(durable.session_data, existing_bytes);
        assert_eq!(durable.revision, 0);
    }

    #[test]
    fn corrupt_ratchet_reopen_fails_closed_without_replacement() {
        let mnemonic = generate_mnemonic().to_string();
        let path = std::env::temp_dir().join(format!(
            "veil-corrupt-ratchet-reopen-{}.db",
            uuid::Uuid::new_v4()
        ));
        remove_test_database(&path);

        let mut seeded = VeilClient::new();
        seeded.init_with_mnemonic(&mnemonic, &path).unwrap();
        let (peer_identity_key, bundle) = test_peer_prekey_bundle();
        seeded
            .establish_session(&peer_identity_key, &bundle)
            .unwrap();
        seeded
            .db()
            .unwrap()
            .upsert_directory_conversation(
                "6a84c960-1d0c-4b83-b0b6-22387f40e8d1",
                ConversationType::DM as u8,
                "https://corrupt-ratchet.test:443",
                Some("Corrupt Ratchet Peer"),
                Some("5fdf3a20-a1df-4c55-9834-609bacade83a"),
                Some(peer_identity_key.as_slice()),
                None,
                "2026-07-20T00:00:00Z",
            )
            .unwrap();
        seeded
            .db()
            .unwrap()
            .clear_pending_initial_header(&peer_identity_key)
            .unwrap();
        let stored = seeded
            .db()
            .unwrap()
            .load_ratchet_session_with_revision_v1(&peer_identity_key)
            .unwrap()
            .unwrap();
        let mut corrupted = String::from_utf8(stored.session_data.to_vec()).unwrap();
        corrupted = corrupted.replacen(
            "\"skipped_keys\":{}",
            "\"skipped_keys\":{\"malformed\":\"AA==\"}",
            1,
        );
        let changed = seeded
            .db()
            .unwrap()
            .conn()
            .execute(
                "UPDATE ratchet_sessions SET session_data = ?1
                 WHERE peer_identity_key = ?2",
                rusqlite::params![corrupted.as_bytes(), peer_identity_key.as_slice()],
            )
            .unwrap();
        assert_eq!(changed, 1);
        let expected_revision = stored.revision;
        drop(stored);
        drop(seeded);

        let mut reopened = VeilClient::new();
        let error = reopened.init_with_mnemonic(&mnemonic, &path).unwrap_err();
        assert!(error.contains("decode persisted ratchet session"));
        assert!(reopened.direct_live_storage_uncertain);
        assert!(reopened.db().is_none());
        assert!(reopened.identity.is_none());
        assert!(reopened.ratchet_sessions.is_empty());
        assert!(reopened.pending_initial_headers.is_empty());

        let db_key = Zeroizing::new(kdf::derive_db_key(&mnemonic).unwrap());
        let inspection = VeilDb::open(&path, &db_key).unwrap();
        let unchanged = inspection
            .load_ratchet_session_with_revision_v1(&peer_identity_key)
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.session_data, corrupted.as_bytes());
        assert_eq!(unchanged.revision, expected_revision);
        assert!(inspection
            .load_pending_initial_headers()
            .unwrap()
            .is_empty());

        drop(unchanged);
        drop(inspection);
        corrupted.zeroize();
        remove_test_database(&path);
    }

    #[test]
    fn x3dh_header_repeats_until_authenticated_peer_possession() {
        let alice_identity = IdentityKeyPair::generate();
        let alice_key = alice_identity.x25519_public_bytes();
        let bob_identity = IdentityKeyPair::generate();
        let bob_key = bob_identity.x25519_public_bytes();
        let bob_signing_key = bob_identity.ed25519_public_bytes();

        let mut alice = VeilClient::from_identity(alice_identity);
        let mut bob = VeilClient::from_identity(bob_identity);
        let bob_prekeys = bob.generate_prekeys().unwrap();
        let (opk, opk_id) = bob_prekeys.otk_publics[0];
        let bundle = x3dh::PreKeyBundle {
            identity_key: bob_key,
            signing_key: bob_signing_key,
            signed_prekey: bob_prekeys.spk_public,
            signed_prekey_signature: bob_prekeys.spk_signature,
            signed_prekey_id: bob_prekeys.spk_id,
            one_time_prekey: Some(opk),
            one_time_prekey_id: Some(opk_id),
        };

        alice.establish_session(&bob_key, &bundle).unwrap();
        alice.bind_dm_conversation("dm-1", bob_key).unwrap();

        let (ciphertext, initial_header) = alice.encrypt_outgoing("dm-1", "top secret").unwrap();
        assert_eq!(initial_header[0], HEADER_INITIAL);
        assert!(!initial_header.is_empty());
        assert_ne!(ciphertext, b"top secret");

        // Conversation/identity metadata is authenticated and a forged first
        // packet must not consume Bob's OPK or install a partial session.
        assert!(bob
            .decrypt_from(&alice_key, "wrong-dm", &initial_header, &ciphertext)
            .is_err());
        assert!(!bob.has_session(&alice_key));

        // Simulate the first stored packet being deleted before Bob fetches it.
        // A server ACK alone must not switch Alice to a bare ratchet header.
        alice.pending_initial_sequences.insert(1, bob_key);
        alice.confirm_initial_message(1).unwrap();
        let (second_ciphertext, repeated_initial_header) =
            alice.encrypt_outgoing("dm-1", "second").unwrap();
        assert_eq!(repeated_initial_header[0], HEADER_INITIAL);
        let second = bob
            .decrypt_from(
                &alice_key,
                "dm-1",
                &repeated_initial_header,
                &second_ciphertext,
            )
            .unwrap();
        match second {
            DecryptedPayload::Text(text) => assert_eq!(text, b"second"),
            DecryptedPayload::Control => panic!("text decoded as control frame"),
        }

        // This helper is called transactionally only after an authenticated
        // inbound DM; from that point the compact ratchet header is safe.
        alice.confirm_peer_session_possession(&bob_key).unwrap();
        let (third_ciphertext, ratchet_header) = alice.encrypt_outgoing("dm-1", "third").unwrap();
        assert_eq!(ratchet_header[0], HEADER_RATCHET);
        let third = bob
            .decrypt_from(&alice_key, "dm-1", &ratchet_header, &third_ciphertext)
            .unwrap();
        match third {
            DecryptedPayload::Text(text) => assert_eq!(text, b"third"),
            DecryptedPayload::Control => panic!("text decoded as control frame"),
        }
    }

    #[test]
    fn direct_v2_roundtrip_binds_origin_accounts_devices_session_and_rejects_downgrade() {
        let origin = "https://direct-v2.example.test:443";
        let conversation_id = "550e8400-e29b-41d4-a716-446655440210";
        let alice_user = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440211").unwrap();
        let bob_user = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440212").unwrap();
        let alice_account = IdentityKeyPair::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let bob_account = IdentityKeyPair::from_mnemonic(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap();
        let alice_key = alice_account.x25519_public_bytes();
        let alice_signing = alice_account.ed25519_public_bytes();
        let bob_key = bob_account.x25519_public_bytes();
        let bob_signing = bob_account.ed25519_public_bytes();
        let mut alice =
            memory_client_with_device(alice_account, alice_user, [0xa1; 16], [0x31; 32]);
        let mut bob = memory_client_with_device(bob_account, bob_user, [0xb1; 16], [0x41; 32]);
        for client in [&mut alice, &mut bob] {
            client.authenticated_server_origin = Some(origin.to_string());
        }
        alice.known_user_keys.insert(bob_user.to_string(), bob_key);
        alice.trusted_signing_keys.insert(bob_key, bob_signing);
        alice
            .dm_conversations
            .insert(conversation_id.to_string(), bob_key);
        bob.known_user_keys
            .insert(alice_user.to_string(), alice_key);
        bob.trusted_signing_keys.insert(alice_key, alice_signing);
        bob.dm_conversations
            .insert(conversation_id.to_string(), alice_key);
        bob.db()
            .unwrap()
            .upsert_directory_conversation(
                conversation_id,
                ConversationType::DM as u8,
                origin,
                Some("Alice"),
                Some(&alice_user.to_string()),
                Some(&alice_key),
                None,
                "2026-08-30T00:00:00Z",
            )
            .unwrap();

        let bob_prekeys = bob.generate_prekeys().unwrap();
        let (one_time_prekey, one_time_prekey_id) = bob_prekeys.otk_publics[0];
        let bundle = x3dh::PreKeyBundle {
            identity_key: bob_key,
            signing_key: bob_signing,
            signed_prekey: bob_prekeys.spk_public,
            signed_prekey_signature: bob_prekeys.spk_signature,
            signed_prekey_id: bob_prekeys.spk_id,
            one_time_prekey: Some(one_time_prekey),
            one_time_prekey_id: Some(one_time_prekey_id),
        };
        let bob_binding = bob.device_identity.as_ref().unwrap().binding().clone();
        let context = alice
            .direct_v2_initiator_context(
                conversation_id,
                &bob_user.to_string(),
                bob_key,
                bob_signing,
                DirectDeviceCoordinateV2 {
                    device_id: bob_binding.device_id,
                    binding_version: bob_binding.version,
                    capabilities: bob_binding.capabilities,
                    status: bob_binding.status,
                    identity_key: bob_binding.device_identity_key,
                    signing_key: bob_binding.device_signing_key,
                    account_signature: bob_binding.account_signature,
                },
            )
            .unwrap();
        alice
            .establish_session_classified_v2(&bob_key, &bundle, context)
            .unwrap();
        let session_id = alice.direct_v2_sessions.get(&bob_key).unwrap().session_id();
        let alice_binding = alice.device_identity.as_ref().unwrap().binding().clone();
        let alice_to_bob = MessageSecurityContextV1::DirectV2(DirectMessageSecurityContextV2 {
            sender_user_id: alice_user.to_string(),
            sender_device_id: alice_binding.device_id,
            sender_binding_version: alice_binding.version,
            sender_device_identity_key: alice_binding.device_identity_key,
            sender_device_signing_key: alice_binding.device_signing_key,
            sender_device_capabilities: alice_binding.capabilities,
            sender_device_binding_status: alice_binding.status,
            sender_account_signature: alice_binding.account_signature,
            target_device_id: bob_binding.device_id,
            target_binding_version: bob_binding.version,
            direct_session_id: session_id,
        });
        let (ciphertext, header) = alice.encrypt_outgoing(conversation_id, "v2 first").unwrap();
        assert_eq!(header[0], HEADER_INITIAL_V2);
        assert_eq!(&header[1..33], session_id.as_slice());
        match bob
            .decrypt_from_with_security_context(
                &alice_key,
                conversation_id,
                &header,
                &ciphertext,
                Some(&alice_to_bob),
            )
            .unwrap()
        {
            DecryptedPayload::Text(plaintext) => assert_eq!(plaintext, b"v2 first"),
            DecryptedPayload::Control => panic!("Direct v2 text decoded as control"),
        }
        bob.db()
            .unwrap()
            .insert_message(
                "550e8400-e29b-41d4-a716-446655440213",
                conversation_id,
                &alice_key,
                "before edit",
                false,
                Some(1),
                None,
            )
            .unwrap();
        let (edit_ciphertext, edit_header) = alice
            .encrypt_outgoing(conversation_id, "v2 edited")
            .unwrap();
        assert_eq!(
            bob.receive_and_persist_edit(
                "550e8400-e29b-41d4-a716-446655440213",
                conversation_id,
                &alice_key,
                None,
                None,
                false,
                Some(&alice_to_bob),
                &edit_header,
                &edit_ciphertext,
                None,
            )
            .unwrap(),
            "v2 edited"
        );
        assert_eq!(
            bob.db().unwrap().get_messages(conversation_id, 10).unwrap()[0].plaintext,
            "v2 edited"
        );
        assert_eq!(
            bob.direct_v2_sessions.get(&alice_key).unwrap().session_id(),
            session_id
        );
        assert!(bob
            .db()
            .unwrap()
            .load_all_direct_session_bindings_v2()
            .unwrap()
            .iter()
            .any(|binding| binding.session_id == session_id));

        let bob_to_alice = MessageSecurityContextV1::DirectV2(DirectMessageSecurityContextV2 {
            sender_user_id: bob_user.to_string(),
            sender_device_id: bob_binding.device_id,
            sender_binding_version: bob_binding.version,
            sender_device_identity_key: bob_binding.device_identity_key,
            sender_device_signing_key: bob_binding.device_signing_key,
            sender_device_capabilities: bob_binding.capabilities,
            sender_device_binding_status: bob_binding.status,
            sender_account_signature: bob_binding.account_signature,
            target_device_id: alice_binding.device_id,
            target_binding_version: alice_binding.version,
            direct_session_id: session_id,
        });
        let (reply_ciphertext, reply_header) =
            bob.encrypt_outgoing(conversation_id, "v2 reply").unwrap();
        assert_eq!(reply_header[0], HEADER_RATCHET_V2);
        match alice
            .decrypt_from_with_security_context(
                &bob_key,
                conversation_id,
                &reply_header,
                &reply_ciphertext,
                Some(&bob_to_alice),
            )
            .unwrap()
        {
            DecryptedPayload::Text(plaintext) => assert_eq!(plaintext, b"v2 reply"),
            DecryptedPayload::Control => panic!("Direct v2 reply decoded as control"),
        }

        let mut substituted_context = alice_to_bob.clone();
        let MessageSecurityContextV1::DirectV2(substituted) = &mut substituted_context else {
            unreachable!();
        };
        substituted.target_binding_version += 1;
        assert!(bob
            .decrypt_from_with_security_context(
                &alice_key,
                conversation_id,
                &header,
                &ciphertext,
                Some(&substituted_context),
            )
            .is_err());
        assert!(bob
            .decrypt_from_with_security_context(
                &alice_key,
                conversation_id,
                &[HEADER_RATCHET],
                b"legacy downgrade",
                None,
            )
            .unwrap_err()
            .contains("downgrade"));
    }

    #[test]
    fn pending_x3dh_header_survives_restart_until_peer_receipt() {
        let mnemonic = generate_mnemonic().to_string();
        let path =
            std::env::temp_dir().join(format!("veil-pending-x3dh-{}.db", uuid::Uuid::new_v4()));
        let bob_identity = IdentityKeyPair::generate();
        let bob_key = bob_identity.x25519_public_bytes();
        let bob_signing = bob_identity.ed25519_public_bytes();
        let mut bob = VeilClient::from_identity(bob_identity);
        let prekeys = bob.generate_prekeys().unwrap();
        let (opk, opk_id) = prekeys.otk_publics[0];
        let bundle = x3dh::PreKeyBundle {
            identity_key: bob_key,
            signing_key: bob_signing,
            signed_prekey: prekeys.spk_public,
            signed_prekey_signature: prekeys.spk_signature,
            signed_prekey_id: prekeys.spk_id,
            one_time_prekey: Some(opk),
            one_time_prekey_id: Some(opk_id),
        };

        let mut alice = VeilClient::new();
        alice.init_with_mnemonic(&mnemonic, &path).unwrap();
        let alice_key = alice.identity_key().unwrap();
        alice.establish_session(&bob_key, &bundle).unwrap();
        alice
            .db()
            .unwrap()
            .upsert_directory_conversation(
                "dm-restart",
                ConversationType::DM as u8,
                "https://restart.test:443",
                Some("Bob"),
                Some("00000000-0000-0000-0000-000000000046"),
                Some(bob_key.as_slice()),
                None,
                "2026-07-12T00:00:00Z",
            )
            .unwrap();
        alice.bind_dm_conversation("dm-restart", bob_key).unwrap();
        let (_discarded_ciphertext, first_header) =
            alice.encrypt_outgoing("dm-restart", "discarded").unwrap();
        assert_eq!(first_header[0], HEADER_INITIAL);
        drop(alice);

        let mut restored = VeilClient::new();
        restored.init_with_mnemonic(&mnemonic, &path).unwrap();
        restored.pin_peer_signing_key(bob_key, bob_signing).unwrap();
        restored
            .bind_dm_conversation("dm-restart", bob_key)
            .unwrap();
        let (ciphertext, header) = restored
            .encrypt_outgoing("dm-restart", "after restart")
            .unwrap();
        assert_eq!(header[0], HEADER_INITIAL);
        match bob
            .decrypt_from(&alice_key, "dm-restart", &header, &ciphertext)
            .unwrap()
        {
            DecryptedPayload::Text(plaintext) => assert_eq!(plaintext, b"after restart"),
            DecryptedPayload::Control => panic!("text decoded as control frame"),
        }
        bob.bind_dm_conversation("dm-restart", alice_key).unwrap();
        let (reply_ciphertext, reply_header) =
            bob.encrypt_outgoing("dm-restart", "receipt").unwrap();
        assert_eq!(
            restored
                .receive_and_persist_message(
                    "reply-message",
                    "dm-restart",
                    &bob_key,
                    None,
                    None,
                    false,
                    None,
                    Some("Bob"),
                    &reply_header,
                    &reply_ciphertext,
                    Some(2000),
                    None,
                    None,
                )
                .unwrap(),
            ReceiveMessageResult::Stored {
                plaintext: "receipt".to_string()
            }
        );
        assert!(!restored.pending_initial_headers.contains_key(&bob_key));
        assert!(restored
            .db()
            .unwrap()
            .load_pending_initial_headers()
            .unwrap()
            .is_empty());
        drop(restored);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn atomic_receive_rolls_back_crypto_state_when_message_insert_fails() {
        let alice_identity = IdentityKeyPair::generate();
        let alice_key = alice_identity.x25519_public_bytes();
        let alice_signing = alice_identity.ed25519_public_bytes();
        let bob_identity = IdentityKeyPair::generate();
        let bob_key = bob_identity.x25519_public_bytes();
        let bob_signing = bob_identity.ed25519_public_bytes();

        let mut alice = VeilClient::from_identity(alice_identity);
        let mut bob = VeilClient::from_identity(bob_identity);
        let bob_path = std::env::temp_dir().join(format!(
            "veil-public-receive-revoke-{}.db",
            uuid::Uuid::new_v4()
        ));
        remove_test_database(&bob_path);
        let bob_db_key = [73u8; 32];
        bob.db = Some(VeilDb::open(&bob_path, &bob_db_key).unwrap());
        let author = AccountSnapshot {
            locator: veil_store::models::ProfileLocator {
                canonical_server_origin: "https://atomic.test:443".to_string(),
                user_id: "00000000-0000-0000-0000-000000000047".to_string(),
                identity_key: alice_key,
            },
            signing_key: alice_signing,
            username: Some("Alice".to_string()),
            display_name: Some("Alice Author".to_string()),
            profile_version: Some(1),
            profile_origin: "https://atomic.test:443".to_string(),
            source: veil_store::models::AccountSnapshotSource::AuthenticatedConversationDirectory,
            observed_at: "2026-07-12T00:00:00Z".to_string(),
        };
        bob.db()
            .unwrap()
            .upsert_identity_directory(std::slice::from_ref(&author))
            .unwrap();
        bob.db()
            .unwrap()
            .upsert_directory_conversation(
                "dm-atomic",
                0,
                "https://atomic.test:443",
                Some("Alice"),
                Some("00000000-0000-0000-0000-000000000047"),
                Some(alice_key.as_slice()),
                None,
                "2026-07-12T00:00:00Z",
            )
            .unwrap();
        bob.pin_peer_signing_key(alice_key, alice_signing).unwrap();

        let prekeys = bob.generate_prekeys().unwrap();
        let (opk, opk_id) = prekeys.otk_publics[0];
        alice
            .establish_session(
                &bob_key,
                &x3dh::PreKeyBundle {
                    identity_key: bob_key,
                    signing_key: bob_signing,
                    signed_prekey: prekeys.spk_public,
                    signed_prekey_signature: prekeys.spk_signature,
                    signed_prekey_id: prekeys.spk_id,
                    one_time_prekey: Some(opk),
                    one_time_prekey_id: Some(opk_id),
                },
            )
            .unwrap();
        alice.bind_dm_conversation("dm-atomic", bob_key).unwrap();
        let (ciphertext, header) = alice
            .encrypt_outgoing("dm-atomic", "transactional")
            .unwrap();

        // A formerly pinned but no-longer-current sender is rejected before
        // X3DH/ratchet or OTK state can advance.
        bob.replace_authorized_conversation_senders("dm-atomic", [bob_key])
            .unwrap();
        assert!(bob
            .receive_and_persist_live_message(
                "server-message",
                "dm-atomic",
                &alice_key,
                None,
                None,
                false,
                None,
                Some("Alice"),
                &header,
                &ciphertext,
                Some(1000),
                None,
                None,
            )
            .is_err());
        assert!(!bob.direct_live_storage_uncertain);
        assert!(bob.db().is_some());
        assert!(bob.identity.is_some());
        assert!(!bob.has_session(&alice_key));
        assert!(bob.otk_secrets.contains_key(&opk_id));
        bob.replace_authorized_conversation_senders("dm-atomic", [bob_key, alice_key])
            .unwrap();

        let mut wrong_origin_author = author.clone();
        wrong_origin_author.locator.canonical_server_origin = "https://other.test:443".to_string();
        wrong_origin_author.profile_origin = "https://other.test:443".to_string();
        assert!(bob
            .receive_and_persist_message(
                "server-message",
                "dm-atomic",
                &alice_key,
                Some(&wrong_origin_author),
                Some(MessageAuthorContext::DirectoryMemberAtObservation),
                false,
                None,
                Some("Alice"),
                &header,
                &ciphertext,
                Some(1000),
                None,
                None,
            )
            .is_err());
        assert!(!bob.direct_live_storage_uncertain);
        assert!(bob.db().is_some());
        assert!(bob.identity.is_some());
        assert!(!bob.has_session(&alice_key));
        assert!(bob.otk_secrets.contains_key(&opk_id));
        assert!(!bob.db().unwrap().message_exists("server-message").unwrap());

        bob.db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER reject_synced_message
                 BEFORE INSERT ON messages
                 BEGIN SELECT RAISE(ABORT, 'simulated message write failure'); END;",
            )
            .unwrap();
        assert!(bob
            .receive_and_persist_message(
                "server-message",
                "dm-atomic",
                &alice_key,
                Some(&author),
                Some(MessageAuthorContext::DirectoryMemberAtObservation),
                false,
                None,
                Some("Alice"),
                &header,
                &ciphertext,
                Some(1000),
                None,
                None,
            )
            .is_err());
        assert!(bob.direct_live_storage_uncertain);
        assert!(bob.connection.is_none());
        assert!(bob.authenticated_user_id.is_none());
        assert!(bob.authenticated_server_origin.is_none());
        assert!(bob.db().is_none());
        assert!(bob.identity.is_none());
        assert!(bob.device_identity.is_none());
        assert!(bob.ratchet_sessions.is_empty());
        assert!(bob.spk_secrets.is_empty());
        assert!(bob.otk_secrets.is_empty());
        assert!(!bob.has_session(&alice_key));
        assert_eq!(
            bob.direct_conversation_availability_v1("dm-atomic"),
            DirectConversationAvailabilityV1::RuntimeRevoked
        );

        let inspection_db = VeilDb::open(&bob_path, &bob_db_key).unwrap();
        inspection_db
            .conn()
            .execute_batch("DROP TRIGGER reject_synced_message")
            .unwrap();
        assert!(!inspection_db.message_exists("server-message").unwrap());
        assert!(inspection_db
            .load_ratchet_session(&alice_key)
            .unwrap()
            .is_none());
        assert!(inspection_db
            .load_local_prekeys()
            .unwrap()
            .iter()
            .any(|prekey| prekey.protocol_key_id == opk_id));
        drop(inspection_db);
        remove_test_database(&bob_path);
    }

    struct DuplicateReceiveFixture {
        alice: VeilClient,
        bob: VeilClient,
        alice_key: [u8; 32],
        bob_key: [u8; 32],
        bob_signing: [u8; 32],
        author: AccountSnapshot,
        header: Vec<u8>,
        ciphertext: Vec<u8>,
    }

    fn duplicate_receive_fixture() -> DuplicateReceiveFixture {
        duplicate_receive_fixture_with_db(VeilDb::open_memory(&[0xD7; 32]).unwrap())
    }

    fn duplicate_receive_fixture_with_db(db: VeilDb) -> DuplicateReceiveFixture {
        let alice_identity = IdentityKeyPair::generate();
        let alice_key = alice_identity.x25519_public_bytes();
        let alice_signing = alice_identity.ed25519_public_bytes();
        let bob_identity = IdentityKeyPair::generate();
        let bob_key = bob_identity.x25519_public_bytes();
        let bob_signing = bob_identity.ed25519_public_bytes();
        let mut alice = VeilClient::from_identity(alice_identity);
        let mut bob = VeilClient::from_identity(bob_identity);
        bob.db = Some(db);

        let author = AccountSnapshot {
            locator: veil_store::models::ProfileLocator {
                canonical_server_origin: "https://duplicate.test:443".to_string(),
                user_id: "00000000-0000-0000-0000-0000000000d7".to_string(),
                identity_key: alice_key,
            },
            signing_key: alice_signing,
            username: Some("Alice".to_string()),
            display_name: Some("Alice Duplicate".to_string()),
            profile_version: Some(1),
            profile_origin: "https://duplicate.test:443".to_string(),
            source: veil_store::models::AccountSnapshotSource::AuthenticatedConversationDirectory,
            observed_at: "2026-07-18T00:00:00Z".to_string(),
        };
        bob.db()
            .unwrap()
            .upsert_identity_directory(std::slice::from_ref(&author))
            .unwrap();
        bob.db()
            .unwrap()
            .upsert_directory_conversation(
                "dm-duplicate",
                0,
                "https://duplicate.test:443",
                Some("Alice"),
                Some("00000000-0000-0000-0000-0000000000d7"),
                Some(alice_key.as_slice()),
                None,
                "2026-07-18T00:00:00Z",
            )
            .unwrap();
        bob.pin_peer_signing_key(alice_key, alice_signing).unwrap();

        let prekeys = bob.generate_prekeys().unwrap();
        let (opk, opk_id) = prekeys.otk_publics[0];
        alice
            .establish_session(
                &bob_key,
                &x3dh::PreKeyBundle {
                    identity_key: bob_key,
                    signing_key: bob_signing,
                    signed_prekey: prekeys.spk_public,
                    signed_prekey_signature: prekeys.spk_signature,
                    signed_prekey_id: prekeys.spk_id,
                    one_time_prekey: Some(opk),
                    one_time_prekey_id: Some(opk_id),
                },
            )
            .unwrap();
        alice.bind_dm_conversation("dm-duplicate", bob_key).unwrap();
        let (ciphertext, header) = alice
            .encrypt_outgoing("dm-duplicate", "duplicate fixture")
            .unwrap();
        assert_eq!(
            bob.receive_and_persist_message(
                "duplicate-message",
                "dm-duplicate",
                &alice_key,
                Some(&author),
                Some(MessageAuthorContext::DirectoryMemberAtObservation),
                false,
                None,
                Some("Alice"),
                &header,
                &ciphertext,
                Some(1700),
                None,
                None,
            )
            .unwrap(),
            ReceiveMessageResult::Stored {
                plaintext: "duplicate fixture".to_string(),
            }
        );

        DuplicateReceiveFixture {
            alice,
            bob,
            alice_key,
            bob_key,
            bob_signing,
            author,
            header,
            ciphertext,
        }
    }

    fn duplicate_ratchet_state(client: &VeilClient, peer_key: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let runtime = serde_json::to_vec(
            client
                .ratchet_sessions
                .get(peer_key)
                .expect("stored fixture message established a ratchet"),
        )
        .unwrap();
        let persisted = client
            .db()
            .unwrap()
            .load_ratchet_session(peer_key)
            .unwrap()
            .expect("stored fixture message persisted its ratchet");
        (runtime, persisted)
    }

    #[test]
    fn rejected_control_frame_restores_sender_key_pending_and_ratchet_state() {
        let mut fixture = duplicate_receive_fixture();
        fixture
            .bob
            .bind_dm_conversation("dm-duplicate", fixture.alice_key)
            .unwrap();
        let group_id = "control-frame-rollback";
        let distribution = fixture
            .alice
            .sender_keys
            .create_outgoing(group_id, &fixture.alice_key);
        let distribution_json = Zeroizing::new(serde_json::to_vec(&distribution).unwrap());
        let mut inner = Zeroizing::new(Vec::with_capacity(1 + distribution_json.len()));
        inner.push(INNER_SKDM);
        inner.extend_from_slice(&distribution_json);
        let (ciphertext, header) = fixture
            .alice
            .encrypt_for_conversation_classified_v1(
                &fixture.bob_key,
                "dm-duplicate",
                inner.as_slice(),
            )
            .unwrap();

        let pending_before = fixture.bob.sender_key_distribution_pending.clone();
        let channels_before = fixture.bob.channel_conversations.clone();
        let runtime_before = fixture
            .bob
            .ratchet_sessions
            .get(&fixture.alice_key)
            .unwrap()
            .serialize()
            .unwrap();
        let durable_before = fixture
            .bob
            .db()
            .unwrap()
            .load_ratchet_session_with_revision_v1(&fixture.alice_key)
            .unwrap()
            .unwrap();
        let message_count_before = fixture
            .bob
            .db()
            .unwrap()
            .get_messages("dm-duplicate", 10)
            .unwrap()
            .len();

        let error = fixture
            .bob
            .receive_and_persist_message(
                "rejected-control-frame",
                "dm-duplicate",
                &fixture.alice_key,
                Some(&fixture.author),
                Some(MessageAuthorContext::DirectoryMemberAtObservation),
                false,
                None,
                Some("Alice"),
                &header,
                &ciphertext,
                Some(1800),
                None,
                None,
            )
            .unwrap_err();
        assert!(error.contains("control frame is not valid"));
        assert!(!fixture.bob.direct_live_storage_uncertain);
        assert!(fixture.bob.db().is_some());
        assert_eq!(fixture.bob.sender_key_distribution_pending, pending_before);
        assert_eq!(fixture.bob.channel_conversations, channels_before);
        assert!(!fixture
            .bob
            .sender_keys
            .has_incoming(group_id, &fixture.alice_key));
        assert!(fixture
            .bob
            .ratchet_sessions
            .get(&fixture.alice_key)
            .unwrap()
            .matches_serialized_v1(&runtime_before)
            .unwrap());
        let durable_after = fixture
            .bob
            .db()
            .unwrap()
            .load_ratchet_session_with_revision_v1(&fixture.alice_key)
            .unwrap()
            .unwrap();
        assert_eq!(durable_after.session_data, durable_before.session_data);
        assert_eq!(durable_after.revision, durable_before.revision);
        assert!(fixture
            .bob
            .db()
            .unwrap()
            .load_incoming_sender_key_generations_for_group(group_id)
            .unwrap()
            .is_empty());
        assert_eq!(
            fixture
                .bob
                .db()
                .unwrap()
                .get_messages("dm-duplicate", 10)
                .unwrap()
                .len(),
            message_count_before
        );
        assert!(!fixture
            .bob
            .db()
            .unwrap()
            .message_exists("rejected-control-frame")
            .unwrap());
    }

    #[test]
    fn encrypted_edit_success_and_ciphertext_rejection_preserve_epoch_semantics() {
        let mut fixture = duplicate_receive_fixture();
        fixture
            .bob
            .bind_dm_conversation("dm-duplicate", fixture.alice_key)
            .unwrap();
        let ratchet_before = runtime_ratchet_fingerprint_v1(&fixture.bob, &fixture.alice_key);

        let rejected = fixture
            .bob
            .receive_and_persist_edit(
                "duplicate-message",
                "dm-duplicate",
                &fixture.alice_key,
                Some(&fixture.author),
                Some(MessageAuthorContext::DirectoryMemberAtObservation),
                false,
                None,
                &[HEADER_RATCHET],
                &[0xFF],
                None,
            )
            .unwrap_err();
        assert!(rejected.contains("invalid Direct history ratchet header length"));
        assert!(!fixture.bob.direct_live_storage_uncertain);
        assert!(fixture.bob.db().is_some());
        assert!(fixture.bob.identity.is_some());
        assert!(fixture.bob.has_session(&fixture.alice_key));
        assert_eq!(
            runtime_ratchet_fingerprint_v1(&fixture.bob, &fixture.alice_key),
            ratchet_before
        );

        let (ciphertext, header) = fixture
            .alice
            .encrypt_outgoing("dm-duplicate", "edited successfully")
            .unwrap();
        assert_eq!(
            fixture
                .bob
                .receive_and_persist_edit(
                    "duplicate-message",
                    "dm-duplicate",
                    &fixture.alice_key,
                    Some(&fixture.author),
                    Some(MessageAuthorContext::DirectoryMemberAtObservation),
                    false,
                    None,
                    &header,
                    &ciphertext,
                    None,
                )
                .unwrap(),
            "edited successfully"
        );
        let messages = fixture
            .bob
            .db()
            .unwrap()
            .get_messages("dm-duplicate", 10)
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].plaintext, "edited successfully");
    }

    #[test]
    fn encrypted_edit_storage_failure_revokes_and_preserves_durable_state() {
        let path = std::env::temp_dir().join(format!(
            "veil-edit-storage-revoke-{}.db",
            uuid::Uuid::new_v4()
        ));
        remove_test_database(&path);
        let db_key = [0xD8; 32];
        let mut fixture = duplicate_receive_fixture_with_db(VeilDb::open(&path, &db_key).unwrap());
        fixture
            .bob
            .bind_dm_conversation("dm-duplicate", fixture.alice_key)
            .unwrap();
        let durable_ratchet_before =
            durable_ratchet_fingerprint_v1(fixture.bob.db().unwrap(), &fixture.alice_key);
        let (ciphertext, header) = fixture
            .alice
            .encrypt_outgoing("dm-duplicate", "must not commit")
            .unwrap();
        fixture
            .bob
            .db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER reject_public_edit
                 BEFORE UPDATE OF plaintext ON messages
                 BEGIN SELECT RAISE(ABORT, 'forced public edit failure'); END;",
            )
            .unwrap();

        let error = fixture
            .bob
            .receive_and_persist_edit(
                "duplicate-message",
                "dm-duplicate",
                &fixture.alice_key,
                Some(&fixture.author),
                Some(MessageAuthorContext::DirectoryMemberAtObservation),
                false,
                None,
                &header,
                &ciphertext,
                None,
            )
            .unwrap_err();
        assert!(error.contains("forced public edit failure"));
        assert_failed_initialization_epoch_is_scrubbed_v1(&fixture.bob, &fixture.alice_key);

        let inspection_db = VeilDb::open(&path, &db_key).unwrap();
        inspection_db
            .conn()
            .execute_batch("DROP TRIGGER reject_public_edit")
            .unwrap();
        let messages = inspection_db.get_messages("dm-duplicate", 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].plaintext, "duplicate fixture");
        assert_eq!(
            durable_ratchet_fingerprint_v1(&inspection_db, &fixture.alice_key),
            durable_ratchet_before
        );
        drop(inspection_db);
        drop(fixture);
        remove_test_database(&path);
    }

    #[test]
    fn remote_metadata_storage_failures_revoke_but_peer_rejections_do_not() {
        for variant in 0..2 {
            let mut fixture = duplicate_receive_fixture();
            fixture
                .bob
                .bind_dm_conversation("dm-duplicate", fixture.alice_key)
                .unwrap();
            let metadata = RemoteMessageMetadata {
                revision_ms: 1700,
                reactions: None,
            };
            let state = if variant == 0 {
                fixture
                    .bob
                    .db()
                    .unwrap()
                    .conn()
                    .execute_batch(
                        "CREATE TRIGGER reject_metadata_delete
                         BEFORE DELETE ON messages
                         BEGIN SELECT RAISE(ABORT, 'forced metadata delete failure'); END;",
                    )
                    .unwrap();
                RemoteMessageStateKind::Deleted
            } else {
                assert_eq!(
                    fixture
                        .bob
                        .reconcile_remote_message_metadata(
                            "duplicate-message",
                            "dm-duplicate",
                            &fixture.alice_key,
                            &metadata,
                            RemoteMessageStateKind::Active,
                        )
                        .unwrap(),
                    RemoteReconcileAction::Unchanged
                );
                fixture
                    .bob
                    .db()
                    .unwrap()
                    .conn()
                    .execute_batch(
                        "CREATE TRIGGER reject_metadata_unchanged
                         BEFORE INSERT ON remote_message_state
                         BEGIN SELECT RAISE(ABORT, 'forced unchanged metadata failure'); END;",
                    )
                    .unwrap();
                RemoteMessageStateKind::Active
            };

            assert!(fixture
                .bob
                .reconcile_remote_message_metadata(
                    "duplicate-message",
                    "dm-duplicate",
                    &fixture.alice_key,
                    &metadata,
                    state,
                )
                .is_err());
            assert_failed_initialization_epoch_is_scrubbed_v1(&fixture.bob, &fixture.alice_key);
        }

        let mut rejected = duplicate_receive_fixture();
        rejected
            .bob
            .bind_dm_conversation("dm-duplicate", rejected.alice_key)
            .unwrap();
        let wrong_sender = [0xE1; 32];
        let metadata = RemoteMessageMetadata {
            revision_ms: 1700,
            reactions: None,
        };
        let error = rejected
            .bob
            .reconcile_remote_message_metadata(
                "duplicate-message",
                "dm-duplicate",
                &wrong_sender,
                &metadata,
                RemoteMessageStateKind::Active,
            )
            .unwrap_err();
        assert!(error.contains("conflicts with its local binding"));
        assert!(!rejected.bob.direct_live_storage_uncertain);
        assert!(rejected.bob.db().is_some());
        assert!(rejected.bob.identity.is_some());
        assert!(rejected.bob.has_session(&rejected.alice_key));
        assert_eq!(
            rejected
                .bob
                .direct_conversation_availability_v1("dm-duplicate"),
            DirectConversationAvailabilityV1::Available
        );
    }

    fn assert_duplicate_rejected_without_mutation(
        fixture: &mut DuplicateReceiveFixture,
        message_id: &str,
        conversation_id: &str,
        sender_key: &[u8; 32],
        server_timestamp: Option<i64>,
    ) {
        let binding_before = fixture
            .bob
            .db()
            .unwrap()
            .get_message_binding(message_id)
            .unwrap();
        let ratchet_before = duplicate_ratchet_state(&fixture.bob, &fixture.alice_key);
        let (messages_before, conversations_before, authors_before): (i64, i64, i64) = fixture
            .bob
            .db()
            .unwrap()
            .conn()
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM messages),
                    (SELECT COUNT(*) FROM conversations),
                    (SELECT COUNT(*) FROM message_author_snapshots_v1)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert!(matches!(
            fixture
                .bob
                .receive_and_persist_message_with_attachments_classified(
                    message_id,
                    conversation_id,
                    sender_key,
                    Some(&fixture.author),
                    Some(MessageAuthorContext::DirectoryMemberAtObservation),
                    false,
                    None,
                    Some("Alice"),
                    &fixture.header,
                    &fixture.ciphertext,
                    server_timestamp,
                    None,
                    &[],
                    None,
                    AtomicReceiveDecryptMode::General,
                ),
            Err(DirectHistoryMutationError::ConversationRejected(_))
        ));
        assert_eq!(
            fixture
                .bob
                .db()
                .unwrap()
                .get_message_binding(message_id)
                .unwrap(),
            binding_before
        );
        assert_eq!(
            duplicate_ratchet_state(&fixture.bob, &fixture.alice_key),
            ratchet_before
        );
        assert_eq!(
            fixture
                .bob
                .db()
                .unwrap()
                .conn()
                .query_row(
                    "SELECT
                        (SELECT COUNT(*) FROM messages),
                        (SELECT COUNT(*) FROM conversations),
                        (SELECT COUNT(*) FROM message_author_snapshots_v1)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap(),
            (messages_before, conversations_before, authors_before)
        );
    }

    fn assert_exact_duplicate_without_mutation(
        fixture: &mut DuplicateReceiveFixture,
        presented_server_timestamp: Option<i64>,
    ) {
        let binding_before = fixture
            .bob
            .db()
            .unwrap()
            .get_message_binding("duplicate-message")
            .unwrap();
        let ratchet_before = duplicate_ratchet_state(&fixture.bob, &fixture.alice_key);
        let message_before = serde_json::to_vec(
            &fixture
                .bob
                .db()
                .unwrap()
                .get_messages("dm-duplicate", 10)
                .unwrap()[0],
        )
        .unwrap();

        assert_eq!(
            fixture
                .bob
                .receive_and_persist_message_with_attachments_classified(
                    "duplicate-message",
                    "dm-duplicate",
                    &fixture.alice_key,
                    None,
                    None,
                    false,
                    None,
                    Some("Alice"),
                    &fixture.header,
                    &fixture.ciphertext,
                    presented_server_timestamp,
                    None,
                    &[],
                    None,
                    AtomicReceiveDecryptMode::General,
                )
                .unwrap(),
            ReceiveMessageResult::Duplicate
        );
        assert_eq!(
            fixture
                .bob
                .db()
                .unwrap()
                .get_message_binding("duplicate-message")
                .unwrap(),
            binding_before
        );
        assert_eq!(
            duplicate_ratchet_state(&fixture.bob, &fixture.alice_key),
            ratchet_before
        );
        assert_eq!(
            serde_json::to_vec(
                &fixture
                    .bob
                    .db()
                    .unwrap()
                    .get_messages("dm-duplicate", 10)
                    .unwrap()[0],
            )
            .unwrap(),
            message_before
        );
    }

    #[test]
    fn exact_inbound_duplicate_does_not_advance_ratchet_and_attaches_author() {
        let mut fixture = duplicate_receive_fixture();
        fixture
            .bob
            .db()
            .unwrap()
            .conn()
            .execute(
                "DELETE FROM message_author_snapshots_v1 WHERE message_id = ?1",
                rusqlite::params!["duplicate-message"],
            )
            .unwrap();
        let binding_before = fixture
            .bob
            .db()
            .unwrap()
            .get_message_binding("duplicate-message")
            .unwrap();
        let ratchet_before = duplicate_ratchet_state(&fixture.bob, &fixture.alice_key);

        assert_eq!(
            fixture
                .bob
                .receive_and_persist_message_with_attachments_classified(
                    "duplicate-message",
                    "dm-duplicate",
                    &fixture.alice_key,
                    Some(&fixture.author),
                    Some(MessageAuthorContext::DirectoryMemberAtObservation),
                    false,
                    None,
                    Some("Alice"),
                    &fixture.header,
                    &fixture.ciphertext,
                    Some(1700),
                    None,
                    &[],
                    None,
                    AtomicReceiveDecryptMode::General,
                )
                .unwrap(),
            ReceiveMessageResult::Duplicate
        );
        assert_eq!(
            duplicate_ratchet_state(&fixture.bob, &fixture.alice_key),
            ratchet_before
        );
        assert_eq!(
            fixture
                .bob
                .db()
                .unwrap()
                .get_message_binding("duplicate-message")
                .unwrap(),
            binding_before
        );
        assert_eq!(
            fixture
                .bob
                .db()
                .unwrap()
                .get_messages("dm-duplicate", 10)
                .unwrap()[0]
                .author
                .as_ref(),
            Some(&fixture.author)
        );
    }

    #[test]
    fn duplicate_with_persisted_timestamp_accepts_missing_presented_timestamp() {
        let mut fixture = duplicate_receive_fixture();
        assert_eq!(
            fixture
                .bob
                .db()
                .unwrap()
                .get_message_binding("duplicate-message")
                .unwrap()
                .unwrap()
                .3,
            Some(1700)
        );
        assert_exact_duplicate_without_mutation(&mut fixture, None);
    }

    #[test]
    fn duplicate_with_missing_persisted_timestamp_accepts_presented_timestamp() {
        let mut fixture = duplicate_receive_fixture();
        fixture
            .bob
            .db()
            .unwrap()
            .conn()
            .execute(
                "UPDATE messages SET server_timestamp = NULL WHERE id = ?1",
                rusqlite::params!["duplicate-message"],
            )
            .unwrap();
        assert_eq!(
            fixture
                .bob
                .db()
                .unwrap()
                .get_message_binding("duplicate-message")
                .unwrap()
                .unwrap()
                .3,
            None
        );
        assert_exact_duplicate_without_mutation(&mut fixture, Some(1700));
    }

    #[test]
    fn conflicting_duplicate_binding_is_rejected_without_any_receive_mutation() {
        let mut fixture = duplicate_receive_fixture();
        fixture
            .bob
            .db()
            .unwrap()
            .conn()
            .execute(
                "DELETE FROM message_author_snapshots_v1 WHERE message_id = ?1",
                rusqlite::params!["duplicate-message"],
            )
            .unwrap();
        let mallory_identity = IdentityKeyPair::generate();
        let mallory_key = mallory_identity.x25519_public_bytes();
        fixture
            .bob
            .pin_peer_signing_key(mallory_key, mallory_identity.ed25519_public_bytes())
            .unwrap();
        let alice_key = fixture.alice_key;

        assert_duplicate_rejected_without_mutation(
            &mut fixture,
            "duplicate-message",
            "dm-other",
            &alice_key,
            Some(1700),
        );
        assert_duplicate_rejected_without_mutation(
            &mut fixture,
            "duplicate-message",
            "dm-duplicate",
            &mallory_key,
            Some(1700),
        );
        assert_duplicate_rejected_without_mutation(
            &mut fixture,
            "duplicate-message",
            "dm-duplicate",
            &alice_key,
            Some(1701),
        );

        fixture
            .bob
            .db()
            .unwrap()
            .conn()
            .execute(
                "UPDATE messages SET is_outgoing = 1 WHERE id = ?1",
                rusqlite::params!["duplicate-message"],
            )
            .unwrap();
        assert_duplicate_rejected_without_mutation(
            &mut fixture,
            "duplicate-message",
            "dm-duplicate",
            &alice_key,
            Some(1700),
        );
    }

    #[test]
    fn outgoing_duplicate_row_collision_is_rejected_by_inbound_receive() {
        let mut fixture = duplicate_receive_fixture();
        fixture
            .bob
            .pin_peer_signing_key(fixture.bob_key, fixture.bob_signing)
            .unwrap();
        fixture
            .bob
            .db()
            .unwrap()
            .insert_message(
                "own-duplicate-message",
                "dm-duplicate",
                &fixture.bob_key,
                "already sent",
                true,
                Some(1800),
                None,
            )
            .unwrap();
        let bob_key = fixture.bob_key;
        assert_duplicate_rejected_without_mutation(
            &mut fixture,
            "own-duplicate-message",
            "dm-duplicate",
            &bob_key,
            Some(1800),
        );
    }

    #[test]
    fn same_account_other_device_sender_key_duplicate_is_inbound_and_idempotent() {
        let user_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000d8").unwrap();
        let mut sender = memory_client_with_device(
            IdentityKeyPair::from_mnemonic(PREKEY_TEST_MNEMONIC).unwrap(),
            user_id,
            [0xD8; 16],
            [0xD9; 32],
        );
        let mut recipient = memory_client_with_device(
            IdentityKeyPair::from_mnemonic(PREKEY_TEST_MNEMONIC).unwrap(),
            user_id,
            [0xDA; 16],
            [0xDB; 32],
        );
        let account_identity_key = sender.identity_key().unwrap();
        assert_eq!(recipient.identity_key().unwrap(), account_identity_key);
        let conversation = "00000000-0000-0000-0000-0000000000d9";
        let roster = candidate_with_commitment(
            conversation,
            1,
            vec![
                roster_entry(
                    *user_id.as_bytes(),
                    sender.identity.as_ref().unwrap(),
                    sender.device_identity.as_ref().unwrap().binding(),
                ),
                roster_entry(
                    *user_id.as_bytes(),
                    recipient.identity.as_ref().unwrap(),
                    recipient.device_identity.as_ref().unwrap().binding(),
                ),
            ],
        );
        sender.mark_channel_conversation(conversation);
        recipient.mark_channel_conversation(conversation);
        sender.install_device_roster_v1(roster.clone()).unwrap();
        recipient.install_device_roster_v1(roster).unwrap();
        let target = sender
            .sender_key_device_targets(conversation)
            .unwrap()
            .into_iter()
            .find(|target| target.device_id == recipient.device_id)
            .unwrap();
        let (pending, sealed) = sender.prepare_sender_key_device_envelope(&target).unwrap();
        let route = route_for_test(&sender, &target, &pending);
        let sender_device_identity_key = route.sender_device_identity_key;
        recipient
            .process_sender_key_distribution_v1(&sealed, &route)
            .unwrap();
        sender.mark_sender_key_distributed(conversation).unwrap();
        let (ciphertext, header) = sender
            .encrypt_outgoing(conversation, "from my other device")
            .unwrap();
        let context = MessageSecurityContextV1::SenderKeyV5(SenderKeyMessageSecurityContextV1 {
            roster_version: route.roster_version,
            roster_commitment: route.roster_commitment,
            sender_device_id: route.sender_device_id,
            target_device_id: route.target_device_id,
            sender_binding_version: route.sender_binding_version,
        });
        assert_eq!(
            recipient
                .receive_and_persist_message(
                    "same-account-device-message",
                    conversation,
                    &account_identity_key,
                    None,
                    None,
                    true,
                    Some(&context),
                    Some("Own devices"),
                    &header,
                    &ciphertext,
                    Some(1900),
                    None,
                    None,
                )
                .unwrap(),
            ReceiveMessageResult::Stored {
                plaintext: "from my other device".to_string(),
            }
        );
        let binding_before = recipient
            .db()
            .unwrap()
            .get_message_binding("same-account-device-message")
            .unwrap();
        assert_eq!(
            binding_before,
            Some((
                conversation.to_string(),
                account_identity_key.to_vec(),
                false,
                Some(1900),
            ))
        );
        let runtime_sender_key_before = recipient
            .sender_keys
            .serialize_incoming(conversation, &sender_device_identity_key)
            .unwrap();
        let persisted_sender_keys = |client: &VeilClient| {
            client
                .db()
                .unwrap()
                .load_incoming_sender_key_generations_for_group(conversation)
                .unwrap()
                .into_iter()
                .map(|generation| {
                    (
                        generation.sender_identity_key,
                        generation.generation,
                        generation.iteration,
                        generation.state_revision,
                        generation.distribution_commitment,
                        generation.key_data.to_vec(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let persisted_sender_keys_before = persisted_sender_keys(&recipient);
        let message_before = serde_json::to_vec(
            &recipient
                .db()
                .unwrap()
                .get_messages(conversation, 10)
                .unwrap()[0],
        )
        .unwrap();

        assert_eq!(
            recipient
                .receive_and_persist_message_with_attachments_classified(
                    "same-account-device-message",
                    conversation,
                    &account_identity_key,
                    None,
                    None,
                    true,
                    Some(&context),
                    Some("Own devices"),
                    &header,
                    &ciphertext,
                    Some(1900),
                    None,
                    &[],
                    None,
                    AtomicReceiveDecryptMode::General,
                )
                .unwrap(),
            ReceiveMessageResult::Duplicate
        );
        assert_eq!(
            recipient
                .db()
                .unwrap()
                .get_message_binding("same-account-device-message")
                .unwrap(),
            binding_before
        );
        assert_eq!(
            &*recipient
                .sender_keys
                .serialize_incoming(conversation, &sender_device_identity_key)
                .unwrap(),
            &*runtime_sender_key_before
        );
        assert_eq!(
            persisted_sender_keys(&recipient),
            persisted_sender_keys_before
        );
        assert_eq!(
            serde_json::to_vec(
                &recipient
                    .db()
                    .unwrap()
                    .get_messages(conversation, 10)
                    .unwrap()[0],
            )
            .unwrap(),
            message_before
        );
    }

    #[test]
    #[allow(deprecated)]
    #[ignore = "superseded by exact-device Sender-Key v5 roster tests"]
    fn authenticated_skdm_requires_current_directory_authorization() {
        let alice_identity = IdentityKeyPair::generate();
        let alice_ik = alice_identity.x25519_public_bytes();
        let alice_signing = alice_identity.ed25519_public_bytes();
        let bob_identity = IdentityKeyPair::generate();
        let bob_ik = bob_identity.x25519_public_bytes();
        let mut alice = VeilClient::from_identity(alice_identity);
        let mut bob = VeilClient::from_identity(bob_identity);
        let group = "group-1";

        let distribution = alice.sender_keys.create_outgoing(group, &alice_ik);
        let payload = serde_json::to_vec(&distribution).unwrap();
        let wire = veil_crypto::sender_key::seal_skdm_authenticated(
            alice.identity.as_ref().unwrap(),
            &bob_ik,
            group,
            distribution.key_id,
            &payload,
        )
        .unwrap();

        assert!(bob
            .process_sealed_skdm(&wire, "wrong-group", distribution.key_id)
            .is_err());
        assert!(!bob.trusted_signing_keys.contains_key(&alice_ik));

        bob.mark_channel_conversation(group);
        assert!(bob
            .process_sealed_skdm(&wire, group, distribution.key_id)
            .is_err());
        assert!(!bob.sender_keys.has_incoming(group, &alice_ik));

        bob.pin_peer_signing_key(alice_ik, alice_signing).unwrap();
        bob.replace_authorized_conversation_senders(group, [bob_ik])
            .unwrap();
        assert!(bob
            .process_sealed_skdm(&wire, group, distribution.key_id)
            .is_err());
        assert!(!bob.sender_keys.has_incoming(group, &alice_ik));

        bob.replace_authorized_conversation_senders(group, [bob_ik, alice_ik])
            .unwrap();
        bob.process_sealed_skdm(&wire, group, distribution.key_id)
            .unwrap();
        assert!(bob.sender_keys.has_incoming(group, &alice_ik));
        let ciphertext = alice
            .sender_keys
            .encrypt_signed(group, alice.identity.as_ref().unwrap(), b"group secret")
            .unwrap();
        match bob
            .decrypt_from(&alice_ik, group, &[HEADER_SENDER_KEY], &ciphertext)
            .unwrap()
        {
            DecryptedPayload::Text(plaintext) => assert_eq!(plaintext, b"group secret"),
            DecryptedPayload::Control => panic!("signed group text decoded as control"),
        }
    }

    #[test]
    #[ignore = "superseded by exact-device Sender-Key v5 roster tests"]
    fn sender_key_send_unblocks_only_after_every_ack() {
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        client.rotate_sender_key("group-1").unwrap();
        let pending_10 = pending_sender_key(&client, "group-1", [10u8; 32]);
        let pending_11 = pending_sender_key(&client, "group-1", [11u8; 32]);
        client.pending_sender_key_sequences.insert(10, pending_10);
        client.pending_sender_key_sequences.insert(11, pending_11);

        client.confirm_sender_key_distribution(10, None).unwrap();
        assert!(client.sender_key_distribution_pending.contains("group-1"));
        client.confirm_sender_key_distribution(11, None).unwrap();
        assert!(!client.sender_key_distribution_pending.contains("group-1"));

        let generation_before_reconnect = client.sender_keys.serialize_outgoing("group-1").unwrap();
        client.rotate_sender_key("group-1").unwrap();
        let generation_after_reconnect = client.sender_keys.serialize_outgoing("group-1").unwrap();
        assert_ne!(&*generation_before_reconnect, &*generation_after_reconnect);
        assert!(client.sender_key_distribution_pending.contains("group-1"));
        let pending_12 = pending_sender_key(&client, "group-1", [12u8; 32]);
        client.pending_sender_key_sequences.insert(12, pending_12);
        client.reject_pending_sequence(12).unwrap();
        assert!(client.sender_key_distribution_pending.contains("group-1"));
        assert!(client.failed_sender_key_distributions.contains("group-1"));

        let generation_before_retry = client.sender_keys.serialize_outgoing("group-1").unwrap();
        assert!(client.begin_sender_key_distribution("group-1").unwrap());
        let generation_after_retry = client.sender_keys.serialize_outgoing("group-1").unwrap();
        assert_eq!(&*generation_before_retry, &*generation_after_retry);
        let pending_13 = pending_sender_key(&client, "group-1", [13u8; 32]);
        client.pending_sender_key_sequences.insert(13, pending_13);
        assert!(client.begin_sender_key_distribution("group-1").is_err());

        let our_identity = client.identity_key().unwrap();
        client
            .replace_authorized_conversation_senders("group-1", [our_identity])
            .unwrap();
        client.clear_all_authorized_conversation_senders();
        assert!(client
            .require_currently_authorized_sender("group-1", &our_identity)
            .is_err());
        assert!(client.sender_key_distribution_pending.contains("group-1"));
    }

    #[test]
    #[ignore = "superseded by exact-device Sender-Key v5 retry tests"]
    fn sender_key_lost_ack_retries_exact_persisted_envelopes() {
        let identity = IdentityKeyPair::generate();
        let sender_identity = identity.x25519_public_bytes();
        let target_a = [0x31u8; 32];
        let target_b = [0x32u8; 32];
        let conversation_id = "group-lost-skdm-ack";
        let mut client = VeilClient::from_identity(identity);
        client.db = Some(VeilDb::open_memory(&[0x93u8; 32]).unwrap());
        client.mark_channel_conversation(conversation_id);
        client.rotate_sender_key(conversation_id).unwrap();

        let (key_a, first_a) = client
            .prepare_sender_key_envelope(conversation_id, &target_a)
            .unwrap();
        let (key_b, first_b) = client
            .prepare_sender_key_envelope(conversation_id, &target_b)
            .unwrap();
        assert_eq!(key_a.generation, key_b.generation);
        assert_ne!(first_a, first_b, "recipient binding must change the seal");
        client
            .pending_sender_key_sequences
            .insert(101, key_a.clone());
        client
            .pending_sender_key_sequences
            .insert(102, key_b.clone());

        // One ACK arrives, then the connection dies before the second. The
        // full roster will be retried, so even the acknowledged target's bytes
        // must remain cached until the attempt completes as a whole.
        client.confirm_sender_key_distribution(101, None).unwrap();
        client.mark_pending_sequence_unknown(102).unwrap();
        assert!(client
            .failed_sender_key_distributions
            .contains(conversation_id));
        assert_eq!(
            client
                .db()
                .unwrap()
                .load_pending_sender_key_envelope(
                    conversation_id,
                    key_a.generation,
                    &target_a,
                    &sender_identity,
                )
                .unwrap()
                .unwrap(),
            first_a
        );

        assert!(client
            .begin_sender_key_distribution(conversation_id)
            .unwrap());
        let (retry_key_a, retry_a) = client
            .prepare_sender_key_envelope(conversation_id, &target_a)
            .unwrap();
        let (retry_key_b, retry_b) = client
            .prepare_sender_key_envelope(conversation_id, &target_b)
            .unwrap();
        assert_eq!(retry_a, first_a);
        assert_eq!(retry_b, first_b);
        client.pending_sender_key_sequences.insert(103, retry_key_a);
        client.pending_sender_key_sequences.insert(104, retry_key_b);
        client.confirm_sender_key_distribution(103, None).unwrap();
        assert!(client
            .db()
            .unwrap()
            .load_pending_sender_key_envelope(
                conversation_id,
                key_a.generation,
                &target_a,
                &sender_identity,
            )
            .unwrap()
            .is_some());
        client.confirm_sender_key_distribution(104, None).unwrap();
        assert!(!client
            .sender_key_distribution_pending
            .contains(conversation_id));
        assert!(client.pending_sender_key_envelopes.is_empty());
        assert!(client
            .db()
            .unwrap()
            .load_pending_sender_key_envelope(
                conversation_id,
                key_a.generation,
                &target_a,
                &sender_identity,
            )
            .unwrap()
            .is_none());
    }

    #[test]
    #[ignore = "superseded by exact-device Sender-Key v5 retry tests"]
    fn sender_key_retry_cache_survives_restart_until_rotation_invalidation() {
        let mnemonic = generate_mnemonic().to_string();
        let path = std::env::temp_dir().join(format!(
            "veil-client-pending-skdm-{}.db",
            uuid::Uuid::new_v4()
        ));
        let target = [0x41u8; 32];
        let conversation_id = "group-restart-skdm";
        let (generation, sender_identity, sealed) = {
            let mut client = VeilClient::new();
            client.init_with_mnemonic(&mnemonic, &path).unwrap();
            client.mark_channel_conversation(conversation_id);
            client.rotate_sender_key(conversation_id).unwrap();
            let (key, sealed) = client
                .prepare_sender_key_envelope(conversation_id, &target)
                .unwrap();
            (key.generation, client.identity_key().unwrap(), sealed)
        };

        let mut restored = VeilClient::new();
        restored.init_with_mnemonic(&mnemonic, &path).unwrap();
        assert_eq!(
            restored
                .db()
                .unwrap()
                .load_pending_sender_key_envelope(
                    conversation_id,
                    generation,
                    &target,
                    &sender_identity,
                )
                .unwrap()
                .unwrap(),
            sealed
        );

        // Until a rollback-resistant roster version is persisted, cold restore
        // deliberately rotates. Rotation is the only non-ACK path allowed to
        // invalidate the exact retry cache.
        restored.mark_channel_conversation(conversation_id);
        assert_eq!(
            restored
                .hydrate_channel_sender_keys(conversation_id)
                .unwrap(),
            OfflineSenderKeyRefresh::AlreadyRotated
        );
        assert!(restored
            .db()
            .unwrap()
            .load_pending_sender_key_envelope(
                conversation_id,
                generation,
                &target,
                &sender_identity,
            )
            .unwrap()
            .is_none());

        drop(restored);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    #[ignore = "superseded by exact-device roster rotation tests"]
    fn sender_key_roster_change_rotates_and_blocks_until_new_ack() {
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        let conversation_id = "group-membership-change";
        let our_identity = client.identity_key().unwrap();
        let remaining_member = [41u8; 32];
        let removed_member = [42u8; 32];

        client.mark_channel_conversation(conversation_id);
        client
            .replace_authorized_conversation_senders(
                conversation_id,
                [our_identity, remaining_member, removed_member],
            )
            .unwrap();
        client.rotate_sender_key(conversation_id).unwrap();
        client.mark_sender_key_distributed(conversation_id).unwrap();
        let initial_state = client
            .sender_keys
            .serialize_outgoing(conversation_id)
            .unwrap();
        let initial_generation = serde_json::from_slice::<serde_json::Value>(&initial_state)
            .unwrap()["key_id"]
            .as_u64()
            .unwrap();

        client
            .replace_authorized_conversation_senders(
                conversation_id,
                [our_identity, remaining_member],
            )
            .unwrap();
        let rotated_state = client
            .sender_keys
            .serialize_outgoing(conversation_id)
            .unwrap();
        let rotated_generation = serde_json::from_slice::<serde_json::Value>(&rotated_state)
            .unwrap()["key_id"]
            .as_u64()
            .unwrap();
        assert_eq!(rotated_generation, initial_generation + 1);
        assert!(client
            .encrypt_outgoing(conversation_id, "must wait")
            .is_err());

        assert!(client
            .begin_sender_key_distribution(conversation_id)
            .unwrap());
        let pending_77 = pending_sender_key(&client, conversation_id, remaining_member);
        client.pending_sender_key_sequences.insert(77, pending_77);
        assert!(client
            .encrypt_outgoing(conversation_id, "still waiting")
            .is_err());
        client.confirm_sender_key_distribution(77, None).unwrap();
        assert!(client
            .encrypt_outgoing(conversation_id, "fresh generation")
            .is_ok());
    }

    #[test]
    #[ignore = "superseded by exact-device roster rotation tests"]
    fn sender_key_iteration_limit_rotates_once_and_blocks_until_distribution_complete() {
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        let conversation_id = "group-iteration-limit";
        let our_identity = client.identity_key().unwrap();

        client.mark_channel_conversation(conversation_id);
        client
            .replace_authorized_conversation_senders(conversation_id, [our_identity])
            .unwrap();
        client.rotate_sender_key(conversation_id).unwrap();
        client.mark_sender_key_distributed(conversation_id).unwrap();

        let initial_state = client
            .sender_keys
            .serialize_outgoing(conversation_id)
            .unwrap();
        let initial_generation = serde_json::from_slice::<serde_json::Value>(&initial_state)
            .unwrap()["key_id"]
            .as_u64()
            .unwrap();

        // Iterations 0..1999 are the complete allowed generation. The next
        // application message must rotate, but must not produce ciphertext.
        for _ in 0..2_000 {
            client
                .encrypt_outgoing(conversation_id, "within generation")
                .unwrap();
        }
        assert!(client.sender_keys.needs_rotation(conversation_id));

        let error = client
            .encrypt_outgoing(conversation_id, "must wait for distribution")
            .unwrap_err();
        assert!(error.contains("rotation requires distribution"));
        assert!(client
            .sender_key_distribution_pending
            .contains(conversation_id));

        let rotated_state = client
            .sender_keys
            .serialize_outgoing(conversation_id)
            .unwrap();
        let rotated_json = serde_json::from_slice::<serde_json::Value>(&rotated_state).unwrap();
        assert_eq!(
            rotated_json["key_id"].as_u64().unwrap(),
            initial_generation + 1
        );
        assert_eq!(rotated_json["iteration"].as_u64().unwrap(), 0);

        // A retry while pending neither emits ciphertext nor rotates again.
        assert!(client
            .encrypt_outgoing(conversation_id, "still blocked")
            .is_err());
        assert_eq!(
            &*client
                .sender_keys
                .serialize_outgoing(conversation_id)
                .unwrap(),
            &*rotated_state
        );

        // The normal distribution-complete transition unlocks this exact
        // generation; the first ciphertext then advances it to iteration 1.
        assert!(client
            .begin_sender_key_distribution(conversation_id)
            .unwrap());
        client.mark_sender_key_distributed(conversation_id).unwrap();
        let (_ciphertext, header) = client
            .encrypt_outgoing(conversation_id, "fresh generation")
            .unwrap();
        assert_eq!(header, vec![HEADER_SENDER_KEY]);
        let distributed_state = client
            .sender_keys
            .serialize_outgoing(conversation_id)
            .unwrap();
        let distributed_json =
            serde_json::from_slice::<serde_json::Value>(&distributed_state).unwrap();
        assert_eq!(
            distributed_json["key_id"].as_u64().unwrap(),
            initial_generation + 1
        );
        assert_eq!(distributed_json["iteration"].as_u64().unwrap(), 1);
    }

    #[test]
    #[ignore = "superseded by exact-device cold-restore tests"]
    fn cold_restore_conservatively_rotates_once_when_roster_continuity_is_unknown() {
        let identity = IdentityKeyPair::generate();
        let our_identity = identity.x25519_public_bytes();
        let removed_identity = [0xA7u8; 32];
        let conversation_id = "channel-offline-removal";
        let mut client = VeilClient::from_identity(identity);
        client.db = Some(VeilDb::open_memory(&[0x51u8; 32]).unwrap());
        client
            .replace_authorized_conversation_senders(
                conversation_id,
                [our_identity, removed_identity],
            )
            .unwrap();
        client.mark_channel_conversation(conversation_id);
        client.rotate_sender_key(conversation_id).unwrap();
        client.mark_sender_key_distributed(conversation_id).unwrap();

        let persisted_state = client
            .sender_keys
            .serialize_outgoing(conversation_id)
            .unwrap();
        let persisted_generation = serde_json::from_slice::<serde_json::Value>(&persisted_state)
            .unwrap()["key_id"]
            .as_u64()
            .unwrap();

        // Simulate the process/session losing its in-memory roster and keys
        // while the removed member disappears from the authoritative directory.
        client.sender_keys = SenderKeyStore::new();
        client.channel_conversations.clear();
        client.authorized_conversation_senders.clear();
        client.sender_key_distribution_pending.clear();
        client.prepared_sender_key_generations.clear();
        client
            .replace_authorized_conversation_senders(conversation_id, [our_identity])
            .unwrap();
        client.mark_channel_conversation(conversation_id);
        let refresh = client.hydrate_channel_sender_keys(conversation_id).unwrap();
        assert_eq!(refresh, OfflineSenderKeyRefresh::AlreadyRotated);

        let rotated_state = client
            .sender_keys
            .serialize_outgoing(conversation_id)
            .unwrap();
        let rotated_json = serde_json::from_slice::<serde_json::Value>(&rotated_state).unwrap();
        assert_eq!(
            rotated_json["key_id"].as_u64().unwrap(),
            persisted_generation + 1
        );
        assert_eq!(rotated_json["iteration"].as_u64().unwrap(), 0);
        assert!(client
            .sender_key_distribution_pending
            .contains(conversation_id));
        assert!(client
            .encrypt_outgoing(conversation_id, "must not reuse the restored generation")
            .is_err());

        // Repeated hydration in the same native session restores the same
        // freshly persisted generation and cannot rotate forever.
        assert_eq!(
            client.hydrate_channel_sender_keys(conversation_id).unwrap(),
            OfflineSenderKeyRefresh::AlreadyRotated
        );
        assert_eq!(
            &*client
                .sender_keys
                .serialize_outgoing(conversation_id)
                .unwrap(),
            &*rotated_state
        );

        // This is the client-side unit boundary used by desktop offline-sync:
        // hydration already created N+1, so preparing fanout must not create
        // N+2. Sending remains fail-closed until distribution is completed.
        assert!(client
            .begin_offline_sender_key_distribution(conversation_id, refresh)
            .unwrap());
        assert_eq!(
            &*client
                .sender_keys
                .serialize_outgoing(conversation_id)
                .unwrap(),
            &*rotated_state
        );
        assert!(client
            .encrypt_outgoing(conversation_id, "still blocked before ACK")
            .is_err());
        client.mark_sender_key_distributed(conversation_id).unwrap();
        assert!(client
            .encrypt_outgoing(conversation_id, "new roster only")
            .is_ok());
    }

    #[test]
    #[ignore = "superseded by exact-device cold-restore tests"]
    fn cold_restore_early_hydration_cannot_cause_a_second_rotation() {
        let mnemonic = generate_mnemonic().to_string();
        let path = std::env::temp_dir().join(format!(
            "veil-client-cold-restore-once-{}.db",
            uuid::Uuid::new_v4()
        ));
        let conversation_id = "channel-cold-restore-once";
        let peer = [0xB4u8; 32];
        let persisted_generation = {
            let mut initial = VeilClient::new();
            initial.init_with_mnemonic(&mnemonic, &path).unwrap();
            let our_identity = initial.identity_key().unwrap();
            initial
                .replace_authorized_conversation_senders(conversation_id, [our_identity, peer])
                .unwrap();
            initial.mark_channel_conversation(conversation_id);
            initial.rotate_sender_key(conversation_id).unwrap();
            initial
                .mark_sender_key_distributed(conversation_id)
                .unwrap();
            initial
                .sender_keys
                .build_distribution(conversation_id)
                .unwrap()
                .key_id
        };

        let mut restored = VeilClient::new();
        restored.init_with_mnemonic(&mnemonic, &path).unwrap();

        // Reproduce the real race that used to create N+2: a renderer-driven
        // hydration happens before offline sync and discards its return value.
        restored.mark_channel_conversation(conversation_id);
        assert_eq!(
            restored
                .hydrate_channel_sender_keys(conversation_id)
                .unwrap(),
            OfflineSenderKeyRefresh::AlreadyRotated
        );
        let once_rotated_generation = restored
            .sender_keys
            .build_distribution(conversation_id)
            .unwrap()
            .key_id;
        assert_eq!(once_rotated_generation, persisted_generation + 1);

        // Offline directory pinning/hydration runs later. The session marker,
        // not the discarded first return value, carries the exact transition.
        let our_identity = restored.identity_key().unwrap();
        restored
            .replace_authorized_conversation_senders(conversation_id, [our_identity, peer])
            .unwrap();
        let sync_refresh = restored
            .hydrate_channel_sender_keys(conversation_id)
            .unwrap();
        assert_eq!(sync_refresh, OfflineSenderKeyRefresh::AlreadyRotated);
        assert!(restored
            .begin_offline_sender_key_distribution(conversation_id, sync_refresh)
            .unwrap());
        assert_eq!(
            restored
                .sender_keys
                .build_distribution(conversation_id)
                .unwrap()
                .key_id,
            once_rotated_generation
        );
        assert!(restored
            .encrypt_outgoing(conversation_id, "blocked until durable fanout")
            .is_err());

        drop(restored);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    #[ignore = "superseded by exact-device retry tests"]
    fn pending_security_refresh_rotates_once_but_failed_retry_reuses_it() {
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        let conversation_id = "channel-security-refresh";
        client.mark_channel_conversation(conversation_id);
        client.rotate_sender_key(conversation_id).unwrap();
        client.mark_sender_key_distributed(conversation_id).unwrap();
        let generation_before = client
            .sender_keys
            .build_distribution(conversation_id)
            .unwrap()
            .key_id;

        // A peer-generation/security invalidation marks distribution pending
        // without having prepared a new local generation yet.
        client
            .sender_key_distribution_pending
            .insert(conversation_id.to_string());
        assert!(client
            .begin_sender_key_distribution(conversation_id)
            .unwrap());
        let prepared_generation = client
            .sender_keys
            .build_distribution(conversation_id)
            .unwrap()
            .key_id;
        assert_eq!(prepared_generation, generation_before + 1);

        // A retry of that still-pending attempt is immutable and cannot rotate
        // again merely because the transport failed before producing an ACK.
        client.mark_sender_key_distribution_failed(conversation_id);
        assert!(client
            .begin_sender_key_distribution(conversation_id)
            .unwrap());
        assert_eq!(
            client
                .sender_keys
                .build_distribution(conversation_id)
                .unwrap()
                .key_id,
            prepared_generation
        );
    }

    #[test]
    #[ignore = "superseded by exact-device atomic rotation tests"]
    fn failed_rotation_keeps_live_generation_and_exact_retry_cache() {
        let identity = IdentityKeyPair::generate();
        let sender_identity = identity.x25519_public_bytes();
        let target_identity = IdentityKeyPair::generate().x25519_public_bytes();
        let conversation_id = "channel-atomic-rotation-failure";
        let mut client = VeilClient::from_identity(identity);
        client.db = Some(VeilDb::open_memory(&[0x96u8; 32]).unwrap());
        client.mark_channel_conversation(conversation_id);
        client.rotate_sender_key(conversation_id).unwrap();
        client.mark_sender_key_distributed(conversation_id).unwrap();
        let (cache_key, cached_wire) = client
            .prepare_sender_key_envelope(conversation_id, &target_identity)
            .unwrap();
        let state_before = client
            .sender_keys
            .serialize_outgoing(conversation_id)
            .unwrap();
        client
            .db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER abort_client_rotation_cache_delete
                 BEFORE DELETE ON pending_sender_key_envelopes
                 BEGIN
                   SELECT RAISE(ABORT, 'injected client rotation failure');
                 END;",
            )
            .unwrap();

        let error = client.rotate_sender_key(conversation_id).unwrap_err();
        assert!(error.contains("injected client rotation failure"));
        assert_eq!(
            client
                .sender_keys
                .serialize_outgoing(conversation_id)
                .unwrap()
                .as_slice(),
            state_before.as_slice()
        );
        assert_eq!(
            client.pending_sender_key_envelopes.get(&cache_key),
            Some(&cached_wire)
        );
        assert_eq!(
            client
                .db()
                .unwrap()
                .load_pending_sender_key_envelope(
                    conversation_id,
                    cache_key.generation,
                    &target_identity,
                    &sender_identity,
                )
                .unwrap()
                .unwrap(),
            cached_wire
        );
    }

    #[test]
    #[ignore = "superseded by exact-device cold-restore tests"]
    fn stale_offline_rotation_marker_fails_closed() {
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        let error = client
            .begin_offline_sender_key_distribution(
                "channel-stale-offline-marker",
                OfflineSenderKeyRefresh::AlreadyRotated,
            )
            .unwrap_err();
        assert!(error.contains("marker is stale"));
        assert!(!client
            .sender_keys
            .has_outgoing("channel-stale-offline-marker"));
    }

    #[test]
    fn asynchronous_send_rejection_keeps_plaintext_as_failed_local_draft() {
        let identity = IdentityKeyPair::generate();
        let our_identity = identity.x25519_public_bytes();
        let mut client = VeilClient::from_identity(identity);
        let db = VeilDb::open_memory(&[0x72u8; 32]).unwrap();
        db.insert_conversation("dm-rejected", 0, None, Some(&[0x19u8; 32]), None)
            .unwrap();
        db.insert_outgoing_pending_message(
            "local-rejected",
            "dm-rejected",
            &our_identity,
            "do not lose this",
            None,
        )
        .unwrap();
        client.db = Some(db);
        client.pending_outgoing_messages.insert(
            91,
            PendingOutgoingMessage {
                local_message_id: "local-rejected".to_string(),
                conversation_id: "dm-rejected".to_string(),
                sender_identity_key: our_identity,
                plaintext: "do not lose this".to_string(),
                durable_direct_outbox: false,
                direct_ack_deadline: None,
            },
        );

        assert_eq!(
            client.reject_pending_sequence(91).unwrap().as_deref(),
            Some("local-rejected")
        );
        assert!(!client.pending_outgoing_messages.contains_key(&91));
        let failed = client
            .db()
            .unwrap()
            .get_messages("dm-rejected", 10)
            .unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].status, veil_store::models::MessageStatus::Failed);
        assert_eq!(failed[0].plaintext, "do not lose this");
    }

    #[test]
    fn lost_ack_marks_delivery_unknown_instead_of_encouraging_blind_retry() {
        let identity = IdentityKeyPair::generate();
        let our_identity = identity.x25519_public_bytes();
        let mut client = VeilClient::from_identity(identity);
        let db = VeilDb::open_memory(&[0x73u8; 32]).unwrap();
        db.insert_conversation("dm-unknown", 0, None, Some(&[0x29u8; 32]), None)
            .unwrap();
        db.insert_outgoing_pending_message(
            "local-unknown",
            "dm-unknown",
            &our_identity,
            "may already be delivered",
            None,
        )
        .unwrap();
        client.db = Some(db);
        client.pending_outgoing_messages.insert(
            92,
            PendingOutgoingMessage {
                local_message_id: "local-unknown".to_string(),
                conversation_id: "dm-unknown".to_string(),
                sender_identity_key: our_identity,
                plaintext: "may already be delivered".to_string(),
                durable_direct_outbox: false,
                direct_ack_deadline: None,
            },
        );

        assert_eq!(
            client.mark_pending_sequence_unknown(92).unwrap().as_deref(),
            Some("local-unknown")
        );
        let unknown = client.db().unwrap().get_messages("dm-unknown", 10).unwrap();
        assert_eq!(unknown.len(), 1);
        assert_eq!(
            unknown[0].status,
            veil_store::models::MessageStatus::Unknown
        );
        assert_eq!(unknown[0].plaintext, "may already be delivered");
    }

    #[tokio::test]
    async fn disconnected_event_marks_every_outstanding_message_delivery_unknown() {
        let identity = IdentityKeyPair::generate();
        let our_identity = identity.x25519_public_bytes();
        let mut client = VeilClient::from_identity(identity);
        let db = VeilDb::open_memory(&[0x74u8; 32]).unwrap();
        db.insert_conversation("dm-disconnected", 0, None, Some(&[0x39u8; 32]), None)
            .unwrap();
        for (sequence, local_id, plaintext) in [
            (
                93,
                "10000000-0000-0000-0000-000000000093",
                "possibly sent a",
            ),
            (
                94,
                "10000000-0000-0000-0000-000000000094",
                "possibly sent b",
            ),
        ] {
            db.insert_outgoing_pending_message(
                local_id,
                "dm-disconnected",
                &our_identity,
                plaintext,
                None,
            )
            .unwrap();
            client.pending_outgoing_messages.insert(
                sequence,
                PendingOutgoingMessage {
                    local_message_id: local_id.to_string(),
                    conversation_id: "dm-disconnected".to_string(),
                    sender_identity_key: our_identity,
                    plaintext: plaintext.to_string(),
                    durable_direct_outbox: false,
                    direct_ack_deadline: None,
                },
            );
        }
        client.db = Some(db);
        let event_budget = crate::connection::ConnectionEventBudgetV1::with_limits(
            LIVE_EVENT_QUEUE_CAPACITY,
            LIVE_EVENT_RETAINED_BYTES,
        );
        client
            .deferred_connection_events
            .try_extend(vec![event_budget
                .try_wrap(ConnectionEvent::Disconnected {
                    reason: "ws write error: connection reset".to_string(),
                })
                .unwrap()])
            .unwrap();

        assert!(matches!(
            client.poll_event().await.unwrap(),
            Some(ConnectionEvent::Disconnected { .. })
        ));
        assert_eq!(
            client.direct_live_stop,
            Some(DirectLiveReplayStopV1::RetryableTransport)
        );
        assert!(client.pending_outgoing_messages.is_empty());
        let messages = client
            .db()
            .unwrap()
            .get_messages("dm-disconnected", 10)
            .unwrap();
        assert_eq!(messages.len(), 2);
        assert!(messages
            .iter()
            .all(|message| message.status == veil_store::models::MessageStatus::Unknown));
    }

    #[test]
    fn remote_revision_reconciliation_is_monotonic_and_erases_tombstone_metadata() {
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        let sender = [8u8; 32];
        let db = VeilDb::open_memory(&[51u8; 32]).unwrap();
        db.insert_conversation("dm-remote", 0, Some("Peer"), Some(&sender), None)
            .unwrap();
        db.insert_message(
            "remote-message",
            "dm-remote",
            &sender,
            "original",
            false,
            Some(100),
            None,
        )
        .unwrap();
        client.db = Some(db);

        let reactions = [RemoteReaction {
            emoji: "ok".to_string(),
            user_id: "u1".to_string(),
            username: "Alice".to_string(),
        }];
        let created = RemoteMessageMetadata {
            revision_ms: 100,
            reactions: Some(&reactions),
        };
        assert_eq!(
            client
                .reconcile_remote_message_metadata(
                    "remote-message",
                    "dm-remote",
                    &sender,
                    &created,
                    RemoteMessageStateKind::Active,
                )
                .unwrap(),
            RemoteReconcileAction::Unchanged
        );
        assert_eq!(
            client
                .db()
                .unwrap()
                .get_reactions("remote-message")
                .unwrap()
                .len(),
            1
        );

        let edited = RemoteMessageMetadata {
            revision_ms: 101,
            reactions: Some(&reactions),
        };
        assert_eq!(
            client
                .reconcile_remote_message_metadata(
                    "remote-message",
                    "dm-remote",
                    &sender,
                    &edited,
                    RemoteMessageStateKind::Active,
                )
                .unwrap(),
            RemoteReconcileAction::NeedsEncryptedEdit
        );
        assert_eq!(
            client
                .db()
                .unwrap()
                .get_remote_message_state("remote-message")
                .unwrap()
                .unwrap()
                .revision_ms,
            100
        );

        let deleted = RemoteMessageMetadata {
            revision_ms: 102,
            // Even a stale/malicious tombstone reaction list must be erased.
            reactions: Some(&reactions),
        };
        assert_eq!(
            client
                .reconcile_remote_message_metadata(
                    "remote-message",
                    "dm-remote",
                    &sender,
                    &deleted,
                    RemoteMessageStateKind::Deleted,
                )
                .unwrap(),
            RemoteReconcileAction::Deleted
        );
        assert!(!client
            .db()
            .unwrap()
            .message_exists("remote-message")
            .unwrap());
        assert!(client
            .db()
            .unwrap()
            .get_reactions("remote-message")
            .unwrap()
            .is_empty());
        assert!(client
            .reconcile_remote_message_metadata(
                "remote-message",
                "dm-remote",
                &sender,
                &edited,
                RemoteMessageStateKind::Active,
            )
            .is_err());

        assert_eq!(
            client
                .reconcile_remote_message_metadata(
                    "unavailable-message",
                    "dm-remote",
                    &sender,
                    &created,
                    RemoteMessageStateKind::Unavailable,
                )
                .unwrap(),
            RemoteReconcileAction::Unavailable
        );
        assert!(client
            .db()
            .unwrap()
            .get_reactions("unavailable-message")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn outgoing_ack_maps_local_id_to_server_id() {
        let identity = IdentityKeyPair::generate();
        let our_key = identity.x25519_public_bytes();
        let mut client = VeilClient::from_identity(identity);
        let db = VeilDb::open_memory(&[44u8; 32]).unwrap();
        db.insert_conversation("dm-ack", 0, None, Some(&[6u8; 32]), None)
            .unwrap();
        db.insert_outgoing_pending_message("local-message", "dm-ack", &our_key, "hello", None)
            .unwrap();
        client.db = Some(db);
        client.pending_outgoing_messages.insert(
            77,
            PendingOutgoingMessage {
                local_message_id: "local-message".to_string(),
                conversation_id: "dm-ack".to_string(),
                sender_identity_key: our_key,
                plaintext: "hello".to_string(),
                durable_direct_outbox: false,
                direct_ack_deadline: None,
            },
        );

        assert_eq!(
            client
                .finalize_outgoing_message(77, Some("local-message"), "server-message", 2_000_000)
                .unwrap(),
            Some("local-message".to_string())
        );
        assert!(!client.pending_outgoing_messages.contains_key(&77));
        let messages = client.db().unwrap().get_messages("dm-ack", 10).unwrap();
        assert_eq!(messages[0].id, "server-message");
        assert_eq!(messages[0].server_timestamp, Some(2));
    }

    #[tokio::test]
    async fn friend_mutations_reject_malformed_or_oversized_input_before_transport() {
        let client = VeilClient::new();
        assert_eq!(
            client
                .send_friend_request("not-a-uuid", None)
                .await
                .unwrap_err(),
            "invalid friend request"
        );
        assert_eq!(
            client
                .send_friend_request(
                    "a0000000-0000-4000-8000-000000000001",
                    Some(&"x".repeat(1_025)),
                )
                .await
                .unwrap_err(),
            "invalid friend request"
        );
        assert_eq!(
            client
                .respond_friend_request("not-a-uuid", true)
                .await
                .unwrap_err(),
            "invalid friend request response"
        );
        assert_eq!(
            client
                .remove_friend(uuid::Uuid::nil().to_string().as_str())
                .await
                .unwrap_err(),
            "invalid friend id"
        );
    }
}

#[cfg(test)]
#[path = "direct_v1_fixture_tests.rs"]
mod direct_v1_fixture_tests;
