use bip39::Mnemonic;
use rand::{rngs::OsRng, seq::SliceRandom, RngCore};
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;
use veil_crypto::{
    aead, fingerprint, kdf, keys, ratchet, share, signature, x3dh, IdentityKeyPair, RatchetSession,
};
use zeroize::{Zeroize, Zeroizing};

uniffi::setup_scaffolding!();

// ── Error type ──────────────────────────────────────────────

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VeilError {
    #[error("Crypto error: {msg}")]
    Crypto { msg: String },
    #[error("Invalid input: {msg}")]
    InvalidInput { msg: String },
    #[error("Session error: {msg}")]
    Session { msg: String },
}

// ── Record types (plain data, serialized across FFI) ────────

#[derive(uniffi::Record)]
pub struct AeadResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct FingerprintResult {
    pub emoji: String,
    pub hex: String,
}

#[derive(uniffi::Record)]
pub struct RatchetMessage {
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct ShareBundle {
    pub ciphertext: Vec<u8>,
    pub content_key: Vec<u8>,
    pub wrapped_key: Option<Vec<u8>>,
    pub salt: Option<Vec<u8>>,
}

#[derive(uniffi::Record)]
pub struct X3dhResultData {
    pub shared_secret: Vec<u8>,
    pub ephemeral_public: Vec<u8>,
    pub associated_data: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct KeyBundleData {
    pub identity_key: Vec<u8>,
    pub signing_key: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct PreKeyBundleData {
    pub identity_key: Vec<u8>,
    pub signing_key: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub signed_prekey_id: u32,
    pub one_time_prekey: Option<Vec<u8>>,
    pub one_time_prekey_id: Option<u32>,
}

#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobileAuthenticatedBinding {
    pub canonical_server_origin: String,
    pub user_id: String,
}

#[derive(Clone, Eq, PartialEq)]
struct MobileAuthenticatedEpoch {
    binding: MobileAuthenticatedBinding,
    generation: u64,
}

struct MobileDirectSyncState {
    token: String,
    epoch: MobileAuthenticatedEpoch,
    phase: MobileDirectSyncPhase,
    own_prekey_publication: Option<veil_client::prekeys::OwnPreKeyPublication>,
    next_cursor: Option<String>,
    directory_history: veil_client::direct::DirectDirectorySyncHistory,
    peers: HashMap<String, MobileDirectPeer>,
    history_order: Vec<String>,
    history_index: usize,
    current_history: Option<veil_client::direct_history::DirectHistorySyncState>,
    blocked_conversations: BTreeMap<String, MobileDirectHistoryOutcome>,
    outstanding_request: Option<MobileDirectOutstandingRequest>,
    /// Native-owned FIFO cursor for the exact durable Direct outbox. It is
    /// born as `None` with every new authenticated lease and never crosses the
    /// FFI boundary, so Android cannot skip or replay a caller-selected row.
    outbox_replay_cursor: Option<u64>,
    /// The renderer and send boundary stay closed after live history reaches
    /// Ready until this lease has visited the complete durable outbox.
    outbox_replay_complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MobileDirectSyncPhase {
    OwnPreKeys,
    Directory,
    DirectHistory,
    HistorySynchronizedAwaitingLive,
    Ready,
    Failed,
}

#[derive(Clone)]
struct MobileDirectPeer {
    user_id: String,
    identity_key: [u8; 32],
    signing_key: [u8; 32],
}

#[derive(Clone, Eq, PartialEq)]
struct MobileDirectOutstandingRequest {
    kind: MobileDirectOutstandingRequestKind,
    token: String,
    method: &'static str,
    target: String,
    body: Zeroizing<Vec<u8>>,
    response_limit_bytes: u32,
    /// A peer prekey GET is destructive at the server because it claims one
    /// one-time prekey. Native code therefore releases at most one signature
    /// for that exact request capability. Other request kinds leave this false
    /// and retain their existing retry behavior.
    peer_prekey_signature_released: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum MobileDirectOutstandingRequestKind {
    OwnPreKeyCount,
    OwnPreKeyUpload,
    Directory,
    History { conversation_id: String },
    PeerPreKey { conversation_id: String },
}

const MOBILE_OWN_PREKEY_UPLOAD_RESPONSE_LIMIT: u32 = 4 * 1024;

#[derive(Debug, uniffi::Record)]
pub struct MobileDirectSyncLease {
    pub token: String,
    pub canonical_server_origin: String,
    pub user_id: String,
}

#[derive(Debug, uniffi::Record)]
pub struct MobileDirectRestRequest {
    pub request_token: String,
    pub method: String,
    pub request_target: String,
    pub body: Vec<u8>,
    pub response_limit_bytes: u32,
}

fn mobile_direct_rest_request_data(
    request: &MobileDirectOutstandingRequest,
) -> MobileDirectRestRequest {
    MobileDirectRestRequest {
        request_token: request.token.clone(),
        method: request.method.to_string(),
        request_target: request.target.clone(),
        body: request.body.to_vec(),
        response_limit_bytes: request.response_limit_bytes,
    }
}

fn mobile_direct_outstanding_request<'a>(
    state: &'a MobileDirectSyncState,
    request_token: &str,
) -> Result<&'a MobileDirectOutstandingRequest, VeilError> {
    state
        .outstanding_request
        .as_ref()
        .filter(|request| request.token == request_token)
        .ok_or_else(|| VeilError::Session {
            msg: "mobile Direct request is stale".to_string(),
        })
}

fn require_mobile_direct_response_limit(
    request: &MobileDirectOutstandingRequest,
    response: &[u8],
) -> Result<(), VeilError> {
    if request.response_limit_bytes == 0 || response.len() > request.response_limit_bytes as usize {
        return Err(VeilError::Session {
            msg: "mobile Direct response exceeds the native request limit".to_string(),
        });
    }
    Ok(())
}

fn fail_mobile_direct_sync_sticky(state: &mut MobileDirectSyncState) {
    state.phase = MobileDirectSyncPhase::Failed;
    state.outstanding_request = None;
    state.current_history = None;
    state.own_prekey_publication = None;
    state.outbox_replay_cursor = None;
    state.outbox_replay_complete = false;
}

fn finish_mobile_direct_history_conversation(
    state: &mut MobileDirectSyncState,
    conversation_id: &str,
    outcome: MobileDirectHistoryOutcome,
) -> Result<(), VeilError> {
    if state.phase != MobileDirectSyncPhase::DirectHistory
        || state
            .history_order
            .get(state.history_index)
            .map(String::as_str)
            != Some(conversation_id)
    {
        fail_mobile_direct_sync_sticky(state);
        return Err(VeilError::Session {
            msg: "mobile Direct history scheduler diverged".to_string(),
        });
    }
    if outcome != MobileDirectHistoryOutcome::Complete {
        if state.blocked_conversations.len()
            >= veil_client::direct::DIRECT_DIRECTORY_MAX_CONVERSATIONS
        {
            fail_mobile_direct_sync_sticky(state);
            return Err(VeilError::Session {
                msg: "mobile Direct blocked-conversation bound exceeded".to_string(),
            });
        }
        state
            .blocked_conversations
            .insert(conversation_id.to_string(), outcome);
    }
    state.current_history = None;
    state.history_index = state
        .history_index
        .checked_add(1)
        .ok_or_else(|| VeilError::Session {
            msg: "mobile Direct history index overflow".to_string(),
        })?;
    if state.history_index == state.history_order.len() {
        state.phase = MobileDirectSyncPhase::HistorySynchronizedAwaitingLive;
    } else if state.history_index > state.history_order.len() {
        fail_mobile_direct_sync_sticky(state);
        return Err(VeilError::Session {
            msg: "mobile Direct history index exceeded its order".to_string(),
        });
    }
    Ok(())
}

fn begin_mobile_direct_history_phase(state: &mut MobileDirectSyncState) -> Result<(), VeilError> {
    if state.phase != MobileDirectSyncPhase::Directory
        || state.outstanding_request.is_some()
        || state.next_cursor.is_some()
        || !state.history_order.is_empty()
        || state.history_index != 0
        || state.current_history.is_some()
        || !state.blocked_conversations.is_empty()
    {
        fail_mobile_direct_sync_sticky(state);
        return Err(VeilError::Session {
            msg: "mobile Direct history phase transition is invalid".to_string(),
        });
    }
    state.history_order = state.peers.keys().cloned().collect();
    state.history_order.sort_unstable();
    state.phase = MobileDirectSyncPhase::DirectHistory;
    Ok(())
}

#[derive(Debug, uniffi::Record)]
pub struct MobileDirectOwnPreKeyProgress {
    pub publication_complete: bool,
}

#[derive(Debug, uniffi::Record)]
pub struct MobileDirectConversationData {
    pub conversation_id: String,
    pub name: String,
    pub peer_user_id: String,
    pub peer_username: String,
    pub peer_identity_key_hex: String,
    pub peer_signing_key_hex: String,
    pub needs_prekey: bool,
}

#[derive(Debug, uniffi::Record)]
pub struct MobileDirectDirectoryPageData {
    pub conversations: Vec<MobileDirectConversationData>,
    pub next_cursor: Option<String>,
    pub skipped_non_direct: u32,
    pub directory_complete: bool,
}

#[derive(Debug, uniffi::Record)]
pub struct MobileDirectPreKeyResult {
    pub status: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, uniffi::Enum)]
pub enum MobileDirectHistoryOutcome {
    InProgress,
    Complete,
    IncompleteSelfHistory,
    ConversationRejected,
    StorageUncertain,
}

#[derive(Debug, uniffi::Record)]
pub struct MobileDirectHistoryNext {
    pub request: Option<MobileDirectRestRequest>,
    pub histories_terminal: bool,
}

#[derive(Debug, uniffi::Record)]
pub struct MobileDirectHistoryProgress {
    pub outcome: MobileDirectHistoryOutcome,
    pub histories_terminal: bool,
}

#[derive(Debug, uniffi::Record)]
pub struct MobileDirectLiveBufferProgress {
    pub buffered_events: u32,
    pub history_synchronized: bool,
}

/// Aggregate-only result of one bounded authenticated Direct live-replay turn.
///
/// No message, conversation, account, ciphertext, plaintext, or key identifier
/// crosses this boundary. Android schedules another turn when requested and
/// may expose Direct projections only after `ready` becomes true.
#[derive(Debug, uniffi::Record)]
pub struct MobileDirectLiveReplayProgress {
    pub consumed: u32,
    pub projection_changed: bool,
    pub needs_immediate_pump: bool,
    /// Live history is quiescent, but the exact durable outbox still owns the
    /// renderer-opening barrier for this lease.
    pub outbox_replay_required: bool,
    pub ready: bool,
}

/// Aggregate-only result of one bounded exact-byte Direct outbox replay turn.
///
/// Queue order, message IDs, conversation IDs, ciphertext and plaintext stay
/// native. Android may only schedule another turn or revoke the connection.
#[derive(Debug, uniffi::Record)]
pub struct MobileDirectOutboxReplayProgress {
    pub visited: u32,
    pub enqueued: u32,
    pub needs_immediate_pump: bool,
    pub replay_complete: bool,
}

/// Opaque terminal outcome for one explicit Direct text user intent.
///
/// `AcceptedForReplay` still means SQLCipher owns the intent. Android must not
/// create a second intent; it closes the current lease and reconnects so the
/// exact persisted bytes/ID can be replayed after the next Ready checkpoint.
#[derive(Debug, Clone, Copy, Eq, PartialEq, uniffi::Enum)]
pub enum MobileDirectTextSendOutcome {
    Accepted,
    AcceptedForReplay,
    NeedsPreKey,
    Rejected,
    Unavailable,
}

/// Opaque UI availability for one caller-supplied Direct conversation.
///
/// The unavailable state deliberately does not distinguish a quarantined
/// conversation, a revoked native runtime, an unknown route, or a stale
/// lifecycle epoch. That distinction stays in Rust and cannot be used by a
/// renderer to enumerate blocked conversation identifiers.
#[derive(Debug, Clone, Copy, Eq, PartialEq, uniffi::Enum)]
pub enum MobileDirectMessageProjectionAvailability {
    Available,
    Unavailable,
}

/// Coarse, advisory send readiness for exactly one Direct conversation under
/// the caller's current authenticated lease.
///
/// `Unavailable` deliberately collapses malformed or stale leases, lifecycle
/// changes, blocked or unknown routes, storage revocation, and transport loss.
/// No denial detail or key identifier crosses the FFI boundary. A future send
/// operation must repeat every authority, storage, transport, and session
/// guard atomically; this value is never a send capability.
#[derive(Debug, Clone, Copy, Eq, PartialEq, uniffi::Enum)]
pub enum MobileDirectSendReadiness {
    Ready,
    NeedsPreKey,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, uniffi::Enum)]
pub enum MobileDirectMessageDirection {
    Incoming,
    Outgoing,
}

/// Delivery state intentionally collapses delivered/read into `Sent` for the
/// first Direct preview. `Unknown` must never be presented as safe to retry.
#[derive(Debug, Clone, Copy, Eq, PartialEq, uniffi::Enum)]
pub enum MobileDirectMessageDelivery {
    Sending,
    Sent,
    Failed,
    Unknown,
}

/// Minimal decrypted Direct-text row allowed to cross the native UI boundary.
/// Sender keys, ciphertext, protocol headers, author key snapshots, reply
/// metadata, attachment keys, and raw database handles are intentionally
/// absent.
#[derive(uniffi::Object)]
pub struct MobileDirectMessageData {
    message_id: Zeroizing<String>,
    text: Zeroizing<String>,
    /// Authenticated server time when known. A local pending row deliberately
    /// keeps this absent instead of inventing a trusted timestamp.
    timestamp_ms: Option<i64>,
    direction: MobileDirectMessageDirection,
    delivery: MobileDirectMessageDelivery,
}

#[uniffi::export]
impl MobileDirectMessageData {
    pub fn message_id(&self) -> String {
        self.message_id.to_string()
    }

    pub fn text(&self) -> String {
        self.text.to_string()
    }

    pub fn timestamp_ms(&self) -> Option<i64> {
        self.timestamp_ms
    }

    pub fn direction(&self) -> MobileDirectMessageDirection {
        self.direction
    }

    pub fn delivery(&self) -> MobileDirectMessageDelivery {
        self.delivery
    }
}

#[derive(uniffi::Record)]
pub struct MobileDirectMessageProjection {
    pub availability: MobileDirectMessageProjectionAvailability,
    pub messages: Vec<Arc<MobileDirectMessageData>>,
}

const MOBILE_DIRECT_MESSAGE_PROJECTION_LIMIT: u32 = 100;
const MOBILE_DIRECT_MESSAGE_MAX_PLAINTEXT_BYTES: usize = 32 * 1024;
const MOBILE_DIRECT_MESSAGE_PROJECTION_MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
const MOBILE_DIRECT_OUTBOX_REPLAY_MAX_BATCH: usize = 64;

fn unavailable_mobile_direct_message_projection() -> MobileDirectMessageProjection {
    MobileDirectMessageProjection {
        availability: MobileDirectMessageProjectionAvailability::Unavailable,
        messages: Vec::new(),
    }
}

fn mobile_direct_projection_availability(
    availability: veil_client::api::DirectConversationAvailabilityV1,
) -> MobileDirectMessageProjectionAvailability {
    match availability {
        veil_client::api::DirectConversationAvailabilityV1::Available => {
            MobileDirectMessageProjectionAvailability::Available
        }
        veil_client::api::DirectConversationAvailabilityV1::Quarantined
        | veil_client::api::DirectConversationAvailabilityV1::RuntimeRevoked
        | veil_client::api::DirectConversationAvailabilityV1::NotDirect => {
            MobileDirectMessageProjectionAvailability::Unavailable
        }
    }
}

fn mobile_direct_message_delivery(status: u8) -> Option<MobileDirectMessageDelivery> {
    match status {
        0 => Some(MobileDirectMessageDelivery::Sending),
        1..=3 => Some(MobileDirectMessageDelivery::Sent),
        4 => Some(MobileDirectMessageDelivery::Failed),
        5 => Some(MobileDirectMessageDelivery::Unknown),
        _ => None,
    }
}

fn mobile_direct_projection_scope(
    client: &veil_client::api::VeilClient,
    state: &MobileDirectSyncState,
    conversation_id: &str,
) -> Option<([u8; 32], [u8; 32])> {
    let peer = state.peers.get(conversation_id)?;
    let Ok(authenticated_user_id) = client.authenticated_user_id() else {
        return None;
    };
    if authenticated_user_id != state.epoch.binding.user_id {
        return None;
    }
    let db = client.db()?;
    let Ok(scope) = db.resolve_authenticated_direct_history_scope_v1(
        &state.epoch.binding.canonical_server_origin,
        &authenticated_user_id,
        conversation_id,
    ) else {
        return None;
    };
    let Ok(self_identity_key) = client.identity_key() else {
        return None;
    };
    let Ok(self_signing_key) = client.signing_key() else {
        return None;
    };
    let matches = scope.conversation_id == conversation_id
        && scope.self_account.locator.canonical_server_origin
            == state.epoch.binding.canonical_server_origin
        && scope.self_account.locator.user_id == authenticated_user_id
        && scope.self_account.locator.identity_key == self_identity_key
        && scope.self_account.signing_key == self_signing_key
        && scope.self_account.source.as_u8() == 2
        && scope.peer_account.locator.canonical_server_origin
            == state.epoch.binding.canonical_server_origin
        && scope.peer_account.locator.user_id == peer.user_id
        && scope.peer_account.locator.identity_key == peer.identity_key
        && scope.peer_account.signing_key == peer.signing_key
        && scope.peer_account.source.as_u8() == 2
        && client.known_user_identity(&peer.user_id) == Some(peer.identity_key)
        && client.peer_signing_key_is_pinned(&peer.identity_key, &peer.signing_key)
        && client
            .ensure_dm_conversation_binding_compatible(conversation_id, peer.identity_key)
            .is_ok();
    matches.then_some((self_identity_key, peer.identity_key))
}

/// The caller must hold `direct_sync -> binding -> client`; all authority
/// checks themselves stay centralized here so a future atomic send cannot
/// accidentally omit the exact token, Ready phase, or epoch binding.
fn mobile_direct_send_readiness_for_current_lease(
    client: &veil_client::api::VeilClient,
    state: &MobileDirectSyncState,
    current_binding: Option<&MobileAuthenticatedEpoch>,
    lease_token: &str,
    conversation_id: &str,
) -> MobileDirectSendReadiness {
    if state.token != lease_token
        || state.phase != MobileDirectSyncPhase::Ready
        || !state.outbox_replay_complete
        || current_binding != Some(&state.epoch)
    {
        return MobileDirectSendReadiness::Unavailable;
    }
    if mobile_direct_projection_availability(
        client.direct_conversation_availability_v1(conversation_id),
    ) != MobileDirectMessageProjectionAvailability::Available
        || state.blocked_conversations.contains_key(conversation_id)
    {
        return MobileDirectSendReadiness::Unavailable;
    }
    let Some((_, peer_identity_key)) =
        mobile_direct_projection_scope(client, state, conversation_id)
    else {
        return MobileDirectSendReadiness::Unavailable;
    };
    if !client.is_connected() {
        return MobileDirectSendReadiness::Unavailable;
    }
    if client.has_session(&peer_identity_key) {
        MobileDirectSendReadiness::Ready
    } else {
        MobileDirectSendReadiness::NeedsPreKey
    }
}

fn mobile_direct_prekey_unavailable_error() -> VeilError {
    VeilError::Session {
        msg: "mobile Direct prekey route is unavailable".to_string(),
    }
}

/// Revoke one already-locked mobile Direct epoch after transport loss or a
/// native invariant failure. Callers must retain `direct_sync -> binding ->
/// client` while invoking this helper.
fn revoke_mobile_direct_epoch_locked(
    state: &mut MobileDirectSyncState,
    binding: &mut Option<MobileAuthenticatedEpoch>,
    client: &mut veil_client::api::VeilClient,
) {
    *binding = None;
    fail_mobile_direct_sync_sticky(state);
    client.disconnect();
}

#[derive(uniffi::Record)]
pub struct RestSignatureData {
    pub user_id: String,
    pub timestamp_ms: String,
    pub signature_base64: String,
}

// ── VeilIdentity (opaque object) ────────────────────────────

#[derive(uniffi::Object)]
pub struct VeilIdentity {
    inner: IdentityKeyPair,
}

#[uniffi::export]
impl VeilIdentity {
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        Arc::new(Self {
            inner: IdentityKeyPair::generate(),
        })
    }

    #[uniffi::constructor]
    /// Compatibility constructor for non-mobile callers. Android must use
    /// `from_mnemonic_bytes` so its decrypted mnemonic never becomes a JVM
    /// `String`.
    pub fn from_mnemonic(mnemonic: String) -> Result<Arc<Self>, VeilError> {
        Self::from_mnemonic_bytes(mnemonic.into_bytes())
    }

    #[uniffi::constructor]
    pub fn from_mnemonic_bytes(mnemonic_utf8: Vec<u8>) -> Result<Arc<Self>, VeilError> {
        let mnemonic_utf8 = guard_utf8_secret(mnemonic_utf8, "mnemonic")?;
        let mnemonic =
            std::str::from_utf8(mnemonic_utf8.as_slice()).map_err(|_| VeilError::InvalidInput {
                msg: "mnemonic must be valid UTF-8".to_string(),
            })?;
        let kp =
            IdentityKeyPair::from_mnemonic(mnemonic).map_err(|e| VeilError::Crypto { msg: e })?;
        Ok(Arc::new(Self { inner: kp }))
    }

    pub fn identity_key(&self) -> Vec<u8> {
        self.inner.x25519_public_bytes().to_vec()
    }

    pub fn signing_key(&self) -> Vec<u8> {
        self.inner.ed25519_public_bytes().to_vec()
    }

    pub fn sign(&self, message: Vec<u8>) -> Vec<u8> {
        signature::sign(&self.inner, &message).to_vec()
    }

    pub fn to_key_bundle(&self) -> KeyBundleData {
        KeyBundleData {
            identity_key: self.inner.x25519_public_bytes().to_vec(),
            signing_key: self.inner.ed25519_public_bytes().to_vec(),
        }
    }
}

// ── VeilRecoveryDraft (native-only recovery state) ─────────

const RECOVERY_WORD_COUNT: u8 = 12;
const RECOVERY_DICTIONARY_WORD_COUNT: u16 = 2048;
const RECOVERY_CHALLENGE_COUNT: u8 = 3;
const RECOVERY_CHALLENGE_CHOICE_COUNT: u8 = 4;
const RECOVERY_EMPTY_WORD_INDEX: u16 = u16::MAX;

enum RecoveryDraftMode {
    Create,
    Restore,
}

struct RecoveryChallenge {
    position: u8,
    choices: [u16; RECOVERY_CHALLENGE_CHOICE_COUNT as usize],
    confirmed: bool,
}

impl RecoveryChallenge {
    fn clear(&mut self) {
        self.position.zeroize();
        self.choices.zeroize();
        self.confirmed = false;
    }
}

impl Drop for RecoveryChallenge {
    fn drop(&mut self) {
        self.clear();
    }
}

struct RecoveryDraftState {
    mode: RecoveryDraftMode,
    words: [u16; RECOVERY_WORD_COUNT as usize],
    challenges: [RecoveryChallenge; RECOVERY_CHALLENGE_COUNT as usize],
    commit_authorized: bool,
    cancelled: bool,
}

impl RecoveryDraftState {
    fn clear_secret_state(&mut self) {
        self.words.zeroize();
        for challenge in &mut self.challenges {
            challenge.clear();
        }
        self.commit_authorized = false;
    }

    fn cancel(&mut self) {
        self.clear_secret_state();
        self.cancelled = true;
    }

    fn ensure_active(&self) -> Result<(), VeilError> {
        if self.cancelled {
            Err(recovery_unavailable())
        } else {
            Ok(())
        }
    }

    fn ensure_create(&self) -> Result<(), VeilError> {
        self.ensure_active()?;
        if matches!(self.mode, RecoveryDraftMode::Create) {
            Ok(())
        } else {
            Err(recovery_unavailable())
        }
    }

    fn ensure_restore(&self) -> Result<(), VeilError> {
        self.ensure_active()?;
        if matches!(self.mode, RecoveryDraftMode::Restore) {
            Ok(())
        } else {
            Err(recovery_unavailable())
        }
    }
}

impl Drop for RecoveryDraftState {
    fn drop(&mut self) {
        self.clear_secret_state();
        self.cancelled = true;
    }
}

/// Opaque, serialized recovery setup state for Android.
///
/// The object deliberately exposes only scalar word indices and positions.
/// A complete recovery phrase is never represented by a UniFFI `String` or
/// collection. Android maps indices through its pinned public BIP39 English
/// dictionary and assembles one short-lived mutable ASCII buffer only after
/// this draft authorizes commit.
#[derive(uniffi::Object)]
pub struct VeilRecoveryDraft {
    state: Mutex<RecoveryDraftState>,
}

#[uniffi::export]
impl VeilRecoveryDraft {
    #[uniffi::constructor]
    pub fn new_create() -> Arc<Self> {
        let words = create_recovery_word_indices();
        let challenges = create_recovery_challenges(&words);
        Arc::new(Self {
            state: Mutex::new(RecoveryDraftState {
                mode: RecoveryDraftMode::Create,
                words,
                challenges,
                commit_authorized: false,
                cancelled: false,
            }),
        })
    }

    #[uniffi::constructor]
    pub fn new_restore() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(RecoveryDraftState {
                mode: RecoveryDraftMode::Restore,
                words: [RECOVERY_EMPTY_WORD_INDEX; RECOVERY_WORD_COUNT as usize],
                challenges: empty_recovery_challenges(),
                commit_authorized: false,
                cancelled: false,
            }),
        })
    }

    pub fn word_count(&self) -> u8 {
        RECOVERY_WORD_COUNT
    }

    /// Return one generated word index for the create flow.
    pub fn word_index(&self, position: u8) -> Result<u16, VeilError> {
        let position = recovery_position(position)?;
        let state = self.recovery_state()?;
        state.ensure_create()?;
        Ok(state.words[position])
    }

    /// Set one word index for the restore flow. Every edit revokes a previous
    /// checksum authorization until `validate_import` succeeds again.
    pub fn set_import_word_index(&self, position: u8, index: u16) -> Result<(), VeilError> {
        let position = recovery_position(position)?;
        require_recovery_word_index(index)?;
        let mut state = self.recovery_state()?;
        state.ensure_restore()?;
        state.words[position] = index;
        state.commit_authorized = false;
        Ok(())
    }

    /// Validate all imported indices and the BIP39 checksum. Invalid or
    /// incomplete input returns `false` without diagnostics derived from it.
    pub fn validate_import(&self) -> Result<bool, VeilError> {
        let mut state = self.recovery_state()?;
        state.ensure_restore()?;
        let valid = recovery_indices_have_valid_checksum(&state.words);
        state.commit_authorized = valid;
        Ok(valid)
    }

    pub fn challenge_count(&self) -> u8 {
        RECOVERY_CHALLENGE_COUNT
    }

    pub fn challenge_position(&self, slot: u8) -> Result<u8, VeilError> {
        let slot = recovery_challenge_slot(slot)?;
        let state = self.recovery_state()?;
        state.ensure_create()?;
        Ok(state.challenges[slot].position)
    }

    pub fn challenge_choice_count(&self) -> u8 {
        RECOVERY_CHALLENGE_CHOICE_COUNT
    }

    pub fn challenge_choice_word_index(&self, slot: u8, choice: u8) -> Result<u16, VeilError> {
        let slot = recovery_challenge_slot(slot)?;
        let choice = recovery_challenge_choice(choice)?;
        let state = self.recovery_state()?;
        state.ensure_create()?;
        Ok(state.challenges[slot].choices[choice])
    }

    /// Confirm one randomized create-flow challenge. A wrong answer revokes
    /// that slot and therefore revokes commit authorization.
    pub fn confirm_challenge(&self, slot: u8, chosen: u16) -> Result<bool, VeilError> {
        let slot = recovery_challenge_slot(slot)?;
        require_recovery_word_index(chosen)?;
        let mut state = self.recovery_state()?;
        state.ensure_create()?;
        let position = state.challenges[slot].position as usize;
        if !state.challenges[slot].choices.contains(&chosen) {
            state.challenges[slot].confirmed = false;
            state.commit_authorized = false;
            return Ok(false);
        }
        let correct = state.words[position] == chosen;
        state.challenges[slot].confirmed = correct;
        state.commit_authorized = state.challenges.iter().all(|item| item.confirmed);
        Ok(correct)
    }

    pub fn is_commit_authorized(&self) -> bool {
        self.state
            .lock()
            .map(|state| !state.cancelled && state.commit_authorized)
            .unwrap_or(false)
    }

    /// Atomically consume the authorization immediately before provisioning.
    /// The first authorized caller wins; the draft is then zeroized and
    /// terminal. Provisioning failures must restart recovery setup.
    pub fn consume_commit_authorization(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.cancelled || !state.commit_authorized {
            return false;
        }
        state.cancel();
        true
    }

    /// Terminal, idempotent cancellation. Poison recovery is used only to
    /// erase state; no secret operation is permitted afterwards.
    pub fn cancel(&self) {
        match self.state.lock() {
            Ok(mut state) => state.cancel(),
            Err(poisoned) => poisoned.into_inner().cancel(),
        }
    }
}

impl VeilRecoveryDraft {
    fn recovery_state(&self) -> Result<std::sync::MutexGuard<'_, RecoveryDraftState>, VeilError> {
        self.state.lock().map_err(|_| recovery_unavailable())
    }
}

fn create_recovery_word_indices() -> [u16; RECOVERY_WORD_COUNT as usize] {
    let mnemonic = keys::generate_mnemonic();
    let mut words = [0u16; RECOVERY_WORD_COUNT as usize];
    for (target, index) in words.iter_mut().zip(mnemonic.word_indices()) {
        *target = u16::try_from(index).expect("BIP39 English indices fit in u16");
    }
    words
}

fn create_recovery_challenges(
    words: &[u16; RECOVERY_WORD_COUNT as usize],
) -> [RecoveryChallenge; RECOVERY_CHALLENGE_COUNT as usize] {
    let mut rng = OsRng;
    let mut positions = [0u8; RECOVERY_WORD_COUNT as usize];
    for (position, value) in positions.iter_mut().enumerate() {
        *value = u8::try_from(position).expect("recovery positions fit in u8");
    }
    positions.shuffle(&mut rng);

    std::array::from_fn(|slot| {
        let position = positions[slot];
        let correct = words[position as usize];
        let mut choices = [RECOVERY_EMPTY_WORD_INDEX; RECOVERY_CHALLENGE_CHOICE_COUNT as usize];
        choices[0] = correct;
        let mut filled = 1;
        while filled < choices.len() {
            // 2048 divides the u32 range, so masking is unbiased here.
            let candidate = (rng.next_u32() as u16) & (RECOVERY_DICTIONARY_WORD_COUNT - 1);
            if !choices[..filled].contains(&candidate) {
                choices[filled] = candidate;
                filled += 1;
            }
        }
        choices.shuffle(&mut rng);
        RecoveryChallenge {
            position,
            choices,
            confirmed: false,
        }
    })
}

fn empty_recovery_challenges() -> [RecoveryChallenge; RECOVERY_CHALLENGE_COUNT as usize] {
    std::array::from_fn(|_| RecoveryChallenge {
        position: 0,
        choices: [0; RECOVERY_CHALLENGE_CHOICE_COUNT as usize],
        confirmed: false,
    })
}

fn recovery_indices_have_valid_checksum(words: &[u16; RECOVERY_WORD_COUNT as usize]) -> bool {
    if words
        .iter()
        .any(|index| *index >= RECOVERY_DICTIONARY_WORD_COUNT)
    {
        return false;
    }

    // A 12-word BIP39 phrase contains 128 entropy bits followed by a 4-bit
    // checksum. Recover only the entropy bytes, ask `bip39` to recompute the
    // canonical indices, compare, and erase the temporary entropy.
    let mut entropy = [0u8; 16];
    for bit in 0..128usize {
        let word = words[bit / 11];
        let word_bit = 10 - (bit % 11);
        let value = ((word >> word_bit) & 1) as u8;
        entropy[bit / 8] |= value << (7 - (bit % 8));
    }
    let canonical = Mnemonic::from_entropy(&entropy).ok();
    entropy.zeroize();
    canonical.is_some_and(|mnemonic| {
        mnemonic
            .word_indices()
            .zip(words.iter().copied().map(usize::from))
            .all(|(actual, expected)| actual == expected)
    })
}

fn recovery_position(position: u8) -> Result<usize, VeilError> {
    if position >= RECOVERY_WORD_COUNT {
        return Err(recovery_invalid_input());
    }
    Ok(position as usize)
}

fn recovery_challenge_slot(slot: u8) -> Result<usize, VeilError> {
    if slot >= RECOVERY_CHALLENGE_COUNT {
        return Err(recovery_invalid_input());
    }
    Ok(slot as usize)
}

fn recovery_challenge_choice(choice: u8) -> Result<usize, VeilError> {
    if choice >= RECOVERY_CHALLENGE_CHOICE_COUNT {
        return Err(recovery_invalid_input());
    }
    Ok(choice as usize)
}

fn require_recovery_word_index(index: u16) -> Result<(), VeilError> {
    if index >= RECOVERY_DICTIONARY_WORD_COUNT {
        return Err(recovery_invalid_input());
    }
    Ok(())
}

fn recovery_invalid_input() -> VeilError {
    VeilError::InvalidInput {
        msg: "recovery input is invalid".to_string(),
    }
}

fn recovery_unavailable() -> VeilError {
    VeilError::Session {
        msg: "recovery draft is unavailable".to_string(),
    }
}

// ── MobileConnectCancellation (thread-safe cooperative cancellation) ──

/// One-shot cancellation capability for a single mobile connection attempt.
///
/// `cancel` is the only mobile-session-adjacent operation designed to run from
/// an Android lifecycle thread while `connect_*_cancellable` is blocked on the
/// serialized native runtime thread. It never locks or closes `VeilClient`.
#[derive(uniffi::Object)]
pub struct MobileConnectCancellation {
    cancelled: AtomicBool,
    notify: Notify,
}

#[uniffi::export]
impl MobileConnectCancellation {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    /// Request cancellation without waiting for the mobile client mutex.
    /// Repeated calls are harmless and cancellation remains sticky.
    pub fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            self.notify.notify_waiters();
        }
    }
}

impl MobileConnectCancellation {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }

            // Register before the second atomic read. This closes the race in
            // which cancel happens between observing false and awaiting Notify.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

// ── VeilMobileSession (native account/origin binding) ──────

/// Native mobile session backed by the same SQLCipher/per-device engine as
/// desktop. Account authentication and request signatures never cross into
/// JavaScript; Kotlin receives only bounded public binding metadata.
///
/// Any operation needing more than one guard must acquire them in this order:
/// `direct_sync` -> `binding` -> `client`. Lifecycle invalidation never waits
/// for `direct_sync` while retaining `client`, preventing a reconnect/history
/// callback inversion from deadlocking the serialized Android runtime. Initial
/// authentication is the deliberate exception: it holds `client` while
/// publishing a previously invalidated `binding`; no current Direct lease can
/// exist until that publication has completed.
#[derive(uniffi::Object)]
pub struct VeilMobileSession {
    client: Mutex<veil_client::api::VeilClient>,
    runtime: tokio::runtime::Runtime,
    binding: Mutex<Option<MobileAuthenticatedEpoch>>,
    direct_sync: Mutex<Option<MobileDirectSyncState>>,
    next_binding_generation: AtomicU64,
    last_rest_timestamp_ms: AtomicI64,
    #[cfg(test)]
    direct_post_sign_pre_postflight_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

#[uniffi::export]
impl VeilMobileSession {
    #[uniffi::constructor]
    /// Compatibility constructor for non-mobile callers. Android must pass
    /// decrypted mnemonic bytes to `from_mnemonic_bytes` and clear its own
    /// `ByteArray` immediately after this call.
    pub fn from_mnemonic(mnemonic: String, database_path: String) -> Result<Arc<Self>, VeilError> {
        Self::from_mnemonic_bytes(mnemonic.into_bytes(), database_path)
    }

    #[uniffi::constructor]
    pub fn from_mnemonic_bytes(
        mnemonic_utf8: Vec<u8>,
        database_path: String,
    ) -> Result<Arc<Self>, VeilError> {
        let mnemonic_utf8 = guard_utf8_secret(mnemonic_utf8, "mnemonic")?;
        let mnemonic =
            std::str::from_utf8(mnemonic_utf8.as_slice()).map_err(|_| VeilError::InvalidInput {
                msg: "mnemonic must be valid UTF-8".to_string(),
            })?;
        if database_path.is_empty() || database_path.len() > 4096 {
            return Err(VeilError::InvalidInput {
                msg: "mobile database path is empty or oversized".to_string(),
            });
        }
        let path = PathBuf::from(database_path);
        if !path.is_absolute() {
            return Err(VeilError::InvalidInput {
                msg: "mobile database path must be absolute".to_string(),
            });
        }
        let mut client = veil_client::api::VeilClient::new();
        client
            .init_with_mnemonic(mnemonic, &path)
            .map_err(|msg| VeilError::Session { msg })?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .thread_name("veil-mobile-native")
            .build()
            .map_err(|error| VeilError::Session {
                msg: format!("create mobile native runtime: {error}"),
            })?;
        Ok(Arc::new(Self {
            client: Mutex::new(client),
            runtime,
            binding: Mutex::new(None),
            direct_sync: Mutex::new(None),
            next_binding_generation: AtomicU64::new(0),
            last_rest_timestamp_ms: AtomicI64::new(0),
            #[cfg(test)]
            direct_post_sign_pre_postflight_hook: Mutex::new(None),
        }))
    }

    pub fn connect(
        &self,
        websocket_url: String,
        canonical_server_origin: String,
    ) -> Result<MobileAuthenticatedBinding, VeilError> {
        self.connect_inner(websocket_url, canonical_server_origin, None, None)
    }

    /// Connect with lifecycle-safe cooperative cancellation.
    ///
    /// Cancelling never closes this UniFFI object from another thread. Instead,
    /// it wakes the in-flight future so the serialized native thread can tear
    /// down the partially-open transport and clear its authenticated binding.
    pub fn connect_cancellable(
        &self,
        websocket_url: String,
        canonical_server_origin: String,
        cancellation: Arc<MobileConnectCancellation>,
    ) -> Result<MobileAuthenticatedBinding, VeilError> {
        self.connect_inner(
            websocket_url,
            canonical_server_origin,
            None,
            Some(cancellation.as_ref()),
        )
    }

    /// Connect a newly enrolled account with a single-use Node Access Pass.
    /// The pass remains in native memory, is never returned in diagnostics,
    /// and is zeroized after this connection attempt (including early errors).
    pub fn connect_with_node_access_pass(
        &self,
        websocket_url: String,
        canonical_server_origin: String,
        node_access_pass: Vec<u8>,
    ) -> Result<MobileAuthenticatedBinding, VeilError> {
        self.connect_inner(
            websocket_url,
            canonical_server_origin,
            Some(node_access_pass),
            None,
        )
    }

    /// Connect a newly enrolled account with cooperative lifecycle
    /// cancellation. The access pass remains zeroized on every exit path.
    pub fn connect_with_node_access_pass_cancellable(
        &self,
        websocket_url: String,
        canonical_server_origin: String,
        node_access_pass: Vec<u8>,
        cancellation: Arc<MobileConnectCancellation>,
    ) -> Result<MobileAuthenticatedBinding, VeilError> {
        self.connect_inner(
            websocket_url,
            canonical_server_origin,
            Some(node_access_pass),
            Some(cancellation.as_ref()),
        )
    }

    pub fn authenticated_binding(&self) -> Result<MobileAuthenticatedBinding, VeilError> {
        Ok(self.authenticated_epoch()?.binding)
    }

    /// Start an object-bound Direct directory sync for the exact current
    /// WebSocket generation. The random token never crosses into JavaScript;
    /// Kotlin must return it with every raw REST response.
    pub fn begin_direct_sync(&self) -> Result<MobileDirectSyncLease, VeilError> {
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        let epoch = binding.clone().ok_or_else(|| VeilError::Session {
            msg: "mobile account is not authenticated".to_string(),
        })?;
        let mut client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;
        let authenticated_user_id = client
            .authenticated_user_id()
            .map_err(|msg| VeilError::Session { msg })?;
        if authenticated_user_id != epoch.binding.user_id {
            return Err(VeilError::Session {
                msg: "mobile authenticated principal changed before Direct sync".to_string(),
            });
        }

        client.clear_known_user_identities();
        client.clear_server_scoped_conversation_routing();
        client.clear_all_authorized_conversation_senders();
        let token = new_mobile_sync_token();
        *sync = Some(MobileDirectSyncState {
            token: token.clone(),
            epoch: epoch.clone(),
            phase: MobileDirectSyncPhase::OwnPreKeys,
            own_prekey_publication: None,
            next_cursor: None,
            directory_history: veil_client::direct::DirectDirectorySyncHistory::default(),
            peers: HashMap::new(),
            history_order: Vec::new(),
            history_index: 0,
            current_history: None,
            blocked_conversations: BTreeMap::new(),
            outstanding_request: None,
            outbox_replay_cursor: None,
            outbox_replay_complete: false,
        });
        Ok(MobileDirectSyncLease {
            token,
            canonical_server_origin: epoch.binding.canonical_server_origin,
            user_id: epoch.binding.user_id,
        })
    }

    /// Prepare the next origin-scoped own-prekey bootstrap request. A durable
    /// pending publication is retried immediately; otherwise native first
    /// obtains the exact local-device count and then prepares a persisted POST.
    /// Kotlin receives public wire bytes but never chooses the target, method,
    /// key ids, or whether a fresh batch may be generated.
    pub fn prepare_own_prekey_request(
        &self,
        lease_token: String,
    ) -> Result<MobileDirectRestRequest, VeilError> {
        require_mobile_sync_token(&lease_token)?;
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let state = sync.as_mut().ok_or_else(|| VeilError::Session {
            msg: "mobile Direct sync is unavailable".to_string(),
        })?;
        if state.token != lease_token || state.phase != MobileDirectSyncPhase::OwnPreKeys {
            return Err(VeilError::Session {
                msg: "mobile own-prekey lease is stale or complete".to_string(),
            });
        }
        if state.next_cursor.is_some() || !state.peers.is_empty() {
            return Err(VeilError::Session {
                msg: "mobile Direct directory started before own-prekey publication".to_string(),
            });
        }
        let binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        if binding.as_ref() != Some(&state.epoch) {
            return Err(VeilError::Session {
                msg: "mobile own-prekey lease is stale".to_string(),
            });
        }
        if let Some(outstanding) = state.outstanding_request.as_ref() {
            if matches!(
                outstanding.kind,
                MobileDirectOutstandingRequestKind::OwnPreKeyCount
                    | MobileDirectOutstandingRequestKind::OwnPreKeyUpload
            ) {
                return Ok(mobile_direct_rest_request_data(outstanding));
            }
            return Err(VeilError::Session {
                msg: "another mobile Direct request is already outstanding".to_string(),
            });
        }

        let client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;

        if state.own_prekey_publication.is_none() {
            let persisted = client
                .own_prekey_publication(
                    &state.epoch.binding.canonical_server_origin,
                    &state.epoch.binding.user_id,
                )
                .map_err(|_| VeilError::Session {
                    msg: "mobile own-prekey outbox is unavailable".to_string(),
                })?;
            if persisted
                .as_ref()
                .is_some_and(|publication| !publication.acknowledged)
            {
                state.own_prekey_publication = persisted;
            }
        }

        let request = if let Some(publication) = state.own_prekey_publication.as_ref() {
            MobileDirectOutstandingRequest {
                kind: MobileDirectOutstandingRequestKind::OwnPreKeyUpload,
                token: new_mobile_sync_token(),
                method: "POST",
                target: "/v1/prekeys".to_string(),
                body: Zeroizing::new(publication.request_body.clone()),
                response_limit_bytes: MOBILE_OWN_PREKEY_UPLOAD_RESPONSE_LIMIT,
                peer_prekey_signature_released: false,
            }
        } else {
            let target = client
                .own_prekey_count_target()
                .map_err(|_| VeilError::Session {
                    msg: "mobile own-prekey count request is unavailable".to_string(),
                })?;
            MobileDirectOutstandingRequest {
                kind: MobileDirectOutstandingRequestKind::OwnPreKeyCount,
                token: new_mobile_sync_token(),
                method: "GET",
                target,
                body: Zeroizing::new(Vec::new()),
                response_limit_bytes: veil_client::prekeys::OWN_PREKEY_RESPONSE_LIMIT as u32,
                peer_prekey_signature_released: false,
            }
        };
        let result = mobile_direct_rest_request_data(&request);
        state.outstanding_request = Some(request);
        Ok(result)
    }

    /// Install one own-prekey count or upload response under the exact native
    /// lease/request capability. A count never opens the directory; a valid
    /// upload acknowledgement is the sole transition to `publication_complete`.
    pub fn install_own_prekey_response(
        &self,
        lease_token: String,
        request_token: String,
        response: Vec<u8>,
    ) -> Result<MobileDirectOwnPreKeyProgress, VeilError> {
        require_mobile_sync_token(&lease_token)?;
        require_mobile_sync_token(&request_token)?;
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let state = sync.as_mut().ok_or_else(|| VeilError::Session {
            msg: "mobile Direct sync is unavailable".to_string(),
        })?;
        if state.token != lease_token || state.phase != MobileDirectSyncPhase::OwnPreKeys {
            return Err(VeilError::Session {
                msg: "mobile own-prekey lease is stale or complete".to_string(),
            });
        }
        let outstanding = state
            .outstanding_request
            .as_ref()
            .filter(|outstanding| {
                outstanding.token == request_token
                    && matches!(
                        outstanding.kind,
                        MobileDirectOutstandingRequestKind::OwnPreKeyCount
                            | MobileDirectOutstandingRequestKind::OwnPreKeyUpload
                    )
            })
            .cloned()
            .ok_or_else(|| VeilError::Session {
                msg: "mobile own-prekey request is stale".to_string(),
            })?;
        let response = Zeroizing::new(response);
        if let Err(error) = require_mobile_direct_response_limit(&outstanding, response.as_slice())
        {
            fail_mobile_direct_sync_sticky(state);
            return Err(error);
        }
        let binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        if binding.as_ref() != Some(&state.epoch) {
            return Err(VeilError::Session {
                msg: "mobile own-prekey lease is stale".to_string(),
            });
        }
        let mut client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;

        match &outstanding.kind {
            MobileDirectOutstandingRequestKind::OwnPreKeyCount => {
                if state.own_prekey_publication.is_some()
                    || outstanding.method != "GET"
                    || !outstanding.body.is_empty()
                {
                    return Err(VeilError::Session {
                        msg: "mobile own-prekey count state is invalid".to_string(),
                    });
                }
                let publication = client
                    .prepare_own_prekey_publication_after_count(
                        &state.epoch.binding.canonical_server_origin,
                        &state.epoch.binding.user_id,
                        response.as_slice(),
                    )
                    .map_err(|_| VeilError::Session {
                        msg: "mobile own-prekey count response was rejected".to_string(),
                    })?;
                state.own_prekey_publication = Some(publication);
                state.outstanding_request = None;
                Ok(MobileDirectOwnPreKeyProgress {
                    publication_complete: false,
                })
            }
            MobileDirectOutstandingRequestKind::OwnPreKeyUpload => {
                let publication =
                    state
                        .own_prekey_publication
                        .as_ref()
                        .ok_or_else(|| VeilError::Session {
                            msg: "mobile own-prekey upload state is invalid".to_string(),
                        })?;
                if outstanding.method != "POST"
                    || outstanding.target != "/v1/prekeys"
                    || outstanding.body.as_slice() != publication.request_body.as_slice()
                {
                    return Err(VeilError::Session {
                        msg: "mobile own-prekey upload request changed".to_string(),
                    });
                }
                let _ = client
                    .acknowledge_own_prekey_publication(
                        &state.epoch.binding.canonical_server_origin,
                        &state.epoch.binding.user_id,
                        publication.signed_prekey_id,
                        &publication.body_sha256,
                        response.as_slice(),
                    )
                    .map_err(|_| VeilError::Session {
                        msg: "mobile own-prekey upload response was rejected".to_string(),
                    })?;
                state.phase = MobileDirectSyncPhase::Directory;
                state.own_prekey_publication = None;
                state.outstanding_request = None;
                Ok(MobileDirectOwnPreKeyProgress {
                    publication_complete: true,
                })
            }
            _ => unreachable!("own-prekey request kind was preflighted"),
        }
    }

    pub fn prepare_direct_directory_request(
        &self,
        lease_token: String,
    ) -> Result<MobileDirectRestRequest, VeilError> {
        require_mobile_sync_token(&lease_token)?;
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let state = sync.as_mut().ok_or_else(|| VeilError::Session {
            msg: "mobile Direct sync is unavailable".to_string(),
        })?;
        if state.token != lease_token || state.phase != MobileDirectSyncPhase::Directory {
            return Err(VeilError::Session {
                msg: "mobile Direct sync lease is stale or directory is complete".to_string(),
            });
        }
        let binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        if binding.as_ref() != Some(&state.epoch) {
            return Err(VeilError::Session {
                msg: "mobile Direct sync lease is stale".to_string(),
            });
        }
        if let Some(request) = state.outstanding_request.as_ref() {
            if request.kind == MobileDirectOutstandingRequestKind::Directory {
                return Ok(mobile_direct_rest_request_data(request));
            }
            return Err(VeilError::Session {
                msg: "another mobile Direct request is already outstanding".to_string(),
            });
        }
        let request = MobileDirectOutstandingRequest {
            kind: MobileDirectOutstandingRequestKind::Directory,
            token: new_mobile_sync_token(),
            method: "GET",
            target: mobile_direct_directory_target(state.next_cursor.as_deref())?,
            body: Zeroizing::new(Vec::new()),
            response_limit_bytes: veil_client::direct::DIRECT_DIRECTORY_RESPONSE_LIMIT as u32,
            peer_prekey_signature_released: false,
        };
        let result = mobile_direct_rest_request_data(&request);
        state.outstanding_request = Some(request);
        Ok(result)
    }

    /// Validate and install one raw directory response under the exact lease
    /// that issued its request. Binding and client guards stay held across the
    /// mutation, making reconnect/disconnect linearize before or after it.
    pub fn install_direct_directory_page(
        &self,
        lease_token: String,
        request_token: String,
        response: Vec<u8>,
    ) -> Result<MobileDirectDirectoryPageData, VeilError> {
        require_mobile_sync_token(&lease_token)?;
        require_mobile_sync_token(&request_token)?;
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let state = sync.as_mut().ok_or_else(|| VeilError::Session {
            msg: "mobile Direct sync is unavailable".to_string(),
        })?;
        if state.token != lease_token {
            return Err(VeilError::Session {
                msg: "mobile Direct sync lease is stale".to_string(),
            });
        }
        if state.phase != MobileDirectSyncPhase::Directory {
            return Err(VeilError::Session {
                msg: "mobile Direct directory is already complete".to_string(),
            });
        }
        let outstanding = state
            .outstanding_request
            .as_ref()
            .filter(|request| {
                request.token == request_token
                    && request.kind == MobileDirectOutstandingRequestKind::Directory
            })
            .ok_or_else(|| VeilError::Session {
                msg: "mobile Direct directory request is stale".to_string(),
            })?;
        let response = Zeroizing::new(response);
        if let Err(error) = require_mobile_direct_response_limit(outstanding, response.as_slice()) {
            fail_mobile_direct_sync_sticky(state);
            return Err(error);
        }
        let binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        if binding.as_ref() != Some(&state.epoch) {
            return Err(VeilError::Session {
                msg: "mobile Direct sync lease is stale".to_string(),
            });
        }
        let mut client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;
        let page = veil_client::direct::install_authenticated_direct_directory_page_tracked(
            &mut client,
            &state.epoch.binding.canonical_server_origin,
            &state.epoch.binding.user_id,
            state.next_cursor.as_deref(),
            &mut state.directory_history,
            response.as_slice(),
        )
        .map_err(|msg| VeilError::Session { msg })?;
        let skipped_non_direct =
            page.skipped_non_direct
                .try_into()
                .map_err(|_| VeilError::Session {
                    msg: "mobile Direct skipped conversation count overflow".to_string(),
                })?;
        state.outstanding_request = None;
        let mut conversations = Vec::with_capacity(page.conversations.len());
        for conversation in page.conversations {
            state.peers.insert(
                conversation.conversation_id.clone(),
                MobileDirectPeer {
                    user_id: conversation.peer_user_id.clone(),
                    identity_key: conversation.peer_identity_key,
                    signing_key: conversation.peer_signing_key,
                },
            );
            conversations.push(MobileDirectConversationData {
                conversation_id: conversation.conversation_id,
                name: conversation.name,
                peer_user_id: conversation.peer_user_id,
                peer_username: conversation.peer_username,
                peer_identity_key_hex: hex::encode(conversation.peer_identity_key),
                peer_signing_key_hex: hex::encode(conversation.peer_signing_key),
                needs_prekey: conversation.needs_prekey,
            });
        }
        state.next_cursor = page.next_cursor.clone();
        let directory_complete = page.next_cursor.is_none();
        if directory_complete {
            begin_mobile_direct_history_phase(state)?;
        }
        Ok(MobileDirectDirectoryPageData {
            conversations,
            next_cursor: page.next_cursor,
            skipped_non_direct,
            directory_complete,
        })
    }

    /// Prepare exactly one immutable Direct-history GET. The scheduler owns
    /// conversation order and cursors; Android can only transport the returned
    /// capability. Repeating this operation before installation returns the
    /// same immutable request token and bytes.
    pub fn prepare_next_direct_history_request(
        &self,
        lease_token: String,
    ) -> Result<MobileDirectHistoryNext, VeilError> {
        require_mobile_sync_token(&lease_token)?;
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let state = sync.as_mut().ok_or_else(|| VeilError::Session {
            msg: "mobile Direct sync is unavailable".to_string(),
        })?;
        if state.token != lease_token {
            return Err(VeilError::Session {
                msg: "mobile Direct history lease is stale".to_string(),
            });
        }
        let binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        if binding.as_ref() != Some(&state.epoch) {
            return Err(VeilError::Session {
                msg: "mobile Direct history lease is stale".to_string(),
            });
        }
        if state.phase == MobileDirectSyncPhase::HistorySynchronizedAwaitingLive {
            return Ok(MobileDirectHistoryNext {
                request: None,
                histories_terminal: true,
            });
        }
        if state.phase != MobileDirectSyncPhase::DirectHistory {
            return Err(VeilError::Session {
                msg: "mobile Direct history is unavailable in this phase".to_string(),
            });
        }

        if state.history_index >= state.history_order.len() {
            state.phase = MobileDirectSyncPhase::HistorySynchronizedAwaitingLive;
            state.current_history = None;
            return Ok(MobileDirectHistoryNext {
                request: None,
                histories_terminal: true,
            });
        }
        let conversation_id = state.history_order[state.history_index].clone();
        if let Some(request) = state.outstanding_request.as_ref() {
            if request.kind
                == (MobileDirectOutstandingRequestKind::History {
                    conversation_id: conversation_id.clone(),
                })
            {
                return Ok(MobileDirectHistoryNext {
                    request: Some(mobile_direct_rest_request_data(request)),
                    histories_terminal: false,
                });
            }
            return Err(VeilError::Session {
                msg: "another mobile Direct request is already outstanding".to_string(),
            });
        }

        if state.current_history.is_none() {
            let history = match veil_client::direct_history::DirectHistorySyncState::new(
                &state.epoch.binding.canonical_server_origin,
                &state.epoch.binding.user_id,
                &conversation_id,
            ) {
                Ok(history) => history,
                Err(_) => {
                    fail_mobile_direct_sync_sticky(state);
                    return Err(VeilError::Session {
                        msg: "mobile Direct history scope is invalid".to_string(),
                    });
                }
            };
            state.current_history = Some(history);
        }
        let history = state
            .current_history
            .as_ref()
            .ok_or_else(|| VeilError::Session {
                msg: "mobile Direct history state is unavailable".to_string(),
            })?;
        if history.conversation_id() != conversation_id {
            fail_mobile_direct_sync_sticky(state);
            return Err(VeilError::Session {
                msg: "mobile Direct history scheduler diverged".to_string(),
            });
        }
        let target = match veil_client::direct_history::direct_history_request_target(history) {
            Ok(target) => target,
            Err(_) => {
                fail_mobile_direct_sync_sticky(state);
                return Err(VeilError::Session {
                    msg: "mobile Direct history request is unavailable".to_string(),
                });
            }
        };
        let request = MobileDirectOutstandingRequest {
            kind: MobileDirectOutstandingRequestKind::History { conversation_id },
            token: new_mobile_sync_token(),
            method: "GET",
            target,
            body: Zeroizing::new(Vec::new()),
            response_limit_bytes: veil_client::direct_history::DIRECT_HISTORY_RESPONSE_LIMIT as u32,
            peer_prekey_signature_released: false,
        };
        let result = mobile_direct_rest_request_data(&request);
        state.outstanding_request = Some(request);
        Ok(MobileDirectHistoryNext {
            request: Some(result),
            histories_terminal: false,
        })
    }

    /// Install one bounded history page and return only a coarse typed
    /// scheduler outcome. Conversation rejection is isolated; uncertain local
    /// storage is a sticky global abort for this authenticated generation.
    pub fn install_direct_history_response(
        &self,
        lease_token: String,
        request_token: String,
        response: Vec<u8>,
    ) -> Result<MobileDirectHistoryProgress, VeilError> {
        require_mobile_sync_token(&lease_token)?;
        require_mobile_sync_token(&request_token)?;
        let response = Zeroizing::new(response);
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let state = sync.as_mut().ok_or_else(|| VeilError::Session {
            msg: "mobile Direct sync is unavailable".to_string(),
        })?;
        if state.token != lease_token || state.phase != MobileDirectSyncPhase::DirectHistory {
            return Err(VeilError::Session {
                msg: "mobile Direct history lease is stale or terminal".to_string(),
            });
        }
        let outstanding = state
            .outstanding_request
            .as_ref()
            .filter(|request| request.token == request_token)
            .cloned()
            .ok_or_else(|| VeilError::Session {
                msg: "mobile Direct history request is stale".to_string(),
            })?;
        let conversation_id = match &outstanding.kind {
            MobileDirectOutstandingRequestKind::History { conversation_id } => {
                conversation_id.clone()
            }
            _ => {
                return Err(VeilError::Session {
                    msg: "mobile Direct request stage changed".to_string(),
                })
            }
        };
        if let Err(error) = require_mobile_direct_response_limit(&outstanding, response.as_slice())
        {
            fail_mobile_direct_sync_sticky(state);
            return Err(error);
        }
        let binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        if binding.as_ref() != Some(&state.epoch) {
            return Err(VeilError::Session {
                msg: "mobile Direct history lease is stale".to_string(),
            });
        }
        if state.history_order.get(state.history_index) != Some(&conversation_id)
            || state
                .current_history
                .as_ref()
                .is_none_or(|history| history.conversation_id() != conversation_id)
        {
            fail_mobile_direct_sync_sticky(state);
            return Err(VeilError::Session {
                msg: "mobile Direct history scheduler diverged".to_string(),
            });
        }

        let mut client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;
        let install = veil_client::direct_history::install_authenticated_direct_history_page(
            &mut client,
            state
                .current_history
                .as_mut()
                .expect("history state preflighted"),
            response.as_slice(),
        );
        state.outstanding_request = None;

        use veil_client::direct_history::{DirectHistoryInstallError, DirectHistorySyncOutcome};
        let outcome = match install {
            Ok(page) => match page.outcome {
                DirectHistorySyncOutcome::InProgress => MobileDirectHistoryOutcome::InProgress,
                DirectHistorySyncOutcome::Complete => {
                    finish_mobile_direct_history_conversation(
                        state,
                        &conversation_id,
                        MobileDirectHistoryOutcome::Complete,
                    )?;
                    MobileDirectHistoryOutcome::Complete
                }
                DirectHistorySyncOutcome::IncompleteSelfHistory => {
                    finish_mobile_direct_history_conversation(
                        state,
                        &conversation_id,
                        MobileDirectHistoryOutcome::IncompleteSelfHistory,
                    )?;
                    MobileDirectHistoryOutcome::IncompleteSelfHistory
                }
            },
            Err(DirectHistoryInstallError::ConversationRejected { .. }) => {
                finish_mobile_direct_history_conversation(
                    state,
                    &conversation_id,
                    MobileDirectHistoryOutcome::ConversationRejected,
                )?;
                MobileDirectHistoryOutcome::ConversationRejected
            }
            Err(DirectHistoryInstallError::StorageUncertain) => {
                fail_mobile_direct_sync_sticky(state);
                MobileDirectHistoryOutcome::StorageUncertain
            }
        };
        Ok(MobileDirectHistoryProgress {
            outcome,
            histories_terminal: state.phase
                == MobileDirectSyncPhase::HistorySynchronizedAwaitingLive,
        })
    }

    /// Pump authenticated WebSocket events into the shared bounded deferred
    /// FIFO while REST bootstrap/history is still in progress. This method
    /// never drains or publishes the FIFO; the separate bounded replay method
    /// owns the only history-to-live transition to Ready.
    pub fn buffer_direct_live_events_during_sync(
        &self,
        lease_token: String,
    ) -> Result<MobileDirectLiveBufferProgress, VeilError> {
        require_mobile_sync_token(&lease_token)?;
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let state = sync.as_mut().ok_or_else(|| VeilError::Session {
            msg: "mobile Direct sync is unavailable".to_string(),
        })?;
        if state.token != lease_token
            || !matches!(
                state.phase,
                MobileDirectSyncPhase::OwnPreKeys
                    | MobileDirectSyncPhase::Directory
                    | MobileDirectSyncPhase::DirectHistory
            )
        {
            return Err(VeilError::Session {
                msg: "mobile Direct live buffer lease is stale or unavailable".to_string(),
            });
        }
        let binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        if binding.as_ref() != Some(&state.epoch) {
            return Err(VeilError::Session {
                msg: "mobile Direct live buffer lease is stale".to_string(),
            });
        }
        let mut client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;
        let buffered = match client.buffer_connection_events_during_sync() {
            Ok(buffered) => buffered,
            Err(_) => {
                fail_mobile_direct_sync_sticky(state);
                return Err(VeilError::Session {
                    msg: "mobile Direct live buffer terminated".to_string(),
                });
            }
        };
        Ok(MobileDirectLiveBufferProgress {
            buffered_events: buffered.try_into().map_err(|_| VeilError::Session {
                msg: "mobile Direct live buffer count overflow".to_string(),
            })?,
            history_synchronized: state.phase
                == MobileDirectSyncPhase::HistorySynchronizedAwaitingLive,
        })
    }

    /// Drain one bounded, authenticated Direct live-replay turn.
    ///
    /// The history-to-live handoff reaches `Ready` only after the shared FIFO
    /// explicitly reports quiescence. A full batch must be scheduled again;
    /// terminal transport or uncertain SQLCipher state poisons this lease and
    /// never opens the renderer projection boundary.
    pub fn replay_direct_live_events(
        &self,
        lease_token: String,
    ) -> Result<MobileDirectLiveReplayProgress, VeilError> {
        require_mobile_sync_token(&lease_token)?;
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let state = sync.as_mut().ok_or_else(|| VeilError::Session {
            msg: "mobile Direct sync is unavailable".to_string(),
        })?;
        if state.token != lease_token
            || !matches!(
                state.phase,
                MobileDirectSyncPhase::HistorySynchronizedAwaitingLive
                    | MobileDirectSyncPhase::Ready
            )
        {
            return Err(VeilError::Session {
                msg: "mobile Direct live replay lease is stale or unavailable".to_string(),
            });
        }
        if state.phase == MobileDirectSyncPhase::HistorySynchronizedAwaitingLive
            && (state.outstanding_request.is_some()
                || state.current_history.is_some()
                || state.history_index != state.history_order.len())
        {
            fail_mobile_direct_sync_sticky(state);
            return Err(VeilError::Session {
                msg: "mobile Direct history-to-live checkpoint diverged".to_string(),
            });
        }

        let mut binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        if binding.as_ref() != Some(&state.epoch) {
            fail_mobile_direct_sync_sticky(state);
            return Err(VeilError::Session {
                msg: "mobile Direct live replay lease is stale".to_string(),
            });
        }
        let mut client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;
        let report = match self.runtime.block_on(client.replay_direct_live_events_v1()) {
            Ok(report) => report,
            Err(_) => {
                *binding = None;
                fail_mobile_direct_sync_sticky(state);
                return Err(VeilError::Session {
                    msg: "mobile Direct live replay terminated".to_string(),
                });
            }
        };
        if report.consumed > veil_client::api::DIRECT_LIVE_REPLAY_MAX_BATCH_V1
            || (!report.quiescent
                && report.consumed != veil_client::api::DIRECT_LIVE_REPLAY_MAX_BATCH_V1)
        {
            *binding = None;
            fail_mobile_direct_sync_sticky(state);
            return Err(VeilError::Session {
                msg: "mobile Direct live replay violated its batch contract".to_string(),
            });
        }
        if report.quiescent {
            state.phase = MobileDirectSyncPhase::Ready;
        }
        Ok(MobileDirectLiveReplayProgress {
            consumed: report
                .consumed
                .try_into()
                .expect("Direct live replay batch fits u32"),
            projection_changed: report.stored > 0
                || report.duplicates > 0
                || report.newly_blocked > 0
                || report.visible_mutations > 0,
            needs_immediate_pump: !report.quiescent,
            outbox_replay_required: state.phase == MobileDirectSyncPhase::Ready
                && !state.outbox_replay_complete,
            ready: state.phase == MobileDirectSyncPhase::Ready && state.outbox_replay_complete,
        })
    }

    /// Replay one native-owned FIFO page of the exact durable Direct outbox.
    ///
    /// This barrier is available only after authenticated history/live replay
    /// reached the exact lease's Ready phase. The cursor never crosses FFI and
    /// is reset to `None` by construction for every new lease. Renderer and
    /// send projection guards remain closed until a bounded turn reports the
    /// end of the queue.
    pub fn replay_direct_outbox(
        &self,
        lease_token: String,
    ) -> Result<MobileDirectOutboxReplayProgress, VeilError> {
        require_mobile_sync_token(&lease_token)?;
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let state = sync.as_mut().ok_or_else(|| VeilError::Session {
            msg: "mobile Direct outbox replay is unavailable".to_string(),
        })?;
        if state.token != lease_token
            || state.phase != MobileDirectSyncPhase::Ready
            || state.outstanding_request.is_some()
        {
            return Err(VeilError::Session {
                msg: "mobile Direct outbox replay lease is stale or unavailable".to_string(),
            });
        }

        let mut binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        if binding.as_ref() != Some(&state.epoch) {
            fail_mobile_direct_sync_sticky(state);
            return Err(VeilError::Session {
                msg: "mobile Direct outbox replay lease is stale".to_string(),
            });
        }
        let mut client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;

        if state.outbox_replay_complete {
            return Ok(MobileDirectOutboxReplayProgress {
                visited: 0,
                enqueued: 0,
                needs_immediate_pump: false,
                replay_complete: true,
            });
        }

        let previous_cursor = state.outbox_replay_cursor;
        let report = match self.runtime.block_on(
            client.replay_direct_outbox_v1(previous_cursor, MOBILE_DIRECT_OUTBOX_REPLAY_MAX_BATCH),
        ) {
            Ok(report) => report,
            Err(veil_client::api::DirectSendErrorV1::Rejected(_)) => {
                revoke_mobile_direct_epoch_locked(state, &mut binding, &mut client);
                return Err(VeilError::Session {
                    msg: "mobile Direct outbox replay was rejected".to_string(),
                });
            }
            Err(veil_client::api::DirectSendErrorV1::StorageUncertain(_)) => {
                *binding = None;
                fail_mobile_direct_sync_sticky(state);
                return Err(VeilError::Session {
                    msg: "mobile Direct outbox replay storage is uncertain".to_string(),
                });
            }
        };

        let cursor_is_valid = match (previous_cursor, report.next_queue_order, report.visited) {
            (previous, next, 0) => previous == next,
            (None, Some(next), _) => next > 0,
            (Some(previous), Some(next), _) => next > previous,
            _ => false,
        };
        let report_is_valid = report.visited <= MOBILE_DIRECT_OUTBOX_REPLAY_MAX_BATCH
            && report.enqueued <= report.visited
            && report.pending_total <= veil_client::api::DIRECT_OUTBOX_MAX_PENDING_V1
            && cursor_is_valid
            && !(report.reached_end && report.transport_blocked)
            && (report.reached_end
                || report.transport_blocked
                || report.visited == MOBILE_DIRECT_OUTBOX_REPLAY_MAX_BATCH);
        if !report_is_valid {
            revoke_mobile_direct_epoch_locked(state, &mut binding, &mut client);
            return Err(VeilError::Session {
                msg: "mobile Direct outbox replay violated its batch contract".to_string(),
            });
        }

        if report.transport_blocked {
            revoke_mobile_direct_epoch_locked(state, &mut binding, &mut client);
            return Err(VeilError::Session {
                msg: "mobile Direct outbox replay transport is unavailable".to_string(),
            });
        }
        let progress = MobileDirectOutboxReplayProgress {
            visited: report
                .visited
                .try_into()
                .expect("bounded Direct outbox replay count fits u32"),
            enqueued: report
                .enqueued
                .try_into()
                .expect("bounded Direct outbox enqueue count fits u32"),
            needs_immediate_pump: !report.reached_end,
            replay_complete: report.reached_end,
        };
        state.outbox_replay_cursor = report.next_queue_order;
        if report.reached_end {
            state.outbox_replay_complete = true;
        }
        Ok(progress)
    }

    /// Atomically accept one explicit Direct text intent under the exact Ready
    /// lease. Every authority guard is repeated while retaining the documented
    /// `direct_sync -> binding -> client` lock order. No message ID, sequence,
    /// ciphertext or error detail crosses FFI.
    pub fn send_direct_text(
        &self,
        lease_token: String,
        conversation_id: String,
        plaintext_utf8: Vec<u8>,
    ) -> Result<MobileDirectTextSendOutcome, VeilError> {
        let plaintext_utf8 = Zeroizing::new(plaintext_utf8);
        if require_mobile_sync_token(&lease_token).is_err() {
            return Ok(MobileDirectTextSendOutcome::Unavailable);
        }
        let Ok(conversation_id) =
            require_canonical_user_id("Direct conversation ID", &conversation_id)
        else {
            return Ok(MobileDirectTextSendOutcome::Unavailable);
        };
        let Ok(plaintext) = std::str::from_utf8(plaintext_utf8.as_slice()) else {
            return Ok(MobileDirectTextSendOutcome::Rejected);
        };
        if plaintext.is_empty() || plaintext.len() > MOBILE_DIRECT_MESSAGE_MAX_PLAINTEXT_BYTES {
            return Ok(MobileDirectTextSendOutcome::Rejected);
        }

        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let Some(state) = sync.as_mut() else {
            return Ok(MobileDirectTextSendOutcome::Unavailable);
        };
        let mut binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        let mut client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;
        if state.outstanding_request.is_some() {
            return Ok(MobileDirectTextSendOutcome::Unavailable);
        }
        match mobile_direct_send_readiness_for_current_lease(
            &client,
            state,
            binding.as_ref(),
            &lease_token,
            &conversation_id,
        ) {
            MobileDirectSendReadiness::NeedsPreKey => {
                return Ok(MobileDirectTextSendOutcome::NeedsPreKey)
            }
            MobileDirectSendReadiness::Unavailable => {
                return Ok(MobileDirectTextSendOutcome::Unavailable)
            }
            MobileDirectSendReadiness::Ready => {}
        }

        match self
            .runtime
            .block_on(client.enqueue_direct_text_v1(&conversation_id, plaintext))
        {
            Ok(report) if report.transport_enqueued && report.sequence > 0 => {
                Ok(MobileDirectTextSendOutcome::Accepted)
            }
            Ok(_) => {
                // SQLCipher already owns this exact user intent. Revoke the
                // transport lease so only a new Ready epoch can replay it.
                revoke_mobile_direct_epoch_locked(state, &mut binding, &mut client);
                Ok(MobileDirectTextSendOutcome::AcceptedForReplay)
            }
            Err(veil_client::api::DirectSendErrorV1::Rejected(_)) => {
                Ok(MobileDirectTextSendOutcome::Rejected)
            }
            Err(veil_client::api::DirectSendErrorV1::StorageUncertain(_)) => {
                *binding = None;
                fail_mobile_direct_sync_sticky(state);
                Err(VeilError::Session {
                    msg: "mobile Direct send storage is uncertain".to_string(),
                })
            }
        }
    }

    /// Return coarse, advisory send readiness for one exact Direct route under
    /// the current Ready lease.
    ///
    /// Every malformed, stale, denied, poisoned, disconnected, or revoked
    /// state collapses to `Unavailable`. The result exposes neither denial
    /// detail nor key material and must never be treated as a send capability:
    /// a future send operation must repeat all guards atomically.
    pub fn direct_send_readiness(
        &self,
        lease_token: String,
        conversation_id: String,
    ) -> MobileDirectSendReadiness {
        if require_mobile_sync_token(&lease_token).is_err() {
            return MobileDirectSendReadiness::Unavailable;
        }
        let Ok(conversation_id) =
            require_canonical_user_id("Direct conversation ID", &conversation_id)
        else {
            return MobileDirectSendReadiness::Unavailable;
        };
        let Ok(sync) = self.direct_sync.lock() else {
            return MobileDirectSendReadiness::Unavailable;
        };
        let Some(state) = sync.as_ref() else {
            return MobileDirectSendReadiness::Unavailable;
        };
        let Ok(binding) = self.binding.lock() else {
            return MobileDirectSendReadiness::Unavailable;
        };
        let Ok(client) = self.client.lock() else {
            return MobileDirectSendReadiness::Unavailable;
        };
        mobile_direct_send_readiness_for_current_lease(
            &client,
            state,
            binding.as_ref(),
            &lease_token,
            &conversation_id,
        )
    }

    /// Return a bounded UI projection for exactly one authenticated Direct.
    ///
    /// The caller supplies the conversation id it is about to render. Native
    /// code checks the current directory lease, the exact live-replay
    /// availability, and the guarded client projection while retaining the
    /// documented `direct_sync -> binding -> client` lock order. Every denied
    /// state is collapsed to the same opaque result with no identifiers.
    pub fn project_direct_messages(
        &self,
        conversation_id: String,
    ) -> Result<MobileDirectMessageProjection, VeilError> {
        let conversation_id =
            require_canonical_user_id("Direct conversation ID", &conversation_id)?;
        let sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let Some(state) = sync.as_ref() else {
            return Ok(unavailable_mobile_direct_message_projection());
        };
        if state.phase != MobileDirectSyncPhase::Ready || !state.outbox_replay_complete {
            return Ok(unavailable_mobile_direct_message_projection());
        }

        let binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        if binding.as_ref() != Some(&state.epoch) {
            return Ok(unavailable_mobile_direct_message_projection());
        }

        let client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;
        let availability = mobile_direct_projection_availability(
            client.direct_conversation_availability_v1(&conversation_id),
        );
        if availability != MobileDirectMessageProjectionAvailability::Available
            || state.blocked_conversations.contains_key(&conversation_id)
        {
            return Ok(unavailable_mobile_direct_message_projection());
        }
        let Some((self_identity_key, peer_identity_key)) =
            mobile_direct_projection_scope(&client, state, &conversation_id)
        else {
            return Ok(unavailable_mobile_direct_message_projection());
        };

        let messages = match client
            .direct_messages_projection_v1(&conversation_id, MOBILE_DIRECT_MESSAGE_PROJECTION_LIMIT)
        {
            Ok(messages) => messages,
            Err(_) => return Ok(unavailable_mobile_direct_message_projection()),
        };
        if messages.len() > MOBILE_DIRECT_MESSAGE_PROJECTION_LIMIT as usize {
            return Ok(unavailable_mobile_direct_message_projection());
        }
        let mut total_plaintext_bytes = 0usize;
        for message in &messages {
            const MAX_TIMESTAMP_MS: i64 = 253_402_300_799_999;
            let canonical_message_id = uuid::Uuid::parse_str(&message.id).is_ok_and(|parsed| {
                !parsed.is_nil() && parsed.hyphenated().to_string() == message.id
            });
            let timestamp_is_valid = message
                .server_timestamp
                .is_none_or(|timestamp_ms| (0..=MAX_TIMESTAMP_MS).contains(&timestamp_ms));
            if mobile_direct_message_delivery(message.status as u8).is_none() {
                return Ok(unavailable_mobile_direct_message_projection());
            }
            let expected_sender = if message.is_outgoing {
                &self_identity_key
            } else {
                &peer_identity_key
            };
            let plaintext_bytes = message.plaintext.len();
            let Some(next_total_plaintext_bytes) =
                total_plaintext_bytes.checked_add(plaintext_bytes)
            else {
                return Ok(unavailable_mobile_direct_message_projection());
            };
            // Stage 5 publishes only immutable, non-expiring Direct text.
            // Future protocol shapes need an explicit projection contract.
            if message.conversation_id != conversation_id
                || message.sender_key.as_slice() != expected_sender.as_slice()
                || message.plaintext.is_empty()
                || plaintext_bytes > MOBILE_DIRECT_MESSAGE_MAX_PLAINTEXT_BYTES
                || next_total_plaintext_bytes > MOBILE_DIRECT_MESSAGE_PROJECTION_MAX_PLAINTEXT_BYTES
                || message.msg_type != 0
                || message.reply_to_id.is_some()
                || message.expires_at.is_some()
                || !message.attachments.is_empty()
                || !canonical_message_id
                || !timestamp_is_valid
            {
                return Ok(unavailable_mobile_direct_message_projection());
            }
            total_plaintext_bytes = next_total_plaintext_bytes;
        }

        let mut projected = Vec::with_capacity(messages.len());
        for message in messages {
            projected.push(Arc::new(MobileDirectMessageData {
                message_id: Zeroizing::new(message.id),
                text: Zeroizing::new(message.plaintext),
                timestamp_ms: message.server_timestamp,
                direction: if message.is_outgoing {
                    MobileDirectMessageDirection::Outgoing
                } else {
                    MobileDirectMessageDirection::Incoming
                },
                delivery: mobile_direct_message_delivery(message.status as u8)
                    .expect("delivery state preflighted"),
            }));
        }
        Ok(MobileDirectMessageProjection {
            availability: MobileDirectMessageProjectionAvailability::Available,
            messages: projected,
        })
    }

    /// Prepare one peer-prekey fetch only while the exact live route still
    /// authoritatively needs a session. The advisory readiness result is never
    /// accepted as a capability: every guard is repeated here while retaining
    /// `direct_sync -> binding -> client`.
    pub fn prepare_direct_prekey_request(
        &self,
        lease_token: String,
        conversation_id: String,
    ) -> Result<MobileDirectRestRequest, VeilError> {
        require_mobile_sync_token(&lease_token)?;
        require_canonical_user_id("Direct conversation ID", &conversation_id)?;
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let state = sync
            .as_mut()
            .ok_or_else(mobile_direct_prekey_unavailable_error)?;
        // A caller from an older generation must never revoke a capability
        // owned by the current lease, even when it guesses the public route.
        if state.token != lease_token || state.phase != MobileDirectSyncPhase::Ready {
            return Err(mobile_direct_prekey_unavailable_error());
        }
        let binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        if binding.as_ref() != Some(&state.epoch) {
            return Err(mobile_direct_prekey_unavailable_error());
        }
        let client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;
        let readiness = mobile_direct_send_readiness_for_current_lease(
            &client,
            state,
            binding.as_ref(),
            &lease_token,
            &conversation_id,
        );
        if readiness != MobileDirectSendReadiness::NeedsPreKey {
            let revoke_exact = state.outstanding_request.as_ref().is_some_and(|request| {
                request.kind
                    == (MobileDirectOutstandingRequestKind::PeerPreKey {
                        conversation_id: conversation_id.clone(),
                    })
            });
            if revoke_exact {
                state.outstanding_request = None;
            }
            return Err(mobile_direct_prekey_unavailable_error());
        }
        let peer = state
            .peers
            .get(&conversation_id)
            .cloned()
            .expect("prekey readiness preflighted the peer");
        if let Some(request) = state.outstanding_request.as_ref() {
            if request.kind
                == (MobileDirectOutstandingRequestKind::PeerPreKey {
                    conversation_id: conversation_id.clone(),
                })
            {
                return Ok(mobile_direct_rest_request_data(request));
            }
            return Err(VeilError::Session {
                msg: "another mobile Direct request is already outstanding".to_string(),
            });
        }
        let request = MobileDirectOutstandingRequest {
            kind: MobileDirectOutstandingRequestKind::PeerPreKey {
                conversation_id: conversation_id.clone(),
            },
            token: new_mobile_sync_token(),
            method: "GET",
            target: format!("/v1/prekeys/{}", hex::encode(peer.identity_key)),
            body: Zeroizing::new(Vec::new()),
            response_limit_bytes: veil_client::direct::DIRECT_PREKEY_RESPONSE_LIMIT as u32,
            peer_prekey_signature_released: false,
        };
        let result = mobile_direct_rest_request_data(&request);
        state.outstanding_request = Some(request);
        Ok(result)
    }

    pub fn install_direct_prekey_bundle(
        &self,
        lease_token: String,
        request_token: String,
        conversation_id: String,
        response: Vec<u8>,
    ) -> Result<MobileDirectPreKeyResult, VeilError> {
        // The server controls these bytes. Guard them before every validation
        // or late response path so rejected and revoked bodies are wiped too.
        let response = Zeroizing::new(response);
        require_mobile_sync_token(&lease_token)?;
        require_mobile_sync_token(&request_token)?;
        require_canonical_user_id("Direct conversation ID", &conversation_id)?;
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let state = sync
            .as_mut()
            .ok_or_else(mobile_direct_prekey_unavailable_error)?;
        // Validate the lease owner before inspecting or consuming any current
        // request capability. A delayed generation cannot cancel its successor.
        if state.token != lease_token || state.phase != MobileDirectSyncPhase::Ready {
            return Err(mobile_direct_prekey_unavailable_error());
        }
        let mut binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        if binding.as_ref() != Some(&state.epoch) {
            return Err(mobile_direct_prekey_unavailable_error());
        }
        let outstanding = state
            .outstanding_request
            .as_ref()
            .filter(|request| {
                request.token == request_token
                    && request.kind
                        == (MobileDirectOutstandingRequestKind::PeerPreKey {
                            conversation_id: conversation_id.clone(),
                        })
            })
            .ok_or_else(|| VeilError::Session {
                msg: "mobile Direct prekey request is stale".to_string(),
            })?
            .clone();
        // Preserve the existing bounded-response sticky abort even when a late
        // response observes Ready or another revoked route state.
        if let Err(error) = require_mobile_direct_response_limit(&outstanding, response.as_slice())
        {
            fail_mobile_direct_sync_sticky(state);
            return Err(error);
        }
        let mut client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;

        if !outstanding.peer_prekey_signature_released {
            // A response without the one native-released signature cannot be
            // tied to this destructive GET. Consume only its exact capability.
            state.outstanding_request = None;
            return Err(mobile_direct_prekey_unavailable_error());
        }

        let peer = match mobile_direct_send_readiness_for_current_lease(
            &client,
            state,
            binding.as_ref(),
            &lease_token,
            &conversation_id,
        ) {
            MobileDirectSendReadiness::NeedsPreKey => {
                let peer = state
                    .peers
                    .get(&conversation_id)
                    .cloned()
                    .expect("prekey readiness preflighted the peer");
                // A signed destructive claim is one-shot even when its body is
                // malformed or cryptographically rejected. Take it before any
                // response parsing or ratchet mutation.
                state.outstanding_request = None;
                peer
            }
            MobileDirectSendReadiness::Ready => {
                // An authenticated incoming message may establish the session
                // while the destructive GET is in flight. Consume only the
                // matching capability and never parse or reset that ratchet.
                state.outstanding_request = None;
                return Ok(MobileDirectPreKeyResult {
                    status: "already_established".to_string(),
                });
            }
            MobileDirectSendReadiness::Unavailable => {
                // A denied route can never resume this server claim safely.
                // Revoke its exact outstanding/signing capability, but leave
                // ratchet and durable state untouched.
                state.outstanding_request = None;
                return Err(mobile_direct_prekey_unavailable_error());
            }
        };
        let result =
            match veil_client::direct::install_authenticated_direct_prekey_bundle_classified_v1(
                &mut client,
                &peer.user_id,
                peer.identity_key,
                peer.signing_key,
                response.as_slice(),
            ) {
                Ok(result) => result,
                Err(veil_client::direct::DirectPreKeyInstallErrorV1::Rejected(_)) => {
                    return Err(VeilError::Session {
                        msg: "mobile Direct prekey bundle was rejected".to_string(),
                    });
                }
                Err(veil_client::direct::DirectPreKeyInstallErrorV1::StorageUncertain(_)) => {
                    *binding = None;
                    fail_mobile_direct_sync_sticky(state);
                    return Err(VeilError::Session {
                        msg: "mobile Direct prekey storage terminated".to_string(),
                    });
                }
            };
        let status = match result {
            veil_client::direct::DirectPreKeyInstallResult::Established => "established",
            veil_client::direct::DirectPreKeyInstallResult::AlreadyEstablished => {
                "already_established"
            }
        };
        Ok(MobileDirectPreKeyResult {
            status: status.to_string(),
        })
    }

    pub fn cancel_direct_sync(&self, lease_token: String) -> Result<(), VeilError> {
        require_mobile_sync_token(&lease_token)?;
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        if sync
            .as_ref()
            .is_some_and(|state| state.token == lease_token)
        {
            *sync = None;
            Ok(())
        } else {
            Err(VeilError::Session {
                msg: "mobile Direct sync lease is stale".to_string(),
            })
        }
    }

    /// Sign only the exact native-owned Direct request identified by the
    /// current lease and request capability. The transport never supplies
    /// method, target, or body to the signing boundary. Peer-prekey GETs repeat
    /// the complete live route guard before and after signing and release at
    /// most one signature because each server fetch consumes an OPK.
    pub fn sign_direct_rest_request(
        &self,
        lease_token: String,
        request_token: String,
    ) -> Result<RestSignatureData, VeilError> {
        require_mobile_sync_token(&lease_token)?;
        require_mobile_sync_token(&request_token)?;
        let (epoch, request) = {
            let mut sync = self
                .direct_sync
                .lock()
                .map_err(|error| VeilError::Session {
                    msg: format!("lock mobile Direct sync: {error}"),
                })?;
            let state = sync.as_mut().ok_or_else(|| VeilError::Session {
                msg: "mobile Direct sync is unavailable".to_string(),
            })?;
            if state.token != lease_token {
                return Err(VeilError::Session {
                    msg: "mobile Direct sync lease is stale".to_string(),
                });
            }
            let request = mobile_direct_outstanding_request(state, &request_token)?.clone();
            if let MobileDirectOutstandingRequestKind::PeerPreKey { conversation_id } =
                &request.kind
            {
                let binding = self.binding.lock().map_err(|error| VeilError::Session {
                    msg: format!("lock mobile binding: {error}"),
                })?;
                let client = self.client.lock().map_err(|error| VeilError::Session {
                    msg: format!("lock mobile client: {error}"),
                })?;
                if mobile_direct_send_readiness_for_current_lease(
                    &client,
                    state,
                    binding.as_ref(),
                    &lease_token,
                    conversation_id,
                ) != MobileDirectSendReadiness::NeedsPreKey
                {
                    state.outstanding_request = None;
                    return Err(mobile_direct_prekey_unavailable_error());
                }
                if request.peer_prekey_signature_released {
                    // Retain the winner's outstanding response capability; it
                    // is no longer signable, but install still needs it.
                    return Err(mobile_direct_prekey_unavailable_error());
                }
            }
            (state.epoch.clone(), request)
        };

        let signature = self.sign_mobile_direct_request(&epoch, &request)?;

        #[cfg(test)]
        self.run_direct_post_sign_pre_postflight_hook();

        // The request capability must still name the same immutable bytes
        // after signing. A concurrent cancel/reconnect consumes the signature
        // inside native code instead of releasing it to the transport.
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let state = sync.as_mut().ok_or_else(|| VeilError::Session {
            msg: "mobile Direct sync changed while signing".to_string(),
        })?;
        let lease_drifted = state.token != lease_token || state.epoch != epoch;
        let current_request = state
            .outstanding_request
            .as_ref()
            .filter(|current| current.token == request_token);
        if lease_drifted || current_request != Some(&request) {
            if matches!(
                &request.kind,
                MobileDirectOutstandingRequestKind::PeerPreKey { .. }
            ) {
                let same_peer_prekey_capability = current_request.is_some_and(|current| {
                    current.kind == request.kind
                        && current.method == request.method
                        && current.target == request.target
                        && current.body == request.body
                        && current.response_limit_bytes == request.response_limit_bytes
                });
                if lease_drifted && same_peer_prekey_capability {
                    state.outstanding_request = None;
                }
                // A concurrent winning signer differs only by its released bit;
                // never clear the response capability it still owns.
                return Err(mobile_direct_prekey_unavailable_error());
            }
            return Err(VeilError::Session {
                msg: "mobile Direct request changed while signing".to_string(),
            });
        }
        if let MobileDirectOutstandingRequestKind::PeerPreKey { conversation_id } = &request.kind {
            let binding = self.binding.lock().map_err(|error| VeilError::Session {
                msg: format!("lock mobile binding: {error}"),
            })?;
            let client = self.client.lock().map_err(|error| VeilError::Session {
                msg: format!("lock mobile client: {error}"),
            })?;
            if mobile_direct_send_readiness_for_current_lease(
                &client,
                state,
                binding.as_ref(),
                &lease_token,
                conversation_id,
            ) != MobileDirectSendReadiness::NeedsPreKey
            {
                state.outstanding_request = None;
                return Err(mobile_direct_prekey_unavailable_error());
            }
            state
                .outstanding_request
                .as_mut()
                .expect("peer prekey request was postflighted")
                .peer_prekey_signature_released = true;
        }
        Ok(signature)
    }

    pub fn disconnect(&self) -> Result<(), VeilError> {
        clear_mobile_direct_sync_fail_closed(&self.direct_sync);
        let _client = invalidate_mobile_session(&self.binding, &self.client)?;
        Ok(())
    }
}

impl VeilMobileSession {
    #[cfg(test)]
    fn run_direct_post_sign_pre_postflight_hook(&self) {
        let hook = self
            .direct_post_sign_pre_postflight_hook
            .lock()
            .expect("lock mobile Direct post-sign test hook")
            .clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn sign_mobile_direct_request(
        &self,
        expected_epoch: &MobileAuthenticatedEpoch,
        request: &MobileDirectOutstandingRequest,
    ) -> Result<RestSignatureData, VeilError> {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let origin =
            require_canonical_server_origin(&expected_epoch.binding.canonical_server_origin)?;
        if self.authenticated_epoch()? != *expected_epoch {
            return Err(VeilError::Session {
                msg: "mobile binding changed before signing Direct request".to_string(),
            });
        }
        let method = require_rest_method(request.method)?;
        require_rest_target(&request.target)?;
        if request.body.len() > 64 * 1024 {
            return Err(VeilError::InvalidInput {
                msg: "REST request body exceeds the mobile signing limit".to_string(),
            });
        }
        let timestamp_ms = self.next_rest_timestamp_ms()?;
        let authority = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .ok_or_else(|| VeilError::InvalidInput {
                msg: "canonical origin has no supported scheme".to_string(),
            })?;
        let canonical = format!(
            "veil-rest-v1\n{method}\n{authority}\n{}\n{timestamp_ms}\n{}",
            request.target,
            hex::encode(Sha256::digest(request.body.as_slice())),
        );
        let signature = self
            .client
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile client: {error}"),
            })?
            .sign_message(canonical.as_bytes())
            .map_err(|msg| VeilError::Session { msg })?;
        if self.authenticated_epoch()? != *expected_epoch {
            return Err(VeilError::Session {
                msg: "mobile binding changed while signing Direct request".to_string(),
            });
        }
        Ok(RestSignatureData {
            user_id: expected_epoch.binding.user_id.clone(),
            timestamp_ms: timestamp_ms.to_string(),
            signature_base64: base64::engine::general_purpose::STANDARD.encode(signature),
        })
    }

    fn connect_inner(
        &self,
        websocket_url: String,
        canonical_server_origin: String,
        node_access_pass: Option<Vec<u8>>,
        cancellation: Option<&MobileConnectCancellation>,
    ) -> Result<MobileAuthenticatedBinding, VeilError> {
        let node_access_pass = guard_mobile_node_access_pass(node_access_pass)?;
        validate_mobile_endpoint_pair(&websocket_url, &canonical_server_origin)?;
        // Starting a new authentication attempt invalidates the previous
        // account/origin epoch before locking or touching the network. The
        // previous transport is closed under the client lock so no old event
        // can race with the new authentication result.
        clear_mobile_direct_sync_fail_closed(&self.direct_sync);
        let mut client = invalidate_mobile_session(&self.binding, &self.client)?;
        let has_node_access_pass = node_access_pass.is_some();
        let connection = client.connect_with_client_metadata_and_access_pass(
            &websocket_url,
            "veil-android",
            "veil-android",
            mobile_node_access_pass_bytes(&node_access_pass),
        );
        let user_id = match self
            .runtime
            .block_on(await_mobile_connect(connection, cancellation))
        {
            MobileConnectOutcome::Completed(result) => {
                if cancellation.is_some_and(MobileConnectCancellation::is_cancelled) {
                    return Err(fail_closed_mobile_connect_cancellation(
                        &mut client,
                        &self.binding,
                    ));
                }
                result.map_err(|msg| safe_mobile_connect_error(msg, has_node_access_pass))?
            }
            MobileConnectOutcome::Cancelled => {
                return Err(fail_closed_mobile_connect_cancellation(
                    &mut client,
                    &self.binding,
                ));
            }
        };
        let post_auth_result = (|| {
            require_canonical_user_id("authenticated mobile user ID", &user_id)?;
            let identity_key = client
                .identity_key()
                .map_err(|msg| VeilError::Session { msg })?;
            let signing_key = client
                .signing_key()
                .map_err(|msg| VeilError::Session { msg })?;
            client
                .db()
                .ok_or_else(|| VeilError::Session {
                    msg: "mobile SQLCipher database is unavailable".to_string(),
                })?
                .bind_authenticated_self(
                    &canonical_server_origin,
                    &user_id,
                    &identity_key,
                    &signing_key,
                )
                .map_err(|msg| VeilError::Session { msg })?;
            let binding = MobileAuthenticatedBinding {
                canonical_server_origin,
                user_id,
            };
            let generation = self.next_binding_generation()?;
            *self.binding.lock().map_err(|error| VeilError::Session {
                msg: format!("lock mobile binding: {error}"),
            })? = Some(MobileAuthenticatedEpoch {
                binding: binding.clone(),
                generation,
            });
            Ok(binding)
        })();

        match post_auth_result {
            Ok(binding) => {
                // This load is the cancellation linearization point after all
                // synchronous post-auth work. If connect wins this race, the
                // Kotlin lifecycle epoch still guards publication to JS.
                if cancellation.is_some_and(MobileConnectCancellation::is_cancelled) {
                    Err(fail_closed_mobile_connect_cancellation(
                        &mut client,
                        &self.binding,
                    ))
                } else {
                    Ok(binding)
                }
            }
            Err(error) => {
                fail_closed_mobile_post_auth(|| client.disconnect(), &self.binding, error)
            }
        }
    }

    fn next_rest_timestamp_ms(&self) -> Result<i64, VeilError> {
        let now: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VeilError::Session {
                msg: "system clock is before Unix epoch".to_string(),
            })?
            .as_millis()
            .try_into()
            .map_err(|_| VeilError::Session {
                msg: "system clock exceeds signed millisecond range".to_string(),
            })?;
        let mut previous = self.last_rest_timestamp_ms.load(Ordering::Acquire);
        loop {
            let next = now.max(previous.checked_add(1).ok_or_else(|| VeilError::Session {
                msg: "REST timestamp allocator exhausted".to_string(),
            })?);
            match self.last_rest_timestamp_ms.compare_exchange_weak(
                previous,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(next),
                Err(actual) => previous = actual,
            }
        }
    }

    fn authenticated_epoch(&self) -> Result<MobileAuthenticatedEpoch, VeilError> {
        self.binding
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile binding: {error}"),
            })?
            .clone()
            .ok_or_else(|| VeilError::Session {
                msg: "mobile account is not authenticated".to_string(),
            })
    }

    fn next_binding_generation(&self) -> Result<u64, VeilError> {
        self.next_binding_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| VeilError::Session {
                msg: "mobile authenticated generation exhausted".to_string(),
            })
    }
}

// ── VeilRatchet (opaque object wrapping mutable RatchetSession) ──

#[derive(uniffi::Object)]
pub struct VeilRatchet {
    session: Mutex<RatchetSession>,
}

#[uniffi::export]
impl VeilRatchet {
    #[uniffi::constructor]
    pub fn init_initiator(
        shared_secret: Vec<u8>,
        peer_ratchet_key: Vec<u8>,
    ) -> Result<Arc<Self>, VeilError> {
        let ss = to_32(&shared_secret)?;
        let prk = to_32(&peer_ratchet_key)?;
        Ok(Arc::new(Self {
            session: Mutex::new(RatchetSession::init_initiator(&ss, &prk)),
        }))
    }

    #[uniffi::constructor]
    pub fn init_responder(
        shared_secret: Vec<u8>,
        our_spk_secret: Vec<u8>,
        our_spk_public: Vec<u8>,
    ) -> Result<Arc<Self>, VeilError> {
        let ss = to_32(&shared_secret)?;
        let pub_key = to_32(&our_spk_public)?;
        Ok(Arc::new(Self {
            session: Mutex::new(RatchetSession::init_responder(
                &ss,
                &our_spk_secret,
                &pub_key,
            )),
        }))
    }

    #[uniffi::constructor]
    pub fn deserialize(json: String) -> Result<Arc<Self>, VeilError> {
        let session: RatchetSession =
            serde_json::from_str(&json).map_err(|e| VeilError::Session { msg: e.to_string() })?;
        Ok(Arc::new(Self {
            session: Mutex::new(session),
        }))
    }

    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<RatchetMessage, VeilError> {
        let mut s = self
            .session
            .lock()
            .map_err(|e| VeilError::Session { msg: e.to_string() })?;
        let (header, ciphertext) = s
            .encrypt(&plaintext)
            .map_err(|e| VeilError::Crypto { msg: e })?;
        Ok(RatchetMessage {
            header: header.to_bytes(),
            ciphertext,
        })
    }

    pub fn decrypt(
        &self,
        header_bytes: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, VeilError> {
        let header = ratchet::MessageHeader::from_bytes(&header_bytes)
            .map_err(|e| VeilError::InvalidInput { msg: e })?;
        let mut s = self
            .session
            .lock()
            .map_err(|e| VeilError::Session { msg: e.to_string() })?;
        s.decrypt(&header, &ciphertext)
            .map_err(|e| VeilError::Crypto { msg: e })
    }

    pub fn serialize(&self) -> Result<String, VeilError> {
        let s = self
            .session
            .lock()
            .map_err(|e| VeilError::Session { msg: e.to_string() })?;
        serde_json::to_string(&*s).map_err(|e| VeilError::Session { msg: e.to_string() })
    }
}

// ── Free functions ──────────────────────────────────────────

#[uniffi::export]
pub fn generate_mnemonic() -> String {
    keys::generate_mnemonic().to_string()
}

#[uniffi::export]
pub fn validate_mnemonic(mnemonic: String) -> bool {
    keys::validate_mnemonic(&mnemonic)
}

#[uniffi::export]
pub fn aead_encrypt(key: Vec<u8>, plaintext: Vec<u8>) -> Result<AeadResult, VeilError> {
    let k = to_32(&key)?;
    let (ct, nonce) = aead::encrypt(&k, &plaintext).map_err(|e| VeilError::Crypto { msg: e })?;
    Ok(AeadResult {
        ciphertext: ct,
        nonce: nonce.to_vec(),
    })
}

#[uniffi::export]
pub fn aead_decrypt(
    key: Vec<u8>,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<Vec<u8>, VeilError> {
    let k = to_32(&key)?;
    let n = to_24(&nonce)?;
    aead::decrypt(&k, &ciphertext, &n).map_err(|e| VeilError::Crypto { msg: e })
}

#[uniffi::export]
pub fn ed25519_verify(
    public_key: Vec<u8>,
    message: Vec<u8>,
    sig: Vec<u8>,
) -> Result<bool, VeilError> {
    let pk = to_32(&public_key)?;
    let s = to_64(&sig)?;
    Ok(signature::verify(&pk, &message, &s))
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn generate_account_fingerprint_v2(
    canonical_server_origin: String,
    user_id_a: String,
    identity_key_a: Vec<u8>,
    signing_key_a: Vec<u8>,
    user_id_b: String,
    identity_key_b: Vec<u8>,
    signing_key_b: Vec<u8>,
) -> Result<FingerprintResult, VeilError> {
    let origin = require_canonical_server_origin(&canonical_server_origin)?;
    let user_a = require_canonical_user_id("first account user ID", &user_id_a)?;
    let user_b = require_canonical_user_id("second account user ID", &user_id_b)?;
    let (identity_a, signing_a) =
        require_account_key_pair("first account", &identity_key_a, &signing_key_a)?;
    let (identity_b, signing_b) =
        require_account_key_pair("second account", &identity_key_b, &signing_key_b)?;
    let (emoji, hex) = fingerprint::generate_account_v2(
        &origin,
        fingerprint::AccountFingerprintTuple {
            user_id: &user_a,
            identity_key: &identity_a,
            signing_key: &signing_a,
        },
        fingerprint::AccountFingerprintTuple {
            user_id: &user_b,
            identity_key: &identity_b,
            signing_key: &signing_b,
        },
    );
    Ok(FingerprintResult { emoji, hex })
}

#[uniffi::export]
pub fn derive_key_from_pin(pin: String, salt: Vec<u8>) -> Result<Vec<u8>, VeilError> {
    let s = to_32(&salt)?;
    let key = kdf::derive_key_from_pin(&pin, &s).map_err(|e| VeilError::Crypto { msg: e })?;
    Ok(key.to_vec())
}

#[uniffi::export]
pub fn derive_key_from_password(password: String, salt: Vec<u8>) -> Result<Vec<u8>, VeilError> {
    let s = to_32(&salt)?;
    let key =
        kdf::derive_key_from_password(&password, &s).map_err(|e| VeilError::Crypto { msg: e })?;
    Ok(key.to_vec())
}

#[uniffi::export]
pub fn encrypt_share(payload: Vec<u8>, password: Option<String>) -> Result<ShareBundle, VeilError> {
    let bundle = share::encrypt_share(&payload, password.as_deref())
        .map_err(|e| VeilError::Crypto { msg: e })?;
    Ok(ShareBundle {
        ciphertext: bundle.ciphertext.clone(),
        content_key: bundle.content_key.to_vec(),
        wrapped_key: bundle.wrapped_key.clone(),
        salt: bundle.salt.map(|s| s.to_vec()),
    })
}

#[uniffi::export]
pub fn decrypt_share(
    ciphertext: Vec<u8>,
    content_key: Option<Vec<u8>>,
    password: Option<String>,
    wrapped_key: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
) -> Result<Vec<u8>, VeilError> {
    let ck: Option<[u8; 32]> = match content_key {
        Some(ref v) => Some(to_32(v)?),
        None => None,
    };
    let s: Option<[u8; 32]> = match salt {
        Some(ref sv) => Some(to_32(sv)?),
        None => None,
    };
    share::decrypt_share(
        &ciphertext,
        ck.as_ref(),
        password.as_deref(),
        wrapped_key.as_deref(),
        s.as_ref(),
    )
    .map_err(|e| VeilError::Crypto { msg: e })
}

#[uniffi::export]
pub fn x3dh_initiate(
    identity: &VeilIdentity,
    peer_bundle: PreKeyBundleData,
) -> Result<X3dhResultData, VeilError> {
    let bundle = x3dh::PreKeyBundle {
        identity_key: to_32(&peer_bundle.identity_key)?,
        signing_key: to_32(&peer_bundle.signing_key)?,
        signed_prekey: to_32(&peer_bundle.signed_prekey)?,
        signed_prekey_signature: to_64(&peer_bundle.signed_prekey_signature)?,
        signed_prekey_id: peer_bundle.signed_prekey_id,
        one_time_prekey: match peer_bundle.one_time_prekey {
            Some(ref k) => Some(to_32(k)?),
            None => None,
        },
        one_time_prekey_id: peer_bundle.one_time_prekey_id,
    };

    let result =
        x3dh::initiate(&identity.inner, &bundle).map_err(|e| VeilError::Crypto { msg: e })?;

    Ok(X3dhResultData {
        shared_secret: result.shared_secret.to_vec(),
        ephemeral_public: result.ephemeral_public.to_vec(),
        associated_data: result.associated_data.to_vec(),
    })
}

// ── Helpers ─────────────────────────────────────────────────

fn to_32(data: &[u8]) -> Result<[u8; 32], VeilError> {
    data.try_into().map_err(|_| VeilError::InvalidInput {
        msg: format!("expected 32 bytes, got {}", data.len()),
    })
}

fn to_24(data: &[u8]) -> Result<[u8; 24], VeilError> {
    data.try_into().map_err(|_| VeilError::InvalidInput {
        msg: format!("expected 24 bytes, got {}", data.len()),
    })
}

fn to_64(data: &[u8]) -> Result<[u8; 64], VeilError> {
    data.try_into().map_err(|_| VeilError::InvalidInput {
        msg: format!("expected 64 bytes, got {}", data.len()),
    })
}

fn require_canonical_user_id(label: &str, value: &str) -> Result<String, VeilError> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| VeilError::InvalidInput {
        msg: format!("{label} must be a canonical lowercase UUID"),
    })?;
    let canonical = parsed.hyphenated().to_string();
    if parsed.is_nil() || canonical != value {
        return Err(VeilError::InvalidInput {
            msg: format!("{label} must be a non-nil canonical lowercase UUID"),
        });
    }
    Ok(canonical)
}

fn require_account_key_pair(
    label: &str,
    identity_key: &[u8],
    signing_key: &[u8],
) -> Result<([u8; 32], [u8; 32]), VeilError> {
    let identity_key = to_32(identity_key)?;
    let signing_key = to_32(signing_key)?;
    if identity_key == [0u8; 32]
        || !veil_crypto::public_key::valid_ed25519_public_key(&signing_key)
        || identity_key == signing_key
    {
        return Err(VeilError::InvalidInput {
            msg: format!(
                "{label} keys must contain a non-zero X25519 key and a valid, type-distinct Ed25519 key"
            ),
        });
    }
    Ok((identity_key, signing_key))
}

fn require_canonical_server_origin(value: &str) -> Result<String, VeilError> {
    if value.is_empty() || value.len() > 512 {
        return Err(VeilError::InvalidInput {
            msg: "server origin is empty or oversized".to_string(),
        });
    }
    let parsed = url::Url::parse(value).map_err(|error| VeilError::InvalidInput {
        msg: format!("invalid canonical server origin: {error}"),
    })?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(VeilError::InvalidInput {
            msg: "server origin must not contain credentials, path, query, or fragment".to_string(),
        });
    }
    match parsed.scheme() {
        "https" => {}
        "http" => match parsed.host_str() {
            Some("localhost" | "127.0.0.1" | "::1" | "[::1]") => {}
            _ => {
                return Err(VeilError::InvalidInput {
                    msg: "insecure http:// is allowed only for localhost/loopback".to_string(),
                });
            }
        },
        _ => {
            return Err(VeilError::InvalidInput {
                msg: "server origin must use https:// or loopback http://".to_string(),
            });
        }
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| VeilError::InvalidInput {
            msg: "server origin is missing a host".to_string(),
        })?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| VeilError::InvalidInput {
            msg: "server origin has no effective port".to_string(),
        })?;
    if port == 0 {
        return Err(VeilError::InvalidInput {
            msg: "server origin port must be non-zero".to_string(),
        });
    }
    let canonical = format!(
        "{}://{}:{}",
        parsed.scheme().to_ascii_lowercase(),
        authority,
        port
    );
    if canonical != value {
        return Err(VeilError::InvalidInput {
            msg: "server origin is not canonical".to_string(),
        });
    }
    Ok(canonical)
}

fn validate_mobile_endpoint_pair(
    websocket_url: &str,
    canonical_server_origin: &str,
) -> Result<(), VeilError> {
    let canonical_origin = require_canonical_server_origin(canonical_server_origin)?;
    let rest = url::Url::parse(&canonical_origin).map_err(|error| VeilError::InvalidInput {
        msg: format!("invalid canonical REST origin: {error}"),
    })?;
    let websocket = url::Url::parse(websocket_url).map_err(|error| VeilError::InvalidInput {
        msg: format!("invalid mobile WebSocket URL: {error}"),
    })?;
    if !websocket.username().is_empty()
        || websocket.password().is_some()
        || websocket.query().is_some()
        || websocket.fragment().is_some()
        || websocket.path() != "/ws"
    {
        return Err(VeilError::InvalidInput {
            msg: "mobile WebSocket URL must be an exact /ws endpoint without credentials, query, or fragment"
                .to_string(),
        });
    }
    let expected_scheme = match rest.scheme() {
        "https" => "wss",
        "http" => "ws",
        _ => unreachable!("canonical origin already checked"),
    };
    if websocket.scheme() != expected_scheme
        || websocket.host_str().map(str::to_ascii_lowercase)
            != rest.host_str().map(str::to_ascii_lowercase)
        || websocket.port_or_known_default() != rest.port_or_known_default()
    {
        return Err(VeilError::InvalidInput {
            msg: "mobile WebSocket and REST endpoints must share one secure origin".to_string(),
        });
    }
    Ok(())
}

fn guard_utf8_secret(secret_utf8: Vec<u8>, label: &str) -> Result<Zeroizing<Vec<u8>>, VeilError> {
    let guarded = Zeroizing::new(secret_utf8);
    if guarded.is_empty() || guarded.len() > 1024 {
        return Err(VeilError::InvalidInput {
            msg: format!("{label} is empty or oversized"),
        });
    }
    if std::str::from_utf8(guarded.as_slice()).is_err() {
        return Err(VeilError::InvalidInput {
            msg: format!("{label} must be valid UTF-8"),
        });
    }
    Ok(guarded)
}

fn guard_mobile_node_access_pass(
    node_access_pass: Option<Vec<u8>>,
) -> Result<Option<Zeroizing<Vec<u8>>>, VeilError> {
    let guarded = node_access_pass.map(Zeroizing::new);
    if guarded.as_ref().is_some_and(|pass| pass.len() != 32) {
        return Err(VeilError::InvalidInput {
            msg: "node access pass must contain exactly 32 bytes".to_string(),
        });
    }
    Ok(guarded)
}

fn mobile_node_access_pass_bytes(node_access_pass: &Option<Zeroizing<Vec<u8>>>) -> Option<&[u8]> {
    node_access_pass.as_ref().map(|pass| pass.as_slice())
}

fn new_mobile_sync_token() -> String {
    let mut rng = OsRng;
    loop {
        let mut token = [0u8; 32];
        rng.fill_bytes(&mut token);
        if token != [0u8; 32] {
            return hex::encode(token);
        }
    }
}

fn require_mobile_sync_token(token: &str) -> Result<(), VeilError> {
    if token.len() != 64
        || token
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        || token.bytes().all(|byte| byte == b'0')
    {
        return Err(VeilError::InvalidInput {
            msg: "mobile Direct sync token is invalid".to_string(),
        });
    }
    Ok(())
}

fn mobile_direct_directory_target(cursor: Option<&str>) -> Result<String, VeilError> {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair(
        "limit",
        &veil_client::direct::DIRECT_DIRECTORY_PAGE_LIMIT.to_string(),
    );
    if let Some(cursor) = cursor {
        if cursor.is_empty()
            || cursor.len() > veil_client::direct::DIRECT_DIRECTORY_CURSOR_LIMIT
            || cursor.chars().any(char::is_control)
        {
            return Err(VeilError::InvalidInput {
                msg: "mobile Direct directory cursor is invalid".to_string(),
            });
        }
        query.append_pair("cursor", cursor);
    }
    Ok(format!("/v1/conversations?{}", query.finish()))
}

enum MobileConnectOutcome<T> {
    Completed(T),
    Cancelled,
}

async fn await_mobile_connect<F, T>(
    connection: F,
    cancellation: Option<&MobileConnectCancellation>,
) -> MobileConnectOutcome<T>
where
    F: Future<Output = T>,
{
    match cancellation {
        Some(cancellation) => {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => MobileConnectOutcome::Cancelled,
                result = connection => MobileConnectOutcome::Completed(result),
            }
        }
        None => MobileConnectOutcome::Completed(connection.await),
    }
}

fn fail_closed_mobile_connect_cancellation(
    client: &mut veil_client::api::VeilClient,
    binding: &Mutex<Option<MobileAuthenticatedEpoch>>,
) -> VeilError {
    clear_mobile_binding_fail_closed(binding);
    client.disconnect();
    VeilError::Session {
        msg: "mobile connection attempt cancelled".to_string(),
    }
}

fn safe_mobile_connect_error(msg: String, has_node_access_pass: bool) -> VeilError {
    let msg = if has_node_access_pass {
        match msg.as_str() {
            "node access registration is closed; a valid access pass is required"
            | "node access pass is invalid, expired, or already used" => msg,
            _ => "mobile connection attempt failed".to_string(),
        }
    } else {
        msg
    };
    VeilError::Session { msg }
}

fn clear_mobile_binding_fail_closed(binding: &Mutex<Option<MobileAuthenticatedEpoch>>) {
    clear_mobile_binding_guard(binding.lock());
}

fn clear_mobile_direct_sync_fail_closed(sync: &Mutex<Option<MobileDirectSyncState>>) {
    match sync.lock() {
        Ok(mut guard) => *guard = None,
        Err(poisoned) => *poisoned.into_inner() = None,
    }
}

fn clear_mobile_binding_guard(
    binding: std::sync::LockResult<std::sync::MutexGuard<'_, Option<MobileAuthenticatedEpoch>>>,
) {
    match binding {
        Ok(mut guard) => *guard = None,
        Err(poisoned) => *poisoned.into_inner() = None,
    }
}

fn invalidate_mobile_session<'a>(
    binding: &Mutex<Option<MobileAuthenticatedEpoch>>,
    client: &'a Mutex<veil_client::api::VeilClient>,
) -> Result<std::sync::MutexGuard<'a, veil_client::api::VeilClient>, VeilError> {
    clear_mobile_binding_fail_closed(binding);
    disconnect_mobile_client_guard(client.lock())
}

fn disconnect_mobile_client_guard<'a>(
    client: std::sync::LockResult<std::sync::MutexGuard<'a, veil_client::api::VeilClient>>,
) -> Result<std::sync::MutexGuard<'a, veil_client::api::VeilClient>, VeilError> {
    match client {
        Ok(mut guard) => {
            guard.disconnect();
            Ok(guard)
        }
        Err(poisoned) => {
            let error = VeilError::Session {
                msg: format!("lock mobile client: {poisoned}"),
            };
            // A poisoned mutex still owns a usable guard. Recover it solely
            // to tear down the transport, then preserve the poison error.
            poisoned.into_inner().disconnect();
            Err(error)
        }
    }
}

fn fail_closed_mobile_post_auth<T>(
    disconnect: impl FnOnce(),
    binding: &Mutex<Option<MobileAuthenticatedEpoch>>,
    error: VeilError,
) -> Result<T, VeilError> {
    clear_mobile_binding_fail_closed(binding);
    disconnect();
    Err(error)
}

fn require_rest_method(method: &str) -> Result<&str, VeilError> {
    match method {
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" => Ok(method),
        _ => Err(VeilError::InvalidInput {
            msg: "unsupported REST method".to_string(),
        }),
    }
}

fn require_rest_target(target: &str) -> Result<(), VeilError> {
    if target.is_empty()
        || target.len() > 2048
        || !target.starts_with('/')
        || target.starts_with("//")
        || target.contains('#')
        || target.chars().any(|character| {
            character.is_control() || character.is_whitespace() || !character.is_ascii()
        })
    {
        return Err(VeilError::InvalidInput {
            msg: "REST request target is invalid".to_string(),
        });
    }
    let parsed = url::Url::parse(&format!("https://veil.invalid{target}")).map_err(|_| {
        VeilError::InvalidInput {
            msg: "REST request target is invalid".to_string(),
        }
    })?;
    let canonical = match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_string(),
    };
    if canonical != target {
        return Err(VeilError::InvalidInput {
            msg: "REST request target is not canonical".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Language;
    use sha2::{Digest, Sha256};

    fn load_known_valid_restore(draft: &VeilRecoveryDraft) {
        for position in 0..11 {
            draft.set_import_word_index(position, 0).unwrap();
        }
        // "abandon" x11 + "about" is the standard valid 12-word vector.
        draft.set_import_word_index(11, 3).unwrap();
    }

    fn confirm_all_create_challenges(draft: &VeilRecoveryDraft) {
        for slot in 0..draft.challenge_count() {
            let position = draft.challenge_position(slot).unwrap();
            let correct = draft.word_index(position).unwrap();
            assert!(draft.confirm_challenge(slot, correct).unwrap());
        }
    }

    fn mobile_test_epoch(generation: u64) -> MobileAuthenticatedEpoch {
        MobileAuthenticatedEpoch {
            binding: MobileAuthenticatedBinding {
                canonical_server_origin: "https://old.example.test:443".to_string(),
                user_id: "550e8400-e29b-41d4-a716-446655440001".to_string(),
            },
            generation,
        }
    }

    fn mobile_test_sync_state(
        generation: u64,
        phase: MobileDirectSyncPhase,
    ) -> MobileDirectSyncState {
        MobileDirectSyncState {
            token: "ab".repeat(32),
            epoch: mobile_test_epoch(generation),
            phase,
            own_prekey_publication: None,
            next_cursor: None,
            directory_history: veil_client::direct::DirectDirectorySyncHistory::default(),
            peers: HashMap::new(),
            history_order: Vec::new(),
            history_index: 0,
            current_history: None,
            blocked_conversations: BTreeMap::new(),
            outstanding_request: None,
            outbox_replay_cursor: None,
            outbox_replay_complete: false,
        }
    }

    fn mobile_test_session_with_sync(
        generation: u64,
    ) -> (VeilMobileSession, std::path::PathBuf, String) {
        let mut client = veil_client::api::VeilClient::new();
        let mnemonic = client.generate_mnemonic();
        let path =
            std::env::temp_dir().join(format!("veil-mobile-sync-{}.db", uuid::Uuid::new_v4()));
        client.init_with_mnemonic(&mnemonic, &path).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let epoch = mobile_test_epoch(generation);
        let identity_key = client.identity_key().unwrap();
        let signing_key = client.signing_key().unwrap();
        client
            .db()
            .unwrap()
            .bind_authenticated_self(
                &epoch.binding.canonical_server_origin,
                &epoch.binding.user_id,
                &identity_key,
                &signing_key,
            )
            .unwrap();
        client
            .test_only_restore_authenticated_user_from_durable_binding(
                &epoch.binding.canonical_server_origin,
                &epoch.binding.user_id,
            )
            .unwrap();
        let token = "ab".repeat(32);
        (
            VeilMobileSession {
                client: Mutex::new(client),
                runtime,
                binding: Mutex::new(Some(epoch.clone())),
                direct_sync: Mutex::new(Some(MobileDirectSyncState {
                    token: token.clone(),
                    epoch,
                    phase: MobileDirectSyncPhase::Directory,
                    own_prekey_publication: None,
                    next_cursor: None,
                    directory_history: veil_client::direct::DirectDirectorySyncHistory::default(),
                    peers: HashMap::new(),
                    history_order: Vec::new(),
                    history_index: 0,
                    current_history: None,
                    blocked_conversations: BTreeMap::new(),
                    outstanding_request: None,
                    outbox_replay_cursor: None,
                    outbox_replay_complete: false,
                })),
                next_binding_generation: AtomicU64::new(generation),
                last_rest_timestamp_ms: AtomicI64::new(0),
                direct_post_sign_pre_postflight_hook: Mutex::new(None),
            },
            path,
            token,
        )
    }

    fn mobile_test_directory_response(session: &VeilMobileSession) -> (Vec<u8>, IdentityKeyPair) {
        let client = session.client.lock().unwrap();
        let local_identity = client.identity_key().unwrap();
        let local_signing = client.signing_key().unwrap();
        drop(client);
        let peer = IdentityKeyPair::generate();
        let peer_identity = peer.x25519_public_bytes();
        let response = serde_json::to_vec(&serde_json::json!({
            "count": 1,
            "conversations": [{
                "id": "20000000-0000-4000-8000-000000000001",
                "conv_type": 0,
                "name": null,
                "server_id": null,
                "created_at": "2026-07-18T00:00:00Z",
                "members": [
                    {
                        "user_id": "550e8400-e29b-41d4-a716-446655440001",
                        "username": "self",
                        "identity_key": hex::encode(local_identity),
                        "signing_key": hex::encode(local_signing),
                    },
                    {
                        "user_id": "550e8400-e29b-41d4-a716-446655440002",
                        "username": "peer",
                        "identity_key": hex::encode(peer_identity),
                        "signing_key": hex::encode(peer.ed25519_public_bytes()),
                    }
                ]
            }]
        }))
        .unwrap();
        (response, peer)
    }

    fn mobile_test_install_ready_direct_with_peer(
        session: &VeilMobileSession,
        lease_token: &str,
    ) -> (String, IdentityKeyPair) {
        let (response, peer) = mobile_test_directory_response(session);
        let request = session
            .prepare_direct_directory_request(lease_token.to_string())
            .unwrap();
        let page = session
            .install_direct_directory_page(lease_token.to_string(), request.request_token, response)
            .unwrap();
        assert_eq!(page.conversations.len(), 1);
        assert!(page.conversations[0].needs_prekey);
        let conversation_id = page.conversations[0].conversation_id.clone();
        session.direct_sync.lock().unwrap().as_mut().unwrap().phase = MobileDirectSyncPhase::Ready;
        session
            .direct_sync
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .outbox_replay_complete = true;
        (conversation_id, peer)
    }

    fn mobile_test_install_ready_direct(session: &VeilMobileSession, lease_token: &str) -> String {
        mobile_test_install_ready_direct_with_peer(session, lease_token).0
    }

    fn mobile_test_prekey_bundle(
        peer: IdentityKeyPair,
    ) -> ([u8; 32], veil_crypto::x3dh::PreKeyBundle) {
        let identity_key = peer.x25519_public_bytes();
        let signing_key = peer.ed25519_public_bytes();
        let mut peer_client = veil_client::api::VeilClient::from_identity(peer);
        let prekeys = peer_client.generate_prekeys().unwrap();
        let (one_time_prekey, one_time_prekey_id) = prekeys.otk_publics[0];
        (
            identity_key,
            veil_crypto::x3dh::PreKeyBundle {
                identity_key,
                signing_key,
                signed_prekey: prekeys.spk_public,
                signed_prekey_signature: prekeys.spk_signature,
                signed_prekey_id: prekeys.spk_id,
                one_time_prekey: Some(one_time_prekey),
                one_time_prekey_id: Some(one_time_prekey_id),
            },
        )
    }

    fn mobile_test_prekey_response(peer: IdentityKeyPair) -> ([u8; 32], Vec<u8>) {
        use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

        let identity_key = peer.x25519_public_bytes();
        let signing_key = peer.ed25519_public_bytes();
        let mut peer_client = veil_client::api::VeilClient::from_identity(peer);
        let prekeys = peer_client.generate_prekeys().unwrap();
        let (one_time_prekey, one_time_prekey_id) = prekeys.otk_publics[0];
        let response = serde_json::to_vec(&serde_json::json!({
            "identity_key": BASE64_STANDARD.encode(identity_key),
            "signing_key": BASE64_STANDARD.encode(signing_key),
            "signed_prekey": BASE64_STANDARD.encode(prekeys.spk_public),
            "signed_prekey_signature": BASE64_STANDARD.encode(prekeys.spk_signature),
            "signed_prekey_id": prekeys.spk_id,
            "one_time_prekey": BASE64_STANDARD.encode(one_time_prekey),
            "one_time_prekey_id": one_time_prekey_id,
            "opk_low_warning": false,
            "opk_remaining": 10,
        }))
        .unwrap();
        (identity_key, response)
    }

    fn mobile_test_ready_prekey_fixture(
        generation: u64,
    ) -> (
        VeilMobileSession,
        std::path::PathBuf,
        String,
        String,
        IdentityKeyPair,
        tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        let (session, path, token) = mobile_test_session_with_sync(generation);
        let (conversation_id, peer) = mobile_test_install_ready_direct_with_peer(&session, &token);
        let outbound = mobile_test_install_queued_connection(&session);
        (session, path, token, conversation_id, peer, outbound)
    }

    fn mobile_test_assert_prekey_outstanding(
        session: &VeilMobileSession,
        request_token: &str,
        conversation_id: &str,
        signature_released: bool,
    ) {
        let sync = session.direct_sync.lock().unwrap();
        let request = sync
            .as_ref()
            .unwrap()
            .outstanding_request
            .as_ref()
            .expect("peer prekey request must remain outstanding");
        assert_eq!(request.token, request_token);
        assert_eq!(
            request.kind,
            MobileDirectOutstandingRequestKind::PeerPreKey {
                conversation_id: conversation_id.to_string(),
            }
        );
        assert_eq!(
            request.peer_prekey_signature_released, signature_released,
            "peer prekey signature release state diverged"
        );
    }

    fn mobile_test_assert_no_direct_session(
        session: &VeilMobileSession,
        peer_identity_key: &[u8; 32],
    ) {
        let client = session.client.lock().unwrap();
        assert!(!client.has_session(peer_identity_key));
        assert!(client
            .db()
            .unwrap()
            .load_ratchet_session(peer_identity_key)
            .unwrap()
            .is_none());
    }

    fn mobile_test_pause_direct_post_sign(
        session: &VeilMobileSession,
    ) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let entered_hook = Arc::clone(&entered);
        let release_hook = Arc::clone(&release);
        *session.direct_post_sign_pre_postflight_hook.lock().unwrap() = Some(Arc::new(move || {
            entered_hook.wait();
            release_hook.wait();
        }));
        (entered, release)
    }

    fn mobile_test_clear_direct_post_sign_hook(session: &VeilMobileSession) {
        *session.direct_post_sign_pre_postflight_hook.lock().unwrap() = None;
    }

    #[derive(Clone, Copy, Debug)]
    enum MobileTestPreKeyDenial {
        RuntimeQuarantined,
        OriginScopeDrift,
        PeerSigningScopeDrift,
        Disconnected,
        HistoryBlocked,
    }

    fn mobile_test_apply_prekey_denial(
        session: &VeilMobileSession,
        conversation_id: &str,
        denial: MobileTestPreKeyDenial,
    ) {
        match denial {
            MobileTestPreKeyDenial::RuntimeQuarantined => assert!(session
                .client
                .lock()
                .unwrap()
                .test_only_quarantine_direct_conversation_v1(conversation_id)),
            MobileTestPreKeyDenial::OriginScopeDrift => {
                let drifted_epoch = {
                    let mut sync = session.direct_sync.lock().unwrap();
                    let state = sync.as_mut().unwrap();
                    state.epoch.binding.canonical_server_origin =
                        "https://drift.example.test:443".to_string();
                    state.epoch.clone()
                };
                *session.binding.lock().unwrap() = Some(drifted_epoch);
            }
            MobileTestPreKeyDenial::PeerSigningScopeDrift => {
                session
                    .direct_sync
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .peers
                    .get_mut(conversation_id)
                    .unwrap()
                    .signing_key = IdentityKeyPair::generate().ed25519_public_bytes();
            }
            MobileTestPreKeyDenial::Disconnected => {
                session.client.lock().unwrap().disconnect();
            }
            MobileTestPreKeyDenial::HistoryBlocked => {
                session
                    .direct_sync
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .blocked_conversations
                    .insert(
                        conversation_id.to_string(),
                        MobileDirectHistoryOutcome::ConversationRejected,
                    );
            }
        }
    }

    fn mobile_test_install_queued_connection(
        session: &VeilMobileSession,
    ) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
        let _runtime_guard = session.runtime.enter();
        session
            .client
            .lock()
            .unwrap()
            .test_only_install_queued_connection()
    }

    fn mobile_test_direct_identities(
        session: &VeilMobileSession,
        conversation_id: &str,
    ) -> ([u8; 32], [u8; 32]) {
        let self_identity_key = session.client.lock().unwrap().identity_key().unwrap();
        let peer_identity_key = session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .peers
            .get(conversation_id)
            .unwrap()
            .identity_key;
        (self_identity_key, peer_identity_key)
    }

    fn mobile_test_insert_direct_message(
        session: &VeilMobileSession,
        conversation_id: &str,
        id_tail: u64,
        sender_key: &[u8; 32],
        plaintext: &str,
        is_outgoing: bool,
    ) {
        session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .insert_message(
                &format!("30000000-0000-4000-8000-{id_tail:012}"),
                conversation_id,
                sender_key,
                plaintext,
                is_outgoing,
                Some(1_700_000_000_000 + id_tail as i64),
                None,
            )
            .unwrap();
    }

    #[test]
    fn test_generate_and_validate_mnemonic() {
        let m = generate_mnemonic();
        assert!(validate_mnemonic(m));
    }

    #[test]
    fn recovery_dictionary_contract_is_pinned() {
        let canonical = Language::English.word_list().join("\n");
        assert_eq!(Language::English.word_list().len(), 2048);
        assert_eq!(canonical.len(), 13_115);
        assert!(!canonical.ends_with('\n'));
        assert_eq!(
            hex::encode(Sha256::digest(canonical.as_bytes())),
            "187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae"
        );
    }

    #[test]
    fn recovery_create_indices_and_challenges_are_bounded_and_unique() {
        let draft = VeilRecoveryDraft::new_create();
        assert_eq!(draft.word_count(), 12);
        assert_eq!(draft.challenge_count(), 3);
        assert_eq!(draft.challenge_choice_count(), 4);

        for position in 0..draft.word_count() {
            assert!(draft.word_index(position).unwrap() < RECOVERY_DICTIONARY_WORD_COUNT);
        }

        let mut positions = Vec::new();
        for slot in 0..draft.challenge_count() {
            let position = draft.challenge_position(slot).unwrap();
            positions.push(position);
            let correct = draft.word_index(position).unwrap();
            let mut choices = Vec::new();
            for choice in 0..draft.challenge_choice_count() {
                choices.push(draft.challenge_choice_word_index(slot, choice).unwrap());
            }
            assert!(choices.contains(&correct));
            choices.sort_unstable();
            choices.dedup();
            assert_eq!(choices.len(), RECOVERY_CHALLENGE_CHOICE_COUNT as usize);
        }
        positions.sort_unstable();
        positions.dedup();
        assert_eq!(positions.len(), RECOVERY_CHALLENGE_COUNT as usize);
    }

    #[test]
    fn recovery_rejects_all_position_index_and_choice_bounds_generically() {
        let create = VeilRecoveryDraft::new_create();
        let restore = VeilRecoveryDraft::new_restore();

        let errors = [
            create.word_index(RECOVERY_WORD_COUNT).unwrap_err(),
            create
                .challenge_position(RECOVERY_CHALLENGE_COUNT)
                .unwrap_err(),
            create
                .challenge_choice_word_index(0, RECOVERY_CHALLENGE_CHOICE_COUNT)
                .unwrap_err(),
            create
                .confirm_challenge(0, RECOVERY_DICTIONARY_WORD_COUNT)
                .unwrap_err(),
            restore
                .set_import_word_index(RECOVERY_WORD_COUNT, 0)
                .unwrap_err(),
            restore
                .set_import_word_index(0, RECOVERY_DICTIONARY_WORD_COUNT)
                .unwrap_err(),
        ];
        for error in errors {
            assert_eq!(
                error.to_string(),
                "Invalid input: recovery input is invalid"
            );
        }
    }

    #[test]
    fn recovery_mode_misuse_is_fail_closed_and_generic() {
        let create = VeilRecoveryDraft::new_create();
        let restore = VeilRecoveryDraft::new_restore();

        assert_eq!(
            create.set_import_word_index(0, 0).unwrap_err().to_string(),
            "Session error: recovery draft is unavailable"
        );
        assert_eq!(
            create.validate_import().unwrap_err().to_string(),
            "Session error: recovery draft is unavailable"
        );
        assert_eq!(
            restore.word_index(0).unwrap_err().to_string(),
            "Session error: recovery draft is unavailable"
        );
        assert_eq!(
            restore.challenge_position(0).unwrap_err().to_string(),
            "Session error: recovery draft is unavailable"
        );
    }

    #[test]
    fn recovery_restore_requires_complete_valid_checksum_and_revalidates_edits() {
        let draft = VeilRecoveryDraft::new_restore();
        assert!(!draft.is_commit_authorized());
        assert!(!draft.validate_import().unwrap());

        load_known_valid_restore(&draft);
        assert!(draft.validate_import().unwrap());
        assert!(draft.is_commit_authorized());

        // Every edit revokes the previous validation, even before the caller
        // asks to validate the newly entered phrase.
        draft.set_import_word_index(11, 0).unwrap();
        assert!(!draft.is_commit_authorized());
        assert!(!draft.validate_import().unwrap());
        assert!(!draft.is_commit_authorized());

        draft.set_import_word_index(11, 3).unwrap();
        assert!(!draft.is_commit_authorized());
        assert!(draft.validate_import().unwrap());
        assert!(draft.is_commit_authorized());
    }

    #[test]
    fn recovery_wrong_create_answer_never_authorizes_and_can_revoke() {
        let draft = VeilRecoveryDraft::new_create();
        let position = draft.challenge_position(0).unwrap();
        let correct = draft.word_index(position).unwrap();
        let wrong = (0..draft.challenge_choice_count())
            .map(|choice| draft.challenge_choice_word_index(0, choice).unwrap())
            .find(|candidate| *candidate != correct)
            .unwrap();

        assert!(!draft.confirm_challenge(0, wrong).unwrap());
        assert!(!draft.is_commit_authorized());
        confirm_all_create_challenges(&draft);
        assert!(draft.is_commit_authorized());

        assert!(!draft.confirm_challenge(0, wrong).unwrap());
        assert!(!draft.is_commit_authorized());
        assert!(draft.confirm_challenge(0, correct).unwrap());
        assert!(draft.is_commit_authorized());
    }

    #[test]
    fn recovery_cancel_is_terminal_idempotent_and_zeroizes_state() {
        let draft = VeilRecoveryDraft::new_create();
        draft.cancel();
        draft.cancel();

        assert!(!draft.is_commit_authorized());
        assert!(!draft.consume_commit_authorization());
        assert_eq!(
            draft.word_index(0).unwrap_err().to_string(),
            "Session error: recovery draft is unavailable"
        );
        assert_eq!(
            draft.challenge_position(0).unwrap_err().to_string(),
            "Session error: recovery draft is unavailable"
        );
        assert_eq!(
            draft.confirm_challenge(0, 0).unwrap_err().to_string(),
            "Session error: recovery draft is unavailable"
        );

        let state = draft.state.lock().unwrap();
        assert!(state.cancelled);
        assert_eq!(state.words, [0; RECOVERY_WORD_COUNT as usize]);
        assert!(state.challenges.iter().all(|challenge| {
            challenge.position == 0
                && challenge.choices == [0; RECOVERY_CHALLENGE_CHOICE_COUNT as usize]
                && !challenge.confirmed
        }));
    }

    #[test]
    fn recovery_commit_authorization_is_one_shot_under_race() {
        let draft = VeilRecoveryDraft::new_create();
        confirm_all_create_challenges(&draft);
        assert!(draft.is_commit_authorized());

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let draft = Arc::clone(&draft);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                draft.consume_commit_authorization()
            }));
        }
        barrier.wait();
        let successes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|result| *result)
            .count();

        assert_eq!(successes, 1);
        assert!(!draft.is_commit_authorized());
        assert!(!draft.consume_commit_authorization());
        assert!(draft.word_index(0).is_err());

        let state = draft.state.lock().unwrap();
        assert!(state.cancelled);
        assert_eq!(state.words, [0; RECOVERY_WORD_COUNT as usize]);
    }

    #[test]
    fn recovery_restore_authorization_is_also_consumed_once() {
        let draft = VeilRecoveryDraft::new_restore();
        load_known_valid_restore(&draft);
        assert!(draft.validate_import().unwrap());
        assert!(draft.consume_commit_authorization());
        assert!(!draft.consume_commit_authorization());
        assert!(draft.validate_import().is_err());
        assert!(draft.set_import_word_index(0, 0).is_err());
    }

    #[test]
    fn test_identity_roundtrip() {
        let id = VeilIdentity::generate();
        assert_eq!(id.identity_key().len(), 32);
        assert_eq!(id.signing_key().len(), 32);
    }

    #[test]
    fn mnemonic_byte_constructor_matches_legacy_identity_constructor() {
        let mnemonic = generate_mnemonic();
        let legacy = VeilIdentity::from_mnemonic(mnemonic.clone()).unwrap();
        let from_bytes = VeilIdentity::from_mnemonic_bytes(mnemonic.into_bytes()).unwrap();
        assert_eq!(legacy.identity_key(), from_bytes.identity_key());
        assert_eq!(legacy.signing_key(), from_bytes.signing_key());
    }

    #[test]
    fn mnemonic_byte_constructors_reject_invalid_utf8_before_use() {
        let identity_error = match VeilIdentity::from_mnemonic_bytes(vec![0xff, 0xfe]) {
            Err(error) => error,
            Ok(_) => panic!("invalid UTF-8 mnemonic unexpectedly created an identity"),
        };
        assert_eq!(
            identity_error.to_string(),
            "Invalid input: mnemonic must be valid UTF-8"
        );

        let session_error = match VeilMobileSession::from_mnemonic_bytes(
            vec![0xff, 0xfe],
            "database-path-must-not-be-reached".to_string(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("invalid UTF-8 mnemonic unexpectedly created a mobile session"),
        };
        assert_eq!(
            session_error.to_string(),
            "Invalid input: mnemonic must be valid UTF-8"
        );
    }

    #[test]
    fn test_aead_roundtrip() {
        let key = vec![42u8; 32];
        let plain = b"hello veil".to_vec();
        let enc = aead_encrypt(key.clone(), plain.clone()).unwrap();
        let dec = aead_decrypt(key, enc.ciphertext, enc.nonce).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_sign_verify() {
        let id = VeilIdentity::generate();
        let msg = b"test message".to_vec();
        let sig = id.sign(msg.clone());
        assert!(ed25519_verify(id.signing_key(), msg, sig).unwrap());
    }

    #[test]
    fn test_account_fingerprint_v2() {
        let account_a = VeilIdentity::generate();
        let account_b = VeilIdentity::generate();
        let identity_a = account_a.identity_key();
        let signing_a = account_a.signing_key();
        let identity_b = account_b.identity_key();
        let signing_b = account_b.signing_key();
        let fp_ab = generate_account_fingerprint_v2(
            "https://chat.example.test:443".to_string(),
            "550e8400-e29b-41d4-a716-446655440001".to_string(),
            identity_a.clone(),
            signing_a.clone(),
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            identity_b.clone(),
            signing_b.clone(),
        )
        .unwrap();
        let fp_ba = generate_account_fingerprint_v2(
            "https://chat.example.test:443".to_string(),
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            identity_b,
            signing_b,
            "550e8400-e29b-41d4-a716-446655440001".to_string(),
            identity_a,
            signing_a,
        )
        .unwrap();
        assert!(!fp_ab.emoji.is_empty());
        assert_eq!(fp_ab.hex.len(), 64);
        assert_eq!(fp_ab.hex, fp_ba.hex);
    }

    #[test]
    fn account_fingerprint_v2_rejects_ambiguous_scope() {
        let account_a = VeilIdentity::generate();
        let account_b = VeilIdentity::generate();
        let identity_a = account_a.identity_key();
        let signing_a = account_a.signing_key();
        let identity_b = account_b.identity_key();
        let signing_b = account_b.signing_key();
        assert!(generate_account_fingerprint_v2(
            "https://chat.example.test".to_string(),
            "550e8400-e29b-41d4-a716-446655440001".to_string(),
            identity_a.clone(),
            signing_a.clone(),
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            identity_b.clone(),
            signing_b.clone(),
        )
        .is_err());
        assert!(generate_account_fingerprint_v2(
            "https://chat.example.test:443".to_string(),
            "550E8400-E29B-41D4-A716-446655440001".to_string(),
            identity_a.clone(),
            signing_a.clone(),
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            identity_b.clone(),
            signing_b.clone(),
        )
        .is_err());
        assert!(generate_account_fingerprint_v2(
            "https://chat.example.test:443".to_string(),
            "550e8400-e29b-41d4-a716-446655440001".to_string(),
            vec![0u8; 32],
            signing_a,
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            identity_b,
            signing_b,
        )
        .is_err());
        assert!(generate_account_fingerprint_v2(
            "https://chat.example.test:443".to_string(),
            "550e8400-e29b-41d4-a716-446655440001".to_string(),
            vec![7u8; 32],
            vec![7u8; 32],
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            vec![3u8; 32],
            vec![4u8; 32],
        )
        .is_err());
    }

    #[test]
    fn account_fingerprint_v2_accepts_canonical_ipv6_loopback_origin() {
        let account_a = VeilIdentity::generate();
        let account_b = VeilIdentity::generate();
        assert!(generate_account_fingerprint_v2(
            "http://[::1]:80".to_string(),
            "550e8400-e29b-41d4-a716-446655440001".to_string(),
            account_a.identity_key(),
            account_a.signing_key(),
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            account_b.identity_key(),
            account_b.signing_key(),
        )
        .is_ok());
    }

    #[test]
    fn mobile_endpoint_pair_is_exact_origin_scoped() {
        assert!(validate_mobile_endpoint_pair(
            "wss://chat.example.test/ws",
            "https://chat.example.test:443",
        )
        .is_ok());
        assert!(
            validate_mobile_endpoint_pair("ws://127.0.0.1:9080/ws", "http://127.0.0.1:9080",)
                .is_ok()
        );
        for websocket in [
            "wss://other.example.test/ws",
            "wss://chat.example.test/other",
            "wss://chat.example.test/ws?origin=other",
            "ws://chat.example.test/ws",
        ] {
            assert!(
                validate_mobile_endpoint_pair(websocket, "https://chat.example.test:443",).is_err()
            );
        }
    }

    #[test]
    fn mobile_node_access_pass_is_optional_and_exactly_32_bytes() {
        let absent = guard_mobile_node_access_pass(None).unwrap();
        assert!(mobile_node_access_pass_bytes(&absent).is_none());

        let expected = (0u8..32).collect::<Vec<_>>();
        let guarded = guard_mobile_node_access_pass(Some(expected.clone())).unwrap();
        assert_eq!(
            mobile_node_access_pass_bytes(&guarded),
            Some(expected.as_slice())
        );

        for invalid_length in [0, 1, 31, 33, 64] {
            let error = guard_mobile_node_access_pass(Some(vec![0x42; invalid_length]))
                .expect_err("invalid Node Access Pass length must fail before networking");
            assert!(matches!(error, VeilError::InvalidInput { .. }));
            assert_eq!(
                error.to_string(),
                "Invalid input: node access pass must contain exactly 32 bytes"
            );
        }
    }

    #[test]
    fn mobile_node_access_pass_attempt_never_reflects_server_diagnostics() {
        let secret = "0123456789abcdef0123456789abcdef";
        let error = safe_mobile_connect_error(
            format!("malicious server reflected access pass: {secret}"),
            true,
        );
        let rendered = error.to_string();
        assert_eq!(rendered, "Session error: mobile connection attempt failed");
        assert!(!rendered.contains(secret));

        for safe_reason in [
            "node access registration is closed; a valid access pass is required",
            "node access pass is invalid, expired, or already used",
        ] {
            assert_eq!(
                safe_mobile_connect_error(safe_reason.to_string(), true).to_string(),
                format!("Session error: {safe_reason}")
            );
        }
    }

    #[test]
    fn mobile_connect_cancellation_is_sticky_before_waiting() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let cancellation = MobileConnectCancellation::new();
        cancellation.cancel();
        cancellation.cancel();

        let outcome = runtime
            .block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    await_mobile_connect(std::future::pending::<()>(), Some(cancellation.as_ref())),
                )
                .await
            })
            .expect("pre-cancelled mobile connect must not wait");
        assert!(matches!(outcome, MobileConnectOutcome::Cancelled));
    }

    #[test]
    fn mobile_connect_cancellation_wakes_a_pending_waiter() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let cancellation = MobileConnectCancellation::new();
            let waiter_cancellation = Arc::clone(&cancellation);
            let waiter = tokio::spawn(async move {
                await_mobile_connect(
                    std::future::pending::<()>(),
                    Some(waiter_cancellation.as_ref()),
                )
                .await
            });
            tokio::task::yield_now().await;

            cancellation.cancel();
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
                .await
                .expect("mobile connect cancellation did not wake its waiter")
                .expect("mobile connect cancellation waiter panicked");
            assert!(matches!(outcome, MobileConnectOutcome::Cancelled));
        });
    }

    #[test]
    fn mobile_connect_without_cancellation_preserves_legacy_result() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let outcome = runtime.block_on(await_mobile_connect(async { 42_u8 }, None));
        match outcome {
            MobileConnectOutcome::Completed(value) => assert_eq!(value, 42),
            MobileConnectOutcome::Cancelled => panic!("legacy mobile connect was cancelled"),
        }
    }

    #[test]
    fn mobile_direct_sync_rejects_a_stale_same_account_generation_before_mutation() {
        let (session, path, token) = mobile_test_session_with_sync(7);
        let (response, peer) = mobile_test_directory_response(&session);
        let request = session
            .prepare_direct_directory_request(token.clone())
            .unwrap();
        // Same public origin/account, different private WebSocket generation.
        *session.binding.lock().unwrap() = Some(mobile_test_epoch(8));

        let error = session
            .install_direct_directory_page(token, request.request_token, response)
            .unwrap_err();
        assert!(error.to_string().contains("lease is stale"));
        let client = session.client.lock().unwrap();
        assert!(client.db().unwrap().get_conversations().unwrap().is_empty());
        assert_eq!(
            client.known_user_identity("550e8400-e29b-41d4-a716-446655440002"),
            None
        );
        assert!(!client.has_session(&peer.x25519_public_bytes()));
        drop(client);
        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_own_prekey_barrier_requires_exact_count_upload_and_ack_before_directory() {
        let (session, path, token) = mobile_test_session_with_sync(8);
        {
            let mut sync = session.direct_sync.lock().unwrap();
            let state = sync.as_mut().unwrap();
            state.phase = MobileDirectSyncPhase::OwnPreKeys;
        }

        assert_eq!(
            session
                .prepare_direct_directory_request(token.clone())
                .unwrap_err()
                .to_string(),
            "Session error: mobile Direct sync lease is stale or directory is complete"
        );

        let count = session.prepare_own_prekey_request(token.clone()).unwrap();
        let identity_key = session.client.lock().unwrap().identity_key().unwrap();
        let device_id = session.client.lock().unwrap().device_id();
        assert_eq!(count.method, "GET");
        assert!(count.body.is_empty());
        assert_eq!(
            count.request_target,
            format!("/v1/prekeys/{}/count", hex::encode(identity_key))
        );
        assert_eq!(
            session
                .prepare_own_prekey_request(token.clone())
                .unwrap()
                .request_token,
            count.request_token
        );
        let count_signature = session
            .sign_direct_rest_request(token.clone(), count.request_token.clone())
            .unwrap();
        assert_eq!(
            count_signature.user_id,
            mobile_test_epoch(8).binding.user_id
        );
        assert!(session
            .sign_direct_rest_request(token.clone(), new_mobile_sync_token())
            .is_err());
        assert!(session
            .install_own_prekey_response(token.clone(), new_mobile_sync_token(), b"{}".to_vec(),)
            .unwrap_err()
            .to_string()
            .contains("request is stale"));

        let count_response = serde_json::to_vec(&serde_json::json!({
            "devices": [{
                "device_id": hex::encode(device_id),
                "remaining": 0,
            }]
        }))
        .unwrap();
        let count_progress = session
            .install_own_prekey_response(token.clone(), count.request_token.clone(), count_response)
            .unwrap();
        assert!(!count_progress.publication_complete);
        assert!(session
            .sign_direct_rest_request(token.clone(), count.request_token)
            .is_err());
        assert!(session
            .prepare_direct_directory_request(token.clone())
            .is_err());

        let upload = session.prepare_own_prekey_request(token.clone()).unwrap();
        assert_eq!(upload.method, "POST");
        assert_eq!(upload.request_target, "/v1/prekeys");
        assert!(!upload.body.is_empty());
        assert!(upload.body.len() <= 64 * 1024);
        assert_eq!(
            session
                .prepare_own_prekey_request(token.clone())
                .unwrap()
                .body,
            upload.body
        );
        assert!(session
            .sign_direct_rest_request(token.clone(), upload.request_token.clone())
            .is_ok());
        assert_eq!(
            session
                .install_own_prekey_response(
                    token.clone(),
                    upload.request_token.clone(),
                    br#"{"stored":20,"opk_remaining":20}"#.to_vec(),
                )
                .unwrap_err()
                .to_string(),
            "Session error: mobile own-prekey upload response was rejected"
        );
        let upload_progress = session
            .install_own_prekey_response(
                token.clone(),
                upload.request_token.clone(),
                br#"{"stored":21,"opk_remaining":20}"#.to_vec(),
            )
            .unwrap();
        assert!(upload_progress.publication_complete);
        assert!(session
            .sign_direct_rest_request(token.clone(), upload.request_token)
            .is_err());
        let directory = session
            .prepare_direct_directory_request(token.clone())
            .unwrap();
        assert!(session
            .sign_direct_rest_request(token, directory.request_token)
            .is_ok());

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_history_is_object_bound_repeated_and_blocks_prekeys_until_live_replay() {
        let (session, path, token) = mobile_test_session_with_sync(9);
        let (response, peer) = mobile_test_directory_response(&session);
        let request = session
            .prepare_direct_directory_request(token.clone())
            .unwrap();
        assert_eq!(request.request_target, "/v1/conversations?limit=100");
        assert!(
            session
                .install_direct_directory_page(
                    token.clone(),
                    new_mobile_sync_token(),
                    response.clone(),
                )
                .unwrap_err()
                .to_string()
                .contains("request is stale")
        );
        let page = session
            .install_direct_directory_page(token.clone(), request.request_token.clone(), response)
            .unwrap();
        assert!(page.directory_complete);
        assert!(page.next_cursor.is_none());
        assert_eq!(page.conversations.len(), 1);
        assert_eq!(
            page.conversations[0].conversation_id,
            "20000000-0000-4000-8000-000000000001"
        );
        assert_eq!(
            session
                .install_direct_directory_page(
                    token.clone(),
                    request.request_token,
                    b"{}".to_vec(),
                )
                .unwrap_err()
                .to_string(),
            "Session error: mobile Direct directory is already complete"
        );

        let conversation_id = "20000000-0000-4000-8000-000000000001".to_string();
        assert!(session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap_err()
            .to_string()
            .contains("prekey route is unavailable"));

        let history = session
            .prepare_next_direct_history_request(token.clone())
            .unwrap();
        assert!(!history.histories_terminal);
        let history_request = history.request.unwrap();
        assert_eq!(
            history_request.request_target,
            format!("/v1/messages/{conversation_id}?limit=25")
        );
        assert_eq!(history_request.method, "GET");
        assert!(history_request.body.is_empty());
        assert_eq!(
            history_request.response_limit_bytes,
            veil_client::direct_history::DIRECT_HISTORY_RESPONSE_LIMIT as u32
        );
        let repeated = session
            .prepare_next_direct_history_request(token.clone())
            .unwrap()
            .request
            .unwrap();
        assert_eq!(repeated.request_token, history_request.request_token);
        assert!(session
            .prepare_direct_directory_request(token.clone())
            .unwrap_err()
            .to_string()
            .contains("directory is complete"));
        let installed = session
            .install_direct_history_response(
                token.clone(),
                history_request.request_token,
                br#"{"messages":[],"count":0}"#.to_vec(),
            )
            .unwrap();
        assert_eq!(installed.outcome, MobileDirectHistoryOutcome::Complete);
        assert!(installed.histories_terminal);
        let terminal = session
            .prepare_next_direct_history_request(token.clone())
            .unwrap();
        assert!(terminal.histories_terminal);
        assert!(terminal.request.is_none());
        assert!(session
            .prepare_direct_prekey_request(token.clone(), conversation_id)
            .unwrap_err()
            .to_string()
            .contains("prekey route is unavailable"));
        assert!(!session
            .client
            .lock()
            .unwrap()
            .has_session(&peer.x25519_public_bytes()));

        let first = new_mobile_sync_token();
        let second = new_mobile_sync_token();
        assert_ne!(first, second);
        assert!(require_mobile_sync_token(&first).is_ok());
        assert!(require_mobile_sync_token(&first.to_uppercase()).is_err());
        assert!(require_mobile_sync_token(&"0".repeat(64)).is_err());
        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_history_oversize_is_a_sticky_epoch_abort() {
        let (session, path, token) = mobile_test_session_with_sync(10);
        let (directory_response, _) = mobile_test_directory_response(&session);
        let directory_request = session
            .prepare_direct_directory_request(token.clone())
            .unwrap();
        session
            .install_direct_directory_page(
                token.clone(),
                directory_request.request_token,
                directory_response,
            )
            .unwrap();
        let history_request = session
            .prepare_next_direct_history_request(token.clone())
            .unwrap()
            .request
            .unwrap();
        assert!(session
            .install_direct_history_response(
                token.clone(),
                history_request.request_token.clone(),
                vec![b' '; veil_client::direct_history::DIRECT_HISTORY_RESPONSE_LIMIT + 1],
            )
            .unwrap_err()
            .to_string()
            .contains("response exceeds"));
        assert!(session
            .install_direct_history_response(
                token.clone(),
                history_request.request_token,
                br#"{"messages":[],"count":0}"#.to_vec(),
            )
            .unwrap_err()
            .to_string()
            .contains("stale or terminal"));
        assert!(session
            .prepare_next_direct_history_request(token)
            .unwrap_err()
            .to_string()
            .contains("unavailable in this phase"));
        let projection = session
            .project_direct_messages("20000000-0000-4000-8000-000000000001".to_string())
            .unwrap();
        assert_eq!(
            projection.availability,
            MobileDirectMessageProjectionAvailability::Unavailable
        );
        assert!(projection.messages.is_empty());

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_history_order_is_deterministic_and_lexicographic() {
        let mut state = mobile_test_sync_state(11, MobileDirectSyncPhase::Directory);
        for (conversation_id, marker) in [
            ("20000000-0000-4000-8000-000000000003", 3_u8),
            ("20000000-0000-4000-8000-000000000001", 1_u8),
            ("20000000-0000-4000-8000-000000000002", 2_u8),
        ] {
            state.peers.insert(
                conversation_id.to_string(),
                MobileDirectPeer {
                    user_id: format!("10000000-0000-4000-8000-{marker:012}"),
                    identity_key: [marker; 32],
                    signing_key: [marker.saturating_add(10); 32],
                },
            );
        }

        begin_mobile_direct_history_phase(&mut state).unwrap();
        assert_eq!(state.phase, MobileDirectSyncPhase::DirectHistory);
        assert_eq!(
            state.history_order,
            vec![
                "20000000-0000-4000-8000-000000000001",
                "20000000-0000-4000-8000-000000000002",
                "20000000-0000-4000-8000-000000000003",
            ]
        );
    }

    #[test]
    fn mobile_direct_history_blocks_only_current_conversation_and_advances() {
        let mut state = mobile_test_sync_state(12, MobileDirectSyncPhase::DirectHistory);
        let first = "20000000-0000-4000-8000-000000000001";
        let second = "20000000-0000-4000-8000-000000000002";
        state.history_order = vec![first.to_string(), second.to_string()];

        finish_mobile_direct_history_conversation(
            &mut state,
            first,
            MobileDirectHistoryOutcome::IncompleteSelfHistory,
        )
        .unwrap();
        assert_eq!(state.phase, MobileDirectSyncPhase::DirectHistory);
        assert_eq!(state.history_index, 1);
        assert_eq!(
            state.blocked_conversations.get(first),
            Some(&MobileDirectHistoryOutcome::IncompleteSelfHistory)
        );
        assert!(!state.blocked_conversations.contains_key(second));

        finish_mobile_direct_history_conversation(
            &mut state,
            second,
            MobileDirectHistoryOutcome::ConversationRejected,
        )
        .unwrap();
        assert_eq!(
            state.phase,
            MobileDirectSyncPhase::HistorySynchronizedAwaitingLive
        );
        assert_eq!(state.history_index, 2);
        assert_eq!(
            state.blocked_conversations.get(second),
            Some(&MobileDirectHistoryOutcome::ConversationRejected)
        );
    }

    #[test]
    fn mobile_direct_live_replay_requires_exact_outbox_barrier_after_quiescence() {
        let (session, path, token) = mobile_test_session_with_sync(120);
        let _outbound = mobile_test_install_queued_connection(&session);
        let _conversation_id = mobile_test_install_ready_direct(&session, &token);
        {
            let mut sync = session.direct_sync.lock().unwrap();
            let state = sync.as_mut().unwrap();
            state.history_index = state.history_order.len();
            state.phase = MobileDirectSyncPhase::HistorySynchronizedAwaitingLive;
            state.outbox_replay_cursor = None;
            state.outbox_replay_complete = false;
        }

        let progress = session.replay_direct_live_events(token.clone()).unwrap();

        assert_eq!(progress.consumed, 0);
        assert!(!progress.projection_changed);
        assert!(!progress.needs_immediate_pump);
        assert!(progress.outbox_replay_required);
        assert!(!progress.ready);
        assert_eq!(
            session.direct_sync.lock().unwrap().as_ref().unwrap().phase,
            MobileDirectSyncPhase::Ready
        );
        assert!(
            !session
                .direct_sync
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .outbox_replay_complete
        );

        let outbox = session.replay_direct_outbox(token).unwrap();
        assert_eq!(outbox.visited, 0);
        assert_eq!(outbox.enqueued, 0);
        assert!(!outbox.needs_immediate_pump);
        assert!(outbox.replay_complete);
        assert!(
            session
                .direct_sync
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .outbox_replay_complete
        );

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_live_replay_rejects_a_nonterminal_history_checkpoint() {
        let (session, path, token) = mobile_test_session_with_sync(121);
        {
            let mut sync = session.direct_sync.lock().unwrap();
            let state = sync.as_mut().unwrap();
            state.phase = MobileDirectSyncPhase::HistorySynchronizedAwaitingLive;
            state
                .history_order
                .push("20000000-0000-4000-8000-000000000001".to_string());
        }

        let error = session
            .replay_direct_live_events(token)
            .unwrap_err()
            .to_string();

        assert!(error.contains("history-to-live checkpoint diverged"));
        assert_eq!(
            session.direct_sync.lock().unwrap().as_ref().unwrap().phase,
            MobileDirectSyncPhase::Failed
        );

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_live_terminal_never_opens_ready() {
        let (session, path, token) = mobile_test_session_with_sync(122);
        session.direct_sync.lock().unwrap().as_mut().unwrap().phase =
            MobileDirectSyncPhase::HistorySynchronizedAwaitingLive;
        session.client.lock().unwrap().disconnect();

        let error = session
            .replay_direct_live_events(token)
            .unwrap_err()
            .to_string();

        assert!(error.contains("live replay terminated"));
        assert_eq!(
            session.direct_sync.lock().unwrap().as_ref().unwrap().phase,
            MobileDirectSyncPhase::Failed
        );

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_sticky_failure_clears_current_and_global_outstanding() {
        let mut state = mobile_test_sync_state(13, MobileDirectSyncPhase::DirectHistory);
        let conversation_id = "20000000-0000-4000-8000-000000000001";
        state.history_order.push(conversation_id.to_string());
        state.current_history = Some(
            veil_client::direct_history::DirectHistorySyncState::new(
                &state.epoch.binding.canonical_server_origin,
                &state.epoch.binding.user_id,
                conversation_id,
            )
            .unwrap(),
        );
        state.outstanding_request = Some(MobileDirectOutstandingRequest {
            kind: MobileDirectOutstandingRequestKind::History {
                conversation_id: conversation_id.to_string(),
            },
            token: "cd".repeat(32),
            method: "GET",
            target: format!("/v1/messages/{conversation_id}?limit=25"),
            body: Zeroizing::new(Vec::new()),
            response_limit_bytes: veil_client::direct_history::DIRECT_HISTORY_RESPONSE_LIMIT as u32,
            peer_prekey_signature_released: false,
        });

        fail_mobile_direct_sync_sticky(&mut state);
        assert_eq!(state.phase, MobileDirectSyncPhase::Failed);
        assert!(state.current_history.is_none());
        assert!(state.outstanding_request.is_none());
    }

    #[test]
    fn mobile_direct_global_outstanding_rejects_cross_stage_prepare() {
        let (session, path, token) = mobile_test_session_with_sync(14);
        {
            let mut sync = session.direct_sync.lock().unwrap();
            sync.as_mut().unwrap().outstanding_request = Some(MobileDirectOutstandingRequest {
                kind: MobileDirectOutstandingRequestKind::OwnPreKeyCount,
                token: "cd".repeat(32),
                method: "GET",
                target: "/v1/prekeys/00/count".to_string(),
                body: Zeroizing::new(Vec::new()),
                response_limit_bytes: veil_client::prekeys::OWN_PREKEY_RESPONSE_LIMIT as u32,
                peer_prekey_signature_released: false,
            });
        }
        let error = session
            .prepare_direct_directory_request(token)
            .unwrap_err()
            .to_string();
        assert!(error.contains("another mobile Direct request is already outstanding"));

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_ready_phase_still_denies_history_blocked_conversation() {
        let (session, path, token, conversation_id, _, _outbound) =
            mobile_test_ready_prekey_fixture(15);
        mobile_test_apply_prekey_denial(
            &session,
            &conversation_id,
            MobileTestPreKeyDenial::HistoryBlocked,
        );

        let error = session
            .prepare_direct_prekey_request(token, conversation_id)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Session error: mobile Direct prekey route is unavailable"
        );
        assert!(session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .outstanding_request
            .is_none());

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_prekey_storage_uncertainty_revokes_binding_and_ready_lease() {
        let (session, path, token, conversation_id, peer_identity, _outbound) =
            mobile_test_ready_prekey_fixture(16);
        let prekey_request = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        session
            .sign_direct_rest_request(token.clone(), prekey_request.request_token.clone())
            .unwrap();

        let (peer_identity_key, prekey_response) = mobile_test_prekey_response(peer_identity);
        session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER reject_mobile_initiator_persistence
                 BEFORE INSERT ON ratchet_sessions
                 BEGIN SELECT RAISE(ABORT, 'secret storage diagnostic'); END;",
            )
            .unwrap();

        let error = session
            .install_direct_prekey_bundle(
                token.clone(),
                prekey_request.request_token,
                conversation_id.clone(),
                prekey_response,
            )
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Session error: mobile Direct prekey storage terminated"
        );
        assert!(!error.contains("secret storage diagnostic"));
        assert!(session.binding.lock().unwrap().is_none());
        let sync = session.direct_sync.lock().unwrap();
        let state = sync.as_ref().unwrap();
        assert_eq!(state.phase, MobileDirectSyncPhase::Failed);
        assert!(state.outstanding_request.is_none());
        drop(sync);
        let client = session.client.lock().unwrap();
        assert_eq!(
            client.direct_conversation_availability_v1(&conversation_id),
            veil_client::api::DirectConversationAvailabilityV1::RuntimeRevoked
        );
        assert!(client.db().is_none());
        assert!(!client.has_session(&peer_identity_key));
        drop(client);
        assert!(session
            .prepare_direct_prekey_request(token, conversation_id)
            .is_err());

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_prekey_prepare_revalidates_every_live_route_guard() {
        for (index, denial) in [
            MobileTestPreKeyDenial::RuntimeQuarantined,
            MobileTestPreKeyDenial::OriginScopeDrift,
            MobileTestPreKeyDenial::PeerSigningScopeDrift,
            MobileTestPreKeyDenial::Disconnected,
            MobileTestPreKeyDenial::HistoryBlocked,
        ]
        .into_iter()
        .enumerate()
        {
            let (session, path, token, conversation_id, peer, _outbound) =
                mobile_test_ready_prekey_fixture(200 + index as u64);
            let peer_identity_key = peer.x25519_public_bytes();
            let request = session
                .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
                .unwrap();
            assert_eq!(
                session
                    .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
                    .unwrap()
                    .request_token,
                request.request_token,
                "healthy prepare lost idempotence before {denial:?}"
            );

            mobile_test_apply_prekey_denial(&session, &conversation_id, denial);
            assert_eq!(
                session
                    .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
                    .unwrap_err()
                    .to_string(),
                "Session error: mobile Direct prekey route is unavailable",
                "prepare leaked denial detail for {denial:?}"
            );
            assert!(session
                .direct_sync
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .outstanding_request
                .is_none());
            assert!(session
                .sign_direct_rest_request(token, request.request_token)
                .is_err());
            mobile_test_assert_no_direct_session(&session, &peer_identity_key);

            drop(session);
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn mobile_direct_prekey_stale_lease_never_consumes_the_current_capability() {
        let (session, path, token, conversation_id, peer, _outbound) =
            mobile_test_ready_prekey_fixture(210);
        let request = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        session
            .sign_direct_rest_request(token.clone(), request.request_token.clone())
            .unwrap();
        let (peer_identity_key, response) = mobile_test_prekey_response(peer);
        let stale_token = "cd".repeat(32);

        assert_eq!(
            session
                .prepare_direct_prekey_request(stale_token.clone(), conversation_id.clone())
                .unwrap_err()
                .to_string(),
            "Session error: mobile Direct prekey route is unavailable"
        );
        mobile_test_assert_prekey_outstanding(
            &session,
            &request.request_token,
            &conversation_id,
            true,
        );
        assert_eq!(
            session
                .install_direct_prekey_bundle(
                    stale_token,
                    request.request_token.clone(),
                    conversation_id.clone(),
                    response.clone(),
                )
                .unwrap_err()
                .to_string(),
            "Session error: mobile Direct prekey route is unavailable"
        );
        mobile_test_assert_prekey_outstanding(
            &session,
            &request.request_token,
            &conversation_id,
            true,
        );
        mobile_test_assert_no_direct_session(&session, &peer_identity_key);

        let exact_epoch = session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .epoch
            .clone();
        let mut stale_binding = exact_epoch.clone();
        stale_binding.generation += 1;
        *session.binding.lock().unwrap() = Some(stale_binding);
        assert!(session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .is_err());
        assert!(session
            .install_direct_prekey_bundle(
                token.clone(),
                request.request_token.clone(),
                conversation_id.clone(),
                response.clone(),
            )
            .is_err());
        mobile_test_assert_prekey_outstanding(
            &session,
            &request.request_token,
            &conversation_id,
            true,
        );
        mobile_test_assert_no_direct_session(&session, &peer_identity_key);

        *session.binding.lock().unwrap() = Some(exact_epoch);
        let installed = session
            .install_direct_prekey_bundle(token, request.request_token, conversation_id, response)
            .unwrap();
        assert_eq!(installed.status, "established");
        assert!(session
            .client
            .lock()
            .unwrap()
            .has_session(&peer_identity_key));

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_prekey_late_denials_cannot_mutate_a_session() {
        for (index, denial) in [
            MobileTestPreKeyDenial::RuntimeQuarantined,
            MobileTestPreKeyDenial::OriginScopeDrift,
            MobileTestPreKeyDenial::PeerSigningScopeDrift,
            MobileTestPreKeyDenial::Disconnected,
            MobileTestPreKeyDenial::HistoryBlocked,
        ]
        .into_iter()
        .enumerate()
        {
            let (session, path, token, conversation_id, peer, _outbound) =
                mobile_test_ready_prekey_fixture(220 + index as u64);
            let request = session
                .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
                .unwrap();
            session
                .sign_direct_rest_request(token.clone(), request.request_token.clone())
                .unwrap();
            let (peer_identity_key, response) = mobile_test_prekey_response(peer);

            mobile_test_apply_prekey_denial(&session, &conversation_id, denial);
            assert_eq!(
                session
                    .install_direct_prekey_bundle(
                        token.clone(),
                        request.request_token.clone(),
                        conversation_id.clone(),
                        response,
                    )
                    .unwrap_err()
                    .to_string(),
                "Session error: mobile Direct prekey route is unavailable",
                "late response leaked denial detail for {denial:?}"
            );
            assert!(session
                .direct_sync
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .outstanding_request
                .is_none());
            assert!(session
                .sign_direct_rest_request(token, request.request_token)
                .is_err());
            mobile_test_assert_no_direct_session(&session, &peer_identity_key);

            drop(session);
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn mobile_direct_prekey_quarantine_before_sign_revokes_the_fetch_capability() {
        let (session, path, token, conversation_id, peer, _outbound) =
            mobile_test_ready_prekey_fixture(230);
        let peer_identity_key = peer.x25519_public_bytes();
        let request = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        mobile_test_apply_prekey_denial(
            &session,
            &conversation_id,
            MobileTestPreKeyDenial::RuntimeQuarantined,
        );

        assert_eq!(
            session
                .sign_direct_rest_request(token.clone(), request.request_token.clone())
                .err()
                .unwrap()
                .to_string(),
            "Session error: mobile Direct prekey route is unavailable"
        );
        assert!(session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .outstanding_request
            .is_none());
        assert!(session
            .install_direct_prekey_bundle(
                token,
                request.request_token,
                conversation_id,
                b"must not parse".to_vec(),
            )
            .is_err());
        mobile_test_assert_no_direct_session(&session, &peer_identity_key);

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_peer_prekey_signature_is_released_exactly_once() {
        let (session, path, token, conversation_id, peer, _outbound) =
            mobile_test_ready_prekey_fixture(231);
        let request = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        let session = Arc::new(session);
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut signers = Vec::new();
        for _ in 0..2 {
            let session = Arc::clone(&session);
            let barrier = Arc::clone(&barrier);
            let token = token.clone();
            let request_token = request.request_token.clone();
            signers.push(std::thread::spawn(move || {
                barrier.wait();
                session
                    .sign_direct_rest_request(token, request_token)
                    .is_ok()
            }));
        }
        barrier.wait();
        let released = signers
            .into_iter()
            .map(|signer| signer.join().unwrap() as usize)
            .sum::<usize>();
        assert_eq!(released, 1, "a destructive prekey GET was signed twice");
        mobile_test_assert_prekey_outstanding(
            &session,
            &request.request_token,
            &conversation_id,
            true,
        );
        assert_eq!(
            session
                .sign_direct_rest_request(token.clone(), request.request_token.clone())
                .err()
                .unwrap()
                .to_string(),
            "Session error: mobile Direct prekey route is unavailable"
        );
        mobile_test_assert_prekey_outstanding(
            &session,
            &request.request_token,
            &conversation_id,
            true,
        );

        let (peer_identity_key, response) = mobile_test_prekey_response(peer);
        let installed = session
            .install_direct_prekey_bundle(token, request.request_token, conversation_id, response)
            .unwrap();
        assert_eq!(installed.status, "established");
        assert!(session
            .client
            .lock()
            .unwrap()
            .has_session(&peer_identity_key));

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_prekey_ready_during_signing_revokes_without_releasing_signature() {
        let (session, path, token, conversation_id, peer, _outbound) =
            mobile_test_ready_prekey_fixture(237);
        let request = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        let (post_sign_entered, release_post_sign) = mobile_test_pause_direct_post_sign(&session);
        let session = Arc::new(session);
        let signer_session = Arc::clone(&session);
        let signer_token = token.clone();
        let signer_request_token = request.request_token.clone();
        let signer = std::thread::spawn(move || {
            signer_session.sign_direct_rest_request(signer_token, signer_request_token)
        });

        post_sign_entered.wait();
        let (peer_identity_key, bundle) = mobile_test_prekey_bundle(peer);
        session
            .client
            .lock()
            .unwrap()
            .establish_session(&peer_identity_key, &bundle)
            .unwrap();
        release_post_sign.wait();

        let error = match signer.join().unwrap() {
            Ok(_) => panic!("Ready race released a peer-prekey signature"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "Session error: mobile Direct prekey route is unavailable"
        );
        assert!(session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .outstanding_request
            .is_none());
        assert!(session
            .sign_direct_rest_request(token, request.request_token)
            .is_err());
        assert!(session
            .client
            .lock()
            .unwrap()
            .has_session(&peer_identity_key));
        mobile_test_clear_direct_post_sign_hook(&session);

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_prekey_old_signer_cannot_consume_replaced_lease_capability() {
        let (session, path, token, conversation_id, _peer, _outbound) =
            mobile_test_ready_prekey_fixture(238);
        let old_request = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        let successor_lease_token = new_mobile_sync_token();
        let mut successor_request = session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .outstanding_request
            .as_ref()
            .unwrap()
            .clone();
        successor_request.token = new_mobile_sync_token();
        successor_request.peer_prekey_signature_released = false;
        assert_ne!(successor_lease_token, token);
        assert_ne!(successor_request.token, old_request.request_token);

        let (post_sign_entered, release_post_sign) = mobile_test_pause_direct_post_sign(&session);
        let session = Arc::new(session);
        let signer_session = Arc::clone(&session);
        let signer_token = token;
        let signer_request_token = old_request.request_token;
        let signer = std::thread::spawn(move || {
            signer_session.sign_direct_rest_request(signer_token, signer_request_token)
        });

        post_sign_entered.wait();
        let successor_epoch = {
            let mut sync = session.direct_sync.lock().unwrap();
            let state = sync.as_mut().unwrap();
            let mut epoch = state.epoch.clone();
            epoch.generation = epoch.generation.checked_add(1).unwrap();
            state.token = successor_lease_token.clone();
            state.epoch = epoch.clone();
            state.outstanding_request = Some(successor_request.clone());
            epoch
        };
        *session.binding.lock().unwrap() = Some(successor_epoch);
        release_post_sign.wait();

        let error = match signer.join().unwrap() {
            Ok(_) => panic!("stale signer released a peer-prekey signature"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "Session error: mobile Direct prekey route is unavailable"
        );
        {
            let sync = session.direct_sync.lock().unwrap();
            let state = sync.as_ref().unwrap();
            assert_eq!(state.token, successor_lease_token);
            assert!(
                state.outstanding_request.as_ref() == Some(&successor_request),
                "old signer changed the successor request capability"
            );
        }

        mobile_test_clear_direct_post_sign_hook(&session);
        session
            .sign_direct_rest_request(successor_lease_token, successor_request.token.clone())
            .unwrap();
        mobile_test_assert_prekey_outstanding(
            &session,
            &successor_request.token,
            &conversation_id,
            true,
        );

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_prekey_unsigned_and_rejected_installs_are_one_shot() {
        let (session, path, token, conversation_id, peer, _outbound) =
            mobile_test_ready_prekey_fixture(232);
        let first = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        let (peer_identity_key, response) = mobile_test_prekey_response(peer);
        assert_eq!(
            session
                .install_direct_prekey_bundle(
                    token.clone(),
                    first.request_token.clone(),
                    conversation_id.clone(),
                    response,
                )
                .unwrap_err()
                .to_string(),
            "Session error: mobile Direct prekey route is unavailable"
        );
        assert!(session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .outstanding_request
            .is_none());
        mobile_test_assert_no_direct_session(&session, &peer_identity_key);

        let second = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        assert_ne!(second.request_token, first.request_token);
        session
            .sign_direct_rest_request(token.clone(), second.request_token.clone())
            .unwrap();
        assert_eq!(
            session
                .install_direct_prekey_bundle(
                    token.clone(),
                    second.request_token.clone(),
                    conversation_id.clone(),
                    b"{}".to_vec(),
                )
                .unwrap_err()
                .to_string(),
            "Session error: mobile Direct prekey bundle was rejected"
        );
        assert!(session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .outstanding_request
            .is_none());
        mobile_test_assert_no_direct_session(&session, &peer_identity_key);
        let third = session
            .prepare_direct_prekey_request(token, conversation_id)
            .unwrap();
        assert_ne!(third.request_token, second.request_token);

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_prekey_wrong_request_or_conversation_never_consumes_the_exact_one() {
        let (session, path, token, conversation_id, peer, _outbound) =
            mobile_test_ready_prekey_fixture(233);
        let request = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        session
            .sign_direct_rest_request(token.clone(), request.request_token.clone())
            .unwrap();
        let (peer_identity_key, response) = mobile_test_prekey_response(peer);

        assert!(session
            .install_direct_prekey_bundle(
                token.clone(),
                new_mobile_sync_token(),
                conversation_id.clone(),
                response.clone(),
            )
            .is_err());
        mobile_test_assert_prekey_outstanding(
            &session,
            &request.request_token,
            &conversation_id,
            true,
        );
        assert!(session
            .install_direct_prekey_bundle(
                token.clone(),
                request.request_token.clone(),
                "20000000-0000-4000-8000-000000000099".to_string(),
                response.clone(),
            )
            .is_err());
        mobile_test_assert_prekey_outstanding(
            &session,
            &request.request_token,
            &conversation_id,
            true,
        );
        mobile_test_assert_no_direct_session(&session, &peer_identity_key);

        assert_eq!(
            session
                .install_direct_prekey_bundle(
                    token,
                    request.request_token,
                    conversation_id,
                    response,
                )
                .unwrap()
                .status,
            "established"
        );

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_prekey_late_ready_consumes_without_parsing_or_resetting_ratchet() {
        let (session, path, token, conversation_id, peer, _outbound) =
            mobile_test_ready_prekey_fixture(234);
        let request = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        session
            .sign_direct_rest_request(token.clone(), request.request_token.clone())
            .unwrap();
        let (peer_identity_key, bundle) = mobile_test_prekey_bundle(peer);
        session
            .client
            .lock()
            .unwrap()
            .establish_session(&peer_identity_key, &bundle)
            .unwrap();
        let before = session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .load_ratchet_session(&peer_identity_key)
            .unwrap()
            .unwrap();

        let result = session
            .install_direct_prekey_bundle(
                token.clone(),
                request.request_token,
                conversation_id.clone(),
                vec![0xff, 0x00, 0xfe],
            )
            .unwrap();
        assert_eq!(result.status, "already_established");
        assert!(session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .outstanding_request
            .is_none());
        let after = session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .load_ratchet_session(&peer_identity_key)
            .unwrap()
            .unwrap();
        assert_eq!(after, before, "late prekey response reset the live ratchet");
        assert!(session
            .prepare_direct_prekey_request(token, conversation_id)
            .is_err());

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_prekey_prepare_consumes_cached_capability_after_session_becomes_ready() {
        let (session, path, token, conversation_id, peer, _outbound) =
            mobile_test_ready_prekey_fixture(235);
        let request = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        let (peer_identity_key, bundle) = mobile_test_prekey_bundle(peer);
        session
            .client
            .lock()
            .unwrap()
            .establish_session(&peer_identity_key, &bundle)
            .unwrap();
        let before = session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .load_ratchet_session(&peer_identity_key)
            .unwrap();

        assert_eq!(
            session
                .prepare_direct_prekey_request(token.clone(), conversation_id)
                .unwrap_err()
                .to_string(),
            "Session error: mobile Direct prekey route is unavailable"
        );
        assert!(session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .outstanding_request
            .is_none());
        assert!(session
            .sign_direct_rest_request(token, request.request_token)
            .is_err());
        assert_eq!(
            session
                .client
                .lock()
                .unwrap()
                .db()
                .unwrap()
                .load_ratchet_session(&peer_identity_key)
                .unwrap(),
            before
        );

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_prekey_oversized_late_ready_response_keeps_sticky_abort_semantics() {
        let (session, path, token, conversation_id, peer, _outbound) =
            mobile_test_ready_prekey_fixture(236);
        let request = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        session
            .sign_direct_rest_request(token.clone(), request.request_token.clone())
            .unwrap();
        let (peer_identity_key, bundle) = mobile_test_prekey_bundle(peer);
        session
            .client
            .lock()
            .unwrap()
            .establish_session(&peer_identity_key, &bundle)
            .unwrap();
        let before = session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .load_ratchet_session(&peer_identity_key)
            .unwrap();

        assert!(session
            .install_direct_prekey_bundle(
                token,
                request.request_token,
                conversation_id,
                vec![0; veil_client::direct::DIRECT_PREKEY_RESPONSE_LIMIT + 1],
            )
            .unwrap_err()
            .to_string()
            .contains("response exceeds"));
        let sync = session.direct_sync.lock().unwrap();
        assert_eq!(sync.as_ref().unwrap().phase, MobileDirectSyncPhase::Failed);
        assert!(sync.as_ref().unwrap().outstanding_request.is_none());
        drop(sync);
        assert_eq!(
            session
                .client
                .lock()
                .unwrap()
                .db()
                .unwrap()
                .load_ratchet_session(&peer_identity_key)
                .unwrap(),
            before
        );

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_projection_maps_all_native_denials_to_one_opaque_state() {
        use veil_client::api::DirectConversationAvailabilityV1;

        assert_eq!(
            mobile_direct_projection_availability(DirectConversationAvailabilityV1::Available),
            MobileDirectMessageProjectionAvailability::Available
        );
        for denied in [
            DirectConversationAvailabilityV1::Quarantined,
            DirectConversationAvailabilityV1::RuntimeRevoked,
            DirectConversationAvailabilityV1::NotDirect,
        ] {
            assert_eq!(
                mobile_direct_projection_availability(denied),
                MobileDirectMessageProjectionAvailability::Unavailable
            );
            let projection = unavailable_mobile_direct_message_projection();
            let MobileDirectMessageProjection {
                availability,
                messages,
            } = projection;
            assert_eq!(
                availability,
                MobileDirectMessageProjectionAvailability::Unavailable
            );
            assert!(messages.is_empty());
        }
    }

    #[test]
    fn mobile_direct_send_readiness_uses_the_live_session_not_directory_snapshot() {
        let (session, path, token) = mobile_test_session_with_sync(124);
        let (conversation_id, peer) = mobile_test_install_ready_direct_with_peer(&session, &token);
        let _outbound = mobile_test_install_queued_connection(&session);

        assert_eq!(
            session.direct_send_readiness(token.clone(), conversation_id.clone()),
            MobileDirectSendReadiness::NeedsPreKey
        );

        let (peer_identity_key, bundle) = mobile_test_prekey_bundle(peer);
        session
            .client
            .lock()
            .unwrap()
            .establish_session(&peer_identity_key, &bundle)
            .unwrap();
        assert_eq!(
            session.direct_send_readiness(token, conversation_id),
            MobileDirectSendReadiness::Ready
        );

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_text_send_is_native_atomic_and_projects_only_the_durable_row() {
        let (session, path, token, conversation_id, peer, mut outbound) =
            mobile_test_ready_prekey_fixture(130);
        let (peer_identity_key, bundle) = mobile_test_prekey_bundle(peer);
        session
            .client
            .lock()
            .unwrap()
            .establish_session(&peer_identity_key, &bundle)
            .unwrap();

        assert_eq!(
            session
                .send_direct_text(
                    token,
                    conversation_id.clone(),
                    b"durable mobile hello".to_vec(),
                )
                .unwrap(),
            MobileDirectTextSendOutcome::Accepted
        );
        let wire = session
            .runtime
            .block_on(async { outbound.recv().await })
            .expect("accepted Direct text must enter the native transport");
        assert!(!wire.is_empty());
        let pending_count: i64 = session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM direct_message_outbox_v1 WHERE state = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_count, 1);
        let projection = session.project_direct_messages(conversation_id).unwrap();
        assert_eq!(
            projection.availability,
            MobileDirectMessageProjectionAvailability::Available
        );
        assert_eq!(projection.messages.len(), 1);
        assert_eq!(projection.messages[0].text(), "durable mobile hello");
        assert_eq!(
            projection.messages[0].delivery(),
            MobileDirectMessageDelivery::Sending
        );

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_text_send_needs_prekey_without_accepting_an_intent() {
        let (session, path, token, conversation_id, _peer, mut outbound) =
            mobile_test_ready_prekey_fixture(131);

        assert_eq!(
            session
                .send_direct_text(token, conversation_id, b"not accepted yet".to_vec())
                .unwrap(),
            MobileDirectTextSendOutcome::NeedsPreKey
        );
        let pending_count: i64 = session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .conn()
            .query_row("SELECT COUNT(*) FROM direct_message_outbox_v1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(pending_count, 0);
        assert!(matches!(
            outbound.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_text_transport_loss_keeps_intent_and_revokes_the_lease() {
        let (session, path, token, conversation_id, peer, outbound) =
            mobile_test_ready_prekey_fixture(132);
        let (peer_identity_key, bundle) = mobile_test_prekey_bundle(peer);
        session
            .client
            .lock()
            .unwrap()
            .establish_session(&peer_identity_key, &bundle)
            .unwrap();
        drop(outbound);

        assert_eq!(
            session
                .send_direct_text(token, conversation_id, b"replay me exactly".to_vec())
                .unwrap(),
            MobileDirectTextSendOutcome::AcceptedForReplay
        );
        assert!(session.binding.lock().unwrap().is_none());
        assert_eq!(
            session.direct_sync.lock().unwrap().as_ref().unwrap().phase,
            MobileDirectSyncPhase::Failed
        );
        let pending_count: i64 = session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM direct_message_outbox_v1 WHERE state = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_count, 1);

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_new_ready_lease_replays_the_exact_persisted_payload() {
        let (session, path, token, conversation_id, peer, mut first_outbound) =
            mobile_test_ready_prekey_fixture(133);
        let (peer_identity_key, bundle) = mobile_test_prekey_bundle(peer);
        session
            .client
            .lock()
            .unwrap()
            .establish_session(&peer_identity_key, &bundle)
            .unwrap();
        assert_eq!(
            session
                .send_direct_text(token, conversation_id, b"survive reconnect".to_vec(),)
                .unwrap(),
            MobileDirectTextSendOutcome::Accepted
        );
        let first_wire = session
            .runtime
            .block_on(async { first_outbound.recv().await })
            .unwrap();
        let exact_payload: Vec<u8> = session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .conn()
            .query_row(
                "SELECT exact_send_message_payload FROM direct_message_outbox_v1 WHERE state = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(first_wire.ends_with(&exact_payload));

        let renewed_epoch = mobile_test_epoch(134);
        let renewed_token = "cd".repeat(32);
        {
            let mut client = session.client.lock().unwrap();
            client.disconnect();
            client
                .test_only_reconcile_previous_transport_before_install_v1()
                .unwrap();
            client
                .test_only_restore_authenticated_user_from_durable_binding(
                    &renewed_epoch.binding.canonical_server_origin,
                    &renewed_epoch.binding.user_id,
                )
                .unwrap();
        }
        let mut replay_outbound = mobile_test_install_queued_connection(&session);
        {
            let mut sync = session.direct_sync.lock().unwrap();
            let state = sync.as_mut().unwrap();
            state.token = renewed_token.clone();
            state.epoch = renewed_epoch.clone();
            state.phase = MobileDirectSyncPhase::Ready;
            state.outbox_replay_cursor = None;
            state.outbox_replay_complete = false;
        }
        *session.binding.lock().unwrap() = Some(renewed_epoch);

        let replay = session.replay_direct_outbox(renewed_token).unwrap();
        assert_eq!(replay.visited, 1);
        assert_eq!(replay.enqueued, 1);
        assert!(replay.replay_complete);
        assert!(!replay.needs_immediate_pump);
        let replay_wire = session
            .runtime
            .block_on(async { replay_outbound.recv().await })
            .unwrap();
        assert!(replay_wire.ends_with(&exact_payload));
        assert_eq!(
            first_wire, replay_wire,
            "fresh test sockets restart the same outer sequence; the exact frame must match"
        );

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_text_storage_uncertainty_revokes_all_mobile_authority() {
        let (session, path, token, conversation_id, peer, _outbound) =
            mobile_test_ready_prekey_fixture(135);
        let (peer_identity_key, bundle) = mobile_test_prekey_bundle(peer);
        session
            .client
            .lock()
            .unwrap()
            .establish_session(&peer_identity_key, &bundle)
            .unwrap();
        session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER reject_mobile_direct_outbox
                 BEFORE INSERT ON direct_message_outbox_v1
                 BEGIN
                    SELECT RAISE(ABORT, 'forced mobile outbox failure');
                 END;",
            )
            .unwrap();

        let error = session
            .send_direct_text(token, conversation_id, b"uncertain".to_vec())
            .unwrap_err()
            .to_string();
        assert!(error.contains("send storage is uncertain"));
        assert!(session.binding.lock().unwrap().is_none());
        assert_eq!(
            session.direct_sync.lock().unwrap().as_ref().unwrap().phase,
            MobileDirectSyncPhase::Failed
        );
        assert!(!session.client.lock().unwrap().is_connected());

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_send_readiness_collapses_all_route_and_lease_denials() {
        let (session, path, token) = mobile_test_session_with_sync(125);
        let (conversation_id, peer) = mobile_test_install_ready_direct_with_peer(&session, &token);
        let _outbound = mobile_test_install_queued_connection(&session);
        let (peer_identity_key, bundle) = mobile_test_prekey_bundle(peer);
        session
            .client
            .lock()
            .unwrap()
            .establish_session(&peer_identity_key, &bundle)
            .unwrap();
        assert_eq!(
            session.direct_send_readiness(token.clone(), conversation_id.clone()),
            MobileDirectSendReadiness::Ready
        );

        let original_epoch = session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .epoch
            .clone();
        let renewed_token = "cd".repeat(32);
        let renewed_epoch = mobile_test_epoch(126);
        {
            let mut sync = session.direct_sync.lock().unwrap();
            let state = sync.as_mut().unwrap();
            state.token = renewed_token.clone();
            state.epoch = renewed_epoch.clone();
        }
        *session.binding.lock().unwrap() = Some(renewed_epoch);
        assert_eq!(
            session.direct_send_readiness(token.clone(), conversation_id.clone()),
            MobileDirectSendReadiness::Unavailable
        );
        assert_eq!(
            session.direct_send_readiness(renewed_token, conversation_id.clone()),
            MobileDirectSendReadiness::Ready
        );
        {
            let mut sync = session.direct_sync.lock().unwrap();
            let state = sync.as_mut().unwrap();
            state.token = token.clone();
            state.epoch = original_epoch.clone();
        }
        *session.binding.lock().unwrap() = Some(original_epoch);

        for malformed_lease in ["not-a-lease".to_string(), "00".repeat(32)] {
            assert_eq!(
                session.direct_send_readiness(malformed_lease, conversation_id.clone()),
                MobileDirectSendReadiness::Unavailable
            );
        }
        assert_eq!(
            session.direct_send_readiness("cd".repeat(32), conversation_id.clone()),
            MobileDirectSendReadiness::Unavailable
        );
        for malformed_conversation in [
            "not-a-conversation".to_string(),
            "00000000-0000-0000-0000-000000000000".to_string(),
            "20000000-0000-4000-8000-00000000000A".to_string(),
        ] {
            assert_eq!(
                session.direct_send_readiness(token.clone(), malformed_conversation),
                MobileDirectSendReadiness::Unavailable
            );
        }
        assert_eq!(
            session.direct_send_readiness(
                token.clone(),
                "20000000-0000-4000-8000-000000000099".to_string(),
            ),
            MobileDirectSendReadiness::Unavailable
        );

        session.direct_sync.lock().unwrap().as_mut().unwrap().phase =
            MobileDirectSyncPhase::HistorySynchronizedAwaitingLive;
        assert_eq!(
            session.direct_send_readiness(token.clone(), conversation_id.clone()),
            MobileDirectSendReadiness::Unavailable
        );
        session.direct_sync.lock().unwrap().as_mut().unwrap().phase = MobileDirectSyncPhase::Ready;

        let exact_epoch = session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .epoch
            .clone();
        *session.binding.lock().unwrap() = Some(mobile_test_epoch(126));
        assert_eq!(
            session.direct_send_readiness(token.clone(), conversation_id.clone()),
            MobileDirectSendReadiness::Unavailable
        );
        *session.binding.lock().unwrap() = Some(exact_epoch);

        session
            .direct_sync
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .blocked_conversations
            .insert(
                conversation_id.clone(),
                MobileDirectHistoryOutcome::ConversationRejected,
            );
        assert_eq!(
            session.direct_send_readiness(token.clone(), conversation_id.clone()),
            MobileDirectSendReadiness::Unavailable
        );
        session
            .direct_sync
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .blocked_conversations
            .remove(&conversation_id);

        let pinned_signing_key = {
            let mut sync = session.direct_sync.lock().unwrap();
            let peer = sync
                .as_mut()
                .unwrap()
                .peers
                .get_mut(&conversation_id)
                .unwrap();
            let pinned = peer.signing_key;
            peer.signing_key = IdentityKeyPair::generate().ed25519_public_bytes();
            pinned
        };
        assert_eq!(
            session.direct_send_readiness(token.clone(), conversation_id.clone()),
            MobileDirectSendReadiness::Unavailable
        );
        session
            .direct_sync
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .peers
            .get_mut(&conversation_id)
            .unwrap()
            .signing_key = pinned_signing_key;

        session.client.lock().unwrap().disconnect();
        assert_eq!(
            session.direct_send_readiness(token, conversation_id),
            MobileDirectSendReadiness::Unavailable
        );

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_send_readiness_collapses_storage_revocation() {
        let (session, path, token) = mobile_test_session_with_sync(127);
        let (conversation_id, peer) = mobile_test_install_ready_direct_with_peer(&session, &token);
        let _outbound = mobile_test_install_queued_connection(&session);
        assert_eq!(
            session.direct_send_readiness(token.clone(), conversation_id.clone()),
            MobileDirectSendReadiness::NeedsPreKey
        );
        session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER reject_readiness_session_persistence
                 BEFORE INSERT ON ratchet_sessions
                 BEGIN
                    SELECT RAISE(ABORT, 'forced readiness storage failure');
                 END;",
            )
            .unwrap();
        let (peer_identity_key, bundle) = mobile_test_prekey_bundle(peer);
        assert!(session
            .client
            .lock()
            .unwrap()
            .establish_session(&peer_identity_key, &bundle)
            .is_err());
        assert_eq!(
            session
                .client
                .lock()
                .unwrap()
                .direct_conversation_availability_v1(&conversation_id),
            veil_client::api::DirectConversationAvailabilityV1::RuntimeRevoked
        );
        assert_eq!(
            session.direct_send_readiness(token, conversation_id),
            MobileDirectSendReadiness::Unavailable
        );

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_send_readiness_collapses_missing_and_poisoned_native_state() {
        let canonical_conversation = "20000000-0000-4000-8000-000000000001".to_string();

        let (missing, missing_path, token) = mobile_test_session_with_sync(128);
        *missing.direct_sync.lock().unwrap() = None;
        assert_eq!(
            missing.direct_send_readiness(token, canonical_conversation.clone()),
            MobileDirectSendReadiness::Unavailable
        );
        drop(missing);
        let _ = std::fs::remove_file(missing_path);

        let (sync_poisoned, sync_path, token) = mobile_test_session_with_sync(129);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = sync_poisoned.direct_sync.lock().unwrap();
            panic!("poison Direct sync for readiness test");
        }))
        .is_err());
        assert_eq!(
            sync_poisoned.direct_send_readiness(token, canonical_conversation.clone()),
            MobileDirectSendReadiness::Unavailable
        );
        drop(sync_poisoned);
        let _ = std::fs::remove_file(sync_path);

        let (binding_poisoned, binding_path, token) = mobile_test_session_with_sync(130);
        let conversation_id = mobile_test_install_ready_direct(&binding_poisoned, &token);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = binding_poisoned.binding.lock().unwrap();
            panic!("poison binding for readiness test");
        }))
        .is_err());
        assert_eq!(
            binding_poisoned.direct_send_readiness(token, conversation_id),
            MobileDirectSendReadiness::Unavailable
        );
        drop(binding_poisoned);
        let _ = std::fs::remove_file(binding_path);

        let (client_poisoned, client_path, token) = mobile_test_session_with_sync(131);
        let conversation_id = mobile_test_install_ready_direct(&client_poisoned, &token);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = client_poisoned.client.lock().unwrap();
            panic!("poison client for readiness test");
        }))
        .is_err());
        assert_eq!(
            client_poisoned.direct_send_readiness(token, conversation_id),
            MobileDirectSendReadiness::Unavailable
        );
        drop(client_poisoned);
        let _ = std::fs::remove_file(client_path);
    }

    #[test]
    fn mobile_direct_projection_returns_only_minimal_text_dto_for_healthy_exact_route() {
        let (session, path, token) = mobile_test_session_with_sync(16);
        let conversation_id = mobile_test_install_ready_direct(&session, &token);
        let peer_identity_key = session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .peers
            .get(&conversation_id)
            .unwrap()
            .identity_key;
        let message_id = "30000000-0000-4000-8000-000000000001";
        session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .insert_message(
                message_id,
                &conversation_id,
                &peer_identity_key,
                "authenticated preview text",
                false,
                Some(1_700_000_000_123),
                None,
            )
            .unwrap();

        let projection = session
            .project_direct_messages(conversation_id.clone())
            .unwrap();
        assert_eq!(
            projection.availability,
            MobileDirectMessageProjectionAvailability::Available
        );
        assert_eq!(projection.messages.len(), 1);
        let message = projection.messages.into_iter().next().unwrap();
        assert_eq!(message.message_id(), message_id);
        assert_eq!(message.text(), "authenticated preview text");
        assert_eq!(message.timestamp_ms(), Some(1_700_000_000_123));
        assert_eq!(message.direction(), MobileDirectMessageDirection::Incoming);
        assert_eq!(message.delivery(), MobileDirectMessageDelivery::Sent);

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_projection_denies_cross_peer_and_signing_pin_drift() {
        let (session, path, token) = mobile_test_session_with_sync(18);
        let conversation_id = mobile_test_install_ready_direct(&session, &token);
        let durable_peer = session
            .direct_sync
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .peers
            .get(&conversation_id)
            .unwrap()
            .clone();
        session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .insert_message(
                "30000000-0000-4000-8000-000000000003",
                &conversation_id,
                &durable_peer.identity_key,
                "durable peer B plaintext",
                false,
                Some(1_700_000_000_789),
                None,
            )
            .unwrap();

        let substituted_peer = IdentityKeyPair::generate();
        session
            .direct_sync
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .peers
            .insert(
                conversation_id.clone(),
                MobileDirectPeer {
                    user_id: "550e8400-e29b-41d4-a716-446655440099".to_string(),
                    identity_key: substituted_peer.x25519_public_bytes(),
                    signing_key: substituted_peer.ed25519_public_bytes(),
                },
            );
        let cross_peer = session
            .project_direct_messages(conversation_id.clone())
            .unwrap();
        let MobileDirectMessageProjection {
            availability,
            messages,
        } = cross_peer;
        assert_eq!(
            availability,
            MobileDirectMessageProjectionAvailability::Unavailable
        );
        assert!(messages.is_empty());

        let unpinned_signing = IdentityKeyPair::generate().ed25519_public_bytes();
        let mut signing_drift = durable_peer.clone();
        signing_drift.signing_key = unpinned_signing;
        session
            .direct_sync
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .peers
            .insert(conversation_id.clone(), signing_drift);
        let signing_mismatch = session
            .project_direct_messages(conversation_id.clone())
            .unwrap();
        assert_eq!(
            signing_mismatch.availability,
            MobileDirectMessageProjectionAvailability::Unavailable
        );
        assert!(signing_mismatch.messages.is_empty());

        session
            .direct_sync
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .peers
            .insert(conversation_id.clone(), durable_peer);
        let healthy = session.project_direct_messages(conversation_id).unwrap();
        assert_eq!(
            healthy.availability,
            MobileDirectMessageProjectionAvailability::Available
        );
        assert_eq!(healthy.messages.len(), 1);
        assert_eq!(healthy.messages[0].text(), "durable peer B plaintext");

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_direct_projection_denies_sender_direction_drift_without_a_prefix() {
        for (generation, is_outgoing) in [(19, false), (20, true)] {
            let (session, path, token) = mobile_test_session_with_sync(generation);
            let conversation_id = mobile_test_install_ready_direct(&session, &token);
            let (self_identity_key, peer_identity_key) =
                mobile_test_direct_identities(&session, &conversation_id);
            let wrong_sender = if is_outgoing {
                peer_identity_key
            } else {
                self_identity_key
            };
            mobile_test_insert_direct_message(
                &session,
                &conversation_id,
                100 + generation,
                &wrong_sender,
                "sender tuple must not render",
                is_outgoing,
            );

            let projection = session.project_direct_messages(conversation_id).unwrap();
            assert_eq!(
                projection.availability,
                MobileDirectMessageProjectionAvailability::Unavailable
            );
            assert!(projection.messages.is_empty());

            drop(session);
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn mobile_direct_projection_enforces_utf8_row_and_total_plaintext_budgets() {
        let (row_session, row_path, row_token) = mobile_test_session_with_sync(21);
        let row_conversation = mobile_test_install_ready_direct(&row_session, &row_token);
        let (_, row_peer) = mobile_test_direct_identities(&row_session, &row_conversation);
        let exact_row = "a".repeat(MOBILE_DIRECT_MESSAGE_MAX_PLAINTEXT_BYTES);
        mobile_test_insert_direct_message(
            &row_session,
            &row_conversation,
            200,
            &row_peer,
            &exact_row,
            false,
        );
        assert_eq!(
            row_session
                .project_direct_messages(row_conversation.clone())
                .unwrap()
                .availability,
            MobileDirectMessageProjectionAvailability::Available
        );
        let oversized_row = "b".repeat(MOBILE_DIRECT_MESSAGE_MAX_PLAINTEXT_BYTES + 1);
        mobile_test_insert_direct_message(
            &row_session,
            &row_conversation,
            201,
            &row_peer,
            &oversized_row,
            false,
        );
        let row_denied = row_session
            .project_direct_messages(row_conversation)
            .unwrap();
        assert_eq!(
            row_denied.availability,
            MobileDirectMessageProjectionAvailability::Unavailable
        );
        assert!(row_denied.messages.is_empty());
        drop(row_session);
        let _ = std::fs::remove_file(row_path);

        let (total_session, total_path, total_token) = mobile_test_session_with_sync(22);
        let total_conversation = mobile_test_install_ready_direct(&total_session, &total_token);
        let (_, total_peer) = mobile_test_direct_identities(&total_session, &total_conversation);
        for index in 0..32 {
            mobile_test_insert_direct_message(
                &total_session,
                &total_conversation,
                300 + index,
                &total_peer,
                &exact_row,
                false,
            );
        }
        let exact_total = total_session
            .project_direct_messages(total_conversation.clone())
            .unwrap();
        assert_eq!(
            exact_total.availability,
            MobileDirectMessageProjectionAvailability::Available
        );
        assert_eq!(exact_total.messages.len(), 32);
        mobile_test_insert_direct_message(
            &total_session,
            &total_conversation,
            332,
            &total_peer,
            "x",
            false,
        );
        let total_denied = total_session
            .project_direct_messages(total_conversation)
            .unwrap();
        assert_eq!(
            total_denied.availability,
            MobileDirectMessageProjectionAvailability::Unavailable
        );
        assert!(total_denied.messages.is_empty());
        drop(total_session);
        let _ = std::fs::remove_file(total_path);

        let (utf8_session, utf8_path, utf8_token) = mobile_test_session_with_sync(23);
        let utf8_conversation = mobile_test_install_ready_direct(&utf8_session, &utf8_token);
        let (_, utf8_peer) = mobile_test_direct_identities(&utf8_session, &utf8_conversation);
        let exact_utf8 = "🦀".repeat(MOBILE_DIRECT_MESSAGE_MAX_PLAINTEXT_BYTES / 4);
        assert_eq!(exact_utf8.len(), MOBILE_DIRECT_MESSAGE_MAX_PLAINTEXT_BYTES);
        mobile_test_insert_direct_message(
            &utf8_session,
            &utf8_conversation,
            400,
            &utf8_peer,
            &exact_utf8,
            false,
        );
        assert_eq!(
            utf8_session
                .project_direct_messages(utf8_conversation.clone())
                .unwrap()
                .availability,
            MobileDirectMessageProjectionAvailability::Available
        );
        let oversized_utf8 = "🦀".repeat(MOBILE_DIRECT_MESSAGE_MAX_PLAINTEXT_BYTES / 4 + 1);
        mobile_test_insert_direct_message(
            &utf8_session,
            &utf8_conversation,
            401,
            &utf8_peer,
            &oversized_utf8,
            false,
        );
        let utf8_denied = utf8_session
            .project_direct_messages(utf8_conversation)
            .unwrap();
        assert_eq!(
            utf8_denied.availability,
            MobileDirectMessageProjectionAvailability::Unavailable
        );
        assert!(utf8_denied.messages.is_empty());
        drop(utf8_session);
        let _ = std::fs::remove_file(utf8_path);
    }

    #[test]
    fn mobile_direct_projection_hides_history_blocked_exact_route_without_identifiers() {
        let (session, path, token) = mobile_test_session_with_sync(17);
        let conversation_id = mobile_test_install_ready_direct(&session, &token);
        session
            .client
            .lock()
            .unwrap()
            .db()
            .unwrap()
            .insert_message(
                "30000000-0000-4000-8000-000000000002",
                &conversation_id,
                &[9; 32],
                "must stay native",
                false,
                Some(1_700_000_000_456),
                None,
            )
            .unwrap();
        session
            .direct_sync
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .blocked_conversations
            .insert(
                conversation_id.clone(),
                MobileDirectHistoryOutcome::ConversationRejected,
            );

        let projection = session
            .project_direct_messages(conversation_id.clone())
            .unwrap();
        assert_eq!(
            projection.availability,
            MobileDirectMessageProjectionAvailability::Unavailable
        );
        assert!(projection.messages.is_empty());

        drop(session);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mobile_connect_cancellation_clears_binding_and_disconnects_fail_closed() {
        let binding = Mutex::new(Some(mobile_test_epoch(1)));
        let mut client = veil_client::api::VeilClient::new();

        let error = fail_closed_mobile_connect_cancellation(&mut client, &binding);

        assert!(binding.lock().unwrap().is_none());
        assert!(!client.is_connected());
        assert_eq!(
            error.to_string(),
            "Session error: mobile connection attempt cancelled"
        );
    }

    #[test]
    fn mobile_post_auth_failure_disconnects_clears_and_preserves_error() {
        let binding = Mutex::new(Some(mobile_test_epoch(2)));
        let disconnect_count = std::cell::Cell::new(0);
        let result: Result<(), VeilError> = fail_closed_mobile_post_auth(
            || disconnect_count.set(disconnect_count.get() + 1),
            &binding,
            VeilError::Session {
                msg: "original sanitized post-auth failure".to_string(),
            },
        );

        assert_eq!(disconnect_count.get(), 1);
        assert!(binding.lock().unwrap().is_none());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Session error: original sanitized post-auth failure"
        );
    }

    #[test]
    fn mobile_binding_cleanup_recovers_a_poisoned_guard() {
        let binding = Mutex::new(Some(mobile_test_epoch(3)));
        let guard = binding.lock().unwrap();
        clear_mobile_binding_guard(Err(std::sync::PoisonError::new(guard)));
        assert!(binding.lock().unwrap().is_none());
    }

    #[test]
    fn mobile_session_invalidation_clears_binding_and_closes_prior_epoch() {
        let binding = Mutex::new(Some(mobile_test_epoch(4)));
        let client = Mutex::new(veil_client::api::VeilClient::new());

        let client_guard = invalidate_mobile_session(&binding, &client).unwrap();
        assert!(binding.lock().unwrap().is_none());
        assert!(!client_guard.is_connected());
    }

    #[test]
    fn poisoned_mobile_client_guard_is_disconnected_and_reports_lock_error() {
        let client = Mutex::new(veil_client::api::VeilClient::new());
        let guard = client.lock().unwrap();
        let error = match disconnect_mobile_client_guard(Err(std::sync::PoisonError::new(guard))) {
            Err(error) => error,
            Ok(_) => panic!("synthetic poisoned client guard unexpectedly succeeded"),
        };

        assert!(error
            .to_string()
            .starts_with("Session error: lock mobile client:"));
        assert!(!client.lock().unwrap().is_connected());
    }

    #[test]
    fn mobile_rest_signing_inputs_are_canonical_and_bounded() {
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
            assert!(require_rest_method(method).is_ok());
        }
        assert!(require_rest_method("get").is_err());
        assert!(require_rest_target("/v1/push/vapid-key").is_ok());
        assert!(require_rest_target("/v1/push/subscriptions/7/confirm").is_ok());
        for target in [
            "v1/push/vapid-key",
            "//other.example.test/v1/push",
            "/v1/push#fragment",
            "/v1/push\nforged",
            "/v1/пуш",
        ] {
            assert!(require_rest_target(target).is_err());
        }
    }
}
