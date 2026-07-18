use bip39::Mnemonic;
use rand::{rngs::OsRng, seq::SliceRandom, RngCore};
use std::{
    collections::HashMap,
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
    next_cursor: Option<String>,
    directory_complete: bool,
    history: veil_client::direct::DirectDirectorySyncHistory,
    peers: HashMap<String, MobileDirectPeer>,
    outstanding_directory_request: Option<MobileDirectOutstandingRequest>,
    outstanding_prekey_requests: HashMap<String, MobileDirectOutstandingRequest>,
}

#[derive(Clone)]
struct MobileDirectPeer {
    user_id: String,
    identity_key: [u8; 32],
    signing_key: [u8; 32],
}

#[derive(Clone)]
struct MobileDirectOutstandingRequest {
    token: String,
    target: String,
}

#[derive(Debug, uniffi::Record)]
pub struct MobileDirectSyncLease {
    pub token: String,
    pub canonical_server_origin: String,
    pub user_id: String,
}

#[derive(Debug, uniffi::Record)]
pub struct MobileDirectRestRequest {
    pub request_token: String,
    pub request_target: String,
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
#[derive(uniffi::Object)]
pub struct VeilMobileSession {
    client: Mutex<veil_client::api::VeilClient>,
    runtime: tokio::runtime::Runtime,
    binding: Mutex<Option<MobileAuthenticatedEpoch>>,
    direct_sync: Mutex<Option<MobileDirectSyncState>>,
    next_binding_generation: AtomicU64,
    last_rest_timestamp_ms: AtomicI64,
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
            next_cursor: None,
            directory_complete: false,
            history: veil_client::direct::DirectDirectorySyncHistory::default(),
            peers: HashMap::new(),
            outstanding_directory_request: None,
            outstanding_prekey_requests: HashMap::new(),
        });
        Ok(MobileDirectSyncLease {
            token,
            canonical_server_origin: epoch.binding.canonical_server_origin,
            user_id: epoch.binding.user_id,
        })
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
        if state.token != lease_token || state.directory_complete {
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
        if let Some(request) = state.outstanding_directory_request.as_ref() {
            return Ok(MobileDirectRestRequest {
                request_token: request.token.clone(),
                request_target: request.target.clone(),
            });
        }
        let request = MobileDirectOutstandingRequest {
            token: new_mobile_sync_token(),
            target: mobile_direct_directory_target(state.next_cursor.as_deref())?,
        };
        let result = MobileDirectRestRequest {
            request_token: request.token.clone(),
            request_target: request.target.clone(),
        };
        state.outstanding_directory_request = Some(request);
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
        if state.directory_complete {
            return Err(VeilError::Session {
                msg: "mobile Direct directory is already complete".to_string(),
            });
        }
        if state
            .outstanding_directory_request
            .as_ref()
            .is_none_or(|request| request.token != request_token)
        {
            return Err(VeilError::Session {
                msg: "mobile Direct directory request is stale".to_string(),
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
        let mut client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;
        let page = veil_client::direct::install_authenticated_direct_directory_page_tracked(
            &mut client,
            &state.epoch.binding.canonical_server_origin,
            &state.epoch.binding.user_id,
            state.next_cursor.as_deref(),
            &mut state.history,
            &response,
        )
        .map_err(|msg| VeilError::Session { msg })?;
        let skipped_non_direct =
            page.skipped_non_direct
                .try_into()
                .map_err(|_| VeilError::Session {
                    msg: "mobile Direct skipped conversation count overflow".to_string(),
                })?;
        state.outstanding_directory_request = None;
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
        state.directory_complete = page.next_cursor.is_none();
        Ok(MobileDirectDirectoryPageData {
            conversations,
            next_cursor: page.next_cursor,
            skipped_non_direct,
            directory_complete: state.directory_complete,
        })
    }

    /// Install a peer bundle by the conversation route learned under this
    /// lease. Kotlin cannot substitute peer account keys.
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
        let state = sync.as_mut().ok_or_else(|| VeilError::Session {
            msg: "mobile Direct sync is unavailable".to_string(),
        })?;
        if state.token != lease_token || !state.directory_complete {
            return Err(VeilError::Session {
                msg: "mobile Direct sync lease is stale or directory is incomplete".to_string(),
            });
        }
        let peer =
            state
                .peers
                .get(&conversation_id)
                .cloned()
                .ok_or_else(|| VeilError::Session {
                    msg: "Direct conversation is absent from the authenticated lease".to_string(),
                })?;
        let binding = self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })?;
        if binding.as_ref() != Some(&state.epoch) {
            return Err(VeilError::Session {
                msg: "mobile Direct sync lease is stale".to_string(),
            });
        }
        let client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;
        if client.has_session(&peer.identity_key) {
            return Err(VeilError::Session {
                msg: "Direct session is already established".to_string(),
            });
        }
        if let Some(request) = state.outstanding_prekey_requests.get(&conversation_id) {
            return Ok(MobileDirectRestRequest {
                request_token: request.token.clone(),
                request_target: request.target.clone(),
            });
        }
        let request = MobileDirectOutstandingRequest {
            token: new_mobile_sync_token(),
            target: format!("/v1/prekeys/{}", hex::encode(peer.identity_key)),
        };
        let result = MobileDirectRestRequest {
            request_token: request.token.clone(),
            request_target: request.target.clone(),
        };
        state
            .outstanding_prekey_requests
            .insert(conversation_id, request);
        Ok(result)
    }

    pub fn install_direct_prekey_bundle(
        &self,
        lease_token: String,
        request_token: String,
        conversation_id: String,
        response: Vec<u8>,
    ) -> Result<MobileDirectPreKeyResult, VeilError> {
        require_mobile_sync_token(&lease_token)?;
        require_mobile_sync_token(&request_token)?;
        require_canonical_user_id("Direct conversation ID", &conversation_id)?;
        let mut sync = self
            .direct_sync
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile Direct sync: {error}"),
            })?;
        let state = sync.as_mut().ok_or_else(|| VeilError::Session {
            msg: "mobile Direct sync is unavailable".to_string(),
        })?;
        if state.token != lease_token || !state.directory_complete {
            return Err(VeilError::Session {
                msg: "mobile Direct sync lease is stale or directory is incomplete".to_string(),
            });
        }
        let peer =
            state
                .peers
                .get(&conversation_id)
                .cloned()
                .ok_or_else(|| VeilError::Session {
                    msg: "Direct conversation is absent from the authenticated lease".to_string(),
                })?;
        if state
            .outstanding_prekey_requests
            .get(&conversation_id)
            .is_none_or(|request| request.token != request_token)
        {
            return Err(VeilError::Session {
                msg: "mobile Direct prekey request is stale".to_string(),
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
        let mut client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;
        let result = veil_client::direct::install_authenticated_direct_prekey_bundle(
            &mut client,
            &peer.user_id,
            peer.identity_key,
            peer.signing_key,
            &response,
        )
        .map_err(|msg| VeilError::Session { msg })?;
        state.outstanding_prekey_requests.remove(&conversation_id);
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

    pub fn sign_rest_request(
        &self,
        canonical_server_origin: String,
        method: String,
        request_target: String,
        body: Vec<u8>,
    ) -> Result<RestSignatureData, VeilError> {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let origin = require_canonical_server_origin(&canonical_server_origin)?;
        let epoch = self.authenticated_epoch()?;
        if epoch.binding.canonical_server_origin != origin {
            return Err(VeilError::Session {
                msg: "REST origin differs from the authenticated mobile binding".to_string(),
            });
        }
        let method = require_rest_method(&method)?;
        require_rest_target(&request_target)?;
        if body.len() > 64 * 1024 {
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
            "veil-rest-v1\n{method}\n{authority}\n{request_target}\n{timestamp_ms}\n{}",
            hex::encode(Sha256::digest(&body)),
        );
        let signature = self
            .client
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile client: {error}"),
            })?
            .sign_message(canonical.as_bytes())
            .map_err(|msg| VeilError::Session { msg })?;
        // Re-check after signing so a concurrent disconnect cannot publish a
        // signature from an invalidated account/origin epoch.
        if self.authenticated_epoch()? != epoch {
            return Err(VeilError::Session {
                msg: "mobile binding changed while signing REST request".to_string(),
            });
        }
        Ok(RestSignatureData {
            user_id: epoch.binding.user_id,
            timestamp_ms: timestamp_ms.to_string(),
            signature_base64: base64::engine::general_purpose::STANDARD.encode(signature),
        })
    }

    pub fn disconnect(&self) -> Result<(), VeilError> {
        clear_mobile_direct_sync_fail_closed(&self.direct_sync);
        let _client = invalidate_mobile_session(&self.binding, &self.client)?;
        Ok(())
    }
}

impl VeilMobileSession {
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
    use base64::Engine;
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
        let token = "ab".repeat(32);
        (
            VeilMobileSession {
                client: Mutex::new(client),
                runtime,
                binding: Mutex::new(Some(epoch.clone())),
                direct_sync: Mutex::new(Some(MobileDirectSyncState {
                    token: token.clone(),
                    epoch,
                    next_cursor: None,
                    directory_complete: false,
                    history: veil_client::direct::DirectDirectorySyncHistory::default(),
                    peers: HashMap::new(),
                    outstanding_directory_request: None,
                    outstanding_prekey_requests: HashMap::new(),
                })),
                next_binding_generation: AtomicU64::new(generation),
                last_rest_timestamp_ms: AtomicI64::new(0),
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
    fn mobile_direct_sync_installs_only_under_its_object_bound_random_lease() {
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
        let prekey_request = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        assert_eq!(
            prekey_request.request_target,
            format!("/v1/prekeys/{}", hex::encode(peer.x25519_public_bytes()))
        );
        let repeated_request = session
            .prepare_direct_prekey_request(token.clone(), conversation_id.clone())
            .unwrap();
        assert_eq!(repeated_request.request_token, prekey_request.request_token);

        let peer_identity = peer.x25519_public_bytes();
        let peer_signing = peer.ed25519_public_bytes();
        let mut peer_client = veil_client::api::VeilClient::from_identity(peer);
        let prekeys = peer_client.generate_prekeys().unwrap();
        let (one_time_prekey, one_time_prekey_id) = prekeys.otk_publics[0];
        let b64 = base64::engine::general_purpose::STANDARD;
        let prekey_response = serde_json::to_vec(&serde_json::json!({
            "identity_key": b64.encode(peer_identity),
            "signing_key": b64.encode(peer_signing),
            "signed_prekey": b64.encode(prekeys.spk_public),
            "signed_prekey_signature": b64.encode(prekeys.spk_signature),
            "signed_prekey_id": prekeys.spk_id,
            "one_time_prekey": b64.encode(one_time_prekey),
            "one_time_prekey_id": one_time_prekey_id,
        }))
        .unwrap();
        assert!(session
            .install_direct_prekey_bundle(
                token.clone(),
                new_mobile_sync_token(),
                conversation_id.clone(),
                prekey_response.clone(),
            )
            .unwrap_err()
            .to_string()
            .contains("request is stale"));
        let installed = session
            .install_direct_prekey_bundle(
                token.clone(),
                prekey_request.request_token,
                conversation_id.clone(),
                prekey_response,
            )
            .unwrap();
        assert_eq!(installed.status, "established");
        assert!(session.client.lock().unwrap().has_session(&peer_identity));
        assert!(session
            .prepare_direct_prekey_request(token.clone(), conversation_id)
            .unwrap_err()
            .to_string()
            .contains("already established"));

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
