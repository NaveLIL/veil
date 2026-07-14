use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use veil_crypto::kdf;
use veil_crypto::keys::{generate_mnemonic, validate_mnemonic, IdentityKeyPair};
use veil_crypto::ratchet::{MessageHeader, RatchetSession};
use veil_crypto::sender_key::{SenderKeyDistribution, SenderKeyStore};
use veil_crypto::x3dh;
use veil_search::Indexer;
use veil_store::db::{
    DeviceBindingPinV1, DeviceRosterSnapshotV1, HistoricalDeviceBindingProofV1,
    IncomingSenderKeyRouteV1, LocalPreKey, PendingSenderKeyDeviceEnvelopeV1, VeilDb,
};
use veil_store::models::{
    AccountSnapshot, ConversationType, MessageAuthorContext, RemoteMessageStateKind, RemoteReaction,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::connection::{ConfirmedMutation, Connection, ConnectionConfig, ConnectionEvent};
use crate::device_identity::{
    device_binding_signing_bytes, DeviceIdentityV1, DEVICE_BINDING_STATUS_ACTIVE,
    REQUIRED_DEVICE_CAPABILITIES,
};
use crate::protocol::proto;

// Wire header type tags
const HEADER_INITIAL: u8 = 0x01; // X3DH init + ratchet header
const HEADER_RATCHET: u8 = 0x02; // Ratchet header only
const HEADER_SENDER_KEY: u8 = 0x05; // Group/channel sender-key encrypted message

// Inner type bytes (inside ratchet-decrypted plaintext for pairwise channel)
const INNER_TEXT: u8 = 0x00; // UTF-8 text message
const INNER_SKDM: u8 = 0x01; // Sender Key Distribution Message (JSON)
const RATCHET_AD_DOMAIN: &[u8] = b"veil-ratchet-message-v1";
const MAX_PLAINTEXT_BYTES: usize = 32 * 1024;
const DEVICE_ROSTER_COMMITMENT_DOMAIN: &[u8] = b"veil-conversation-device-roster-v1\0";

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
struct PendingInitialHeader {
    ephemeral_public: [u8; 32],
    signed_prekey_id: u32,
    one_time_prekey_id: Option<u32>,
}

#[derive(Clone)]
struct PendingOutgoingMessage {
    local_message_id: String,
    conversation_id: String,
    sender_identity_key: [u8; 32],
    plaintext: String,
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
    envelope_commitment: [u8; 32],
}

struct ReceiveCryptoSnapshot {
    ratchet_sessions: HashMap<[u8; 32], RatchetSession>,
    otk_secrets: HashMap<u32, [u8; 32]>,
    sender_keys: SenderKeyStore,
    channel_conversations: HashSet<String>,
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
        self.sender_keys = SenderKeyStore::new();
    }
}

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
pub enum MessageSecurityContextV1 {
    SenderKeyV5(SenderKeyMessageSecurityContextV1),
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

/// Main client API — the single entry point for all UI interactions.
///
/// All methods are synchronous from the caller's perspective.
/// Crypto operations happen in Rust, never exposed to UI layer.
pub struct VeilClient {
    identity: Option<IdentityKeyPair>,
    /// Independent per-install keypair loaded only after SQLCipher unlock.
    /// It is deliberately not exposed through the renderer-facing API.
    device_identity: Option<DeviceIdentityV1>,
    db: Option<VeilDb>,
    connection: Option<Connection>,
    /// Non-control events observed while installing the authenticated retained
    /// SKDM barrier are replayed to the normal live dispatcher afterwards.
    deferred_connection_events: VecDeque<ConnectionEvent>,
    /// Server-assigned UUID from the authenticated WebSocket session.
    authenticated_user_id: Option<String>,
    device_id: [u8; 16],
    /// Active ratchet sessions keyed by peer identity key (X25519 public).
    ratchet_sessions: HashMap<[u8; 32], RatchetSession>,
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
            otk_secrets: self.otk_secrets.clone(),
            sender_keys: self.sender_keys.clone(),
            channel_conversations: self.channel_conversations.clone(),
            pending_initial_headers: self.pending_initial_headers.clone(),
            pending_initial_sequences: self.pending_initial_sequences.clone(),
        }
    }

    fn restore_receive_crypto(&mut self, mut snapshot: ReceiveCryptoSnapshot) {
        self.ratchet_sessions = std::mem::take(&mut snapshot.ratchet_sessions);
        self.otk_secrets = std::mem::take(&mut snapshot.otk_secrets);
        self.sender_keys = std::mem::replace(&mut snapshot.sender_keys, SenderKeyStore::new());
        self.channel_conversations = std::mem::take(&mut snapshot.channel_conversations);
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
            deferred_connection_events: VecDeque::new(),
            authenticated_user_id: None,
            device_id,
            ratchet_sessions: HashMap::new(),
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
            deferred_connection_events: VecDeque::new(),
            authenticated_user_id: None,
            device_id,
            ratchet_sessions: HashMap::new(),
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
            indexer: None,
        }
    }

    /// Attach a local search index. Subsequent message inserts/edits/deletes
    /// will be mirrored into it on a best-effort basis.
    pub fn set_indexer(&mut self, indexer: Arc<Indexer>) {
        self.indexer = Some(indexer);
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
            match prekey.key_type {
                0 => {
                    self.spk_secrets
                        .insert(prekey.protocol_key_id, (secret, prekey.public_key));
                }
                1 => {
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
        self.spk_next_id = db
            .max_local_prekey_id(0)?
            .checked_add(1)
            .ok_or_else(|| "signed prekey id exhausted".to_string())?;
        self.otk_next_id = db
            .max_local_prekey_id(1)?
            .checked_add(1)
            .ok_or_else(|| "one-time prekey id exhausted".to_string())?;
        self.trusted_signing_keys = db.load_trusted_signing_keys()?.into_iter().collect();

        // Restore ratchet material, but never publish bare conversation UUID
        // routing before an authenticated origin directory is selected. Sync
        // rebinds only conversations accepted for the current origin.
        self.dm_conversations.clear();
        self.authorized_conversation_senders.clear();
        self.ratchet_sessions.clear();
        self.pending_initial_headers.clear();
        self.pending_initial_sequences.clear();
        for conversation in db.get_conversations()? {
            if let Some(peer) = conversation.peer_identity_key {
                if let Ok(peer) = <[u8; 32]>::try_from(peer.as_slice()) {
                    if let Ok(Some(data)) = db.load_ratchet_session(&peer) {
                        let data = Zeroizing::new(data);
                        if let Ok(session) = serde_json::from_slice::<RatchetSession>(&data) {
                            self.ratchet_sessions.insert(peer, session);
                        }
                    }
                }
            }
        }
        for (peer, header_data) in db.load_pending_initial_headers()? {
            let header: PendingInitialHeader = serde_json::from_slice(&header_data)
                .map_err(|e| format!("decode pending X3DH header: {e}"))?;
            if header.ephemeral_public == [0u8; 32] || header.signed_prekey_id == 0 {
                return Err("invalid persisted pending X3DH header".to_string());
            }
            if let std::collections::hash_map::Entry::Vacant(entry) =
                self.ratchet_sessions.entry(peer)
            {
                let data = db
                    .load_ratchet_session(&peer)?
                    .ok_or("pending X3DH header has no ratchet session")?;
                let data = Zeroizing::new(data);
                let session = serde_json::from_slice::<RatchetSession>(&data)
                    .map_err(|e| format!("decode pending initiator ratchet: {e}"))?;
                entry.insert(session);
            }
            self.pending_initial_headers.insert(peer, header);
        }

        self.device_identity = Some(device_identity);
        self.identity = Some(identity);
        self.db = Some(db);
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

    /// Stable device key sent during WebSocket auth and used by the prekey API.
    pub fn device_id(&self) -> [u8; 16] {
        self.device_id
    }

    fn prepare_device_roster_v1(
        &self,
        candidate: &DeviceRosterCandidateV1,
    ) -> Result<PreparedDeviceRosterV1, String> {
        const LEGACY_UNBOUND_STATUS: u8 = 4;
        if !candidate.ready {
            return Err("device roster is not ready for encrypted traffic".to_string());
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

    pub fn invalidate_device_roster_v1(&mut self, conversation_id: &str) {
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
        self.dm_conversations
            .insert(conversation_id.to_string(), peer_identity_key);
        Ok(())
    }

    /// Sign an arbitrary message with our Ed25519 identity key. Used for
    /// authenticating REST requests via the X-Veil-Signature header scheme.
    pub fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], String> {
        let id = self.identity.as_ref().ok_or("not initialized")?;
        Ok(veil_crypto::signature::sign(id, message))
    }

    // ─── Connection ──────────────────────────────────

    /// Connect to the Veil gateway server via WebSocket.
    /// Performs Ed25519 challenge-response authentication.
    /// Returns the server-assigned user_id (UUID).
    pub async fn connect(&mut self, server_url: &str) -> Result<String, String> {
        self.connect_with_client_metadata(server_url, "veil-desktop", "veil-desktop")
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
        if device_name.is_empty()
            || device_name.len() > 128
            || device_name.chars().any(|character| {
                character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
            })
        {
            return Err("device name is invalid".to_string());
        }
        if client_id.is_empty()
            || client_id.len() > 64
            || !client_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err("client id is invalid".to_string());
        }
        let identity = self.identity.as_ref().ok_or("not initialized")?;
        let device_identity = self
            .device_identity
            .as_ref()
            .ok_or("per-device identity is missing; unlock migration is required")?;
        let config = ConnectionConfig {
            server_url: server_url.to_string(),
        };

        let mut conn =
            Connection::connect(&config, identity, device_identity, device_name, client_id).await?;

        // Drain the Authenticated event to get user_id
        let user_id = match conn.events.try_recv() {
            Ok(ConnectionEvent::Authenticated { user_id }) => user_id,
            _ => String::new(),
        };

        if user_id.is_empty() {
            return Err("server authenticated without a user id".to_string());
        }

        // Sequence numbers restart for every WebSocket. Resolve all old
        // pending entries before installing the new connection so a new ACK
        // can never confirm an unrelated pre-reconnect message or mutation.
        self.mark_all_pending_sequences_unknown()?;
        // REST backlog is authoritative for anything not processed from the
        // previous socket. Never replay its deferred events in the new epoch.
        self.deferred_connection_events.clear();
        self.authenticated_user_id = Some(user_id.clone());
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
        self.deferred_connection_events.clear();
    }

    /// Install retained SKDMs that were authenticated before the WS AuthResult
    /// barrier. Call only after the signed conversation/member directory has
    /// been pinned and before decrypting REST history.
    pub fn process_retained_sender_keys_before_sync(
        &mut self,
    ) -> Result<RetainedSenderKeyProcessReportV1, String> {
        let mut retained = Vec::new();
        let mut live = Vec::new();
        if let Some(connection) = self.connection.as_mut() {
            retained.extend(connection.retained_events.drain(..));
            // AuthResult is the protocol barrier. Everything in the live
            // channel arrived after it and must later pass the exact-current
            // live route checks, even when SenderKeyDist is the first event.
            while let Ok(event) = connection.events.try_recv() {
                live.push(event);
            }
        }
        self.process_retained_and_defer_live_events_v1(retained, live)
    }

    fn process_retained_and_defer_live_events_v1(
        &mut self,
        retained: Vec<ConnectionEvent>,
        live: Vec<ConnectionEvent>,
    ) -> Result<RetainedSenderKeyProcessReportV1, String> {
        self.deferred_connection_events.extend(live);
        self.process_retained_sender_key_events_v1(retained)
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
    pub fn buffer_connection_events_during_sync(&mut self) -> usize {
        let mut buffered = 0usize;
        if let Some(connection) = self.connection.as_mut() {
            while let Ok(event) = connection.events.try_recv() {
                self.deferred_connection_events.push_back(event);
                buffered += 1;
            }
        }
        buffered
    }

    /// Poll for the next incoming event from the server.
    /// Returns None if no event is available (non-blocking).
    pub async fn poll_event(&mut self) -> Result<Option<ConnectionEvent>, String> {
        let mut event = if let Some(event) = self.deferred_connection_events.pop_front() {
            Some(event)
        } else if let Some(ref mut conn) = self.connection {
            conn.events.try_recv().ok()
        } else {
            None
        };
        match event.as_mut() {
            Some(ConnectionEvent::MessageAcked {
                message_id,
                server_timestamp,
                ref_seq,
                local_message_id,
                mutation,
                sender_key,
            }) => {
                *local_message_id =
                    self.finalize_outgoing_message(*ref_seq, message_id, *server_timestamp)?;
                *mutation = self.confirm_pending_mutation(*ref_seq, *server_timestamp)?;
                self.confirm_initial_message(*ref_seq)?;
                self.confirm_sender_key_distribution(*ref_seq, sender_key.as_ref())?;
            }
            Some(ConnectionEvent::Error {
                code,
                ref_seq: Some(ref_seq),
                local_message_id,
                conversation_id,
                stale_roster_context,
                ..
            }) => {
                let pending_conversation = self
                    .pending_sender_key_sequences
                    .get(ref_seq)
                    .map(|pending| pending.conversation_id.clone())
                    .or_else(|| {
                        self.pending_outgoing_messages
                            .get(ref_seq)
                            .map(|pending| pending.conversation_id.clone())
                    });
                if *code == 409 {
                    if let Some(pending_conversation) = pending_conversation.as_ref() {
                        if self.channel_conversations.contains(pending_conversation) {
                            self.invalidate_device_roster_v1(pending_conversation);
                            *conversation_id = Some(pending_conversation.clone());
                            *stale_roster_context = true;
                        }
                    }
                }
                *local_message_id = self.reject_pending_sequence(*ref_seq)?;
            }
            Some(ConnectionEvent::Disconnected { reason }) => {
                // There can be no trustworthy delivery conclusion once the
                // socket epoch ends: a frame may have reached the gateway and
                // only its ACK may have been lost. Preserve every local row as
                // DeliveryUnknown instead of deleting it or inviting a blind
                // retry that could duplicate the message.
                self.connection = None;
                if let Err(error) = self.mark_all_pending_sequences_unknown() {
                    // The transport terminal event must still reach the UI so
                    // it stops claiming that the socket is connected. Keep
                    // the pending maps for a fail-closed retry before the next
                    // connect; startup recovery is the final fallback.
                    reason.push_str(&format!(
                        "; local delivery-state persistence failed: {error}"
                    ));
                }
            }
            _ => {}
        }
        Ok(event)
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
            db.mark_outgoing_messages_unknown(&local_message_ids)?;
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

    fn finalize_outgoing_message(
        &mut self,
        sequence: u64,
        server_message_id: &str,
        server_timestamp: u64,
    ) -> Result<Option<String>, String> {
        let Some(pending) = self.pending_outgoing_messages.get(&sequence).cloned() else {
            return Ok(None);
        };
        if server_message_id.is_empty() {
            return Err("message ACK is missing the server message id".to_string());
        }
        let timestamp_ms = i64::try_from(server_timestamp / 1_000_000)
            .map_err(|_| "server message timestamp exceeds i64".to_string())?;
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
        let Some(peer_identity_key) = self.pending_initial_sequences.get(&sequence).copied() else {
            return Ok(());
        };
        if let (Some(db), Some(session)) = (
            self.db.as_ref(),
            self.ratchet_sessions.get(&peer_identity_key),
        ) {
            let data = Zeroizing::new(
                serde_json::to_vec(session)
                    .map_err(|e| format!("serialize acknowledged ratchet session: {e}"))?,
            );
            db.save_ratchet_session(&peer_identity_key, &data)?;
        }
        // A server ACK proves durable transport only, not that the peer can
        // derive this X3DH session. Keep attaching the initial metadata until
        // an authenticated inbound DM proves peer possession.
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
        let Some(mutation) = self.pending_mutations.get(&sequence).cloned() else {
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

        if let Some(ConfirmedMutation::Edit { new_text, .. }) =
            self.pending_mutations.remove(&sequence).as_mut()
        {
            new_text.zeroize();
        }
        Ok(Some(mutation))
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
        if plaintext.is_empty() && attachments.is_empty() {
            return Err("message plaintext must not be empty".to_string());
        }
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(format!(
                "message plaintext exceeds {MAX_PLAINTEXT_BYTES} bytes"
            ));
        }
        if self.connection.is_none() {
            return Err("not connected".to_string());
        }
        let (encrypted_plaintext, wire_attachments, stored_attachments) =
            if attachments.is_empty() {
                (
                    Zeroizing::new(plaintext.to_string()),
                    Vec::new(),
                    Vec::new(),
                )
            } else {
                let (payload, wire, stored) =
                    crate::attachments::build_outgoing_attachment_message_v1(
                        conversation_id,
                        plaintext,
                        attachments,
                    )?;
                (
                    Zeroizing::new(String::from_utf8(payload.to_vec()).map_err(|_| {
                        "attachment payload is not valid protocol UTF-8".to_string()
                    })?),
                    wire,
                    stored,
                )
            };
        let seq = self
            .connection
            .as_ref()
            .ok_or("not connected")?
            .next_seq()
            .await;

        // Encrypt first (needs mutable borrow)
        let (ciphertext, header_bytes) =
            self.encrypt_outgoing(conversation_id, &encrypted_plaintext)?;
        let initial_peer = (header_bytes.first() == Some(&HEADER_INITIAL))
            .then(|| self.dm_conversations.get(conversation_id).copied())
            .flatten();
        let our_key = self.identity_key()?;
        let local_message_id = uuid::Uuid::new_v4().to_string();
        let local_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch".to_string())?
            .as_millis()
            .try_into()
            .map_err(|_| "local message timestamp exceeds i64".to_string())?;

        if let Some(db) = self.db.as_ref() {
            db.insert_outgoing_pending_message_with_attachments(
                &local_message_id,
                conversation_id,
                &our_key,
                plaintext,
                reply_to_id,
                &stored_attachments,
            )?;
            match db.resolve_account_by_conversation_sender(conversation_id, &our_key) {
                Ok(Some(author_snapshot)) => {
                    if let Err(error) =
                        db.attach_message_author(&local_message_id, &author_snapshot)
                    {
                        db.mark_outgoing_message_failed(&local_message_id)?;
                        return Err(format!(
                            "persist outgoing message author attribution: {error}"
                        ));
                    }
                }
                Ok(None) => {
                    // Legacy unscoped conversations remain usable; their own
                    // messages are still rendered as `You`, without inventing
                    // an origin or account locator.
                }
                Err(error) => {
                    db.mark_outgoing_message_failed(&local_message_id)?;
                    return Err(format!(
                        "resolve outgoing message author attribution: {error}"
                    ));
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
                        db.mark_outgoing_message_failed(&local_message_id)?;
                    }
                    let _ = indexer.delete(&local_message_id);
                    return Err(format!("index pending outgoing message: {error}"));
                }
            }
        }

        let roster_proof = if self.channel_conversations.contains(conversation_id) {
            let roster = self
                .device_rosters
                .get(conversation_id)
                .ok_or("validated current device roster is unavailable")?;
            Some((roster.version, roster.commitment))
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
            roster_version: roster_proof.map_or(0, |proof| proof.0),
            roster_commitment: roster_proof.map_or_else(Vec::new, |proof| proof.1.to_vec()),
        };

        let env = proto::Envelope {
            seq,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::SendMessage(send_msg)),
        };

        if let Err(error) = self
            .connection
            .as_ref()
            .ok_or("not connected")?
            .send_envelope(&env)
            .await
        {
            if let Some(db) = self.db.as_ref() {
                db.mark_outgoing_message_failed(&local_message_id)?;
            } else if let Some(indexer) = self.indexer.as_ref() {
                let _ = indexer.delete(&local_message_id);
            }
            return Err(error);
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
            },
        );

        Ok(seq)
    }

    /// Check if we're connected to the server.
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    // ─── E2E Encryption ──────────────────────────────────

    /// Generate prekeys for X3DH. Call after identity init, upload result to server.
    pub fn generate_prekeys(&mut self) -> Result<PreKeySet, String> {
        let identity = self.identity.as_ref().ok_or("not initialized")?;

        let spk_id = self.spk_next_id;
        self.spk_next_id = self
            .spk_next_id
            .checked_add(1)
            .ok_or_else(|| "signed prekey id exhausted".to_string())?;
        let spk = x3dh::SignedPreKey::generate(identity, spk_id);
        let spk_pub = *spk.public.as_bytes();
        let spk_sig = spk.signature;
        let spk_secret = spk.secret.to_bytes();

        self.spk_secrets.insert(spk_id, (spk_secret, spk_pub));

        let mut otk_publics = Vec::new();
        let mut local_prekeys = Vec::with_capacity(21);
        local_prekeys.push(LocalPreKey {
            key_type: 0,
            protocol_key_id: spk_id,
            secret_key: spk_secret,
            public_key: spk_pub,
            signature: Some(spk_sig),
        });
        let next_otk_id = self
            .otk_next_id
            .checked_add(20)
            .ok_or_else(|| "one-time prekey id exhausted".to_string())?;
        for i in 0..20u32 {
            let id = self
                .otk_next_id
                .checked_add(i)
                .ok_or_else(|| "one-time prekey id exhausted".to_string())?;
            let otk = x3dh::OneTimePreKey::generate(id);
            let pub_bytes = *otk.public.as_bytes();
            let secret_bytes = otk.secret.to_bytes();
            self.otk_secrets.insert(id, secret_bytes);
            otk_publics.push((pub_bytes, id));
            local_prekeys.push(LocalPreKey {
                key_type: 1,
                protocol_key_id: id,
                secret_key: secret_bytes,
                public_key: pub_bytes,
                signature: None,
            });
        }
        if let Some(db) = self.db.as_ref() {
            db.save_local_prekeys(&local_prekeys)?;
        }
        self.otk_next_id = next_otk_id;

        Ok(PreKeySet {
            spk_public: spk_pub,
            spk_id,
            spk_signature: spk_sig,
            signing_key: identity.ed25519_public_bytes(),
            otk_publics,
        })
    }

    /// Initiate X3DH with a peer's prekey bundle, create ratchet session.
    pub fn establish_session(
        &mut self,
        peer_identity_key: &[u8; 32],
        bundle: &x3dh::PreKeyBundle,
    ) -> Result<(), String> {
        let identity = self.identity.as_ref().ok_or("not initialized")?;
        let result = x3dh::initiate(identity, bundle)?;

        let session = RatchetSession::init_initiator(&result.shared_secret, &bundle.signed_prekey);

        // The first encrypted message must carry the X3DH metadata so the
        // responder can derive the same ratchet session before decryption.
        let pending_header = PendingInitialHeader {
            ephemeral_public: result.ephemeral_public,
            signed_prekey_id: bundle.signed_prekey_id,
            one_time_prekey_id: bundle.one_time_prekey_id,
        };
        if let Some(db) = self.db.as_ref() {
            let session_data = Zeroizing::new(
                serde_json::to_vec(&session)
                    .map_err(|e| format!("serialize initiator ratchet session: {e}"))?,
            );
            let header_data = serde_json::to_vec(&pending_header)
                .map_err(|e| format!("serialize pending X3DH header: {e}"))?;
            db.save_initiator_session(peer_identity_key, &session_data, &header_data)?;
        }
        self.pending_initial_headers
            .insert(*peer_identity_key, pending_header);
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
        let session =
            self.build_responder_session(sender_identity_key, ephemeral_key, spk_id, opk_id)?;

        if let Some(db) = self.db.as_ref() {
            let data = Zeroizing::new(
                serde_json::to_vec(&session)
                    .map_err(|e| format!("serialize initial ratchet session: {e}"))?,
            );
            db.commit_initial_ratchet_session(sender_identity_key, &data, opk_id)?;
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
        Ok(RatchetSession::init_responder(
            &result.shared_secret,
            &spk_secret_bytes,
            &spk_pub,
        ))
    }

    /// Check if a ratchet session exists with a peer.
    pub fn has_session(&self, peer_identity_key: &[u8; 32]) -> bool {
        self.ratchet_sessions.contains_key(peer_identity_key)
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
        if self.channel_conversations.contains(conversation_id) {
            if self
                .sender_key_distribution_pending
                .contains(conversation_id)
            {
                return Err(
                    "sender-key distribution is incomplete; channel send is blocked".to_string(),
                );
            }
            // Creating a fresh generation is itself a distribution event. It
            // must never fall through to encryption in the same call: no
            // recipient has durably received that generation yet. Keeping the
            // pending flag set also makes retries distribute this exact state
            // instead of rotating again.
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
            return Ok((ct, vec![HEADER_SENDER_KEY]));
        }

        // No automatic pairwise lookup yet — callers use `encrypt_for` directly
        // when they know the peer identity key.
        let peer_identity_key = self
            .dm_conversations
            .get(conversation_id)
            .copied()
            .ok_or_else(|| {
                format!(
                    "E2E session unavailable: conversation {conversation_id} is not bound to a peer"
                )
            })?;
        let inner = Self::wrap_text_inner(plaintext);
        self.encrypt_for_conversation(&peer_identity_key, conversation_id, &inner)
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

    fn encrypt_for_conversation(
        &mut self,
        peer_identity_key: &[u8; 32],
        conversation_id: &str,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let our_identity_key = self.identity_key()?;
        let pending = self.pending_initial_headers.get(peer_identity_key).copied();
        let mut wire_prefix = Vec::with_capacity(1 + 32 + 4 + 4);
        if let Some(initial) = pending {
            wire_prefix.push(HEADER_INITIAL);
            wire_prefix.extend_from_slice(&initial.ephemeral_public);
            wire_prefix.extend_from_slice(&initial.signed_prekey_id.to_be_bytes());
            wire_prefix
                .extend_from_slice(&initial.one_time_prekey_id.unwrap_or(u32::MAX).to_be_bytes());
        } else {
            wire_prefix.push(HEADER_RATCHET);
        }
        let associated_data = ratchet_associated_data(
            conversation_id,
            &our_identity_key,
            peer_identity_key,
            &wire_prefix,
        )?;
        let mut candidate = self
            .ratchet_sessions
            .get(peer_identity_key)
            .cloned()
            .ok_or("no ratchet session with this peer")?;

        let (ratchet_header, ciphertext) =
            candidate.encrypt_with_ad(plaintext, &associated_data)?;
        let rh_bytes = ratchet_header.to_bytes();

        // Every message carries the same X3DH metadata until an authenticated
        // inbound DM proves peer possession. Thus a deleted/missed first
        // offline packet does not make all subsequent ratchet packets opaque.
        let mut header = wire_prefix;
        header.extend_from_slice(&rh_bytes);

        // Persist before the packet can reach the transport. Reusing a message
        // key after an ACK-loss/crash would be worse than skipping an unsent
        // chain step, which Double Ratchet is designed to tolerate.
        if let Some(ref db) = self.db {
            let data = Zeroizing::new(
                serde_json::to_vec(&candidate)
                    .map_err(|e| format!("serialize ratchet session: {e}"))?,
            );
            db.save_ratchet_session(peer_identity_key, &data)?;
        }
        self.ratchet_sessions.insert(*peer_identity_key, candidate);

        Ok((ciphertext, header))
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
        let MessageSecurityContextV1::SenderKeyV5(context) = security_context;
        let local = self
            .device_identity
            .as_ref()
            .ok_or("per-device identity is not initialized")?;
        if context.target_device_id != self.device_id {
            return Err("Sender-Key message targets another device".to_string());
        }
        let unverified = veil_crypto::sender_key::inspect_signed_sender_key_metadata(ciphertext)?;
        let local_account_identity = self.identity_key()?;
        let local_account_signing = self.signing_key()?;
        if *sender_account_identity_key == local_account_identity
            && context.sender_device_id == self.device_id
        {
            let roster = self
                .device_rosters
                .get(conversation_id)
                .filter(|roster| {
                    roster.version == context.roster_version
                        && roster.commitment == context.roster_commitment
                })
                .ok_or("self-authored Sender-Key message has no exact current roster proof")?;
            let current = roster
                .eligible_devices
                .get(&self.device_id)
                .ok_or("current device is absent from its installed roster")?;
            if current.device_identity_key != local.binding().device_identity_key
                || current.device_signing_key != local.binding().device_signing_key
                || current.account_signing_key != local_account_signing
                || current.binding_version != context.sender_binding_version
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
                    roster_version: context.roster_version,
                    roster_commitment: context.roster_commitment,
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
                target_device_id: context.target_device_id,
                message_roster_version: context.roster_version,
                message_roster_commitment: context.roster_commitment,
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
            || route.sender_device_id != context.sender_device_id
            || route.sender_binding_version != context.sender_binding_version
            || route.target_device_id != context.target_device_id
            || route.target_device_id != self.device_id
            || route.target_binding_version == 0
            || route.target_binding_version > local.binding().version
            || route.roster_version != context.roster_version
            || route.roster_commitment != context.roster_commitment
        {
            return Err(
                "Sender-Key message security context does not match installed route".to_string(),
            );
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
        if header.is_empty() {
            // Network messages without an authenticated E2E header are a
            // downgrade attempt (or unsupported legacy data), not plaintext.
            return Err("rejected unencrypted message: missing E2E header".to_string());
        }

        match header[0] {
            HEADER_INITIAL => {
                // Parse X3DH init header
                if header.len() != 1 + 32 + 4 + 4 + 41 {
                    return Err(format!(
                        "invalid initial header length: expected 82, got {}",
                        header.len()
                    ));
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

                let rh = MessageHeader::from_bytes(&header[41..82])?;
                let our_identity_key = self.identity_key()?;
                let associated_data = ratchet_associated_data(
                    conversation_id,
                    sender_identity_key,
                    &our_identity_key,
                    &header[..41],
                )?;
                let plaintext = if self.has_session(sender_identity_key) {
                    let mut candidate = self
                        .ratchet_sessions
                        .get(sender_identity_key)
                        .cloned()
                        .ok_or("session lookup failed")?;
                    let plaintext = candidate.decrypt_with_ad(&rh, ciphertext, &associated_data)?;
                    if let Some(db) = self.db.as_ref() {
                        let data = Zeroizing::new(
                            serde_json::to_vec(&candidate)
                                .map_err(|e| format!("serialize ratchet session: {e}"))?,
                        );
                        db.save_ratchet_session(sender_identity_key, &data)?;
                    }
                    self.ratchet_sessions
                        .insert(*sender_identity_key, candidate);
                    plaintext
                } else {
                    // Do not consume the OPK or install/persist a responder
                    // session until the first packet authenticates successfully.
                    let mut candidate =
                        self.build_responder_session(sender_identity_key, &ek, spk_id, opk_id)?;
                    let plaintext = candidate.decrypt_with_ad(&rh, ciphertext, &associated_data)?;
                    if let Some(db) = self.db.as_ref() {
                        let data = Zeroizing::new(
                            serde_json::to_vec(&candidate)
                                .map_err(|e| format!("serialize initial ratchet session: {e}"))?,
                        );
                        db.commit_initial_ratchet_session(sender_identity_key, &data, opk_id)?;
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

                self.process_ratchet_plaintext(sender_identity_key, plaintext)
            }
            HEADER_RATCHET => {
                if header.len() != 1 + 41 {
                    return Err(format!(
                        "invalid ratchet header length: expected 42, got {}",
                        header.len()
                    ));
                }
                let rh = MessageHeader::from_bytes(&header[1..])?;
                let our_identity_key = self.identity_key()?;
                let associated_data = ratchet_associated_data(
                    conversation_id,
                    sender_identity_key,
                    &our_identity_key,
                    &header[..1],
                )?;
                let mut candidate = self
                    .ratchet_sessions
                    .get(sender_identity_key)
                    .cloned()
                    .ok_or("no ratchet session with this peer")?;
                let plaintext = candidate.decrypt_with_ad(&rh, ciphertext, &associated_data)?;

                if let Some(ref db) = self.db {
                    let data = Zeroizing::new(
                        serde_json::to_vec(&candidate)
                            .map_err(|e| format!("serialize ratchet session: {e}"))?,
                    );
                    db.save_ratchet_session(sender_identity_key, &data)?;
                }
                self.ratchet_sessions
                    .insert(*sender_identity_key, candidate);

                self.process_ratchet_plaintext(sender_identity_key, plaintext)
            }
            HEADER_SENDER_KEY => {
                let context = security_context
                    .ok_or("Sender-Key v5 message is missing persisted device security context")?;
                let (generation, route) = match self.validated_sender_key_route_for_message(
                    conversation_id,
                    sender_identity_key,
                    ciphertext,
                    context,
                )? {
                    ValidatedSenderKeyRouteForMessageV1::Verified { generation, route } => {
                        (generation, route)
                    }
                    ValidatedSenderKeyRouteForMessageV1::MissingExactRoute { .. } => {
                        return Err(
                            "trusted historical Sender-Key route is unavailable".to_string()
                        );
                    }
                };
                self.ensure_incoming_sender_key_loaded(
                    conversation_id,
                    &route.sender_device_identity_key,
                    generation,
                )?;
                let mut decrypted = self.sender_keys.decrypt_signed_with_metadata(
                    conversation_id,
                    &route.sender_device_identity_key,
                    &route.sender_device_signing_key,
                    ciphertext,
                )?;
                if decrypted.generation != generation {
                    return Err("sender-key generation changed during authenticated decrypt".into());
                }
                self.persist_incoming_sender_key(
                    conversation_id,
                    &route.sender_device_identity_key,
                    generation,
                )?;
                Ok(DecryptedPayload::Text(std::mem::take(
                    &mut *decrypted.plaintext,
                )))
            }
            _ => {
                // Unknown wire versions are never interpreted as plaintext.
                Err(format!(
                    "rejected message with unknown E2E header type {:#04x}",
                    header[0]
                ))
            }
        }
    }

    /// Strip the inner type byte from ratchet-decrypted plaintext.
    /// `0x00` = real text (return Text), `0x01` = SKDM (process and return Control).
    /// Unprefixed/unknown payloads are rejected to prevent inner-protocol
    /// downgrade after successful ratchet decryption.
    fn process_ratchet_plaintext(
        &mut self,
        sender_identity_key: &[u8; 32],
        plaintext: Vec<u8>,
    ) -> Result<DecryptedPayload, String> {
        let mut plaintext = Zeroizing::new(plaintext);
        if plaintext.is_empty() {
            return Err("ratchet plaintext is missing its inner type".to_string());
        }
        match plaintext[0] {
            INNER_TEXT => {
                plaintext.remove(0);
                Ok(DecryptedPayload::Text(std::mem::take(&mut *plaintext)))
            }
            INNER_SKDM => {
                let body = &plaintext[1..];
                let dist: SenderKeyDistribution =
                    serde_json::from_slice(body).map_err(|e| format!("decode SKDM: {e}"))?;
                // Only honour SKDMs whose declared sender matches the ratchet peer.
                if &dist.sender_identity_key != sender_identity_key {
                    return Err("SKDM sender mismatch".to_string());
                }
                let group_id = dist.group_id.clone();
                self.sender_keys.process_distribution(&dist)?;
                self.channel_conversations.insert(group_id.clone());
                self.sender_key_distribution_pending
                    .insert(group_id.clone());
                self.persist_incoming_sender_key(&group_id, sender_identity_key, dist.key_id)?;
                Ok(DecryptedPayload::Control)
            }
            _ => {
                // A valid ratchet frame must still carry a known inner type.
                Err(format!("unknown ratchet inner type {:#04x}", plaintext[0]))
            }
        }
    }

    /// Mark a conversation as a channel — outgoing messages will be encrypted
    /// with a sender key, and incoming messages will look up the sender key store.
    pub fn mark_channel_conversation(&mut self, conversation_id: &str) {
        self.channel_conversations
            .insert(conversation_id.to_string());
        if !self.sender_keys.has_outgoing(conversation_id) {
            self.sender_key_distribution_pending
                .insert(conversation_id.to_string());
        }
    }

    pub fn is_channel_conversation(&self, conversation_id: &str) -> bool {
        self.channel_conversations.contains(conversation_id)
    }

    pub fn replace_authorized_conversation_senders(
        &mut self,
        conversation_id: &str,
        senders: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<(), String> {
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
        self.failed_sender_key_distributions
            .insert(conversation_id.to_string());
        self.sender_key_distribution_pending
            .insert(conversation_id.to_string());
    }

    pub fn sender_key_distribution_status(&self, conversation_id: &str) -> &'static str {
        if self
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
                    envelope_commitment: cached.envelope_commitment,
                };
                if cached.target_account_identity_key != target.account_identity_key
                    || cached.target_device_identity_key != target.device_identity_key
                    || cached.sender_device_id != self.device_id
                    || cached.sender_device_identity_key != local.binding().device_identity_key
                    || cached.sender_binding_version != local.binding().version
                    || cached.roster_commitment != target.roster_commitment
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
        if self.dm_conversations.contains_key(&route.conversation_id) {
            return Err("sender keys are forbidden for DM conversations".to_string());
        }
        if !self.channel_conversations.contains(&route.conversation_id) {
            return Err(
                "sender-key conversation is not an authenticated group/channel".to_string(),
            );
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
        let mut sent = 0usize;
        while let Some(receipt) = self.pending_sender_key_receipts.front().cloned() {
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
        if message_id.is_empty() || conversation_id.is_empty() {
            return Err("inbound message and conversation ids must not be empty".to_string());
        }
        if header.is_empty() || ciphertext.is_empty() {
            return Err("inbound E2E header and ciphertext must not be empty".to_string());
        }
        if author_snapshot.is_some() != author_context.is_some() {
            return Err(
                "inbound author snapshot and observation context must be paired".to_string(),
            );
        }
        if !sender_key_mode && !self.trusted_signing_keys.contains_key(sender_identity_key) {
            return Err("inbound sender identity is not pinned to a signing key".to_string());
        }
        let wire_uses_sender_key = header.first() == Some(&HEADER_SENDER_KEY);
        if wire_uses_sender_key != sender_key_mode {
            return Err(
                "inbound E2E header conflicts with the pinned conversation type".to_string(),
            );
        }
        if sender_key_mode != security_context.is_some() {
            return Err(
                "inbound message security context conflicts with the conversation type".to_string(),
            );
        }
        if let Some(security_context) = security_context {
            self.validate_sender_key_message_context_v1(
                conversation_id,
                sender_identity_key,
                ciphertext,
                security_context,
            )?;
        }

        let crypto_snapshot = self.receive_crypto_snapshot();

        self.db
            .as_ref()
            .ok_or("database not initialized")?
            .begin_receive_savepoint()?;

        let operation = (|| {
            if self
                .db
                .as_ref()
                .ok_or("database not initialized")?
                .message_exists(message_id)?
            {
                if let (Some(author_snapshot), Some(author_context)) =
                    (author_snapshot, author_context)
                {
                    self.db
                        .as_ref()
                        .ok_or("database not initialized")?
                        .attach_message_author_with_context(
                            message_id,
                            author_snapshot,
                            author_context,
                        )?;
                }
                return Ok(ReceiveMessageResult::Duplicate);
            }
            self.db
                .as_ref()
                .ok_or("database not initialized")?
                .ensure_receive_conversation(
                    conversation_id,
                    sender_key_mode,
                    sender_identity_key,
                    fallback_conversation_name,
                )?;

            let decrypted = match self.decrypt_from_with_security_context(
                sender_identity_key,
                conversation_id,
                header,
                ciphertext,
                security_context,
            )? {
                DecryptedPayload::Text(plaintext) => plaintext,
                DecryptedPayload::Control => {
                    return Err(
                        "control frame is not valid on the chat message receive path".to_string(),
                    );
                }
            };
            let (plaintext, private_attachments) = if attachments.is_empty() {
                if crate::attachments::is_attachment_payload_v1(&decrypted) {
                    return Err(
                        "attachment payload has no authenticated public descriptors".to_string()
                    );
                }
                (
                    String::from_utf8(decrypted)
                        .map_err(|_| "inbound plaintext is not valid UTF-8".to_string())?,
                    Vec::new(),
                )
            } else {
                let opened = crate::attachments::open_attachment_message_v1(
                    conversation_id,
                    &decrypted,
                    attachments,
                )?;
                (opened.text, opened.attachments)
            };
            if !sender_key_mode {
                // Successful authenticated ratchet decryption is the first
                // evidence that the peer possesses this session. Clearing the
                // repeatable X3DH header participates in the same savepoint as
                // the message and ratchet-state commit.
                self.confirm_peer_session_possession(sender_identity_key)?;
            }
            self.db
                .as_ref()
                .ok_or("database not initialized")?
                .insert_message(
                    message_id,
                    conversation_id,
                    sender_identity_key,
                    &plaintext,
                    false,
                    server_timestamp,
                    reply_to_id,
                )?;
            self.db
                .as_ref()
                .ok_or("database not initialized")?
                .insert_message_attachments(message_id, &private_attachments)?;
            if let (Some(author_snapshot), Some(author_context)) = (author_snapshot, author_context)
            {
                self.db
                    .as_ref()
                    .ok_or("database not initialized")?
                    .attach_message_author_with_context(
                        message_id,
                        author_snapshot,
                        author_context,
                    )?;
            }
            if let Some(metadata) = remote_metadata {
                let db = self.db.as_ref().ok_or("database not initialized")?;
                db.record_remote_message_state(
                    message_id,
                    conversation_id,
                    sender_identity_key,
                    metadata.revision_ms,
                    RemoteMessageStateKind::Active,
                )?;
                if let Some(reactions) = metadata.reactions {
                    db.replace_message_reactions(message_id, reactions)?;
                }
            }
            Ok(ReceiveMessageResult::Stored { plaintext })
        })();

        let result = match operation {
            Ok(result) => {
                if let Err(commit_error) = self
                    .db
                    .as_ref()
                    .ok_or("database not initialized")?
                    .commit_receive_savepoint()
                {
                    let rollback_error = self
                        .db
                        .as_ref()
                        .and_then(|db| db.rollback_receive_savepoint().err());
                    self.restore_receive_crypto(crypto_snapshot);
                    return Err(match rollback_error {
                        Some(rollback_error) => format!(
                            "{commit_error}; receive rollback also failed: {rollback_error}"
                        ),
                        None => commit_error,
                    });
                }
                result
            }
            Err(error) => {
                let rollback_error = self
                    .db
                    .as_ref()
                    .and_then(|db| db.rollback_receive_savepoint().err());
                self.restore_receive_crypto(crypto_snapshot);
                return Err(match rollback_error {
                    Some(rollback_error) => {
                        format!("{error}; receive rollback also failed: {rollback_error}")
                    }
                    None => error,
                });
            }
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

    fn commit_remote_metadata_only(
        &self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        metadata: &RemoteMessageMetadata<'_>,
        state: RemoteMessageStateKind,
        delete_local: bool,
    ) -> Result<(), String> {
        let db = self.db.as_ref().ok_or("database not initialized")?;
        db.begin_receive_savepoint()?;
        let operation = (|| {
            if delete_local {
                db.delete_message_scoped(message_id, conversation_id)?;
            }
            db.record_remote_message_state(
                message_id,
                conversation_id,
                sender_identity_key,
                metadata.revision_ms,
                state,
            )?;
            if state == RemoteMessageStateKind::Active && db.message_exists(message_id)? {
                if let Some(reactions) = metadata.reactions {
                    db.replace_message_reactions(message_id, reactions)?;
                }
            } else {
                // Tombstones and ciphertext that is intentionally unavailable
                // must not leave reaction metadata for a message body we no
                // longer retain. The reactions table predates foreign keys, so
                // clear it explicitly rather than relying on message deletion.
                db.replace_message_reactions(message_id, &[])?;
            }
            Ok(())
        })();
        match operation {
            Ok(()) => db.commit_receive_savepoint(),
            Err(error) => {
                let rollback = db.rollback_receive_savepoint();
                Err(match rollback {
                    Ok(()) => error,
                    Err(rollback_error) => {
                        format!("{error}; remote metadata rollback failed: {rollback_error}")
                    }
                })
            }
        }
    }

    /// Reconcile server state that either needs no ciphertext or determines
    /// which atomic ciphertext path the caller must take next. Reaction rows
    /// are authoritative and replaced even when the content revision is equal.
    pub fn reconcile_remote_message_metadata(
        &self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        metadata: &RemoteMessageMetadata<'_>,
        state: RemoteMessageStateKind,
    ) -> Result<RemoteReconcileAction, String> {
        if metadata.revision_ms < 0 {
            return Err("remote message revision must not be negative".to_string());
        }
        let db = self.db.as_ref().ok_or("database not initialized")?;
        let binding = db.get_message_binding(message_id)?;
        if let Some((bound_conversation, bound_sender, _, _)) = binding.as_ref() {
            if bound_conversation != conversation_id
                || bound_sender.as_slice() != sender_identity_key
            {
                return Err("remote message conflicts with its local binding".to_string());
            }
        }
        let remote = db.get_remote_message_state(message_id)?;
        if let Some(remote) = remote.as_ref() {
            if remote.conversation_id != conversation_id
                || remote.sender_key.as_slice() != sender_identity_key
            {
                return Err("remote message UUID changed scope or sender".to_string());
            }
            if metadata.revision_ms < remote.revision_ms {
                return Err("remote message revision moved backwards".to_string());
            }
        }

        match state {
            RemoteMessageStateKind::Deleted | RemoteMessageStateKind::Expired => {
                self.commit_remote_metadata_only(
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
                self.commit_remote_metadata_only(
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
                        self.commit_remote_metadata_only(
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
                            return Err(
                                "remote message attempted same-revision resurrection".to_string()
                            );
                        }
                        self.commit_remote_metadata_only(
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
                            self.commit_remote_metadata_only(
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
        header: &[u8],
        ciphertext: &[u8],
        remote_metadata: Option<&RemoteMessageMetadata<'_>>,
    ) -> Result<String, String> {
        if sender_key_mode || self.channel_conversations.contains(conversation_id) {
            return Err(
                "encrypted group/channel edits are disabled until an exact device edit protocol exists"
                    .to_string(),
            );
        }
        if author_snapshot.is_some() != author_context.is_some() {
            return Err("edit author snapshot and observation context must be paired".to_string());
        }
        if !self.trusted_signing_keys.contains_key(sender_identity_key) {
            return Err("edit sender identity is not pinned to a signing key".to_string());
        }
        if header.is_empty()
            || ciphertext.is_empty()
            || (header.first() == Some(&HEADER_SENDER_KEY)) != sender_key_mode
        {
            return Err("edit E2E header conflicts with the conversation type".to_string());
        }
        let crypto_snapshot = self.receive_crypto_snapshot();
        self.db
            .as_ref()
            .ok_or("database not initialized")?
            .begin_receive_savepoint()?;
        let operation = (|| {
            self.db
                .as_ref()
                .ok_or("database not initialized")?
                .ensure_receive_conversation(
                    conversation_id,
                    sender_key_mode,
                    sender_identity_key,
                    None,
                )?;
            let plaintext = match self.decrypt_from(
                sender_identity_key,
                conversation_id,
                header,
                ciphertext,
            )? {
                DecryptedPayload::Text(plaintext) => String::from_utf8(plaintext)
                    .map_err(|_| "edited plaintext is not valid UTF-8".to_string())?,
                DecryptedPayload::Control => {
                    return Err("control frame is not valid as a message edit".to_string());
                }
            };
            if !sender_key_mode {
                self.confirm_peer_session_possession(sender_identity_key)?;
            }
            let db = self.db.as_ref().ok_or("database not initialized")?;
            db.update_incoming_message_text_scoped(
                message_id,
                conversation_id,
                sender_identity_key,
                &plaintext,
            )?;
            if let (Some(author_snapshot), Some(author_context)) = (author_snapshot, author_context)
            {
                db.attach_message_author_with_context(message_id, author_snapshot, author_context)?;
            }
            if let Some(metadata) = remote_metadata {
                db.record_remote_message_state(
                    message_id,
                    conversation_id,
                    sender_identity_key,
                    metadata.revision_ms,
                    RemoteMessageStateKind::Active,
                )?;
                if let Some(reactions) = metadata.reactions {
                    db.replace_message_reactions(message_id, reactions)?;
                }
            }
            Ok(plaintext)
        })();

        let plaintext = match operation {
            Ok(plaintext) => {
                if let Err(commit_error) = self
                    .db
                    .as_ref()
                    .ok_or("database not initialized")?
                    .commit_receive_savepoint()
                {
                    let rollback = self
                        .db
                        .as_ref()
                        .and_then(|db| db.rollback_receive_savepoint().err());
                    self.restore_receive_crypto(crypto_snapshot);
                    return Err(rollback.map_or(commit_error.clone(), |rollback| {
                        format!("{commit_error}; edit rollback also failed: {rollback}")
                    }));
                }
                plaintext
            }
            Err(error) => {
                let rollback = self
                    .db
                    .as_ref()
                    .and_then(|db| db.rollback_receive_savepoint().err());
                self.restore_receive_crypto(crypto_snapshot);
                return Err(rollback.map_or(error.clone(), |rollback| {
                    format!("{error}; edit rollback also failed: {rollback}")
                }));
            }
        };
        if let Some(indexer) = self.indexer.as_ref() {
            let _ = indexer.update_message_body(message_id, &plaintext);
        }
        Ok(plaintext)
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
        let initial_peer = (header_bytes.first() == Some(&HEADER_INITIAL))
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
        self.db
            .as_ref()
            .ok_or("database not initialized")?
            .get_reactions(message_id)
    }

    /// Update a message in local DB (for incoming edits).
    pub fn update_local_message(&self, message_id: &str, new_text: &str) -> Result<(), String> {
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
            envelope_commitment: [0xB2; 32],
        }
    }

    #[test]
    fn generated_device_id_is_never_the_legacy_zero_value() {
        assert_ne!(VeilClient::new().device_id, [0u8; 16]);
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
            attachments: Vec::new(),
            security_context: None,
        };
        let report = recipient
            .process_retained_and_defer_live_events_v1(
                Vec::new(),
                vec![
                    ConnectionEvent::SenderKeyDist {
                        sender_key_message: sealed.clone(),
                        route: stale_route.clone(),
                    },
                    next_live,
                ],
            )
            .unwrap();
        assert_eq!(report, RetainedSenderKeyProcessReportV1::default());
        let first = recipient.deferred_connection_events.pop_front().unwrap();
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
            recipient.deferred_connection_events.pop_front(),
            Some(ConnectionEvent::MessageReceived { message_id, .. })
                if message_id == "next-live-message"
        ));
        assert!(recipient.pending_sender_key_receipts.is_empty());
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
        bob.db = Some(VeilDb::open_memory(&[73u8; 32]).unwrap());
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
        assert!(!bob.has_session(&alice_key));
        assert!(bob.otk_secrets.contains_key(&opk_id));
        assert!(bob
            .db()
            .unwrap()
            .load_ratchet_session(&alice_key)
            .unwrap()
            .is_none());
        assert!(!bob.db().unwrap().message_exists("server-message").unwrap());

        bob.db()
            .unwrap()
            .conn()
            .execute_batch("DROP TRIGGER reject_synced_message")
            .unwrap();
        assert_eq!(
            bob.receive_and_persist_message(
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
            .unwrap(),
            ReceiveMessageResult::Stored {
                plaintext: "transactional".to_string()
            }
        );
        assert!(bob.has_session(&alice_key));
        assert!(!bob.otk_secrets.contains_key(&opk_id));
        assert!(bob.db().unwrap().message_exists("server-message").unwrap());
        assert_eq!(
            bob.db().unwrap().get_messages("dm-atomic", 10).unwrap()[0]
                .author
                .as_ref(),
            Some(&author)
        );

        // Simulate a row created before author snapshots existed. The edit
        // transaction must either restore attribution together with plaintext
        // or leave both unchanged on rollback.
        bob.db()
            .unwrap()
            .conn()
            .execute(
                "DELETE FROM message_author_snapshots_v1 WHERE message_id = ?1",
                rusqlite::params!["server-message"],
            )
            .unwrap();
        assert!(bob.db().unwrap().get_messages("dm-atomic", 10).unwrap()[0]
            .author
            .is_none());

        let (edit_ciphertext, edit_header) = alice
            .encrypt_outgoing("dm-atomic", "edited transactionally")
            .unwrap();
        bob.db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER reject_synced_edit
                 BEFORE UPDATE OF plaintext ON messages
                 BEGIN SELECT RAISE(ABORT, 'simulated edit write failure'); END;",
            )
            .unwrap();
        assert!(bob
            .receive_and_persist_edit(
                "server-message",
                "dm-atomic",
                &alice_key,
                Some(&author),
                Some(MessageAuthorContext::DirectoryMemberAtObservation),
                false,
                &edit_header,
                &edit_ciphertext,
                None,
            )
            .is_err());
        assert_eq!(
            bob.db().unwrap().get_messages("dm-atomic", 10).unwrap()[0].plaintext,
            "transactional"
        );
        assert!(bob.db().unwrap().get_messages("dm-atomic", 10).unwrap()[0]
            .author
            .is_none());
        bob.db()
            .unwrap()
            .conn()
            .execute_batch("DROP TRIGGER reject_synced_edit")
            .unwrap();
        assert_eq!(
            bob.receive_and_persist_edit(
                "server-message",
                "dm-atomic",
                &alice_key,
                Some(&author),
                Some(MessageAuthorContext::DirectoryMemberAtObservation),
                false,
                &edit_header,
                &edit_ciphertext,
                None,
            )
            .unwrap(),
            "edited transactionally"
        );
        assert_eq!(
            bob.db().unwrap().get_messages("dm-atomic", 10).unwrap()[0]
                .author
                .as_ref(),
            Some(&author)
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
            (93, "local-disconnected-a", "possibly sent a"),
            (94, "local-disconnected-b", "possibly sent b"),
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
                },
            );
        }
        client.db = Some(db);
        client
            .deferred_connection_events
            .push_back(ConnectionEvent::Disconnected {
                reason: "ws write error: connection reset".to_string(),
            });

        assert!(matches!(
            client.poll_event().await.unwrap(),
            Some(ConnectionEvent::Disconnected { .. })
        ));
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
            },
        );

        assert_eq!(
            client
                .finalize_outgoing_message(77, "server-message", 2_000_000)
                .unwrap(),
            Some("local-message".to_string())
        );
        assert!(!client.pending_outgoing_messages.contains_key(&77));
        let messages = client.db().unwrap().get_messages("dm-ack", 10).unwrap();
        assert_eq!(messages[0].id, "server-message");
        assert_eq!(messages[0].server_timestamp, Some(2));
    }
}
