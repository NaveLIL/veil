use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use veil_crypto::fingerprint;
use veil_crypto::kdf;
use veil_crypto::keys::{generate_mnemonic, validate_mnemonic, IdentityKeyPair};
use veil_crypto::ratchet::{MessageHeader, RatchetSession};
use veil_crypto::sender_key::{SenderKeyDistribution, SenderKeyStore};
use veil_crypto::x3dh;
use veil_search::Indexer;
use veil_store::db::{LocalPreKey, VeilDb};
use veil_store::models::{RemoteMessageStateKind, RemoteReaction};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::connection::{ConfirmedMutation, Connection, ConnectionConfig, ConnectionEvent};
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

fn split_retained_sender_key_prefix(
    queued: Vec<ConnectionEvent>,
) -> (Vec<ConnectionEvent>, VecDeque<ConnectionEvent>) {
    let mut retained = Vec::new();
    let mut deferred = VecDeque::new();
    let mut reached_live_fifo = false;
    for event in queued {
        if !reached_live_fifo && matches!(event, ConnectionEvent::SenderKeyDist { .. }) {
            retained.push(event);
        } else {
            reached_live_fifo = true;
            deferred.push_back(event);
        }
    }
    (retained, deferred)
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
    /// Channels whose fresh outgoing key has not yet been delivered to the
    /// complete current member set. Sending remains blocked while present.
    sender_key_distribution_pending: HashSet<String>,
    pending_sender_key_sequences: HashMap<u64, String>,
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
            sender_key_distribution_pending: HashSet::new(),
            pending_sender_key_sequences: HashMap::new(),
            failed_sender_key_distributions: HashSet::new(),
            indexer: None,
        }
    }

    /// Create a VeilClient with a pre-existing identity (no DB).
    pub fn from_identity(identity: IdentityKeyPair) -> Self {
        let device_id = random_device_id();
        Self {
            identity: Some(identity),
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
            sender_key_distribution_pending: HashSet::new(),
            pending_sender_key_sequences: HashMap::new(),
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
        self.device_id = db.get_or_create_device_id(self.device_id)?;

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

        // Restore explicit DM bindings. A conversation without a known peer is
        // intentionally not sendable until its authenticated directory lookup
        // and X3DH establishment complete.
        self.dm_conversations.clear();
        self.authorized_conversation_senders.clear();
        self.ratchet_sessions.clear();
        self.pending_initial_headers.clear();
        self.pending_initial_sequences.clear();
        for conversation in db.get_conversations()? {
            if let Some(peer) = conversation.peer_identity_key {
                if let Ok(peer) = <[u8; 32]>::try_from(peer.as_slice()) {
                    self.dm_conversations.insert(conversation.id, peer);
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

    /// Remember a server user ID to identity-key binding obtained from a signed
    /// directory response. This is deliberately not populated from UI input.
    pub fn remember_user_identity(&mut self, user_id: &str, identity_key: [u8; 32]) {
        self.known_user_keys
            .insert(user_id.to_string(), identity_key);
    }

    pub fn known_user_identity(&self, user_id: &str) -> Option<[u8; 32]> {
        self.known_user_keys.get(user_id).copied()
    }

    pub fn pin_peer_signing_key(
        &mut self,
        identity_key: [u8; 32],
        signing_key: [u8; 32],
    ) -> Result<(), String> {
        if let Some(existing) = self.trusted_signing_keys.get(&identity_key) {
            if existing != &signing_key {
                return Err("trusted signing key changed for peer identity".to_string());
            }
            return Ok(());
        }
        if let Some(db) = self.db.as_ref() {
            db.pin_trusted_signing_key(&identity_key, &signing_key)?;
        }
        self.trusted_signing_keys.insert(identity_key, signing_key);
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
    pub fn bind_dm_conversation(&mut self, conversation_id: &str, peer_identity_key: [u8; 32]) {
        self.dm_conversations
            .insert(conversation_id.to_string(), peer_identity_key);
        if let Some(ref db) = self.db {
            let _ =
                db.insert_conversation(conversation_id, 0, None, Some(&peer_identity_key), None);
        }
    }

    /// Sign an arbitrary message with our Ed25519 identity key. Used for
    /// authenticating REST requests via the X-Veil-Signature header scheme.
    pub fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], String> {
        let id = self.identity.as_ref().ok_or("not initialized")?;
        Ok(veil_crypto::signature::sign(id, message))
    }

    /// Generate a fingerprint for contact verification.
    pub fn fingerprint(&self, peer_key: &[u8; 32]) -> Result<(String, String), String> {
        let our_key = self.identity_key()?;
        Ok(fingerprint::generate(&our_key, peer_key))
    }

    // ─── Connection ──────────────────────────────────

    /// Connect to the Veil gateway server via WebSocket.
    /// Performs Ed25519 challenge-response authentication.
    /// Returns the server-assigned user_id (UUID).
    pub async fn connect(&mut self, server_url: &str) -> Result<String, String> {
        let identity = self.identity.as_ref().ok_or("not initialized")?;
        let config = ConnectionConfig {
            server_url: server_url.to_string(),
        };

        let mut conn =
            Connection::connect(&config, identity, &self.device_id, "veil-desktop").await?;

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
        let mut stale_sequences: HashSet<u64> = self
            .pending_outgoing_messages
            .keys()
            .chain(self.pending_mutations.keys())
            .chain(self.pending_initial_sequences.keys())
            .chain(self.pending_sender_key_sequences.keys())
            .copied()
            .collect();
        for sequence in stale_sequences.drain() {
            self.reject_pending_sequence(sequence)?;
        }
        // REST backlog is authoritative for anything not processed from the
        // previous socket. Never replay its deferred events in the new epoch.
        self.deferred_connection_events.clear();
        self.authenticated_user_id = Some(user_id.clone());
        self.connection = Some(conn);
        Ok(user_id)
    }

    /// Install retained SKDMs that were authenticated before the WS AuthResult
    /// barrier. Call only after the signed conversation/member directory has
    /// been pinned and before decrypting REST history.
    pub fn process_retained_sender_keys_before_sync(&mut self) -> Result<usize, String> {
        let mut queued = Vec::new();
        if let Some(connection) = self.connection.as_mut() {
            queued.extend(connection.retained_events.drain(..));
            while let Ok(event) = connection.events.try_recv() {
                queued.push(event);
            }
        }

        let (retained, deferred) = split_retained_sender_key_prefix(queued);
        self.deferred_connection_events.extend(deferred);
        let our_identity = self.identity_key()?;
        let mut processed = 0usize;
        for event in retained {
            match event {
                ConnectionEvent::SenderKeyDist {
                    conversation_id,
                    sender_key_message,
                    generation,
                    target_identity_key,
                } => {
                    let target: [u8; 32] =
                        target_identity_key.try_into().map_err(|target: Vec<u8>| {
                            format!("retained SKDM target length is {}", target.len())
                        })?;
                    if target != our_identity {
                        return Err("retained SKDM target identity mismatch".to_string());
                    }
                    self.process_sealed_skdm(&sender_key_message, &conversation_id, generation)?;
                    processed += 1;
                }
                _ => unreachable!("retained prefix contains only sender-key envelopes"),
            }
        }
        Ok(processed)
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
            }) => {
                *local_message_id =
                    self.finalize_outgoing_message(*ref_seq, message_id, *server_timestamp)?;
                *mutation = self.confirm_pending_mutation(*ref_seq, *server_timestamp)?;
                self.confirm_initial_message(*ref_seq)?;
                self.confirm_sender_key_distribution(*ref_seq);
            }
            Some(ConnectionEvent::Error {
                ref_seq: Some(ref_seq),
                local_message_id,
                ..
            }) => *local_message_id = self.reject_pending_sequence(*ref_seq)?,
            _ => {}
        }
        Ok(event)
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

    fn confirm_sender_key_distribution(&mut self, sequence: u64) {
        let Some(group_id) = self.pending_sender_key_sequences.remove(&sequence) else {
            return;
        };
        let still_waiting = self
            .pending_sender_key_sequences
            .values()
            .any(|pending_group| pending_group == &group_id);
        if !still_waiting && !self.failed_sender_key_distributions.contains(&group_id) {
            self.sender_key_distribution_pending.remove(&group_id);
        }
    }

    fn confirm_pending_mutation(
        &mut self,
        sequence: u64,
        server_timestamp: u64,
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
                    conversation_id,
                    new_text,
                } => {
                    let sender_key = self.identity_key()?;
                    let timestamp_ms = i64::try_from(server_timestamp / 1_000_000)
                        .map_err(|_| "server mutation timestamp exceeds i64".to_string())?;
                    let _ = indexer.delete(message_id);
                    let _ = indexer.index_message(
                        message_id,
                        conversation_id,
                        &hex::encode(sender_key),
                        new_text,
                        timestamp_ms,
                    );
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
        self.pending_initial_sequences.remove(&sequence);
        if let Some(ConfirmedMutation::Edit { new_text, .. }) =
            self.pending_mutations.remove(&sequence).as_mut()
        {
            new_text.zeroize();
        }
        if let Some(group_id) = self.pending_sender_key_sequences.remove(&sequence) {
            self.failed_sender_key_distributions.insert(group_id);
        }
        let Some(pending) = self.pending_outgoing_messages.get(&sequence) else {
            return Ok(None);
        };
        if let Some(db) = self.db.as_ref() {
            db.delete_message(&pending.local_message_id)?;
        }
        if let Some(indexer) = self.indexer.as_ref() {
            let _ = indexer.delete(&pending.local_message_id);
        }
        let local_message_id = pending.local_message_id.clone();
        self.pending_outgoing_messages.remove(&sequence);
        Ok(Some(local_message_id))
    }

    /// Send a text message to a conversation.
    /// Fails closed unless the conversation has an established E2E mode.
    pub async fn send_message(
        &mut self,
        conversation_id: &str,
        plaintext: &str,
        reply_to_id: Option<&str>,
    ) -> Result<u64, String> {
        if plaintext.is_empty() {
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
        let seq = self
            .connection
            .as_ref()
            .ok_or("not connected")?
            .next_seq()
            .await;

        // Encrypt first (needs mutable borrow)
        let (ciphertext, header_bytes) = self.encrypt_outgoing(conversation_id, plaintext)?;
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
            db.insert_outgoing_pending_message(
                &local_message_id,
                conversation_id,
                &our_key,
                plaintext,
                reply_to_id,
            )?;
        }
        if let Some(indexer) = self.indexer.as_ref() {
            if let Err(error) = indexer.index_message(
                &local_message_id,
                conversation_id,
                &hex::encode(our_key),
                plaintext,
                local_timestamp,
            ) {
                if let Some(db) = self.db.as_ref() {
                    db.delete_message(&local_message_id)?;
                }
                return Err(format!("index pending outgoing message: {error}"));
            }
        }

        let send_msg = proto::SendMessage {
            conversation_id: conversation_id.to_string(),
            ciphertext,
            header: header_bytes,
            msg_type: proto::MessageType::Text.into(),
            reply_to_id: reply_to_id.map(|s| s.to_string()),
            ttl_seconds: None,
            attachments: vec![],
            sealed: false,
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
                db.delete_message(&local_message_id)?;
            }
            if let Some(indexer) = self.indexer.as_ref() {
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
            let our_key = self.identity_key()?;
            // Make sure we have an outgoing sender key for this channel.
            if !self.sender_keys.has_outgoing(conversation_id)
                || self.sender_keys.needs_rotation(conversation_id)
            {
                let _ = self.sender_keys.create_outgoing(conversation_id, &our_key);
                self.persist_outgoing_sender_key(conversation_id)?;
            }

            let identity = self.identity.as_ref().ok_or("not initialized")?;
            let ct =
                self.sender_keys
                    .encrypt_signed(conversation_id, identity, plaintext.as_bytes())?;
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
                let pinned_signing_key = self
                    .trusted_signing_keys
                    .get(sender_identity_key)
                    .copied()
                    .ok_or("sender-key signer is not pinned")?;
                self.ensure_incoming_sender_key_loaded(conversation_id, sender_identity_key);
                let pt = self.sender_keys.decrypt_signed(
                    conversation_id,
                    sender_identity_key,
                    &pinned_signing_key,
                    ciphertext,
                )?;
                self.persist_incoming_sender_key(conversation_id, sender_identity_key)?;
                Ok(DecryptedPayload::Text(pt))
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
                self.persist_incoming_sender_key(&group_id, sender_identity_key)?;
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
        self.authorized_conversation_senders
            .insert(conversation_id.to_string(), senders);
        if roster_changed && self.channel_conversations.contains(conversation_id) {
            // Reusing a distributed generation after any add/remove would let
            // former members decrypt future traffic (and would omit new
            // members). Rotation also discards outstanding ACK mappings for
            // the old roster and keeps sends blocked until the new SKDM fanout
            // is fully acknowledged.
            self.rotate_sender_key(conversation_id)?;
        }
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

    /// Force-rotate our outgoing sender key for a channel (e.g. after a member leaves).
    pub fn rotate_sender_key(&mut self, conversation_id: &str) -> Result<(), String> {
        let our_key = self.identity_key()?;
        let _ = self.sender_keys.create_outgoing(conversation_id, &our_key);
        self.pending_sender_key_sequences
            .retain(|_, group_id| group_id != conversation_id);
        self.failed_sender_key_distributions.remove(conversation_id);
        self.channel_conversations
            .insert(conversation_id.to_string());
        self.sender_key_distribution_pending
            .insert(conversation_id.to_string());
        self.persist_outgoing_sender_key(conversation_id)?;
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
            .any(|group_id| group_id == conversation_id)
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
        if missing || expired {
            self.rotate_sender_key(conversation_id)?;
        } else {
            self.failed_sender_key_distributions.remove(conversation_id);
            self.sender_key_distribution_pending
                .insert(conversation_id.to_string());
        }
        Ok(true)
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
            .any(|group_id| group_id == conversation_id)
        {
            return Err("sender-key acknowledgements are still pending".to_string());
        }
        self.failed_sender_key_distributions.remove(conversation_id);
        self.sender_key_distribution_pending.remove(conversation_id);
        Ok(())
    }

    pub fn mark_sender_key_distribution_failed(&mut self, conversation_id: &str) {
        self.failed_sender_key_distributions
            .insert(conversation_id.to_string());
        self.sender_key_distribution_pending
            .insert(conversation_id.to_string());
    }

    /// Distribute our current outgoing sender key for `conversation_id` to a single peer.
    /// Sends a sealed SKDM via the server's SenderKeyDistribution envelope.
    pub async fn send_sender_key_to(
        &mut self,
        conversation_id: &str,
        peer_identity_key: &[u8; 32],
    ) -> Result<u64, String> {
        let our_key = self.identity_key()?;
        // Make sure we have an outgoing key.
        if !self.sender_keys.has_outgoing(conversation_id) {
            let _ = self.sender_keys.create_outgoing(conversation_id, &our_key);
            self.persist_outgoing_sender_key(conversation_id)?;
        }

        // Build the distribution directly so chain-key material never passes
        // through a non-zeroizing serde_json::Value tree.
        let dist = self.sender_keys.build_distribution(conversation_id)?;
        let key_id = dist.key_id;
        let json =
            Zeroizing::new(serde_json::to_vec(&dist).map_err(|e| format!("encode SKDM: {e}"))?);

        // Seal for the peer.
        let identity = self.identity.as_ref().ok_or("not initialized")?;
        let sealed = veil_crypto::sender_key::seal_skdm_authenticated(
            identity,
            peer_identity_key,
            conversation_id,
            key_id,
            &json,
        )?;

        let conn = self.connection.as_ref().ok_or("not connected")?;
        let seq = conn.next_seq().await;
        let env = proto::Envelope {
            seq,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::SenderKeyDist(
                proto::SenderKeyDistribution {
                    conversation_id: conversation_id.to_string(),
                    sender_key_message: sealed,
                    generation: key_id,
                    target_identity_key: peer_identity_key.to_vec(),
                },
            )),
        };
        conn.send_envelope(&env).await?;
        self.pending_sender_key_sequences
            .insert(seq, conversation_id.to_string());
        Ok(seq)
    }

    /// Process a sender-key envelope only when the caller supplies a sender
    /// signing key obtained from an authenticated identity directory.
    pub fn process_authenticated_sealed_skdm(
        &mut self,
        sealed_wire: &[u8],
        expected_sender_identity_key: &[u8; 32],
        expected_sender_signing_key: &[u8; 32],
        expected_group_id: &str,
        expected_generation: u32,
    ) -> Result<(), String> {
        let identity = self.identity.as_ref().ok_or("not initialized")?;
        let authenticated = identity.open_authenticated_sealed_skdm(
            expected_sender_identity_key,
            expected_sender_signing_key,
            expected_group_id,
            expected_generation,
            sealed_wire,
        )?;
        self.install_authenticated_skdm(authenticated)
    }

    fn install_authenticated_skdm(
        &mut self,
        authenticated: veil_crypto::sender_key::AuthenticatedSkdm,
    ) -> Result<(), String> {
        self.require_currently_authorized_sender(
            &authenticated.group_id,
            &authenticated.sender_identity_key,
        )?;
        let group_id = authenticated.group_id.clone();
        self.sender_keys
            .process_authenticated_skdm(&authenticated)?;
        self.channel_conversations.insert(group_id.clone());
        // A membership-triggered peer generation is a conservative signal to
        // rotate and redistribute our own key before sending again.
        self.sender_key_distribution_pending
            .insert(group_id.clone());
        self.persist_incoming_sender_key(&group_id, &authenticated.sender_identity_key)?;
        Ok(())
    }

    /// Inspect public v3 metadata only to locate an independently pinned key,
    /// then verify the signature/AEAD against the outer gateway context.
    pub fn process_sealed_skdm(
        &mut self,
        sealed_wire: &[u8],
        outer_group_id: &str,
        outer_generation: u32,
    ) -> Result<(), String> {
        if self.dm_conversations.contains_key(outer_group_id) {
            return Err("sender keys are forbidden for DM conversations".to_string());
        }
        if !self.channel_conversations.contains(outer_group_id) {
            return Err(
                "sender-key conversation is not an authenticated group/channel".to_string(),
            );
        }
        let metadata = veil_crypto::sender_key::inspect_skdm_metadata(sealed_wire)?;
        if metadata.group_id != outer_group_id || metadata.generation != outer_generation {
            return Err("SKDM outer routing context mismatch".to_string());
        }
        let trusted_signing_key = self
            .trusted_signing_keys
            .get(&metadata.sender_identity_key)
            .copied();
        if let Some(trusted_signing_key) = trusted_signing_key {
            if metadata.sender_signing_key != trusted_signing_key {
                return Err(
                    "SKDM embedded signing key does not match pinned directory key".to_string(),
                );
            }
            return self.process_authenticated_sealed_skdm(
                sealed_wire,
                &metadata.sender_identity_key,
                &trusted_signing_key,
                outer_group_id,
                outer_generation,
            );
        }

        Err("SKDM sender has no signing key in the authenticated directory".to_string())
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
        let our_key = self.identity_key()?;
        let data = self
            .sender_keys
            .serialize_outgoing(conversation_id)
            .ok_or_else(|| "cannot persist missing outgoing sender key".to_string())?;
        db.save_sender_key(conversation_id, &our_key, &data, true)
    }

    fn persist_incoming_sender_key(
        &self,
        conversation_id: &str,
        sender_ik: &[u8; 32],
    ) -> Result<(), String> {
        let Some(db) = self.db.as_ref() else {
            return Ok(());
        };
        let data = self
            .sender_keys
            .serialize_incoming(conversation_id, sender_ik)
            .ok_or_else(|| "cannot persist missing incoming sender key".to_string())?;
        db.save_sender_key(conversation_id, sender_ik, &data, false)
    }

    fn ensure_incoming_sender_key_loaded(&mut self, conversation_id: &str, sender_ik: &[u8; 32]) {
        // Already in memory? Nothing to do.
        // (We can't peek into the private map; just attempt a lazy load —
        //  load_incoming is idempotent and overwriting with on-disk state is fine
        //  ONLY if we haven't ratcheted past it. Avoid clobbering newer in-memory state.)
        if self.sender_keys.has_incoming(conversation_id, sender_ik) {
            return;
        }
        if let Some(db) = self.db.as_ref() {
            if let Ok(Some(data)) = db.load_sender_key(conversation_id, sender_ik) {
                let data = Zeroizing::new(data);
                let _ = self
                    .sender_keys
                    .load_incoming(conversation_id, sender_ik, &data);
            }
        }
    }

    /// Hydrate sender keys (outgoing + all incoming) for a channel from the DB.
    pub fn hydrate_channel_sender_keys(&mut self, conversation_id: &str) -> Result<(), String> {
        self.channel_conversations
            .insert(conversation_id.to_string());
        let our_key = self.identity_key().ok();
        if let Some(db) = self.db.as_ref() {
            let rows = db.load_sender_keys_for_group(conversation_id)?;
            for (sender_ik, data, is_outgoing) in rows {
                let data = Zeroizing::new(data);
                if sender_ik.len() != 32 {
                    continue;
                }
                let mut ik = [0u8; 32];
                ik.copy_from_slice(&sender_ik);
                if is_outgoing && Some(ik) == our_key {
                    let _ = self.sender_keys.load_outgoing(conversation_id, &data);
                } else {
                    let _ = self.sender_keys.load_incoming(conversation_id, &ik, &data);
                }
            }
        }
        Ok(())
    }

    /// Authenticate, decrypt and persist one inbound network message as a
    /// single logical transaction. Crypto helpers write their advanced state
    /// to SQLite inside the savepoint; a later FK/message/index preparation
    /// failure rolls those writes and the in-memory ratchets back together.
    ///
    /// `sender_key_mode` is the authenticated directory conversation kind,
    /// not a hint derived from the untrusted wire header.
    // These parameters are the authenticated wire and persistence context;
    // keeping borrowed slices avoids extra plaintext/ciphertext copies.
    #[allow(clippy::too_many_arguments)]
    pub fn receive_and_persist_live_message(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        sender_identity_key: &[u8; 32],
        sender_key_mode: bool,
        fallback_conversation_name: Option<&str>,
        header: &[u8],
        ciphertext: &[u8],
        server_timestamp: Option<i64>,
        reply_to_id: Option<&str>,
        remote_metadata: Option<&RemoteMessageMetadata<'_>>,
    ) -> Result<ReceiveMessageResult, String> {
        self.require_currently_authorized_sender(conversation_id, sender_identity_key)?;
        self.receive_and_persist_message(
            message_id,
            conversation_id,
            sender_identity_key,
            sender_key_mode,
            fallback_conversation_name,
            header,
            ciphertext,
            server_timestamp,
            reply_to_id,
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
        sender_key_mode: bool,
        fallback_conversation_name: Option<&str>,
        header: &[u8],
        ciphertext: &[u8],
        server_timestamp: Option<i64>,
        reply_to_id: Option<&str>,
        remote_metadata: Option<&RemoteMessageMetadata<'_>>,
    ) -> Result<ReceiveMessageResult, String> {
        if message_id.is_empty() || conversation_id.is_empty() {
            return Err("inbound message and conversation ids must not be empty".to_string());
        }
        if header.is_empty() || ciphertext.is_empty() {
            return Err("inbound E2E header and ciphertext must not be empty".to_string());
        }
        if !self.trusted_signing_keys.contains_key(sender_identity_key) {
            return Err("inbound sender identity is not pinned to a signing key".to_string());
        }
        let wire_uses_sender_key = header.first() == Some(&HEADER_SENDER_KEY);
        if wire_uses_sender_key != sender_key_mode {
            return Err(
                "inbound E2E header conflicts with the pinned conversation type".to_string(),
            );
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

            let plaintext = match self.decrypt_from(
                sender_identity_key,
                conversation_id,
                header,
                ciphertext,
            )? {
                DecryptedPayload::Text(plaintext) => String::from_utf8(plaintext)
                    .map_err(|_| "inbound plaintext is not valid UTF-8".to_string())?,
                DecryptedPayload::Control => {
                    return Err(
                        "control frame is not valid on the chat message receive path".to_string(),
                    );
                }
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
        sender_key_mode: bool,
        header: &[u8],
        ciphertext: &[u8],
        remote_metadata: Option<&RemoteMessageMetadata<'_>>,
    ) -> Result<String, String> {
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
            let _ = indexer.delete(message_id);
            let timestamp = remote_metadata
                .map(|metadata| metadata.revision_ms)
                .unwrap_or_else(|| {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|duration| duration.as_millis() as i64)
                        .unwrap_or(0)
                });
            let _ = indexer.index_message(
                message_id,
                conversation_id,
                &hex::encode(sender_identity_key),
                &plaintext,
                timestamp,
            );
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
    pub fn update_local_message(&self, message_id: &str, new_text: &str) {
        if let Some(ref db) = self.db {
            let _ = db.update_message_text(message_id, new_text);
        }
        if let Some(ref idx) = self.indexer {
            // We don't know conversation/sender here without a DB read; the body
            // change is what matters for FTS. Re-issue with empty fields — the
            // next full re-index (rebuild) will restore metadata.
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            let _ = idx.index_message(message_id, "", "", new_text, ts);
        }
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_device_id_is_never_the_legacy_zero_value() {
        assert_ne!(VeilClient::new().device_id, [0u8; 16]);
    }

    #[test]
    fn retained_sender_keys_stop_at_first_live_fifo_event() {
        let skdm = || ConnectionEvent::SenderKeyDist {
            conversation_id: "group".to_string(),
            sender_key_message: vec![1],
            generation: 1,
            target_identity_key: vec![2; 32],
        };
        let live = ConnectionEvent::MessageReceived {
            message_id: "message".to_string(),
            conversation_id: "group".to_string(),
            sender_identity_key: vec![3; 32],
            sender_username: "Alice".to_string(),
            ciphertext: vec![4],
            header: vec![HEADER_SENDER_KEY],
            server_timestamp: 1,
            reply_to_id: None,
        };
        let (retained, deferred) = split_retained_sender_key_prefix(vec![skdm(), live, skdm()]);
        assert_eq!(retained.len(), 1);
        assert_eq!(deferred.len(), 2);
        assert!(matches!(
            deferred.back(),
            Some(ConnectionEvent::SenderKeyDist { .. })
        ));
    }

    #[test]
    fn dm_encryption_fails_closed_without_binding_or_session() {
        let peer = IdentityKeyPair::generate().x25519_public_bytes();
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());

        let err = client.encrypt_outgoing("unknown", "secret").unwrap_err();
        assert!(err.contains("not bound to a peer"));

        client.bind_dm_conversation("dm-1", peer);
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
        alice.bind_dm_conversation("dm-1", bob_key);

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
        alice.bind_dm_conversation("dm-restart", bob_key);
        let (_discarded_ciphertext, first_header) =
            alice.encrypt_outgoing("dm-restart", "discarded").unwrap();
        assert_eq!(first_header[0], HEADER_INITIAL);
        drop(alice);

        let mut restored = VeilClient::new();
        restored.init_with_mnemonic(&mnemonic, &path).unwrap();
        restored.pin_peer_signing_key(bob_key, bob_signing).unwrap();
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
        bob.bind_dm_conversation("dm-restart", alice_key);
        let (reply_ciphertext, reply_header) =
            bob.encrypt_outgoing("dm-restart", "receipt").unwrap();
        assert_eq!(
            restored
                .receive_and_persist_message(
                    "reply-message",
                    "dm-restart",
                    &bob_key,
                    false,
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
        bob.db()
            .unwrap()
            .insert_conversation("dm-atomic", 0, Some("Alice"), Some(&alice_key), None)
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
        alice.bind_dm_conversation("dm-atomic", bob_key);
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
                false,
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
                false,
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
                false,
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
                false,
                &edit_header,
                &edit_ciphertext,
                None,
            )
            .unwrap(),
            "edited transactionally"
        );
    }

    #[test]
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
    fn sender_key_send_unblocks_only_after_every_ack() {
        let mut client = VeilClient::from_identity(IdentityKeyPair::generate());
        client.rotate_sender_key("group-1").unwrap();
        client
            .pending_sender_key_sequences
            .insert(10, "group-1".to_string());
        client
            .pending_sender_key_sequences
            .insert(11, "group-1".to_string());

        client.confirm_sender_key_distribution(10);
        assert!(client.sender_key_distribution_pending.contains("group-1"));
        client.confirm_sender_key_distribution(11);
        assert!(!client.sender_key_distribution_pending.contains("group-1"));

        let generation_before_reconnect = client.sender_keys.serialize_outgoing("group-1").unwrap();
        client.rotate_sender_key("group-1").unwrap();
        let generation_after_reconnect = client.sender_keys.serialize_outgoing("group-1").unwrap();
        assert_ne!(&*generation_before_reconnect, &*generation_after_reconnect);
        assert!(client.sender_key_distribution_pending.contains("group-1"));
        client
            .pending_sender_key_sequences
            .insert(12, "group-1".to_string());
        client.reject_pending_sequence(12).unwrap();
        assert!(client.sender_key_distribution_pending.contains("group-1"));
        assert!(client.failed_sender_key_distributions.contains("group-1"));

        let generation_before_retry = client.sender_keys.serialize_outgoing("group-1").unwrap();
        assert!(client.begin_sender_key_distribution("group-1").unwrap());
        let generation_after_retry = client.sender_keys.serialize_outgoing("group-1").unwrap();
        assert_eq!(&*generation_before_retry, &*generation_after_retry);
        client
            .pending_sender_key_sequences
            .insert(13, "group-1".to_string());
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
        client
            .pending_sender_key_sequences
            .insert(77, conversation_id.to_string());
        assert!(client
            .encrypt_outgoing(conversation_id, "still waiting")
            .is_err());
        client.confirm_sender_key_distribution(77);
        assert!(client
            .encrypt_outgoing(conversation_id, "fresh generation")
            .is_ok());
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
