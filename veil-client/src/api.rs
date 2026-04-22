use std::collections::{HashMap, HashSet};
use std::path::Path;
use veil_crypto::fingerprint;
use veil_crypto::kdf;
use veil_crypto::keys::{generate_mnemonic, validate_mnemonic, IdentityKeyPair};
use veil_crypto::ratchet::{MessageHeader, RatchetSession};
use veil_crypto::sender_key::{SenderKeyDistribution, SenderKeyStore};
use veil_crypto::x3dh;
use veil_store::db::VeilDb;
use veil_store::keychain;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crate::connection::{Connection, ConnectionConfig, ConnectionEvent};
use crate::protocol::proto;

// Wire header type tags
const HEADER_INITIAL: u8 = 0x01; // X3DH init + ratchet header
const HEADER_RATCHET: u8 = 0x02; // Ratchet header only
const HEADER_SENDER_KEY: u8 = 0x05; // Group/channel sender-key encrypted message

// Inner type bytes (inside ratchet-decrypted plaintext for pairwise channel)
const INNER_TEXT: u8 = 0x00; // UTF-8 text message
const INNER_SKDM: u8 = 0x01; // Sender Key Distribution Message (JSON)

/// Result of decrypting an incoming message.
pub enum DecryptedPayload {
    /// Real text or binary content for the UI / persistence.
    Text(Vec<u8>),
    /// Internal control frame (e.g. SKDM) — already processed; do not surface.
    Control,
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
    device_id: [u8; 16],
    /// Active ratchet sessions keyed by peer identity key (X25519 public).
    ratchet_sessions: HashMap<[u8; 32], RatchetSession>,
    /// Our signed prekey secret (for X3DH responder).
    spk_secret: Option<[u8; 32]>,
    spk_public: Option<[u8; 32]>,
    spk_id: u32,
    /// One-time prekey secrets (for X3DH responder).
    otk_secrets: HashMap<u32, [u8; 32]>,
    otk_next_id: u32,
    /// Sender-key store for channel/group E2E.
    sender_keys: SenderKeyStore,
    /// Conversations that should be encrypted with sender keys (channels & encrypted groups).
    channel_conversations: HashSet<String>,
}

impl VeilClient {
    pub fn new() -> Self {
        let mut device_id = [0u8; 16];
        use rand::RngCore;
        let _ = rand::rngs::OsRng.try_fill_bytes(&mut device_id);
        Self {
            identity: None,
            db: None,
            connection: None,
            device_id,
            ratchet_sessions: HashMap::new(),
            spk_secret: None,
            spk_public: None,
            spk_id: 1,
            otk_secrets: HashMap::new(),
            otk_next_id: 1,
            sender_keys: SenderKeyStore::new(),
            channel_conversations: HashSet::new(),
        }
    }

    /// Create a VeilClient with a pre-existing identity (no DB).
    pub fn from_identity(identity: IdentityKeyPair) -> Self {
        let mut device_id = [0u8; 16];
        use rand::RngCore;
        let _ = rand::rngs::OsRng.try_fill_bytes(&mut device_id);
        Self {
            identity: Some(identity),
            db: None,
            connection: None,
            device_id,
            ratchet_sessions: HashMap::new(),
            spk_secret: None,
            spk_public: None,
            spk_id: 1,
            otk_secrets: HashMap::new(),
            otk_next_id: 1,
            sender_keys: SenderKeyStore::new(),
            channel_conversations: HashSet::new(),
        }
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

        let mut db_key = kdf::derive_db_key(mnemonic)?;
        let db = VeilDb::open(db_path, &db_key)?;
        db_key.zeroize();

        // Load persisted ratchet sessions from DB
        // (sessions are stored as JSON-serialized blobs)
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

    /// Store seed in OS keychain.
    pub fn store_seed(&self, mnemonic: &str) -> Result<(), String> {
        let identity_hex = hex::encode(self.identity_key()?);
        keychain::store_seed(&identity_hex, mnemonic)
    }

    /// Retrieve seed from OS keychain.
    pub fn get_stored_seed(&self) -> Result<String, String> {
        let identity_hex = hex::encode(self.identity_key()?);
        keychain::get_seed(&identity_hex)
    }

    // ─── Connection ──────────────────────────────────

    /// Connect to the Veil gateway server via WebSocket.
    /// Performs Ed25519 challenge-response authentication.
    /// Returns the server-assigned user_id (UUID).
    pub async fn connect(&mut self, server_url: &str) -> Result<String, String> {
        let identity = self.identity.as_ref().ok_or("not initialized")?;
        let config = ConnectionConfig {
            server_url: server_url.to_string(),
            cert_pins: vec![],
        };

        let mut conn =
            Connection::connect(&config, identity, &self.device_id, "veil-desktop").await?;

        // Drain the Authenticated event to get user_id
        let user_id = match conn.events.try_recv() {
            Ok(ConnectionEvent::Authenticated { user_id }) => user_id,
            _ => String::new(),
        };

        self.connection = Some(conn);
        Ok(user_id)
    }

    /// Poll for the next incoming event from the server.
    /// Returns None if no event is available (non-blocking).
    pub async fn poll_event(&mut self) -> Option<ConnectionEvent> {
        if let Some(ref mut conn) = self.connection {
            conn.events.try_recv().ok()
        } else {
            None
        }
    }

    /// Send a text message to a conversation.
    /// Uses ratchet encryption if a session exists with the peer, otherwise plaintext.
    pub async fn send_message(
        &mut self,
        conversation_id: &str,
        plaintext: &str,
        reply_to_id: Option<&str>,
    ) -> Result<u64, String> {
        // Encrypt first (needs mutable borrow)
        let (ciphertext, header_bytes) = self.encrypt_outgoing(conversation_id, plaintext)?;

        // Then get connection (immutable borrow of connection only)
        let conn = self.connection.as_ref().ok_or("not connected")?;
        let seq = conn.next_seq().await;

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

        conn.send_envelope(&env).await?;

        // Persist outgoing message to DB
        if let Some(ref db) = self.db {
            let our_key = self.identity_key().unwrap_or([0u8; 32]);
            let msg_id = uuid::Uuid::new_v4().to_string();
            let _ = db.insert_message(&msg_id, conversation_id, &our_key, plaintext, true, None, reply_to_id);
        }

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

        let spk = x3dh::SignedPreKey::generate(identity, self.spk_id);
        let spk_pub = *spk.public.as_bytes();
        let spk_sig = spk.signature;

        self.spk_secret = Some(spk.secret.to_bytes());
        self.spk_public = Some(spk_pub);

        let mut otk_publics = Vec::new();
        for i in 0..20u32 {
            let id = self.otk_next_id + i;
            let otk = x3dh::OneTimePreKey::generate(id);
            let pub_bytes = *otk.public.as_bytes();
            self.otk_secrets.insert(id, otk.secret.to_bytes());
            otk_publics.push((pub_bytes, id));
        }
        self.otk_next_id += 20;

        Ok(PreKeySet {
            spk_public: spk_pub,
            spk_id: self.spk_id,
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

        // Store the ephemeral public key for the first message header
        self.ratchet_sessions.insert(*peer_identity_key, session);

        // Persist session to DB
        if let Some(ref db) = self.db {
            if let Ok(data) =
                serde_json::to_vec(self.ratchet_sessions.get(peer_identity_key).unwrap())
            {
                let _ = db.save_ratchet_session(peer_identity_key, &data);
            }
        }

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
        let identity = self.identity.as_ref().ok_or("not initialized")?;

        let spk_secret_bytes = self.spk_secret.ok_or("no signed prekey")?;
        if self.spk_public.is_none() {
            return Err("no signed prekey public".to_string());
        }
        let spk_pub = self.spk_public.unwrap();

        // Reconstruct SignedPreKey for X3DH respond
        let spk_secret = X25519StaticSecret::from(spk_secret_bytes);
        let spk = x3dh::SignedPreKey {
            secret: spk_secret,
            public: X25519PublicKey::from(spk_pub),
            id: spk_id,
            signature: [0u8; 64], // Not needed for respond
        };

        let otk = opk_id.and_then(|id| {
            self.otk_secrets.remove(&id).map(|secret_bytes| {
                let secret = X25519StaticSecret::from(secret_bytes);
                x3dh::OneTimePreKey {
                    secret,
                    public: X25519PublicKey::from(&X25519StaticSecret::from(secret_bytes)),
                    id,
                }
            })
        });

        let result = x3dh::respond(
            identity,
            &spk,
            otk.as_ref(),
            sender_identity_key,
            ephemeral_key,
        )?;

        let session =
            RatchetSession::init_responder(&result.shared_secret, &spk_secret_bytes, &spk_pub);

        self.ratchet_sessions.insert(*sender_identity_key, session);

        // Persist
        if let Some(ref db) = self.db {
            if let Ok(data) =
                serde_json::to_vec(self.ratchet_sessions.get(sender_identity_key).unwrap())
            {
                let _ = db.save_ratchet_session(sender_identity_key, &data);
            }
        }

        Ok(())
    }

    /// Check if a ratchet session exists with a peer.
    pub fn has_session(&self, peer_identity_key: &[u8; 32]) -> bool {
        self.ratchet_sessions.contains_key(peer_identity_key)
    }

    /// Encrypt outgoing plaintext. Returns (ciphertext, wire_header).
    /// For channel conversations, encrypts with the per-group sender key and
    /// uses a dedicated outer header tag. Otherwise falls back to plaintext
    /// (pairwise sessions for DMs go through `encrypt_for` directly).
    fn encrypt_outgoing(
        &mut self,
        conversation_id: &str,
        plaintext: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        if self.channel_conversations.contains(conversation_id) {
            let our_key = self.identity_key()?;
            // Make sure we have an outgoing sender key for this channel.
            if !self.sender_keys.has_outgoing(conversation_id)
                || self.sender_keys.needs_rotation(conversation_id)
            {
                let _ = self
                    .sender_keys
                    .create_outgoing(conversation_id, &our_key);
                self.persist_outgoing_sender_key(conversation_id);
            }

            let ct = self
                .sender_keys
                .encrypt(conversation_id, plaintext.as_bytes())?;
            self.persist_outgoing_sender_key(conversation_id);
            return Ok((ct, vec![HEADER_SENDER_KEY]));
        }

        // No automatic pairwise lookup yet — callers use `encrypt_for` directly
        // when they know the peer identity key.
        Ok((plaintext.as_bytes().to_vec(), vec![]))
    }

    /// Encrypt for a specific peer (used when peer identity key is known).
    pub fn encrypt_for(
        &mut self,
        peer_identity_key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let session = self
            .ratchet_sessions
            .get_mut(peer_identity_key)
            .ok_or("no ratchet session with this peer")?;

        let (ratchet_header, ciphertext) = session.encrypt(plaintext)?;
        let rh_bytes = ratchet_header.to_bytes();

        // Build wire header: type + ratchet header
        let mut header = Vec::with_capacity(1 + rh_bytes.len());
        header.push(HEADER_RATCHET);
        header.extend_from_slice(&rh_bytes);

        // Persist updated session
        if let Some(ref db) = self.db {
            if let Ok(data) = serde_json::to_vec(session) {
                let _ = db.save_ratchet_session(peer_identity_key, &data);
            }
        }

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
            // No header = plaintext fallback (pre-E2E)
            return Ok(DecryptedPayload::Text(ciphertext.to_vec()));
        }

        match header[0] {
            HEADER_INITIAL => {
                // Parse X3DH init header
                if header.len() < 1 + 32 + 4 + 4 + 40 {
                    return Err("initial header too short".to_string());
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

                // Establish responder session if needed
                if !self.has_session(sender_identity_key) {
                    self.process_initial_message(sender_identity_key, &ek, spk_id, opk_id)?;
                }

                let rh = MessageHeader::from_bytes(&header[41..])?;
                let session = self
                    .ratchet_sessions
                    .get_mut(sender_identity_key)
                    .ok_or("session establishment failed")?;
                let plaintext = session.decrypt(&rh, ciphertext)?;

                // Persist updated session
                if let Some(ref db) = self.db {
                    if let Ok(data) = serde_json::to_vec(session) {
                        let _ = db.save_ratchet_session(sender_identity_key, &data);
                    }
                }

                self.process_ratchet_plaintext(sender_identity_key, plaintext)
            }
            HEADER_RATCHET => {
                if header.len() < 41 {
                    return Err("ratchet header too short".to_string());
                }
                let rh = MessageHeader::from_bytes(&header[1..])?;
                let session = self
                    .ratchet_sessions
                    .get_mut(sender_identity_key)
                    .ok_or("no ratchet session with this peer")?;
                let plaintext = session.decrypt(&rh, ciphertext)?;

                // Persist updated session
                if let Some(ref db) = self.db {
                    if let Ok(data) = serde_json::to_vec(session) {
                        let _ = db.save_ratchet_session(sender_identity_key, &data);
                    }
                }

                self.process_ratchet_plaintext(sender_identity_key, plaintext)
            }
            HEADER_SENDER_KEY => {
                self.ensure_incoming_sender_key_loaded(conversation_id, sender_identity_key);
                let pt =
                    self.sender_keys
                        .decrypt(conversation_id, sender_identity_key, ciphertext)?;
                self.persist_incoming_sender_key(conversation_id, sender_identity_key);
                Ok(DecryptedPayload::Text(pt))
            }
            _ => {
                // Unknown header type — treat as plaintext
                Ok(DecryptedPayload::Text(ciphertext.to_vec()))
            }
        }
    }

    /// Strip the inner type byte from ratchet-decrypted plaintext.
    /// `0x00` = real text (return Text), `0x01` = SKDM (process and return Control).
    /// Legacy plaintexts without a prefix byte are heuristically detected (UTF-8).
    fn process_ratchet_plaintext(
        &mut self,
        sender_identity_key: &[u8; 32],
        mut plaintext: Vec<u8>,
    ) -> Result<DecryptedPayload, String> {
        if plaintext.is_empty() {
            return Ok(DecryptedPayload::Text(plaintext));
        }
        match plaintext[0] {
            INNER_TEXT => {
                plaintext.remove(0);
                Ok(DecryptedPayload::Text(plaintext))
            }
            INNER_SKDM => {
                let body = &plaintext[1..];
                let dist: SenderKeyDistribution = serde_json::from_slice(body)
                    .map_err(|e| format!("decode SKDM: {e}"))?;
                // Only honour SKDMs whose declared sender matches the ratchet peer.
                if &dist.sender_identity_key != sender_identity_key {
                    return Err("SKDM sender mismatch".to_string());
                }
                let group_id = dist.group_id.clone();
                self.sender_keys.process_distribution(&dist);
                self.channel_conversations.insert(group_id.clone());
                self.persist_incoming_sender_key(&group_id, sender_identity_key);
                Ok(DecryptedPayload::Control)
            }
            _ => {
                // Legacy / unprefixed payload — surface as text for backward compat.
                Ok(DecryptedPayload::Text(plaintext))
            }
        }
    }

    /// Mark a conversation as a channel — outgoing messages will be encrypted
    /// with a sender key, and incoming messages will look up the sender key store.
    pub fn mark_channel_conversation(&mut self, conversation_id: &str) {
        self.channel_conversations
            .insert(conversation_id.to_string());
    }

    pub fn is_channel_conversation(&self, conversation_id: &str) -> bool {
        self.channel_conversations.contains(conversation_id)
    }

    /// Build the inner SKDM payload (ratchet-plaintext) for our current outgoing
    /// sender key in `conversation_id`. Creates the key if missing.
    pub fn build_skdm(&mut self, conversation_id: &str) -> Result<Vec<u8>, String> {
        let our_key = self.identity_key()?;
        if !self.sender_keys.has_outgoing(conversation_id) {
            let _ = self
                .sender_keys
                .create_outgoing(conversation_id, &our_key);
            self.persist_outgoing_sender_key(conversation_id);
        }
        let raw = self
            .sender_keys
            .serialize_outgoing(conversation_id)
            .ok_or("missing outgoing sender key")?;
        // Reconstruct the distribution view from the persisted state.
        // (serialize_outgoing returns SenderKeyState; we need a SenderKeyDistribution)
        let state: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| format!("decode outgoing state: {e}"))?;
        let key_id = state["key_id"].as_u64().ok_or("missing key_id")? as u32;
        let chain_arr = state["chain_key"]
            .as_array()
            .ok_or("missing chain_key")?;
        let mut chain_key = [0u8; 32];
        for (i, v) in chain_arr.iter().enumerate().take(32) {
            chain_key[i] = v.as_u64().unwrap_or(0) as u8;
        }
        let dist = SenderKeyDistribution {
            group_id: conversation_id.to_string(),
            sender_identity_key: our_key,
            key_id,
            chain_key,
        };
        let json = serde_json::to_vec(&dist).map_err(|e| format!("encode SKDM: {e}"))?;
        let mut payload = Vec::with_capacity(1 + json.len());
        payload.push(INNER_SKDM);
        payload.extend_from_slice(&json);
        Ok(payload)
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
        let _ = self
            .sender_keys
            .create_outgoing(conversation_id, &our_key);
        self.persist_outgoing_sender_key(conversation_id);
        Ok(())
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
            let _ = self
                .sender_keys
                .create_outgoing(conversation_id, &our_key);
            self.persist_outgoing_sender_key(conversation_id);
        }

        // Build the SKDM JSON payload (sender_identity_key + group_id + key_id + chain_key).
        let raw = self
            .sender_keys
            .serialize_outgoing(conversation_id)
            .ok_or("missing outgoing sender key")?;
        let state: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| format!("decode outgoing state: {e}"))?;
        let key_id = state["key_id"].as_u64().ok_or("missing key_id")? as u32;
        let chain_arr = state["chain_key"].as_array().ok_or("missing chain_key")?;
        let mut chain_key = [0u8; 32];
        for (i, v) in chain_arr.iter().enumerate().take(32) {
            chain_key[i] = v.as_u64().unwrap_or(0) as u8;
        }
        let dist = SenderKeyDistribution {
            group_id: conversation_id.to_string(),
            sender_identity_key: our_key,
            key_id,
            chain_key,
        };
        let json = serde_json::to_vec(&dist).map_err(|e| format!("encode SKDM: {e}"))?;

        // Seal for the peer.
        let sealed =
            veil_crypto::sender_key::seal_skdm(&our_key, peer_identity_key, &json)?;

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
        Ok(seq)
    }

    /// Process an incoming sealed SKDM that the gateway forwarded to us.
    /// Stores the resulting incoming sender key.
    pub fn process_sealed_skdm(&mut self, sealed_wire: &[u8]) -> Result<(), String> {
        let identity = self.identity.as_ref().ok_or("not initialized")?;
        let (sender_ik, payload) = identity.open_sealed_skdm(sealed_wire)?;
        let dist: SenderKeyDistribution = serde_json::from_slice(&payload)
            .map_err(|e| format!("decode SKDM payload: {e}"))?;
        if dist.sender_identity_key != sender_ik {
            return Err("SKDM sender mismatch".to_string());
        }
        let group_id = dist.group_id.clone();
        self.sender_keys.process_distribution(&dist);
        self.channel_conversations.insert(group_id.clone());
        self.persist_incoming_sender_key(&group_id, &sender_ik);
        Ok(())
    }

    /// Drop a peer's incoming sender key (e.g. after a kick/leave WS event).
    pub fn drop_incoming_sender_key(&mut self, conversation_id: &str, sender_ik: &[u8; 32]) {
        self.sender_keys.remove_incoming(conversation_id, sender_ik);
        // Note: per-row delete is not exposed by VeilDb today; on next save it
        // will be overwritten if the peer re-distributes.
    }

    fn persist_outgoing_sender_key(&self, conversation_id: &str) {
        if let (Some(db), Ok(our_key)) = (self.db.as_ref(), self.identity_key()) {
            if let Some(data) = self.sender_keys.serialize_outgoing(conversation_id) {
                let _ = db.save_sender_key(conversation_id, &our_key, &data, true);
            }
        }
    }

    fn persist_incoming_sender_key(&self, conversation_id: &str, sender_ik: &[u8; 32]) {
        if let Some(db) = self.db.as_ref() {
            if let Some(data) = self.sender_keys.serialize_incoming(conversation_id, sender_ik) {
                let _ = db.save_sender_key(conversation_id, sender_ik, &data, false);
            }
        }
    }

    fn ensure_incoming_sender_key_loaded(
        &mut self,
        conversation_id: &str,
        sender_ik: &[u8; 32],
    ) {
        // Already in memory? Nothing to do.
        // (We can't peek into the private map; just attempt a lazy load —
        //  load_incoming is idempotent and overwriting with on-disk state is fine
        //  ONLY if we haven't ratcheted past it. Avoid clobbering newer in-memory state.)
        if self.sender_keys.serialize_incoming(conversation_id, sender_ik).is_some() {
            return;
        }
        if let Some(db) = self.db.as_ref() {
            if let Ok(Some(data)) = db.load_sender_key(conversation_id, sender_ik) {
                let _ = self.sender_keys.load_incoming(conversation_id, sender_ik, &data);
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

    /// Persist a received message to the local DB.
    pub fn persist_incoming_message(
        &self,
        message_id: &str,
        conversation_id: &str,
        sender_key: &[u8],
        plaintext: &str,
        server_timestamp: Option<i64>,
        reply_to_id: Option<&str>,
    ) {
        if let Some(ref db) = self.db {
            let _ = db.insert_message(
                message_id,
                conversation_id,
                sender_key,
                plaintext,
                false,
                server_timestamp,
                reply_to_id,
            );
        }
    }

    /// Send an edit_message to the server.
    pub async fn edit_message(
        &mut self,
        message_id: &str,
        conversation_id: &str,
        new_text: &str,
    ) -> Result<u64, String> {
        let (ciphertext, header_bytes) = self.encrypt_outgoing(conversation_id, new_text)?;

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

        // Update local DB
        if let Some(ref db) = self.db {
            let _ = db.update_message_text(message_id, new_text);
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

        // Delete from local DB
        if let Some(ref db) = self.db {
            let _ = db.delete_message(message_id);
        }

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
        let conn = self.connection.as_ref().ok_or("not connected")?;
        let env = proto::Envelope {
            seq: conn.next_seq().await,
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
        conn.send_envelope(&env).await
    }

    /// Add a reaction to local DB.
    pub fn add_local_reaction(&self, message_id: &str, user_id: &str, emoji: &str, username: &str) {
        if let Some(ref db) = self.db {
            let _ = db.add_reaction(message_id, user_id, emoji, username);
        }
    }

    /// Remove a reaction from local DB.
    pub fn remove_local_reaction(&self, message_id: &str, user_id: &str, emoji: &str) {
        if let Some(ref db) = self.db {
            let _ = db.remove_reaction(message_id, user_id, emoji);
        }
    }

    /// Get reactions for a message from local DB.
    pub fn get_local_reactions(&self, message_id: &str) -> Vec<(String, String, String)> {
        if let Some(ref db) = self.db {
            db.get_reactions(message_id).unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Update a message in local DB (for incoming edits).
    pub fn update_local_message(&self, message_id: &str, new_text: &str) {
        if let Some(ref db) = self.db {
            let _ = db.update_message_text(message_id, new_text);
        }
    }

    /// Delete a message from local DB (for incoming deletes).
    pub fn delete_local_message(&self, message_id: &str) {
        if let Some(ref db) = self.db {
            let _ = db.delete_message(message_id);
        }
    }

    /// Persist a conversation to the local DB.
    pub fn persist_conversation(
        &self,
        id: &str,
        conv_type: u8,
        name: Option<&str>,
        peer_key: Option<&[u8]>,
    ) {
        if let Some(ref db) = self.db {
            let _ = db.insert_conversation(id, conv_type, name, peer_key, None);
        }
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
    pub async fn send_presence(&self, status: i32, status_text: Option<&str>) -> Result<(), String> {
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
