use std::path::Path;
use veil_crypto::fingerprint;
use veil_crypto::kdf;
use veil_crypto::keys::{generate_mnemonic, validate_mnemonic, IdentityKeyPair};
use veil_store::db::VeilDb;
use veil_store::keychain;
use zeroize::Zeroize;

use crate::connection::{Connection, ConnectionConfig, ConnectionEvent};
use crate::protocol::proto;

/// Main client API — the single entry point for all UI interactions.
///
/// All methods are synchronous from the caller's perspective.
/// Crypto operations happen in Rust, never exposed to UI layer.
pub struct VeilClient {
    identity: Option<IdentityKeyPair>,
    db: Option<VeilDb>,
    connection: Option<Connection>,
    device_id: [u8; 16],
}

impl VeilClient {
    pub fn new() -> Self {
        // Generate a random device ID for this instance
        let mut device_id = [0u8; 16];
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(&mut device_id);
        }
        Self {
            identity: None,
            db: None,
            connection: None,
            device_id,
        }
    }

    /// Create a VeilClient with a pre-existing identity (no DB).
    pub fn from_identity(identity: IdentityKeyPair) -> Self {
        let mut device_id = [0u8; 16];
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(&mut device_id);
        }
        Self {
            identity: Some(identity),
            db: None,
            connection: None,
            device_id,
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

        // Derive database encryption key from mnemonic via Argon2id.
        // Argon2id adds brute-force resistance (64 MB, 3 iterations).
        let mut db_key = kdf::derive_db_key(mnemonic)?;

        let db = VeilDb::open(db_path, &db_key)?;
        db_key.zeroize();

        self.identity = Some(identity);
        self.db = Some(db);
        Ok(())
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

        let mut conn = Connection::connect(&config, identity, &self.device_id, "veil-desktop")
            .await?;

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
    /// For now sends plaintext as ciphertext (E2E encryption via ratchet is next step).
    pub async fn send_message(
        &self,
        conversation_id: &str,
        plaintext: &str,
    ) -> Result<u64, String> {
        let conn = self.connection.as_ref().ok_or("not connected")?;
        let seq = conn.next_seq().await;

        let send_msg = proto::SendMessage {
            conversation_id: conversation_id.to_string(),
            ciphertext: plaintext.as_bytes().to_vec(),
            header: vec![],
            msg_type: proto::MessageType::Text.into(),
            reply_to_id: None,
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
        Ok(seq)
    }

    /// Check if we're connected to the server.
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }
}

impl Default for VeilClient {
    fn default() -> Self {
        Self::new()
    }
}
