use std::path::Path;
use veil_crypto::fingerprint;
use veil_crypto::kdf;
use veil_crypto::keys::{generate_mnemonic, validate_mnemonic, IdentityKeyPair};
use veil_store::db::VeilDb;
use veil_store::keychain;
use zeroize::Zeroize;

/// Main client API — the single entry point for all UI interactions.
///
/// All methods are synchronous from the caller's perspective.
/// Crypto operations happen in Rust, never exposed to UI layer.
pub struct VeilClient {
    identity: Option<IdentityKeyPair>,
    db: Option<VeilDb>,
}

impl VeilClient {
    pub fn new() -> Self {
        Self {
            identity: None,
            db: None,
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
}

impl Default for VeilClient {
    fn default() -> Self {
        Self::new()
    }
}
