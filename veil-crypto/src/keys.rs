use bip39::Mnemonic;
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::kdf;

/// A complete identity key pair for a Veil user.
/// Contains X25519 (encryption) and Ed25519 (signing) key pairs.
///
/// Implements ZeroizeOnDrop — keys are zeroed from memory when dropped.
#[derive(ZeroizeOnDrop)]
pub struct IdentityKeyPair {
    /// X25519 static secret (for ECDH key agreement)
    #[zeroize(skip)] // x25519_dalek handles its own zeroize
    x25519_secret: X25519StaticSecret,
    /// X25519 public key
    #[zeroize(skip)]
    x25519_public: X25519PublicKey,
    /// Ed25519 signing key
    #[zeroize(skip)]
    ed25519_signing: Ed25519SigningKey,
    /// Ed25519 verifying (public) key
    #[zeroize(skip)]
    ed25519_verifying: Ed25519VerifyingKey,
}

impl IdentityKeyPair {
    /// Generate a new random identity (for testing or first-time setup before mnemonic backup).
    pub fn generate() -> Self {
        let mnemonic = generate_mnemonic();
        Self::from_mnemonic(&mnemonic.to_string())
            .expect("Generated mnemonic should always be valid")
    }

    /// Derive identity from a BIP39 mnemonic phrase.
    ///
    /// This is the primary way to create an identity:
    /// 1. Mnemonic → Argon2id → 64-byte seed
    /// 2. seed[0..32] → X25519 keypair (encryption)
    /// 3. seed[32..64] → Ed25519 keypair (signing)
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, String> {
        // Validate mnemonic
        let _m: Mnemonic = mnemonic.parse()
            .map_err(|e| format!("invalid mnemonic: {e}"))?;

        // Derive 64-byte seed
        let mut seed = kdf::derive_seed_from_mnemonic(mnemonic)?;

        // Split seed: [0..32] for X25519, [32..64] for Ed25519
        let mut x_bytes = [0u8; 32];
        let mut e_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&seed[..32]);
        e_bytes.copy_from_slice(&seed[32..]);

        // Zeroize the full seed immediately
        seed.zeroize();

        let x25519_secret = X25519StaticSecret::from(x_bytes);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        let ed25519_signing = Ed25519SigningKey::from_bytes(&e_bytes);
        let ed25519_verifying = ed25519_signing.verifying_key();

        // Zeroize intermediate key material
        x_bytes.zeroize();
        e_bytes.zeroize();

        Ok(Self {
            x25519_secret,
            x25519_public,
            ed25519_signing,
            ed25519_verifying,
        })
    }

    /// X25519 public key bytes (32 bytes). Safe to share.
    pub fn x25519_public_bytes(&self) -> [u8; 32] {
        *self.x25519_public.as_bytes()
    }

    /// Ed25519 public (verifying) key bytes (32 bytes). Safe to share.
    pub fn ed25519_public_bytes(&self) -> [u8; 32] {
        self.ed25519_verifying.to_bytes()
    }

    /// Perform X25519 Diffie-Hellman with a peer's public key.
    /// Returns shared secret (32 bytes).
    pub fn x25519_dh(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer_key = X25519PublicKey::from(*peer_public);
        *self.x25519_secret.diffie_hellman(&peer_key).as_bytes()
    }

    /// Get reference to the X25519 static secret (for advanced operations like X3DH).
    pub(crate) fn x25519_secret(&self) -> &X25519StaticSecret {
        &self.x25519_secret
    }

    /// Get reference to the Ed25519 signing key.
    pub(crate) fn ed25519_signing_key(&self) -> &Ed25519SigningKey {
        &self.ed25519_signing
    }

    /// Get reference to the X25519 public key.
    pub fn x25519_public_key(&self) -> &X25519PublicKey {
        &self.x25519_public
    }

    /// Get reference to the Ed25519 verifying key.
    pub fn ed25519_verifying_key(&self) -> &Ed25519VerifyingKey {
        &self.ed25519_verifying
    }

    /// Export the public-only bundle (safe to send to server).
    pub fn to_public_bundle(&self) -> KeyBundle {
        KeyBundle {
            identity_key: self.x25519_public_bytes(),
            signing_key: self.ed25519_public_bytes(),
        }
    }
}

/// Public-only key bundle (no secrets). Safe to transmit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeyBundle {
    /// X25519 public key (32 bytes)
    pub identity_key: [u8; 32],
    /// Ed25519 public key (32 bytes)
    pub signing_key: [u8; 32],
}

/// Generate a new random BIP39 mnemonic (12 words, 128-bit entropy).
pub fn generate_mnemonic() -> Mnemonic {
    let mut entropy = [0u8; 16]; // 128 bits = 12 words
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).expect("Mnemonic generation should not fail");
    entropy.zeroize();
    mnemonic
}

/// Validate a BIP39 mnemonic string.
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    mnemonic.parse::<Mnemonic>().is_ok()
}

/// Generate a random X25519 ephemeral keypair.
/// Used in X3DH and ratchet DH steps.
pub fn generate_x25519_keypair() -> (X25519StaticSecret, X25519PublicKey) {
    let secret = X25519StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    (secret, public)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_generate_mnemonic() {
        let m = generate_mnemonic();
        let s = m.to_string();
        let words: Vec<&str> = s.split_whitespace().collect();
        assert_eq!(words.len(), 12, "BIP39 mnemonic must be 12 words");
        assert!(validate_mnemonic(&m.to_string()));
    }

    #[test]
    fn test_identity_from_mnemonic_deterministic() {
        let id1 = IdentityKeyPair::from_mnemonic(TEST_MNEMONIC).unwrap();
        let id2 = IdentityKeyPair::from_mnemonic(TEST_MNEMONIC).unwrap();
        assert_eq!(id1.x25519_public_bytes(), id2.x25519_public_bytes());
        assert_eq!(id1.ed25519_public_bytes(), id2.ed25519_public_bytes());
    }

    #[test]
    fn test_identity_different_mnemonics() {
        let id1 = IdentityKeyPair::from_mnemonic(TEST_MNEMONIC).unwrap();
        let id2 = IdentityKeyPair::generate();
        assert_ne!(id1.x25519_public_bytes(), id2.x25519_public_bytes());
    }

    #[test]
    fn test_dh_key_agreement() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let shared_ab = alice.x25519_dh(&bob.x25519_public_bytes());
        let shared_ba = bob.x25519_dh(&alice.x25519_public_bytes());

        assert_eq!(shared_ab, shared_ba, "DH shared secrets must match");
    }

    #[test]
    fn test_public_bundle() {
        let id = IdentityKeyPair::generate();
        let bundle = id.to_public_bundle();
        assert_eq!(bundle.identity_key, id.x25519_public_bytes());
        assert_eq!(bundle.signing_key, id.ed25519_public_bytes());
    }

    #[test]
    fn test_invalid_mnemonic() {
        assert!(IdentityKeyPair::from_mnemonic("invalid words here").is_err());
    }

    #[test]
    fn test_validate_mnemonic() {
        assert!(validate_mnemonic(TEST_MNEMONIC));
        assert!(!validate_mnemonic("not a valid mnemonic"));
    }
}
