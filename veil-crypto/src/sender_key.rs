//! # Sender Keys for Group Encryption
//!
//! Each group member maintains a **Sender Key** — a symmetric chain key
//! used to encrypt messages to the group. When a member sends a message:
//!
//! 1. Derive a **message key** from the chain key via HMAC-SHA256
//! 2. Encrypt the message with XChaCha20-Poly1305 using the message key
//! 3. Ratchet the chain key forward (one-way: HMAC(ck, 0x02))
//!
//! ## Key Distribution
//!
//! Sender keys are distributed to group members via pairwise-encrypted
//! messages (using the existing Double Ratchet / X3DH sessions).
//! This means the server never sees sender keys in plaintext.
//!
//! ## Key Rotation
//!
//! A new sender key is generated and distributed when:
//! - A member joins the group (new key for all existing members)
//! - A member leaves the group (new keys for all remaining members)
//! - Periodically after N messages (configurable)
//!
//! ## Wire Format
//!
//! ```text
//! [version: 1B][sender_key_id: 4B][iteration: 4B][nonce: 24B][ciphertext: ...]
//! ```

use crate::aead;
use crate::kdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum messages before mandatory key rotation.
const MAX_CHAIN_ITERATIONS: u32 = 2000;

/// Wire header version for sender key messages.
const SENDER_KEY_VERSION: u8 = 0x03;

/// A Sender Key state for one member in a group.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SenderKeyState {
    /// Unique ID for this sender key generation.
    #[zeroize(skip)]
    pub key_id: u32,
    /// Current chain key (32 bytes). Ratchets forward with each message.
    chain_key: [u8; 32],
    /// Number of messages sent with this chain key.
    #[zeroize(skip)]
    pub iteration: u32,
}

/// A sender key distribution message — sent to each group member
/// via pairwise-encrypted channel.
#[derive(Clone, Serialize, Deserialize)]
pub struct SenderKeyDistribution {
    /// Group/conversation ID.
    pub group_id: String,
    /// Identity key of the sender key owner.
    pub sender_identity_key: [u8; 32],
    /// Unique key ID.
    pub key_id: u32,
    /// Initial chain key (encrypted per-recipient via ratchet session).
    pub chain_key: [u8; 32],
}

/// Manages sender keys for group conversations.
/// Each group has one outgoing key (ours) and N incoming keys (peers).
#[derive(Default)]
pub struct SenderKeyStore {
    /// Our outgoing sender keys per group: group_id → SenderKeyState
    outgoing: std::collections::HashMap<String, SenderKeyState>,
    /// Incoming sender keys: (group_id, sender_ik_hex) → SenderKeyState
    incoming: std::collections::HashMap<(String, [u8; 32]), SenderKeyState>,
}

impl Default for SenderKeyState {
    fn default() -> Self {
        Self::new()
    }
}

impl SenderKeyState {
    /// Create a new sender key with a random chain key.
    pub fn new() -> Self {
        let mut chain_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut chain_key);
        Self {
            key_id: rand::random::<u32>(),
            chain_key,
            iteration: 0,
        }
    }

    /// Create from a received distribution message.
    pub fn from_distribution(key_id: u32, chain_key: [u8; 32]) -> Self {
        Self {
            key_id,
            chain_key,
            iteration: 0,
        }
    }

    /// Derive the current message key without advancing the chain.
    fn message_key(&self) -> [u8; 32] {
        kdf::hmac_sha256(&self.chain_key, b"\x01")
    }

    /// Advance the chain key forward (irreversible).
    fn ratchet(&mut self) {
        self.chain_key = kdf::hmac_sha256(&self.chain_key, b"\x02");
        self.iteration += 1;
    }

    /// Whether this key needs rotation (too many iterations).
    pub fn needs_rotation(&self) -> bool {
        self.iteration >= MAX_CHAIN_ITERATIONS
    }

    /// Encrypt a message, advance the chain.
    ///
    /// Returns the full wire-format bytes:
    /// `[0x03][key_id: 4B LE][iteration: 4B LE][nonce: 24B][ciphertext]`
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mk = self.message_key();
        let (ct, nonce) = aead::encrypt(&mk, plaintext)?;

        // Build wire format
        let mut wire = Vec::with_capacity(1 + 4 + 4 + 24 + ct.len());
        wire.push(SENDER_KEY_VERSION);
        wire.extend_from_slice(&self.key_id.to_le_bytes());
        wire.extend_from_slice(&self.iteration.to_le_bytes());
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&ct);

        self.ratchet();
        Ok(wire)
    }
}

impl SenderKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate (or rotate) our sender key for a group.
    /// Returns the distribution to send to all group members.
    pub fn create_outgoing(
        &mut self,
        group_id: &str,
        our_identity_key: &[u8; 32],
    ) -> SenderKeyDistribution {
        let state = SenderKeyState::new();
        let dist = SenderKeyDistribution {
            group_id: group_id.to_string(),
            sender_identity_key: *our_identity_key,
            key_id: state.key_id,
            chain_key: state.chain_key,
        };
        self.outgoing.insert(group_id.to_string(), state);
        dist
    }

    /// Process a received sender key distribution.
    pub fn process_distribution(&mut self, dist: &SenderKeyDistribution) {
        let state = SenderKeyState::from_distribution(dist.key_id, dist.chain_key);
        self.incoming
            .insert((dist.group_id.clone(), dist.sender_identity_key), state);
    }

    /// Encrypt a group message (using our outgoing sender key).
    pub fn encrypt(&mut self, group_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let state = self.outgoing.get_mut(group_id).ok_or_else(|| {
            "no sender key for this group — call create_outgoing first".to_string()
        })?;

        state.encrypt(plaintext)
    }

    /// Decrypt a group message from a peer.
    pub fn decrypt(
        &mut self,
        group_id: &str,
        sender_ik: &[u8; 32],
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        // Parse wire format
        if wire.len() < 1 + 4 + 4 + 24 + 16 {
            return Err("sender key message too short".to_string());
        }
        if wire[0] != SENDER_KEY_VERSION {
            return Err(format!("unknown sender key version: {:#x}", wire[0]));
        }

        let key_id = u32::from_le_bytes(wire[1..5].try_into().unwrap());
        let iteration = u32::from_le_bytes(wire[5..9].try_into().unwrap());
        let nonce: [u8; 24] = wire[9..33].try_into().unwrap();
        let ciphertext = &wire[33..];

        let lookup = (group_id.to_string(), *sender_ik);
        let state = self.incoming.get_mut(&lookup).ok_or_else(|| {
            "no sender key from this peer — key distribution required".to_string()
        })?;

        // Verify key_id matches
        if state.key_id != key_id {
            return Err(format!(
                "sender key id mismatch: expected {}, got {}",
                state.key_id, key_id
            ));
        }

        // Fast-forward the chain if the sender is ahead of us
        // (we may have missed messages — ratchet forward to catch up)
        if iteration > state.iteration {
            let skip = iteration - state.iteration;
            if skip > MAX_CHAIN_ITERATIONS {
                return Err("sender key too far ahead — key rotation needed".to_string());
            }
            for _ in 0..skip {
                state.ratchet();
            }
        } else if iteration < state.iteration {
            return Err("sender key message from the past — possible replay".to_string());
        }

        // Decrypt with current message key
        let mk = state.message_key();
        let plaintext = aead::decrypt(&mk, ciphertext, &nonce)?;

        // Advance chain
        state.ratchet();

        Ok(plaintext)
    }

    /// Check if our outgoing key for a group needs rotation.
    pub fn needs_rotation(&self, group_id: &str) -> bool {
        self.outgoing
            .get(group_id)
            .map(|s| s.needs_rotation())
            .unwrap_or(true)
    }

    /// Check if we have an outgoing key for a group.
    pub fn has_outgoing(&self, group_id: &str) -> bool {
        self.outgoing.contains_key(group_id)
    }

    /// Remove all keys for a group (when leaving).
    pub fn remove_group(&mut self, group_id: &str) {
        self.outgoing.remove(group_id);
        self.incoming.retain(|(gid, _), _| gid != group_id);
    }

    /// Remove a single incoming key (e.g. when a member leaves the group).
    pub fn remove_incoming(&mut self, group_id: &str, sender_ik: &[u8; 32]) {
        self.incoming.remove(&(group_id.to_string(), *sender_ik));
    }

    /// Serialize the outgoing key state for a group (for persistence).
    pub fn serialize_outgoing(&self, group_id: &str) -> Option<Vec<u8>> {
        self.outgoing
            .get(group_id)
            .and_then(|s| serde_json::to_vec(s).ok())
    }

    /// Serialize an incoming key state (for persistence).
    pub fn serialize_incoming(&self, group_id: &str, sender_ik: &[u8; 32]) -> Option<Vec<u8>> {
        self.incoming
            .get(&(group_id.to_string(), *sender_ik))
            .and_then(|s| serde_json::to_vec(s).ok())
    }

    /// Restore an outgoing key state from persisted bytes.
    pub fn load_outgoing(&mut self, group_id: &str, data: &[u8]) -> Result<(), String> {
        let state: SenderKeyState =
            serde_json::from_slice(data).map_err(|e| format!("decode outgoing sk: {e}"))?;
        self.outgoing.insert(group_id.to_string(), state);
        Ok(())
    }

    /// Restore an incoming key state from persisted bytes.
    pub fn load_incoming(
        &mut self,
        group_id: &str,
        sender_ik: &[u8; 32],
        data: &[u8],
    ) -> Result<(), String> {
        let state: SenderKeyState =
            serde_json::from_slice(data).map_err(|e| format!("decode incoming sk: {e}"))?;
        self.incoming
            .insert((group_id.to_string(), *sender_ik), state);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sender_key_encrypt_decrypt() {
        let alice_ik = [1u8; 32];
        let bob_ik = [2u8; 32];
        let group = "test-group";

        let mut alice_store = SenderKeyStore::new();
        let mut bob_store = SenderKeyStore::new();

        // Alice creates sender key and distributes
        let alice_dist = alice_store.create_outgoing(group, &alice_ik);
        bob_store.process_distribution(&alice_dist);

        // Bob creates sender key and distributes
        let bob_dist = bob_store.create_outgoing(group, &bob_ik);
        alice_store.process_distribution(&bob_dist);

        // Alice encrypts, Bob decrypts
        let msg = b"Hello group!";
        let ct = alice_store.encrypt(group, msg).unwrap();
        let pt = bob_store.decrypt(group, &alice_ik, &ct).unwrap();
        assert_eq!(pt, msg);

        // Bob encrypts, Alice decrypts
        let msg2 = b"Hey Alice!";
        let ct2 = bob_store.encrypt(group, msg2).unwrap();
        let pt2 = alice_store.decrypt(group, &bob_ik, &ct2).unwrap();
        assert_eq!(pt2, msg2);
    }

    #[test]
    fn test_chain_ratchet_forward() {
        let alice_ik = [1u8; 32];
        let group = "test-group";

        let mut alice = SenderKeyStore::new();
        let mut bob = SenderKeyStore::new();

        let dist = alice.create_outgoing(group, &alice_ik);
        bob.process_distribution(&dist);

        // Alice sends 3 messages
        let ct1 = alice.encrypt(group, b"msg1").unwrap();
        let _ct2 = alice.encrypt(group, b"msg2").unwrap();
        let ct3 = alice.encrypt(group, b"msg3").unwrap();

        // Bob receives only msg3 (skipped 1 and 2)
        let pt3 = bob.decrypt(group, &alice_ik, &ct3).unwrap();
        assert_eq!(pt3, b"msg3");

        // Bob cannot decrypt ct1 or ct2 now (chain moved forward)
        assert!(bob.decrypt(group, &alice_ik, &ct1).is_err());
    }

    #[test]
    fn test_key_rotation_flag() {
        let ik = [1u8; 32];
        let group = "test-group";
        let mut store = SenderKeyStore::new();
        store.create_outgoing(group, &ik);
        assert!(!store.needs_rotation(group));
    }
}

// ─── Sealed SKDM Envelope ──────────────────────────────
//
// Sender Key Distribution Messages are delivered to peers without relying on
// the (currently incomplete) cold-start of pairwise Double Ratchet sessions.
// We use ECIES-style sealed envelopes:
//   ephemeral X25519 keypair → DH(eph_priv, recipient_static_pub) → HKDF → AEAD key
// Authenticity of the sender is asserted by including the sender's identity
// public key in the AAD-like context (HKDF salt) so any tampering breaks decryption,
// and by transmitting the SKDM via the server which forwards based on
// conversation_membership of the authenticated sender.
//
// Wire format:
//   [1B version=0x01][32B sender_ik][32B eph_pub][24B nonce][N B ciphertext]

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

const SEALED_SKDM_VERSION: u8 = 0x01;

/// Seal a SKDM JSON for a specific recipient. Returns wire bytes.
pub fn seal_skdm(
    sender_ik: &[u8; 32],
    recipient_ik: &[u8; 32],
    skdm_json: &[u8],
) -> Result<Vec<u8>, String> {
    let mut eph_secret_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut eph_secret_bytes);
    let eph_secret = X25519Secret::from(eph_secret_bytes);
    let eph_pub = X25519PublicKey::from(&eph_secret);

    let recipient_pub = X25519PublicKey::from(*recipient_ik);
    let shared = eph_secret.diffie_hellman(&recipient_pub);
    eph_secret_bytes.zeroize();

    // HKDF salt binds sender_ik || recipient_ik; info is a domain separator.
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(sender_ik);
    salt.extend_from_slice(recipient_ik);
    let key = kdf::hkdf_sha256(&salt, shared.as_bytes(), b"veil-skdm-v1", 32);
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);

    let (ct, nonce) = aead::encrypt(&key_arr, skdm_json)?;
    key_arr.zeroize();

    let mut wire = Vec::with_capacity(1 + 32 + 32 + 24 + ct.len());
    wire.push(SEALED_SKDM_VERSION);
    wire.extend_from_slice(sender_ik);
    wire.extend_from_slice(eph_pub.as_bytes());
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&ct);
    Ok(wire)
}

/// Open a sealed SKDM. Returns `(sender_identity_key, skdm_json_bytes)`.
pub fn open_skdm(
    recipient_ik_secret: &[u8; 32],
    recipient_ik_public: &[u8; 32],
    wire: &[u8],
) -> Result<([u8; 32], Vec<u8>), String> {
    if wire.len() < 1 + 32 + 32 + 24 + 16 {
        return Err("sealed SKDM too short".to_string());
    }
    if wire[0] != SEALED_SKDM_VERSION {
        return Err(format!("unknown sealed SKDM version: {:#x}", wire[0]));
    }
    let mut sender_ik = [0u8; 32];
    sender_ik.copy_from_slice(&wire[1..33]);
    let mut eph_pub_bytes = [0u8; 32];
    eph_pub_bytes.copy_from_slice(&wire[33..65]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&wire[65..89]);
    let ct = &wire[89..];

    let recipient_secret = X25519Secret::from(*recipient_ik_secret);
    let eph_pub = X25519PublicKey::from(eph_pub_bytes);
    let shared = recipient_secret.diffie_hellman(&eph_pub);

    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(&sender_ik);
    salt.extend_from_slice(recipient_ik_public);
    let key = kdf::hkdf_sha256(&salt, shared.as_bytes(), b"veil-skdm-v1", 32);
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);

    let pt = aead::decrypt(&key_arr, ct, &nonce)?;
    key_arr.zeroize();
    Ok((sender_ik, pt))
}

#[cfg(test)]
mod sealed_tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn test_seal_open_roundtrip() {
        let mut rng = rand::rngs::OsRng;
        let mut sender_secret_bytes = [0u8; 32];
        let mut recipient_secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut sender_secret_bytes);
        rng.fill_bytes(&mut recipient_secret_bytes);

        let sender_secret = StaticSecret::from(sender_secret_bytes);
        let recipient_secret = StaticSecret::from(recipient_secret_bytes);
        let sender_pub = PublicKey::from(&sender_secret);
        let recipient_pub = PublicKey::from(&recipient_secret);

        let payload = b"{\"group_id\":\"abc\",\"key_id\":1}";
        let sealed = seal_skdm(sender_pub.as_bytes(), recipient_pub.as_bytes(), payload).unwrap();
        let (got_sender, got_payload) = open_skdm(
            &recipient_secret_bytes,
            recipient_pub.as_bytes(),
            &sealed,
        )
        .unwrap();
        assert_eq!(&got_sender, sender_pub.as_bytes());
        assert_eq!(got_payload, payload);
    }
}
