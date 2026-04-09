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
