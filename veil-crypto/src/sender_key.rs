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
//! [version=0x04: 1B][generation: 4B][iteration: 4B][nonce: 24B][ciphertext: ...]
//! ```
//!
//! The version, generation, iteration, group ID, and sender identity are
//! authenticated as AEAD associated data.

use crate::aead;
use crate::kdf;
use crate::keys::IdentityKeyPair;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Maximum messages before mandatory key rotation.
const MAX_CHAIN_ITERATIONS: u32 = 2000;
/// A sender cannot leave more skipped keys than one complete generation.
const MAX_SKIPPED_KEYS_PER_SENDER: usize = MAX_CHAIN_ITERATIONS as usize;
/// Process-wide bound across all group senders.
const MAX_TOTAL_SKIPPED_SENDER_KEYS: usize = 10_000;
const PERSISTED_INCOMING_SENDER_KEY_VERSION: u8 = 0x01;
const ED25519_SIGNATURE_SIZE: usize = 64;

/// Wire header version for sender key messages. Version 4 authenticates the
/// wire header plus group and sender context as AEAD associated data.
const SENDER_KEY_VERSION: u8 = 0x04;
const SENDER_KEY_MESSAGE_DOMAIN: &[u8] = b"veil-sender-key-message-v4";
/// Signed envelope placed around the symmetric v4 Sender Key message.
const SIGNED_SENDER_KEY_VERSION: u8 = 0x05;
const SIGNED_SENDER_KEY_DOMAIN: &[u8] = b"veil-sender-key-message-v5\0";
const MAX_SIGNED_SENDER_KEY_INNER_SIZE: usize = 16 * 1024 * 1024;

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
    /// Identity key to which this state is cryptographically bound. Legacy
    /// persisted states deserialize as `None` and must be redistributed.
    #[serde(default)]
    owner_identity_key: Option<[u8; 32]>,
}

/// A sender key distribution message — sent to each group member
/// via pairwise-encrypted channel.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SenderKeyDistribution {
    /// Group/conversation ID.
    #[zeroize(skip)]
    pub group_id: String,
    /// Identity key of the sender key owner.
    #[zeroize(skip)]
    pub sender_identity_key: [u8; 32],
    /// Unique key ID.
    #[zeroize(skip)]
    pub key_id: u32,
    /// Initial chain key (encrypted per-recipient via ratchet session).
    pub chain_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SkippedSenderKeyId {
    group_id: String,
    sender_identity_key: [u8; 32],
    generation: u32,
    iteration: u32,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct PendingSkippedSenderKey {
    #[zeroize(skip)]
    id: SkippedSenderKeyId,
    message_key: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct PersistedIncomingSenderKey {
    version: u8,
    state: SenderKeyState,
    skipped_keys: Vec<PersistedSkippedSenderKey>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct PersistedSkippedSenderKey {
    #[zeroize(skip)]
    generation: u32,
    #[zeroize(skip)]
    iteration: u32,
    message_key: [u8; 32],
}

/// Manages sender keys for group conversations.
/// Each group has one outgoing key (ours) and N incoming keys (peers).
#[derive(Default, Clone)]
pub struct SenderKeyStore {
    /// Our outgoing sender keys per group: group_id → SenderKeyState
    outgoing: std::collections::HashMap<String, SenderKeyState>,
    /// Incoming sender keys: (group_id, sender_ik_hex) → SenderKeyState
    incoming: std::collections::HashMap<(String, [u8; 32]), SenderKeyState>,
    /// Out-of-order message keys, retained until authenticated consumption.
    /// Persistence is scoped to each encrypted incoming-state row.
    skipped_message_keys: BTreeMap<SkippedSenderKeyId, [u8; 32]>,
}

impl Drop for SenderKeyStore {
    fn drop(&mut self) {
        for message_key in self.skipped_message_keys.values_mut() {
            message_key.zeroize();
        }
    }
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
            key_id: 1,
            chain_key,
            iteration: 0,
            owner_identity_key: None,
        }
    }

    fn new_for_owner(owner_identity_key: [u8; 32], generation: u32) -> Self {
        let mut state = Self::new();
        state.key_id = generation;
        state.owner_identity_key = Some(owner_identity_key);
        state
    }

    /// Create from a received distribution message.
    pub fn from_distribution(key_id: u32, chain_key: [u8; 32]) -> Self {
        Self {
            key_id,
            chain_key,
            iteration: 0,
            owner_identity_key: None,
        }
    }

    fn from_distribution_for_sender(
        key_id: u32,
        chain_key: [u8; 32],
        sender_identity_key: [u8; 32],
    ) -> Self {
        Self {
            key_id,
            chain_key,
            iteration: 0,
            owner_identity_key: Some(sender_identity_key),
        }
    }

    /// Derive the current message key without advancing the chain.
    fn message_key(&self) -> [u8; 32] {
        kdf::hmac_sha256(&self.chain_key, b"\x01")
    }

    /// Advance the chain key forward (irreversible).
    fn ratchet(&mut self) -> Result<(), String> {
        self.chain_key = kdf::hmac_sha256(&self.chain_key, b"\x02");
        self.iteration = self
            .iteration
            .checked_add(1)
            .ok_or("sender key iteration overflow".to_string())?;
        Ok(())
    }

    /// Whether this key needs rotation (too many iterations).
    pub fn needs_rotation(&self) -> bool {
        self.iteration >= MAX_CHAIN_ITERATIONS
    }

    /// Encrypt a message, advance the chain.
    ///
    /// The context-free method is intentionally disabled: authenticating only
    /// the ciphertext while leaving group and sender metadata unbound permits
    /// cross-context substitution. Use [`SenderKeyStore::encrypt`] instead.
    #[deprecated(note = "use SenderKeyStore::encrypt so group and sender are authenticated")]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let _ = plaintext;
        Err("context-free sender-key encryption is disabled".to_string())
    }

    fn encrypt_bound(
        &mut self,
        group_id: &str,
        sender_identity_key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        if self.needs_rotation() {
            return Err("sender key rotation required".to_string());
        }
        if self.owner_identity_key.as_ref() != Some(sender_identity_key) {
            return Err("sender key owner mismatch".to_string());
        }

        let mut mk = self.message_key();
        let mut header = Vec::with_capacity(9);
        header.push(SENDER_KEY_VERSION);
        header.extend_from_slice(&self.key_id.to_le_bytes());
        header.extend_from_slice(&self.iteration.to_le_bytes());
        let aad = sender_message_aad(group_id, sender_identity_key, &header)?;
        let result = aead::encrypt_with_aad(&mk, plaintext, &aad);
        mk.zeroize();
        let (ct, nonce) = result?;

        // Build wire format
        let mut wire = Vec::with_capacity(1 + 4 + 4 + 24 + ct.len());
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&ct);

        self.ratchet()?;
        Ok(wire)
    }
}

fn sender_message_aad(
    group_id: &str,
    sender_identity_key: &[u8; 32],
    header: &[u8],
) -> Result<Vec<u8>, String> {
    let group_len =
        u32::try_from(group_id.len()).map_err(|_| "sender-key group id too large".to_string())?;
    let mut aad = Vec::with_capacity(
        SENDER_KEY_MESSAGE_DOMAIN.len() + 4 + group_id.len() + 32 + header.len(),
    );
    aad.extend_from_slice(SENDER_KEY_MESSAGE_DOMAIN);
    aad.extend_from_slice(&group_len.to_be_bytes());
    aad.extend_from_slice(group_id.as_bytes());
    aad.extend_from_slice(sender_identity_key);
    aad.extend_from_slice(header);
    Ok(aad)
}

/// Signed Sender Key wire format:
///
/// `[0x05][group_len:2 BE][group][sender_x25519:32][inner_len:4 BE]`
/// `[inner_v4][ed25519_signature:64]`
///
/// The signature covers
/// `veil-sender-key-message-v5\0 || every byte before the signature`, thereby
/// binding the exact group ID, claimed sender identity, and complete v4 wire.
struct ParsedSignedSenderKey<'a> {
    group_id: &'a str,
    sender_identity_key: [u8; 32],
    inner_v4: &'a [u8],
    signed_portion: &'a [u8],
    signature: [u8; ED25519_SIGNATURE_SIZE],
}

fn encode_signed_sender_key(
    signer: &IdentityKeyPair,
    group_id: &str,
    sender_identity_key: &[u8; 32],
    inner_v4: &[u8],
) -> Result<Vec<u8>, String> {
    if group_id.is_empty() {
        return Err("signed sender-key group id must not be empty".to_string());
    }
    let group_len = u16::try_from(group_id.len())
        .map_err(|_| "signed sender-key group id is too long".to_string())?;
    if inner_v4.len() < 1 + 4 + 4 + 24 + 16 || inner_v4.len() > MAX_SIGNED_SENDER_KEY_INNER_SIZE {
        return Err("signed sender-key inner message length is invalid".to_string());
    }
    if inner_v4[0] != SENDER_KEY_VERSION {
        return Err("signed sender-key envelope requires an inner v4 message".to_string());
    }
    let inner_len = u32::try_from(inner_v4.len())
        .map_err(|_| "signed sender-key inner message is too long".to_string())?;

    let mut wire = Vec::with_capacity(
        1 + 2 + group_id.len() + 32 + 4 + inner_v4.len() + ED25519_SIGNATURE_SIZE,
    );
    wire.push(SIGNED_SENDER_KEY_VERSION);
    wire.extend_from_slice(&group_len.to_be_bytes());
    wire.extend_from_slice(group_id.as_bytes());
    wire.extend_from_slice(sender_identity_key);
    wire.extend_from_slice(&inner_len.to_be_bytes());
    wire.extend_from_slice(inner_v4);

    let mut signature_input = Vec::with_capacity(SIGNED_SENDER_KEY_DOMAIN.len() + wire.len());
    signature_input.extend_from_slice(SIGNED_SENDER_KEY_DOMAIN);
    signature_input.extend_from_slice(&wire);
    let signature = crate::signature::sign(signer, &signature_input);
    wire.extend_from_slice(&signature);
    Ok(wire)
}

fn parse_signed_sender_key(wire: &[u8]) -> Result<ParsedSignedSenderKey<'_>, String> {
    const MIN_INNER_SIZE: usize = 1 + 4 + 4 + 24 + 16;
    const FIXED_SIZE: usize = 1 + 2 + 32 + 4 + MIN_INNER_SIZE + ED25519_SIGNATURE_SIZE;
    if wire.len() < FIXED_SIZE {
        return Err("signed sender-key message is too short".to_string());
    }
    if wire[0] != SIGNED_SENDER_KEY_VERSION {
        return Err(format!(
            "unsupported signed sender-key version: {:#x}",
            wire[0]
        ));
    }

    let group_len = u16::from_be_bytes([wire[1], wire[2]]) as usize;
    if group_len == 0 {
        return Err("signed sender-key group id must not be empty".to_string());
    }
    let group_end = 3usize
        .checked_add(group_len)
        .ok_or("invalid signed sender-key group length")?;
    let metadata_end = group_end
        .checked_add(32 + 4)
        .ok_or("invalid signed sender-key metadata length")?;
    if metadata_end > wire.len() {
        return Err("signed sender-key metadata is truncated".to_string());
    }
    let group_id = std::str::from_utf8(&wire[3..group_end])
        .map_err(|_| "signed sender-key group id is not UTF-8")?;

    let mut cursor = group_end;
    let mut sender_identity_key = [0u8; 32];
    sender_identity_key.copy_from_slice(&wire[cursor..cursor + 32]);
    cursor += 32;
    let inner_len = u32::from_be_bytes(
        wire[cursor..cursor + 4]
            .try_into()
            .map_err(|_| "invalid signed sender-key inner length")?,
    ) as usize;
    cursor += 4;
    if !(MIN_INNER_SIZE..=MAX_SIGNED_SENDER_KEY_INNER_SIZE).contains(&inner_len) {
        return Err("signed sender-key inner message length is invalid".to_string());
    }

    let signature_start = cursor
        .checked_add(inner_len)
        .ok_or("invalid signed sender-key inner length")?;
    let expected_len = signature_start
        .checked_add(ED25519_SIGNATURE_SIZE)
        .ok_or("invalid signed sender-key total length")?;
    if expected_len != wire.len() {
        return Err("signed sender-key message has trailing or truncated bytes".to_string());
    }
    let inner_v4 = &wire[cursor..signature_start];
    if inner_v4[0] != SENDER_KEY_VERSION {
        return Err("signed sender-key envelope contains a non-v4 inner message".to_string());
    }
    let signature = wire[signature_start..]
        .try_into()
        .map_err(|_| "invalid signed sender-key signature length")?;

    Ok(ParsedSignedSenderKey {
        group_id,
        sender_identity_key,
        inner_v4,
        signed_portion: &wire[..signature_start],
        signature,
    })
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
        let generation = self
            .outgoing
            .get(group_id)
            .map(|state| {
                state
                    .key_id
                    .checked_add(1)
                    .expect("sender key generation exhausted")
            })
            .unwrap_or(1);
        self.create_outgoing_at_generation(group_id, our_identity_key, generation)
            .expect("validated sender key generation")
    }

    /// Create or rotate an outgoing sender key at an authoritative generation
    /// (for example a server-authenticated membership epoch). This avoids
    /// generation reuse after local state restoration or device migration.
    pub fn create_outgoing_at_generation(
        &mut self,
        group_id: &str,
        our_identity_key: &[u8; 32],
        generation: u32,
    ) -> Result<SenderKeyDistribution, String> {
        if generation == 0 {
            return Err("sender key generation must be non-zero".to_string());
        }
        if let Some(current) = self.outgoing.get(group_id) {
            if generation <= current.key_id {
                return Err("sender key generation must increase".to_string());
            }
        }

        let state = SenderKeyState::new_for_owner(*our_identity_key, generation);
        let dist = SenderKeyDistribution {
            group_id: group_id.to_string(),
            sender_identity_key: *our_identity_key,
            key_id: state.key_id,
            chain_key: state.chain_key,
        };
        self.outgoing.insert(group_id.to_string(), state);
        Ok(dist)
    }

    /// Process an authenticated sender key distribution.
    ///
    /// Generations are strictly monotonic per sender and group. Re-delivery of
    /// the current generation is idempotent and cannot rewind an advanced
    /// receiving chain; older generations are rejected as replays.
    pub fn process_distribution(&mut self, dist: &SenderKeyDistribution) -> Result<bool, String> {
        if dist.key_id == 0 {
            return Err("sender key generation must be non-zero".to_string());
        }
        let lookup = (dist.group_id.clone(), dist.sender_identity_key);
        if let Some(current) = self.incoming.get(&lookup) {
            if dist.key_id < current.key_id {
                return Err("stale sender key distribution rejected".to_string());
            }
            if dist.key_id == current.key_id {
                return Ok(false);
            }
        }

        let state = SenderKeyState::from_distribution_for_sender(
            dist.key_id,
            dist.chain_key,
            dist.sender_identity_key,
        );
        // A generation change makes every cached message key from the previous
        // generation invalid and potentially replayable.
        self.purge_skipped_keys(&dist.group_id, &dist.sender_identity_key);
        self.incoming.insert(lookup, state);
        Ok(true)
    }

    /// Decode, cross-check, and install a distribution obtained from
    /// [`open_skdm_authenticated`]. This is the preferred fail-closed receive
    /// path because it cannot forget to compare payload metadata to the signed
    /// envelope context.
    pub fn process_authenticated_skdm(
        &mut self,
        opened: &AuthenticatedSkdm,
    ) -> Result<bool, String> {
        let distribution = opened.decode_distribution()?;
        self.process_distribution(&distribution)
    }

    /// Encrypt a raw v4 group message using the outgoing symmetric sender key.
    ///
    /// This low-level form is **not sender-authenticated against other group
    /// members**, because every recipient knows the same chain key. Network
    /// callers must use [`Self::encrypt_signed`] instead.
    pub fn encrypt(&mut self, group_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let state = self.outgoing.get_mut(group_id).ok_or_else(|| {
            "no sender key for this group — call create_outgoing first".to_string()
        })?;

        let sender_identity_key = state
            .owner_identity_key
            .ok_or("legacy sender key state has no authenticated owner; rotate it")?;
        state.encrypt_bound(group_id, &sender_identity_key, plaintext)
    }

    /// Encrypt and Ed25519-sign a v5 Sender Key envelope.
    ///
    /// The signing identity's X25519 public key must own the outgoing sender
    /// key. This check happens before the symmetric chain advances.
    pub fn encrypt_signed(
        &mut self,
        group_id: &str,
        sender_identity: &IdentityKeyPair,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        if group_id.is_empty() {
            return Err("signed sender-key group id must not be empty".to_string());
        }
        u16::try_from(group_id.len())
            .map_err(|_| "signed sender-key group id is too long".to_string())?;
        // XChaCha ciphertext includes padded plaintext, a 16-byte tag and the
        // v4 header. This conservative margin guarantees encode cannot fail
        // after the chain state has advanced.
        if plaintext.len() > MAX_SIGNED_SENDER_KEY_INNER_SIZE.saturating_sub(512) {
            return Err("signed sender-key plaintext is too large".to_string());
        }

        let sender_identity_key = sender_identity.x25519_public_bytes();
        let state = self.outgoing.get_mut(group_id).ok_or_else(|| {
            "no sender key for this group — call create_outgoing first".to_string()
        })?;
        if state.owner_identity_key.as_ref() != Some(&sender_identity_key) {
            return Err("sender signing identity does not own this sender key".to_string());
        }
        let inner_v4 = state.encrypt_bound(group_id, &sender_identity_key, plaintext)?;
        encode_signed_sender_key(sender_identity, group_id, &sender_identity_key, &inner_v4)
    }

    /// Decrypt a raw v4 group message from a peer.
    ///
    /// This authenticates possession of the symmetric chain key, not the
    /// claimed sender against other recipients. Network callers must use
    /// [`Self::decrypt_signed`] with a pinned Ed25519 key.
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
        if iteration >= MAX_CHAIN_ITERATIONS {
            return Err("sender key iteration exceeds generation limit".to_string());
        }

        let lookup = (group_id.to_string(), *sender_ik);
        let state = self.incoming.get(&lookup).ok_or_else(|| {
            "no sender key from this peer — key distribution required".to_string()
        })?;

        // Verify key_id matches
        if state.key_id != key_id {
            return Err(format!(
                "sender key id mismatch: expected {}, got {}",
                state.key_id, key_id
            ));
        }

        let aad = sender_message_aad(group_id, sender_ik, &wire[..9])?;
        let skipped_id = SkippedSenderKeyId {
            group_id: group_id.to_string(),
            sender_identity_key: *sender_ik,
            generation: key_id,
            iteration,
        };

        // Previously skipped messages use their cached key. Read first and
        // consume only after successful AEAD authentication, so a tampered
        // late frame cannot destroy the authentic key.
        if let Some(cached_key) = self.skipped_message_keys.get(&skipped_id) {
            let mut message_key = *cached_key;
            let result = aead::decrypt_with_aad(&message_key, ciphertext, &nonce, &aad);
            message_key.zeroize();
            let plaintext = result?;
            if let Some(mut consumed) = self.skipped_message_keys.remove(&skipped_id) {
                consumed.zeroize();
            }
            return Ok(plaintext);
        }

        // Work transactionally so forged metadata or an invalid AEAD tag
        // cannot advance the live receiving chain.
        let mut candidate = state.clone();

        if iteration < candidate.iteration {
            return Err("sender key message replay or unavailable skipped key".to_string());
        }

        // Derive every gap key on the candidate state. Capacity is checked
        // before derivation and nothing is committed until the target frame
        // authenticates.
        let skip = iteration - candidate.iteration;
        self.ensure_skipped_capacity(group_id, sender_ik, skip as usize)?;
        let mut pending_skipped = Vec::with_capacity(skip as usize);
        for _ in 0..skip {
            let skipped_iteration = candidate.iteration;
            let message_key = candidate.message_key();
            candidate.ratchet()?;
            pending_skipped.push(PendingSkippedSenderKey {
                id: SkippedSenderKeyId {
                    group_id: group_id.to_string(),
                    sender_identity_key: *sender_ik,
                    generation: key_id,
                    iteration: skipped_iteration,
                },
                message_key,
            });
        }

        // Decrypt with current message key
        let mut mk = candidate.message_key();
        let result = aead::decrypt_with_aad(&mk, ciphertext, &nonce, &aad);
        mk.zeroize();
        let plaintext = result?;

        // Advance chain
        candidate.ratchet()?;
        for pending in &pending_skipped {
            let replaced = self
                .skipped_message_keys
                .insert(pending.id.clone(), pending.message_key);
            debug_assert!(replaced.is_none());
            if let Some(mut replaced) = replaced {
                replaced.zeroize();
            }
        }
        self.incoming.insert(lookup, candidate);

        Ok(plaintext)
    }

    /// Verify a v5 sender signature and then decrypt its inner v4 message.
    ///
    /// Structural parsing, exact group/sender binding, and verification with
    /// the independently pinned Ed25519 key all complete before [`Self::decrypt`]
    /// is called. Signature failures therefore cannot consume skipped keys or
    /// advance a receiving chain.
    pub fn decrypt_signed(
        &mut self,
        group_id: &str,
        sender_ik: &[u8; 32],
        pinned_sender_signing_key: &[u8; 32],
        signed_wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        let parsed = parse_signed_sender_key(signed_wire)?;
        if parsed.group_id != group_id {
            return Err("signed sender-key group binding mismatch".to_string());
        }
        if !bool::from(parsed.sender_identity_key.ct_eq(sender_ik)) {
            return Err("signed sender-key identity binding mismatch".to_string());
        }

        let mut signature_input =
            Vec::with_capacity(SIGNED_SENDER_KEY_DOMAIN.len() + parsed.signed_portion.len());
        signature_input.extend_from_slice(SIGNED_SENDER_KEY_DOMAIN);
        signature_input.extend_from_slice(parsed.signed_portion);
        if !crate::signature::verify(
            pinned_sender_signing_key,
            &signature_input,
            &parsed.signature,
        ) {
            return Err("invalid signed sender-key Ed25519 signature".to_string());
        }

        self.decrypt(group_id, sender_ik, parsed.inner_v4)
    }

    fn ensure_skipped_capacity(
        &self,
        group_id: &str,
        sender_ik: &[u8; 32],
        additional: usize,
    ) -> Result<(), String> {
        let per_sender = self
            .skipped_message_keys
            .keys()
            .filter(|id| id.group_id == group_id && id.sender_identity_key == *sender_ik)
            .count();
        if per_sender.saturating_add(additional) > MAX_SKIPPED_KEYS_PER_SENDER {
            return Err("sender skipped-key cache limit exceeded".to_string());
        }
        if self.skipped_message_keys.len().saturating_add(additional)
            > MAX_TOTAL_SKIPPED_SENDER_KEYS
        {
            return Err("global sender skipped-key cache limit exceeded".to_string());
        }
        Ok(())
    }

    fn purge_skipped_keys(&mut self, group_id: &str, sender_ik: &[u8; 32]) {
        self.skipped_message_keys.retain(|id, message_key| {
            let remove = id.group_id == group_id && id.sender_identity_key == *sender_ik;
            if remove {
                message_key.zeroize();
            }
            !remove
        });
    }

    fn purge_group_skipped_keys(&mut self, group_id: &str) {
        self.skipped_message_keys.retain(|id, message_key| {
            let remove = id.group_id == group_id;
            if remove {
                message_key.zeroize();
            }
            !remove
        });
    }

    /// Rotate the outgoing key after a membership change and forget incoming
    /// state belonging to removed members. The returned distribution must be
    /// delivered only to the complete post-change member set before another
    /// group message is sent.
    pub fn rotate_after_membership_change(
        &mut self,
        group_id: &str,
        our_identity_key: &[u8; 32],
        removed_members: &[[u8; 32]],
    ) -> Result<SenderKeyDistribution, String> {
        let generation = self
            .outgoing
            .get(group_id)
            .map(|current| {
                current
                    .key_id
                    .checked_add(1)
                    .ok_or("sender key generation exhausted; recreate the group")
            })
            .transpose()?
            .unwrap_or(1);

        self.rotate_after_membership_change_at_generation(
            group_id,
            our_identity_key,
            generation,
            removed_members,
        )
    }

    /// Membership rotation using an authoritative, strictly increasing
    /// generation supplied by the calling protocol.
    pub fn rotate_after_membership_change_at_generation(
        &mut self,
        group_id: &str,
        our_identity_key: &[u8; 32],
        generation: u32,
        removed_members: &[[u8; 32]],
    ) -> Result<SenderKeyDistribution, String> {
        let distribution =
            self.create_outgoing_at_generation(group_id, our_identity_key, generation)?;
        for member in removed_members {
            self.remove_incoming(group_id, member);
        }
        Ok(distribution)
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

    /// Check whether an incoming sender key is already loaded without
    /// serializing secret state as a probe.
    pub fn has_incoming(&self, group_id: &str, sender_ik: &[u8; 32]) -> bool {
        self.incoming
            .contains_key(&(group_id.to_string(), *sender_ik))
    }

    /// Build a zeroizing distribution view of the current outgoing state.
    ///
    /// This avoids round-tripping the secret chain key through an untyped JSON
    /// value merely to distribute it.
    pub fn build_distribution(&self, group_id: &str) -> Result<SenderKeyDistribution, String> {
        let state = self
            .outgoing
            .get(group_id)
            .ok_or("missing outgoing sender key")?;
        let sender_identity_key = state
            .owner_identity_key
            .ok_or("outgoing sender key has no authenticated owner")?;
        Ok(SenderKeyDistribution {
            group_id: group_id.to_string(),
            sender_identity_key,
            key_id: state.key_id,
            chain_key: state.chain_key,
        })
    }

    /// Remove all keys for a group (when leaving).
    pub fn remove_group(&mut self, group_id: &str) {
        self.outgoing.remove(group_id);
        self.incoming.retain(|(gid, _), _| gid != group_id);
        self.purge_group_skipped_keys(group_id);
    }

    /// Remove a single incoming key (e.g. when a member leaves the group).
    pub fn remove_incoming(&mut self, group_id: &str, sender_ik: &[u8; 32]) {
        self.incoming.remove(&(group_id.to_string(), *sender_ik));
        self.purge_skipped_keys(group_id, sender_ik);
    }

    /// Serialize the outgoing key state for a group (for persistence).
    pub fn serialize_outgoing(&self, group_id: &str) -> Option<Zeroizing<Vec<u8>>> {
        self.outgoing
            .get(group_id)
            .and_then(|s| serde_json::to_vec(s).ok())
            .map(Zeroizing::new)
    }

    /// Serialize an incoming key state (for persistence).
    pub fn serialize_incoming(
        &self,
        group_id: &str,
        sender_ik: &[u8; 32],
    ) -> Option<Zeroizing<Vec<u8>>> {
        let state = self.incoming.get(&(group_id.to_string(), *sender_ik))?;
        let skipped_keys = self
            .skipped_message_keys
            .iter()
            .filter(|(id, _)| id.group_id == group_id && id.sender_identity_key == *sender_ik)
            .map(|(id, message_key)| PersistedSkippedSenderKey {
                generation: id.generation,
                iteration: id.iteration,
                message_key: *message_key,
            })
            .collect();
        serde_json::to_vec(&PersistedIncomingSenderKey {
            version: PERSISTED_INCOMING_SENDER_KEY_VERSION,
            state: state.clone(),
            skipped_keys,
        })
        .ok()
        .map(Zeroizing::new)
    }

    /// Restore an outgoing key state from persisted bytes.
    pub fn load_outgoing(&mut self, group_id: &str, data: &[u8]) -> Result<(), String> {
        let state: SenderKeyState =
            serde_json::from_slice(data).map_err(|e| format!("decode outgoing sk: {e}"))?;
        if state.owner_identity_key.is_none() {
            return Err("legacy sender key state is unauthenticated; rotate it".to_string());
        }
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
        let (state, skipped_keys) = match serde_json::from_slice::<PersistedIncomingSenderKey>(data)
        {
            Ok(persisted) => {
                if persisted.version != PERSISTED_INCOMING_SENDER_KEY_VERSION {
                    return Err(format!(
                        "unsupported persisted incoming sender-key version: {}",
                        persisted.version
                    ));
                }
                (persisted.state, persisted.skipped_keys)
            }
            Err(envelope_error) => {
                // Secure pre-cache states used the bare SenderKeyState JSON.
                // They remain readable but naturally restore with no skipped
                // keys, so late frames predating the upgrade cannot downgrade
                // or synthesize cache entries.
                let state: SenderKeyState = serde_json::from_slice(data).map_err(|legacy_error| {
                    format!(
                        "decode incoming sender key: envelope={envelope_error}; legacy={legacy_error}"
                    )
                })?;
                (state, Vec::new())
            }
        };
        if state.owner_identity_key.as_ref() != Some(sender_ik) {
            return Err("persisted sender key owner mismatch; redistribute it".to_string());
        }
        if state.key_id == 0 || state.iteration > MAX_CHAIN_ITERATIONS {
            return Err("persisted sender key state is outside generation bounds".to_string());
        }
        if skipped_keys.len() > MAX_SKIPPED_KEYS_PER_SENDER {
            return Err("persisted sender skipped-key cache exceeds per-sender limit".to_string());
        }

        let mut unique = BTreeSet::new();
        for skipped in &skipped_keys {
            if skipped.generation != state.key_id
                || skipped.iteration >= state.iteration
                || skipped.iteration >= MAX_CHAIN_ITERATIONS
            {
                return Err("persisted sender skipped-key metadata is inconsistent".to_string());
            }
            if !unique.insert((skipped.generation, skipped.iteration)) {
                return Err("persisted sender skipped-key cache contains duplicates".to_string());
            }
        }

        let existing_for_sender = self
            .skipped_message_keys
            .keys()
            .filter(|id| id.group_id == group_id && id.sender_identity_key == *sender_ik)
            .count();
        let retained_total = self
            .skipped_message_keys
            .len()
            .saturating_sub(existing_for_sender);
        if retained_total.saturating_add(skipped_keys.len()) > MAX_TOTAL_SKIPPED_SENDER_KEYS {
            return Err("persisted sender skipped-key cache exceeds global limit".to_string());
        }

        self.purge_skipped_keys(group_id, sender_ik);
        for skipped in &skipped_keys {
            self.skipped_message_keys.insert(
                SkippedSenderKeyId {
                    group_id: group_id.to_string(),
                    sender_identity_key: *sender_ik,
                    generation: skipped.generation,
                    iteration: skipped.iteration,
                },
                skipped.message_key,
            );
        }
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
        bob_store.process_distribution(&alice_dist).unwrap();

        // Bob creates sender key and distributes
        let bob_dist = bob_store.create_outgoing(group, &bob_ik);
        alice_store.process_distribution(&bob_dist).unwrap();

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
    fn test_signed_sender_key_roundtrip() {
        let alice_identity = IdentityKeyPair::generate();
        let alice_ik = alice_identity.x25519_public_bytes();
        let group = "signed-group";
        let mut alice = SenderKeyStore::new();
        let mut bob = SenderKeyStore::new();
        let distribution = alice.create_outgoing(group, &alice_ik);
        bob.process_distribution(&distribution).unwrap();

        let wire = alice
            .encrypt_signed(group, &alice_identity, b"signed group message")
            .unwrap();
        assert_eq!(wire[0], SIGNED_SENDER_KEY_VERSION);
        assert_eq!(
            bob.decrypt_signed(
                group,
                &alice_ik,
                &alice_identity.ed25519_public_bytes(),
                &wire,
            )
            .unwrap(),
            b"signed group message"
        );
    }

    #[test]
    fn test_signed_wire_tamper_and_wrong_key_are_transactional() {
        let alice_identity = IdentityKeyPair::generate();
        let mallory_identity = IdentityKeyPair::generate();
        let alice_ik = alice_identity.x25519_public_bytes();
        let group = "signed-tamper-group";
        let mut alice = SenderKeyStore::new();
        let mut bob = SenderKeyStore::new();
        let distribution = alice.create_outgoing(group, &alice_ik);
        bob.process_distribution(&distribution).unwrap();
        let authentic = alice
            .encrypt_signed(group, &alice_identity, b"authentic")
            .unwrap();
        let before = bob.serialize_incoming(group, &alice_ik).unwrap();

        assert!(bob
            .decrypt_signed(
                group,
                &alice_ik,
                &mallory_identity.ed25519_public_bytes(),
                &authentic,
            )
            .is_err());
        assert_eq!(bob.serialize_incoming(group, &alice_ik).unwrap(), before);

        let mut tampered_inner = authentic.clone();
        let inner_byte = tampered_inner.len() - ED25519_SIGNATURE_SIZE - 1;
        tampered_inner[inner_byte] ^= 1;
        assert!(bob
            .decrypt_signed(
                group,
                &alice_ik,
                &alice_identity.ed25519_public_bytes(),
                &tampered_inner,
            )
            .is_err());
        assert_eq!(bob.serialize_incoming(group, &alice_ik).unwrap(), before);

        let mut tampered_group = authentic.clone();
        tampered_group[3] ^= 1;
        assert!(bob
            .decrypt_signed(
                group,
                &alice_ik,
                &alice_identity.ed25519_public_bytes(),
                &tampered_group,
            )
            .is_err());
        assert_eq!(bob.serialize_incoming(group, &alice_ik).unwrap(), before);

        let mut tampered_sender = authentic.clone();
        let sender_offset = 1 + 2 + group.len();
        tampered_sender[sender_offset] ^= 1;
        assert!(bob
            .decrypt_signed(
                group,
                &alice_ik,
                &alice_identity.ed25519_public_bytes(),
                &tampered_sender,
            )
            .is_err());
        assert_eq!(bob.serialize_incoming(group, &alice_ik).unwrap(), before);

        let mut tampered_signature = authentic.clone();
        *tampered_signature.last_mut().unwrap() ^= 1;
        assert!(bob
            .decrypt_signed(
                group,
                &alice_ik,
                &alice_identity.ed25519_public_bytes(),
                &tampered_signature,
            )
            .is_err());
        assert_eq!(bob.serialize_incoming(group, &alice_ik).unwrap(), before);

        let mut trailing = authentic.clone();
        trailing.push(0);
        assert!(bob
            .decrypt_signed(
                group,
                &alice_ik,
                &alice_identity.ed25519_public_bytes(),
                &trailing,
            )
            .is_err());

        let mut bad_version = authentic.clone();
        bad_version[0] = SENDER_KEY_VERSION;
        assert!(bob
            .decrypt_signed(
                group,
                &alice_ik,
                &alice_identity.ed25519_public_bytes(),
                &bad_version,
            )
            .is_err());

        let mut bad_inner_length = authentic.clone();
        let inner_length_offset = 1 + 2 + group.len() + 32;
        bad_inner_length[inner_length_offset..inner_length_offset + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(bob
            .decrypt_signed(
                group,
                &alice_ik,
                &alice_identity.ed25519_public_bytes(),
                &bad_inner_length,
            )
            .is_err());

        let truncated = &authentic[..authentic.len() - 1];
        assert!(bob
            .decrypt_signed(
                group,
                &alice_ik,
                &alice_identity.ed25519_public_bytes(),
                truncated,
            )
            .is_err());

        assert_eq!(
            bob.decrypt_signed(
                group,
                &alice_ik,
                &alice_identity.ed25519_public_bytes(),
                &authentic,
            )
            .unwrap(),
            b"authentic"
        );
    }

    #[test]
    fn test_recipient_cannot_forge_another_sender() {
        let alice_identity = IdentityKeyPair::generate();
        let mallory_identity = IdentityKeyPair::generate();
        let alice_ik = alice_identity.x25519_public_bytes();
        let group = "member-forgery-group";
        let mut alice = SenderKeyStore::new();
        let distribution = alice.create_outgoing(group, &alice_ik);

        let mut bob = SenderKeyStore::new();
        bob.process_distribution(&distribution).unwrap();

        // Every recipient necessarily knows Alice's symmetric chain key and
        // can therefore construct a valid raw v4 ciphertext.
        let mut mallory_sender = SenderKeyStore::new();
        mallory_sender.outgoing.insert(
            group.to_string(),
            SenderKeyState::from_distribution_for_sender(
                distribution.key_id,
                distribution.chain_key,
                alice_ik,
            ),
        );
        let forged_inner = mallory_sender.encrypt(group, b"forged as Alice").unwrap();
        let forged_signed =
            encode_signed_sender_key(&mallory_identity, group, &alice_ik, &forged_inner).unwrap();
        let before = bob.serialize_incoming(group, &alice_ik).unwrap();

        assert!(bob
            .decrypt_signed(
                group,
                &alice_ik,
                &alice_identity.ed25519_public_bytes(),
                &forged_signed,
            )
            .is_err());
        assert_eq!(bob.serialize_incoming(group, &alice_ik).unwrap(), before);

        // The low-level API demonstrates why callers must require v5.
        assert_eq!(
            bob.decrypt(group, &alice_ik, &forged_inner).unwrap(),
            b"forged as Alice"
        );
    }

    #[test]
    fn test_signed_encrypt_rejects_non_owner_before_ratchet() {
        let alice_identity = IdentityKeyPair::generate();
        let mallory_identity = IdentityKeyPair::generate();
        let group = "owner-bound-group";
        let mut alice = SenderKeyStore::new();
        alice.create_outgoing(group, &alice_identity.x25519_public_bytes());
        let before = alice.serialize_outgoing(group).unwrap();

        assert!(alice
            .encrypt_signed(group, &mallory_identity, b"not Alice")
            .is_err());
        assert_eq!(alice.serialize_outgoing(group).unwrap(), before);
    }

    #[test]
    fn test_out_of_order_messages_use_skipped_key_cache() {
        let alice_ik = [1u8; 32];
        let group = "test-group";

        let mut alice = SenderKeyStore::new();
        let mut bob = SenderKeyStore::new();

        let dist = alice.create_outgoing(group, &alice_ik);
        bob.process_distribution(&dist).unwrap();

        // Alice sends 3 messages
        let ct1 = alice.encrypt(group, b"msg1").unwrap();
        let ct2 = alice.encrypt(group, b"msg2").unwrap();
        let ct3 = alice.encrypt(group, b"msg3").unwrap();

        // Bob receives only msg3 (skipped 1 and 2)
        let pt3 = bob.decrypt(group, &alice_ik, &ct3).unwrap();
        assert_eq!(pt3, b"msg3");

        assert_eq!(bob.skipped_message_keys.len(), 2);
        assert_eq!(bob.decrypt(group, &alice_ik, &ct1).unwrap(), b"msg1");
        assert_eq!(bob.decrypt(group, &alice_ik, &ct2).unwrap(), b"msg2");
        assert!(bob.skipped_message_keys.is_empty());
    }

    #[test]
    fn test_tampered_late_message_does_not_consume_skipped_key() {
        let alice_ik = [1u8; 32];
        let group = "late-frame-group";
        let mut alice = SenderKeyStore::new();
        let mut bob = SenderKeyStore::new();
        let dist = alice.create_outgoing(group, &alice_ik);
        bob.process_distribution(&dist).unwrap();

        let (mut first, second) = (
            alice.encrypt(group, b"N").unwrap(),
            alice.encrypt(group, b"N+1").unwrap(),
        );
        assert_eq!(bob.decrypt(group, &alice_ik, &second).unwrap(), b"N+1");
        assert_eq!(bob.skipped_message_keys.len(), 1);

        let tamper_at = first.len() / 2;
        first[tamper_at] ^= 1;
        assert!(bob.decrypt(group, &alice_ik, &first).is_err());
        assert_eq!(bob.skipped_message_keys.len(), 1);

        first[tamper_at] ^= 1;
        assert_eq!(bob.decrypt(group, &alice_ik, &first).unwrap(), b"N");
        assert!(bob.skipped_message_keys.is_empty());
    }

    #[test]
    fn test_skipped_keys_survive_incoming_state_persistence() {
        let alice_ik = [1u8; 32];
        let group = "persisted-gap-group";
        let mut alice = SenderKeyStore::new();
        let mut bob = SenderKeyStore::new();
        let dist = alice.create_outgoing(group, &alice_ik);
        bob.process_distribution(&dist).unwrap();

        let first = alice.encrypt(group, b"first").unwrap();
        let second = alice.encrypt(group, b"second").unwrap();
        assert_eq!(bob.decrypt(group, &alice_ik, &second).unwrap(), b"second");

        let persisted = bob.serialize_incoming(group, &alice_ik).unwrap();
        let mut restored = SenderKeyStore::new();
        restored
            .load_incoming(group, &alice_ik, &persisted)
            .unwrap();
        assert_eq!(restored.skipped_message_keys.len(), 1);
        assert_eq!(
            restored.decrypt(group, &alice_ik, &first).unwrap(),
            b"first"
        );
        assert!(restored.skipped_message_keys.is_empty());
    }

    #[test]
    fn test_skipped_key_cache_caps_are_enforced_transactionally() {
        let sender_ik = [1u8; 32];
        let group = "bounded-gap-group";
        let mut per_sender = SenderKeyStore::new();
        for iteration in 0..MAX_SKIPPED_KEYS_PER_SENDER as u32 {
            per_sender.skipped_message_keys.insert(
                SkippedSenderKeyId {
                    group_id: group.to_string(),
                    sender_identity_key: sender_ik,
                    generation: 99,
                    iteration,
                },
                [7u8; 32],
            );
        }
        assert!(per_sender
            .ensure_skipped_capacity(group, &sender_ik, 1)
            .is_err());
        assert_eq!(
            per_sender.skipped_message_keys.len(),
            MAX_SKIPPED_KEYS_PER_SENDER
        );

        let mut global = SenderKeyStore::new();
        for index in 0..MAX_TOTAL_SKIPPED_SENDER_KEYS {
            global.skipped_message_keys.insert(
                SkippedSenderKeyId {
                    group_id: format!("group-{index}"),
                    sender_identity_key: [(index % 251) as u8; 32],
                    generation: 1,
                    iteration: 0,
                },
                [8u8; 32],
            );
        }
        assert!(global
            .ensure_skipped_capacity("another-group", &[255u8; 32], 1)
            .is_err());
        assert_eq!(
            global.skipped_message_keys.len(),
            MAX_TOTAL_SKIPPED_SENDER_KEYS
        );
    }

    #[test]
    fn test_generation_rotation_purges_skipped_keys() {
        let alice_ik = [1u8; 32];
        let group = "rotated-gap-group";
        let mut alice = SenderKeyStore::new();
        let mut bob = SenderKeyStore::new();
        let generation_one = alice.create_outgoing(group, &alice_ik);
        bob.process_distribution(&generation_one).unwrap();

        let old_first = alice.encrypt(group, b"old-first").unwrap();
        let old_second = alice.encrypt(group, b"old-second").unwrap();
        bob.decrypt(group, &alice_ik, &old_second).unwrap();
        assert_eq!(bob.skipped_message_keys.len(), 1);

        let generation_two = alice.create_outgoing(group, &alice_ik);
        bob.process_distribution(&generation_two).unwrap();
        assert!(bob.skipped_message_keys.is_empty());
        assert!(bob.decrypt(group, &alice_ik, &old_first).is_err());

        let fresh = alice.encrypt(group, b"fresh").unwrap();
        assert_eq!(bob.decrypt(group, &alice_ik, &fresh).unwrap(), b"fresh");
    }

    #[test]
    fn test_key_rotation_flag() {
        let ik = [1u8; 32];
        let group = "test-group";
        let mut store = SenderKeyStore::new();
        store.create_outgoing(group, &ik);
        assert!(!store.needs_rotation(group));
    }

    #[test]
    fn test_sender_key_header_and_context_are_authenticated_transactionally() {
        let alice_ik = [1u8; 32];
        let group = "group-a";
        let mut alice = SenderKeyStore::new();
        let mut bob = SenderKeyStore::new();
        let dist = alice.create_outgoing(group, &alice_ik);
        bob.process_distribution(&dist).unwrap();

        let wire = alice.encrypt(group, b"bound message").unwrap();
        assert_eq!(wire[0], SENDER_KEY_VERSION);
        let before = bob.serialize_incoming(group, &alice_ik).unwrap();

        let mut tampered_iteration = wire.clone();
        tampered_iteration[5] ^= 1;
        assert!(bob.decrypt(group, &alice_ik, &tampered_iteration).is_err());
        assert_eq!(bob.serialize_incoming(group, &alice_ik).unwrap(), before);

        // Install the same chain under a different group. The ciphertext still
        // cannot cross that authenticated context.
        let mut other_group_dist = dist.clone();
        other_group_dist.group_id = "group-b".to_string();
        bob.process_distribution(&other_group_dist).unwrap();
        assert!(bob.decrypt("group-b", &alice_ik, &wire).is_err());

        assert_eq!(
            bob.decrypt(group, &alice_ik, &wire).unwrap(),
            b"bound message"
        );

        let mut legacy = wire;
        legacy[0] = 0x03;
        assert!(bob.decrypt(group, &alice_ik, &legacy).is_err());
    }

    #[test]
    fn test_membership_rotation_excludes_removed_member_and_rejects_rewind() {
        let alice_ik = [1u8; 32];
        let removed_ik = [3u8; 32];
        let group = "membership-group";
        let mut alice = SenderKeyStore::new();
        let mut bob = SenderKeyStore::new();
        let mut removed = SenderKeyStore::new();

        let generation_one = alice.create_outgoing(group, &alice_ik);
        bob.process_distribution(&generation_one).unwrap();
        removed.process_distribution(&generation_one).unwrap();
        let removed_distribution = removed.create_outgoing(group, &removed_ik);
        alice.process_distribution(&removed_distribution).unwrap();

        let before_change = alice.encrypt(group, b"before").unwrap();
        assert_eq!(
            bob.decrypt(group, &alice_ik, &before_change).unwrap(),
            b"before"
        );
        assert_eq!(
            removed.decrypt(group, &alice_ik, &before_change).unwrap(),
            b"before"
        );
        let removed_before = removed.encrypt(group, b"still a member").unwrap();
        assert_eq!(
            alice.decrypt(group, &removed_ik, &removed_before).unwrap(),
            b"still a member"
        );

        let generation_two = alice
            .rotate_after_membership_change(group, &alice_ik, &[removed_ik])
            .unwrap();
        assert_eq!(generation_two.key_id, generation_one.key_id + 1);
        bob.process_distribution(&generation_two).unwrap();

        let after_change = alice.encrypt(group, b"after").unwrap();
        assert_eq!(
            bob.decrypt(group, &alice_ik, &after_change).unwrap(),
            b"after"
        );
        assert!(removed.decrypt(group, &alice_ik, &after_change).is_err());
        assert!(bob.process_distribution(&generation_one).is_err());
        let removed_after = removed.encrypt(group, b"removed sender").unwrap();
        assert!(alice.decrypt(group, &removed_ik, &removed_after).is_err());
    }

    #[test]
    fn test_duplicate_distribution_does_not_rewind_chain() {
        let alice_ik = [1u8; 32];
        let group = "test-group";
        let mut alice = SenderKeyStore::new();
        let mut bob = SenderKeyStore::new();
        let dist = alice.create_outgoing(group, &alice_ik);
        assert!(bob.process_distribution(&dist).unwrap());
        let wire = alice.encrypt(group, b"once").unwrap();
        assert_eq!(bob.decrypt(group, &alice_ik, &wire).unwrap(), b"once");

        assert!(!bob.process_distribution(&dist).unwrap());
        assert!(bob.decrypt(group, &alice_ik, &wire).is_err());
    }
}

// ─── Sealed SKDM Envelope ──────────────────────────────
//
// Sender Key Distribution Messages use an ECIES-style recipient seal plus an
// Ed25519 sender signature. The v3 signature and AEAD AAD bind group,
// generation, sender X25519 and Ed25519 keys, recipient, and the ephemeral
// key. Older envelopes are rejected.
//
// Wire format:
//   [version=0x03][group_len][group][generation][sender_ik][sender_signing_key]
//   [eph_pub][nonce][ciphertext][Ed25519 signature]

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

const SEALED_SKDM_VERSION: u8 = 0x03;
const SEALED_SKDM_DOMAIN: &[u8] = b"veil-sealed-skdm-v3";

/// Authenticated metadata returned after opening a v3 SKDM envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSkdm {
    pub sender_identity_key: [u8; 32],
    pub sender_signing_key: [u8; 32],
    pub group_id: String,
    /// Sender-key generation. This must equal the embedded distribution's
    /// `key_id` before the distribution is installed.
    pub generation: u32,
    pub payload: Zeroizing<Vec<u8>>,
}

/// Structurally parsed SKDM metadata that has **not** been authenticated.
///
/// This exists so a receiver can locate its independently trusted sender
/// record before calling [`open_skdm_authenticated`]. None of these fields are
/// claims the caller may trust. In particular, never feed
/// `sender_signing_key` back as the expected key unless it first matches a
/// previously authenticated/pinned identity record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedSkdmMetadata {
    pub group_id: String,
    pub generation: u32,
    pub sender_identity_key: [u8; 32],
    pub sender_signing_key: [u8; 32],
}

impl AuthenticatedSkdm {
    /// Decode the encrypted JSON and require its group, sender, and generation
    /// to exactly match the signed envelope metadata.
    pub fn decode_distribution(&self) -> Result<SenderKeyDistribution, String> {
        let distribution: SenderKeyDistribution = serde_json::from_slice(&self.payload)
            .map_err(|e| format!("decode authenticated SKDM payload: {e}"))?;
        if distribution.group_id != self.group_id {
            return Err("SKDM payload group does not match signed envelope".to_string());
        }
        if distribution.sender_identity_key != self.sender_identity_key {
            return Err("SKDM payload sender does not match signed envelope".to_string());
        }
        if distribution.key_id != self.generation {
            return Err("SKDM payload generation does not match signed envelope".to_string());
        }
        Ok(distribution)
    }
}

fn sealed_skdm_aad(
    group_id: &str,
    generation: u32,
    sender_ik: &[u8; 32],
    sender_signing_key: &[u8; 32],
    recipient_ik: &[u8; 32],
    ephemeral_public: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let group_len =
        u16::try_from(group_id.len()).map_err(|_| "SKDM group id is too long".to_string())?;
    let mut aad = Vec::with_capacity(
        SEALED_SKDM_DOMAIN.len() + 1 + 2 + group_id.len() + 4 + 32 + 32 + 32 + 32,
    );
    aad.extend_from_slice(SEALED_SKDM_DOMAIN);
    aad.push(SEALED_SKDM_VERSION);
    aad.extend_from_slice(&group_len.to_be_bytes());
    aad.extend_from_slice(group_id.as_bytes());
    aad.extend_from_slice(&generation.to_be_bytes());
    aad.extend_from_slice(sender_ik);
    aad.extend_from_slice(sender_signing_key);
    aad.extend_from_slice(recipient_ik);
    aad.extend_from_slice(ephemeral_public);
    Ok(aad)
}

struct ParsedSkdm<'a> {
    metadata: UnverifiedSkdmMetadata,
    ephemeral_public: [u8; 32],
    nonce: [u8; 24],
    ciphertext: &'a [u8],
    signature: [u8; ED25519_SIGNATURE_SIZE],
}

/// Parse the public routing/lookup metadata of a sealed SKDM v3 envelope.
///
/// This performs only strict version, length, UTF-8, and generation checks. It
/// deliberately does **not** verify the signature or AEAD tag. The result is
/// therefore named [`UnverifiedSkdmMetadata`] and must be used only to locate
/// independently trusted context for [`open_skdm_authenticated`].
pub fn inspect_skdm_metadata(wire: &[u8]) -> Result<UnverifiedSkdmMetadata, String> {
    Ok(parse_skdm_wire(wire)?.metadata)
}

fn parse_skdm_wire(wire: &[u8]) -> Result<ParsedSkdm<'_>, String> {
    const FIXED_WITHOUT_GROUP: usize = 1 + 2 + 4 + 32 + 32 + 32 + 24 + 16 + ED25519_SIGNATURE_SIZE;
    if wire.len() < FIXED_WITHOUT_GROUP {
        return Err("sealed SKDM too short".to_string());
    }
    if wire[0] != SEALED_SKDM_VERSION {
        return Err(format!(
            "unsupported sealed SKDM version: {:#x}; expected authenticated v3",
            wire[0]
        ));
    }

    let group_len = u16::from_be_bytes([wire[1], wire[2]]) as usize;
    if group_len == 0 {
        return Err("SKDM group id must not be empty".to_string());
    }
    let group_end = 3usize
        .checked_add(group_len)
        .ok_or("invalid SKDM group length")?;
    let minimum_end = group_end
        .checked_add(4 + 32 + 32 + 32 + 24 + 16 + ED25519_SIGNATURE_SIZE)
        .ok_or("invalid SKDM length")?;
    if wire.len() < minimum_end {
        return Err("sealed SKDM truncated".to_string());
    }
    let group_id = std::str::from_utf8(&wire[3..group_end])
        .map_err(|_| "SKDM group id is not UTF-8")?
        .to_string();

    let mut cursor = group_end;
    let generation = u32::from_be_bytes(
        wire[cursor..cursor + 4]
            .try_into()
            .map_err(|_| "invalid SKDM generation")?,
    );
    cursor += 4;
    if generation == 0 {
        return Err("SKDM generation must be non-zero".to_string());
    }

    let mut sender_identity_key = [0u8; 32];
    sender_identity_key.copy_from_slice(&wire[cursor..cursor + 32]);
    cursor += 32;
    let mut sender_signing_key = [0u8; 32];
    sender_signing_key.copy_from_slice(&wire[cursor..cursor + 32]);
    cursor += 32;
    let mut ephemeral_public = [0u8; 32];
    ephemeral_public.copy_from_slice(&wire[cursor..cursor + 32]);
    cursor += 32;
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&wire[cursor..cursor + 24]);
    cursor += 24;

    let signature_start = wire
        .len()
        .checked_sub(ED25519_SIGNATURE_SIZE)
        .ok_or("sealed SKDM missing signature")?;
    if signature_start < cursor + 16 {
        return Err("sealed SKDM ciphertext too short".to_string());
    }
    let signature = wire[signature_start..]
        .try_into()
        .map_err(|_| "invalid SKDM signature length")?;

    Ok(ParsedSkdm {
        metadata: UnverifiedSkdmMetadata {
            group_id,
            generation,
            sender_identity_key,
            sender_signing_key,
        },
        ephemeral_public,
        nonce,
        ciphertext: &wire[cursor..signature_start],
        signature,
    })
}

/// Seal and sign a Sender Key Distribution Message for one recipient.
///
/// The signature and AEAD tag bind the group, generation, sender X25519 and
/// Ed25519 identities, recipient X25519 identity, and ephemeral key. The
/// recipient must still obtain `expected_sender_signing_key` from an
/// independently authenticated identity record.
pub fn seal_skdm_authenticated(
    sender: &IdentityKeyPair,
    recipient_ik: &[u8; 32],
    group_id: &str,
    generation: u32,
    skdm_json: &[u8],
) -> Result<Vec<u8>, String> {
    if group_id.is_empty() {
        return Err("SKDM group id must not be empty".to_string());
    }
    if generation == 0 {
        return Err("SKDM generation must be non-zero".to_string());
    }

    let sender_ik = sender.x25519_public_bytes();
    let sender_signing_key = sender.ed25519_public_bytes();
    let mut eph_secret_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut eph_secret_bytes);
    let eph_secret = X25519Secret::from(eph_secret_bytes);
    let eph_pub = X25519PublicKey::from(&eph_secret);

    let recipient_pub = X25519PublicKey::from(*recipient_ik);
    let shared = eph_secret.diffie_hellman(&recipient_pub);
    eph_secret_bytes.zeroize();
    if bool::from(shared.as_bytes().ct_eq(&[0u8; 32])) {
        return Err("invalid recipient identity key".to_string());
    }

    let aad = sealed_skdm_aad(
        group_id,
        generation,
        &sender_ik,
        &sender_signing_key,
        recipient_ik,
        eph_pub.as_bytes(),
    )?;
    let mut key = kdf::hkdf_sha256(&aad, shared.as_bytes(), b"veil-skdm-key-v3", 32);
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    key.zeroize();

    let result = aead::encrypt_with_aad(&key_arr, skdm_json, &aad);
    key_arr.zeroize();
    let (ct, nonce) = result?;

    let mut signed = Vec::with_capacity(aad.len() + nonce.len() + ct.len());
    signed.extend_from_slice(&aad);
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(&ct);
    let signature = crate::signature::sign(sender, &signed);

    let group_bytes = group_id.as_bytes();
    let mut wire = Vec::with_capacity(
        1 + 2 + group_bytes.len() + 4 + 32 + 32 + 32 + 24 + ct.len() + ED25519_SIGNATURE_SIZE,
    );
    wire.push(SEALED_SKDM_VERSION);
    wire.extend_from_slice(&(group_bytes.len() as u16).to_be_bytes());
    wire.extend_from_slice(group_bytes);
    wire.extend_from_slice(&generation.to_be_bytes());
    wire.extend_from_slice(&sender_ik);
    wire.extend_from_slice(&sender_signing_key);
    wire.extend_from_slice(eph_pub.as_bytes());
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&ct);
    wire.extend_from_slice(&signature);
    Ok(wire)
}

/// Verify and open an authenticated SKDM envelope.
pub fn open_skdm_authenticated(
    recipient: &IdentityKeyPair,
    expected_sender_ik: &[u8; 32],
    expected_sender_signing_key: &[u8; 32],
    expected_group_id: &str,
    expected_generation: u32,
    wire: &[u8],
) -> Result<AuthenticatedSkdm, String> {
    let parsed = parse_skdm_wire(wire)?;
    let metadata = &parsed.metadata;

    if metadata.group_id != expected_group_id {
        return Err("SKDM group binding mismatch".to_string());
    }
    if metadata.generation != expected_generation {
        return Err("SKDM generation binding mismatch".to_string());
    }
    if !bool::from(metadata.sender_identity_key.ct_eq(expected_sender_ik)) {
        return Err("SKDM sender binding mismatch".to_string());
    }
    if !bool::from(
        metadata
            .sender_signing_key
            .ct_eq(expected_sender_signing_key),
    ) {
        return Err("SKDM signing-key binding mismatch".to_string());
    }

    let recipient_ik = recipient.x25519_public_bytes();
    let aad = sealed_skdm_aad(
        &metadata.group_id,
        metadata.generation,
        &metadata.sender_identity_key,
        &metadata.sender_signing_key,
        &recipient_ik,
        &parsed.ephemeral_public,
    )?;
    let mut signed = Vec::with_capacity(aad.len() + parsed.nonce.len() + parsed.ciphertext.len());
    signed.extend_from_slice(&aad);
    signed.extend_from_slice(&parsed.nonce);
    signed.extend_from_slice(parsed.ciphertext);
    if !crate::signature::verify(expected_sender_signing_key, &signed, &parsed.signature) {
        return Err("invalid SKDM sender signature".to_string());
    }

    let eph_pub = X25519PublicKey::from(parsed.ephemeral_public);
    let shared = recipient.x25519_secret().diffie_hellman(&eph_pub);
    if bool::from(shared.as_bytes().ct_eq(&[0u8; 32])) {
        return Err("invalid SKDM ephemeral key".to_string());
    }
    let mut key = kdf::hkdf_sha256(&aad, shared.as_bytes(), b"veil-skdm-key-v3", 32);
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    key.zeroize();
    let result = aead::decrypt_with_aad(&key_arr, parsed.ciphertext, &parsed.nonce, &aad);
    key_arr.zeroize();

    Ok(AuthenticatedSkdm {
        sender_identity_key: metadata.sender_identity_key,
        sender_signing_key: metadata.sender_signing_key,
        group_id: metadata.group_id.clone(),
        generation: metadata.generation,
        payload: Zeroizing::new(result?),
    })
}

/// The unauthenticated v1 sealing API is retained only to make upgrades fail
/// closed at runtime. Callers must migrate to [`seal_skdm_authenticated`].
#[deprecated(note = "unauthenticated SKDM v1 is disabled; use seal_skdm_authenticated")]
pub fn seal_skdm(
    _sender_ik: &[u8; 32],
    _recipient_ik: &[u8; 32],
    _skdm_json: &[u8],
) -> Result<Vec<u8>, String> {
    Err("unauthenticated sealed SKDM v1 is disabled".to_string())
}

/// The unauthenticated v1 opening API is retained only to reject old envelopes.
#[deprecated(note = "unauthenticated SKDM v1 is disabled; use open_skdm_authenticated")]
pub fn open_skdm(
    _recipient_ik_secret: &[u8; 32],
    _recipient_ik_public: &[u8; 32],
    _wire: &[u8],
) -> Result<([u8; 32], Vec<u8>), String> {
    Err("unauthenticated sealed SKDM v1 is disabled".to_string())
}

#[cfg(test)]
mod sealed_tests {
    use super::*;

    #[test]
    fn test_authenticated_seal_open_roundtrip() {
        let sender = IdentityKeyPair::generate();
        let recipient = IdentityKeyPair::generate();
        let distribution = SenderKeyDistribution {
            group_id: "abc".to_string(),
            sender_identity_key: sender.x25519_public_bytes(),
            key_id: 1,
            chain_key: [9u8; 32],
        };
        let payload = serde_json::to_vec(&distribution).unwrap();
        let sealed = seal_skdm_authenticated(
            &sender,
            &recipient.x25519_public_bytes(),
            "abc",
            1,
            &payload,
        )
        .unwrap();
        assert_eq!(sealed[0], SEALED_SKDM_VERSION);
        let unverified = inspect_skdm_metadata(&sealed).unwrap();
        assert_eq!(unverified.group_id, "abc");
        assert_eq!(unverified.generation, 1);
        assert_eq!(unverified.sender_identity_key, sender.x25519_public_bytes());
        assert_eq!(unverified.sender_signing_key, sender.ed25519_public_bytes());
        let opened = open_skdm_authenticated(
            &recipient,
            &sender.x25519_public_bytes(),
            &sender.ed25519_public_bytes(),
            "abc",
            1,
            &sealed,
        )
        .unwrap();
        assert_eq!(opened.sender_identity_key, sender.x25519_public_bytes());
        assert_eq!(opened.sender_signing_key, sender.ed25519_public_bytes());
        assert_eq!(opened.group_id, "abc");
        assert_eq!(opened.generation, 1);
        assert_eq!(opened.payload.as_slice(), payload.as_slice());
        let decoded = opened.decode_distribution().unwrap();
        assert_eq!(decoded.group_id.as_str(), distribution.group_id.as_str());
        assert_eq!(
            decoded.sender_identity_key,
            distribution.sender_identity_key
        );
        assert_eq!(decoded.key_id, distribution.key_id);
        assert_eq!(decoded.chain_key, distribution.chain_key);
    }

    #[test]
    fn test_skdm_signature_and_all_context_bindings() {
        let sender = IdentityKeyPair::generate();
        let recipient = IdentityKeyPair::generate();
        let other = IdentityKeyPair::generate();
        let sealed = seal_skdm_authenticated(
            &sender,
            &recipient.x25519_public_bytes(),
            "group-a",
            7,
            b"distribution",
        )
        .unwrap();

        let open = |recipient: &IdentityKeyPair,
                    sender_ik: &[u8; 32],
                    signing_key: &[u8; 32],
                    group: &str,
                    generation: u32,
                    wire: &[u8]| {
            open_skdm_authenticated(recipient, sender_ik, signing_key, group, generation, wire)
        };

        assert!(open(
            &recipient,
            &sender.x25519_public_bytes(),
            &sender.ed25519_public_bytes(),
            "group-b",
            7,
            &sealed
        )
        .is_err());
        assert!(open(
            &recipient,
            &sender.x25519_public_bytes(),
            &sender.ed25519_public_bytes(),
            "group-a",
            8,
            &sealed
        )
        .is_err());
        assert!(open(
            &recipient,
            &other.x25519_public_bytes(),
            &sender.ed25519_public_bytes(),
            "group-a",
            7,
            &sealed
        )
        .is_err());
        assert!(open(
            &recipient,
            &sender.x25519_public_bytes(),
            &other.ed25519_public_bytes(),
            "group-a",
            7,
            &sealed
        )
        .is_err());
        assert!(open(
            &other,
            &sender.x25519_public_bytes(),
            &sender.ed25519_public_bytes(),
            "group-a",
            7,
            &sealed
        )
        .is_err());

        let mut tampered_signing_key = sealed.clone();
        let signing_key_offset = 3 + "group-a".len() + 4 + 32;
        tampered_signing_key[signing_key_offset] ^= 1;
        let inspected = inspect_skdm_metadata(&tampered_signing_key).unwrap();
        assert_ne!(inspected.sender_signing_key, sender.ed25519_public_bytes());
        assert!(open(
            &recipient,
            &sender.x25519_public_bytes(),
            &sender.ed25519_public_bytes(),
            "group-a",
            7,
            &tampered_signing_key
        )
        .is_err());

        let mut tampered = sealed.clone();
        let ciphertext_byte = tampered.len() - ED25519_SIGNATURE_SIZE - 1;
        tampered[ciphertext_byte] ^= 1;
        assert!(open(
            &recipient,
            &sender.x25519_public_bytes(),
            &sender.ed25519_public_bytes(),
            "group-a",
            7,
            &tampered
        )
        .is_err());

        let mut legacy_v2 = sealed;
        legacy_v2[0] = 0x02;
        assert!(inspect_skdm_metadata(&legacy_v2).is_err());
        assert!(open(
            &recipient,
            &sender.x25519_public_bytes(),
            &sender.ed25519_public_bytes(),
            "group-a",
            7,
            &legacy_v2
        )
        .is_err());
    }

    #[test]
    fn test_authenticated_payload_metadata_must_match_envelope() {
        let distribution = SenderKeyDistribution {
            group_id: "payload-group".to_string(),
            sender_identity_key: [1u8; 32],
            key_id: 4,
            chain_key: [8u8; 32],
        };
        let payload = serde_json::to_vec(&distribution).unwrap();

        for opened in [
            AuthenticatedSkdm {
                sender_identity_key: [2u8; 32],
                sender_signing_key: [3u8; 32],
                group_id: "payload-group".to_string(),
                generation: 4,
                payload: Zeroizing::new(payload.clone()),
            },
            AuthenticatedSkdm {
                sender_identity_key: [1u8; 32],
                sender_signing_key: [3u8; 32],
                group_id: "other-group".to_string(),
                generation: 4,
                payload: Zeroizing::new(payload.clone()),
            },
            AuthenticatedSkdm {
                sender_identity_key: [1u8; 32],
                sender_signing_key: [3u8; 32],
                group_id: "payload-group".to_string(),
                generation: 5,
                payload: Zeroizing::new(payload.clone()),
            },
        ] {
            assert!(opened.decode_distribution().is_err());
        }
    }

    #[test]
    fn test_skdm_inspector_rejects_structurally_invalid_wire() {
        let sender = IdentityKeyPair::generate();
        let recipient = IdentityKeyPair::generate();
        let sealed = seal_skdm_authenticated(
            &sender,
            &recipient.x25519_public_bytes(),
            "group-a",
            7,
            b"payload",
        )
        .unwrap();

        assert!(inspect_skdm_metadata(&[]).is_err());
        assert!(inspect_skdm_metadata(&sealed[..100]).is_err());

        let mut impossible_group_length = sealed.clone();
        impossible_group_length[1..3].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(inspect_skdm_metadata(&impossible_group_length).is_err());

        let mut empty_group = sealed.clone();
        empty_group[1..3].copy_from_slice(&0u16.to_be_bytes());
        assert!(inspect_skdm_metadata(&empty_group).is_err());

        let mut invalid_utf8 = sealed.clone();
        invalid_utf8[3] = 0xff;
        assert!(inspect_skdm_metadata(&invalid_utf8).is_err());

        let mut zero_generation = sealed;
        let generation_offset = 3 + "group-a".len();
        zero_generation[generation_offset..generation_offset + 4].fill(0);
        assert!(inspect_skdm_metadata(&zero_generation).is_err());

        assert!(seal_skdm_authenticated(
            &sender,
            &recipient.x25519_public_bytes(),
            "",
            1,
            b"payload"
        )
        .is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn test_unauthenticated_v1_api_is_fail_closed() {
        assert!(seal_skdm(&[1u8; 32], &[2u8; 32], b"payload").is_err());
        assert!(open_skdm(&[1u8; 32], &[2u8; 32], &[0x01]).is_err());
    }
}
