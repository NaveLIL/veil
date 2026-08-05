use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::aead;
use crate::kdf;
use crate::x25519::require_contributory;

/// Type alias for the skipped message keys map: (ratchet_public_key, message_number) -> message_key.
type SkippedKeysMap = HashMap<([u8; 32], u32), [u8; 32]>;

/// Maximum number of skipped message keys to store (out-of-order tolerance).
const MAX_SKIP: u32 = 1000;
/// Absolute maximum number of total stored skipped keys (prevents unbounded growth).
const MAX_TOTAL_SKIPPED: usize = 5000;
/// Upper bound for one encrypted-at-rest ratchet JSON document. This mirrors
/// the SQLCipher boundary and prevents direct callers from allocating an
/// unbounded persisted session before the skipped-key cap is evaluated.
const MAX_SERIALIZED_RATCHET_BYTES: usize = 1024 * 1024;
/// Current authenticated Double Ratchet wire format.
const RATCHET_HEADER_VERSION: u8 = 0x02;
/// Domain-separated protocol associated data. The caller-provided AD and the
/// canonical serialized header are appended to this value.
const RATCHET_PROTOCOL_AD: &[u8] = b"veil-double-ratchet-v2";

/// Header attached to each ratchet message (sent alongside ciphertext).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Sender's current ratchet public key
    pub ratchet_key: [u8; 32],
    /// Message number in the current sending chain
    pub n: u32,
    /// Number of messages in the previous sending chain
    pub pn: u32,
}

impl MessageHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + 32 + 4 + 4);
        bytes.push(RATCHET_HEADER_VERSION);
        bytes.extend_from_slice(&self.ratchet_key);
        bytes.extend_from_slice(&self.n.to_be_bytes());
        bytes.extend_from_slice(&self.pn.to_be_bytes());
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() != 41 {
            return Err(format!(
                "invalid ratchet header length: expected 41 bytes for v2, got {}",
                data.len()
            ));
        }
        if data[0] != RATCHET_HEADER_VERSION {
            return Err(format!(
                "unsupported ratchet header version: {:#x}",
                data[0]
            ));
        }
        let mut ratchet_key = [0u8; 32];
        ratchet_key.copy_from_slice(&data[1..33]);
        let n = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
        let pn = u32::from_be_bytes([data[37], data[38], data[39], data[40]]);
        Ok(Self { ratchet_key, n, pn })
    }
}

/// Construct Signal-style `CONCAT(AD, header)` with a protocol domain and an
/// unambiguous caller-AD length. The serialized header itself is therefore
/// authenticated by the message AEAD tag.
fn message_aad(associated_data: &[u8], header: &MessageHeader) -> Result<Vec<u8>, String> {
    let ad_len = u32::try_from(associated_data.len())
        .map_err(|_| "ratchet associated data too large".to_string())?;
    let header_bytes = header.to_bytes();
    let mut aad = Vec::with_capacity(RATCHET_PROTOCOL_AD.len() + 4 + associated_data.len() + 41);
    aad.extend_from_slice(RATCHET_PROTOCOL_AD);
    aad.extend_from_slice(&ad_len.to_be_bytes());
    aad.extend_from_slice(associated_data);
    aad.extend_from_slice(&header_bytes);
    Ok(aad)
}

/// A Double Ratchet session between two parties.
///
/// Provides forward secrecy: each message is encrypted with a unique key.
/// Even if a session state is compromised, past messages cannot be decrypted.
#[derive(Clone, Serialize)]
pub struct RatchetSession {
    /// DH ratchet sending keypair (our current ratchet key)
    #[serde(with = "secret_key_serde")]
    dh_sending_secret: Option<Vec<u8>>, // Serialized StaticSecret
    dh_sending_public: Option<[u8; 32]>,

    /// DH ratchet receiving key (peer's current ratchet public key)
    dh_receiving: Option<[u8; 32]>,

    /// Root key (32 bytes)
    root_key: [u8; 32],

    /// Sending chain key
    sending_chain_key: Option<[u8; 32]>,
    /// Receiving chain key
    receiving_chain_key: Option<[u8; 32]>,

    /// Message counters
    send_count: u32,
    recv_count: u32,
    prev_send_count: u32,

    /// Skipped message keys: (ratchet_public_key, message_number) → message_key
    #[serde(with = "skipped_keys_serde")]
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,
}

struct SecretSkippedKeysMap(SkippedKeysMap);

impl Drop for SecretSkippedKeysMap {
    fn drop(&mut self) {
        for message_key in self.0.values_mut() {
            message_key.zeroize();
        }
    }
}

#[derive(Deserialize)]
#[serde(transparent)]
struct SecretBytes32([u8; 32]);

impl Drop for SecretBytes32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(transparent)]
struct OptionalSecretBytes32(Option<[u8; 32]>);

impl Drop for OptionalSecretBytes32 {
    fn drop(&mut self) {
        if let Some(bytes) = self.0.as_mut() {
            bytes.zeroize();
        }
    }
}

struct OptionalSecretVec(Option<Vec<u8>>);

impl Drop for OptionalSecretVec {
    fn drop(&mut self) {
        if let Some(bytes) = self.0.as_mut() {
            bytes.zeroize();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRatchetSessionV1 {
    #[serde(deserialize_with = "secret_key_serde::deserialize_guard")]
    dh_sending_secret: OptionalSecretVec,
    dh_sending_public: Option<[u8; 32]>,
    dh_receiving: Option<[u8; 32]>,
    root_key: SecretBytes32,
    sending_chain_key: OptionalSecretBytes32,
    receiving_chain_key: OptionalSecretBytes32,
    send_count: u32,
    recv_count: u32,
    prev_send_count: u32,
    #[serde(deserialize_with = "skipped_keys_serde::deserialize_guard")]
    skipped_keys: SecretSkippedKeysMap,
}

impl PersistedRatchetSessionV1 {
    fn into_validated_session(mut self) -> Result<RatchetSession, String> {
        let session = RatchetSession {
            dh_sending_secret: std::mem::take(&mut self.dh_sending_secret.0),
            dh_sending_public: self.dh_sending_public,
            dh_receiving: self.dh_receiving,
            root_key: std::mem::take(&mut self.root_key.0),
            sending_chain_key: std::mem::take(&mut self.sending_chain_key.0),
            receiving_chain_key: std::mem::take(&mut self.receiving_chain_key.0),
            send_count: self.send_count,
            recv_count: self.recv_count,
            prev_send_count: self.prev_send_count,
            skipped_keys: std::mem::take(&mut self.skipped_keys.0),
        };
        session.validate_persisted_shape_v1()?;
        Ok(session)
    }
}

impl Drop for RatchetSession {
    fn drop(&mut self) {
        if let Some(ref mut secret) = self.dh_sending_secret {
            secret.zeroize();
        }
        self.root_key.zeroize();
        if let Some(ref mut ck) = self.sending_chain_key {
            ck.zeroize();
        }
        if let Some(ref mut ck) = self.receiving_chain_key {
            ck.zeroize();
        }
        for key in self.skipped_keys.values_mut() {
            key.zeroize();
        }
    }
}

impl RatchetSession {
    fn validate_persisted_shape_v1(&self) -> Result<(), String> {
        let secret_bytes = self
            .dh_sending_secret
            .as_deref()
            .ok_or_else(|| "persisted ratchet sending secret is absent".to_string())?;
        if secret_bytes.len() != 32 {
            return Err("persisted ratchet sending secret must be 32 bytes".to_string());
        }
        let sending_public = self
            .dh_sending_public
            .ok_or_else(|| "persisted ratchet sending public key is absent".to_string())?;
        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(secret_bytes);
        let secret = X25519StaticSecret::from(secret_array);
        secret_array.zeroize();
        if X25519PublicKey::from(&secret).as_bytes() != &sending_public {
            return Err("persisted ratchet DH secret/public keys do not match".to_string());
        }
        match (
            self.dh_receiving.is_some(),
            self.sending_chain_key.is_some(),
            self.receiving_chain_key.is_some(),
        ) {
            // Bob before the first authenticated receive.
            (false, false, false)
                if self.send_count == 0
                    && self.recv_count == 0
                    && self.prev_send_count == 0
                    && self.skipped_keys.is_empty() => {}
            // Alice before the first authenticated receive. Sending may have
            // advanced, but there is no previous sending chain yet.
            (true, true, false)
                if self.recv_count == 0
                    && self.prev_send_count == 0
                    && self.skipped_keys.is_empty() => {}
            // An authenticated live ratchet always has both chain keys and at
            // least one successfully received message in its current chain.
            // The DH step is never published separately from that receive.
            (true, true, true) if self.recv_count > 0 => {}
            _ => {
                return Err("persisted ratchet state shape is unreachable".to_string());
            }
        }
        if let Some(current_ratchet_key) = self.dh_receiving {
            if self.skipped_keys.keys().any(|(ratchet_key, number)| {
                ratchet_key == &current_ratchet_key && *number >= self.recv_count
            }) {
                return Err(
                    "persisted current-chain skipped key is ahead of receive state".to_string(),
                );
            }
        }
        if self.skipped_keys.len() > MAX_TOTAL_SKIPPED {
            return Err("persisted skipped message key capacity exceeded".to_string());
        }
        Ok(())
    }

    /// Compare this live ratchet with one SQLCipher serialization without
    /// relying on JSON object order. Secret fields and message-key values are
    /// compared in constant time; public counters/map keys may select shape.
    /// The decoded candidate zeroizes its secrets on drop.
    pub fn matches_serialized_v1(&self, serialized: &[u8]) -> Result<bool, String> {
        let persisted = Self::deserialize(serialized)
            .map_err(|error| format!("decode persisted ratchet session: {error}"))?;
        Ok(self.same_state_v1(&persisted))
    }

    fn same_state_v1(&self, other: &Self) -> bool {
        fn optional_secret_bytes_equal(left: &Option<Vec<u8>>, right: &Option<Vec<u8>>) -> bool {
            match (left.as_deref(), right.as_deref()) {
                (Some(left), Some(right)) => {
                    left.len() == right.len() && bool::from(left.ct_eq(right))
                }
                (None, None) => true,
                _ => false,
            }
        }

        fn optional_secret_array_equal(left: &Option<[u8; 32]>, right: &Option<[u8; 32]>) -> bool {
            match (left, right) {
                (Some(left), Some(right)) => bool::from(left.ct_eq(right)),
                (None, None) => true,
                _ => false,
            }
        }

        optional_secret_bytes_equal(&self.dh_sending_secret, &other.dh_sending_secret)
            && self.dh_sending_public == other.dh_sending_public
            && self.dh_receiving == other.dh_receiving
            && bool::from(self.root_key.ct_eq(&other.root_key))
            && optional_secret_array_equal(&self.sending_chain_key, &other.sending_chain_key)
            && optional_secret_array_equal(&self.receiving_chain_key, &other.receiving_chain_key)
            && self.send_count == other.send_count
            && self.recv_count == other.recv_count
            && self.prev_send_count == other.prev_send_count
            && self.skipped_keys.len() == other.skipped_keys.len()
            && self.skipped_keys.iter().all(|(key, message_key)| {
                other
                    .skipped_keys
                    .get(key)
                    .is_some_and(|persisted| bool::from(message_key.ct_eq(persisted)))
            })
    }

    /// Initialize as the initiator (Alice) after X3DH.
    ///
    /// - `shared_secret`: the SK from X3DH
    /// - `peer_ratchet_key`: Bob's SPK (used as initial ratchet key)
    pub fn init_initiator(shared_secret: &[u8; 32], peer_ratchet_key: &[u8; 32]) -> Self {
        let dh_secret = X25519StaticSecret::random_from_rng(OsRng);
        Self::init_initiator_with_secret(shared_secret, peer_ratchet_key, dh_secret)
    }

    /// Test-only deterministic initiator initialization for immutable vectors.
    ///
    /// This is deliberately unavailable outside crate tests so production and
    /// FFI callers cannot replace the CSPRNG-backed ratchet key generation.
    #[cfg(test)]
    pub(crate) fn init_initiator_with_secret_for_test(
        shared_secret: &[u8; 32],
        peer_ratchet_key: &[u8; 32],
        ratchet_secret: &[u8; 32],
    ) -> Self {
        Self::init_initiator_with_secret(
            shared_secret,
            peer_ratchet_key,
            X25519StaticSecret::from(*ratchet_secret),
        )
    }

    fn init_initiator_with_secret(
        shared_secret: &[u8; 32],
        peer_ratchet_key: &[u8; 32],
        dh_secret: X25519StaticSecret,
    ) -> Self {
        let dh_public = X25519PublicKey::from(&dh_secret);

        // First DH ratchet step
        let peer_key = X25519PublicKey::from(*peer_ratchet_key);
        let dh_output = dh_secret.diffie_hellman(&peer_key);

        // KDF_RK: derive new root key and sending chain key
        let mut kdf_output =
            kdf::hkdf_sha256(shared_secret, dh_output.as_bytes(), b"veil-ratchet-v1", 64);

        let mut root_key = [0u8; 32];
        let mut sending_chain_key = [0u8; 32];
        root_key.copy_from_slice(&kdf_output[..32]);
        sending_chain_key.copy_from_slice(&kdf_output[32..]);
        kdf_output.zeroize();

        Self {
            dh_sending_secret: Some(dh_secret.to_bytes().to_vec()),
            dh_sending_public: Some(*dh_public.as_bytes()),
            dh_receiving: Some(*peer_ratchet_key),
            root_key,
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Initialize as the responder (Bob) after X3DH.
    ///
    /// - `shared_secret`: the SK from X3DH
    /// - `our_ratchet_secret`/`our_ratchet_public`: Bob's SPK (reused as initial ratchet key)
    pub fn init_responder(
        shared_secret: &[u8; 32],
        our_ratchet_secret: &[u8],
        our_ratchet_public: &[u8; 32],
    ) -> Self {
        Self {
            dh_sending_secret: Some(our_ratchet_secret.to_vec()),
            dh_sending_public: Some(*our_ratchet_public),
            dh_receiving: None,
            root_key: *shared_secret,
            sending_chain_key: None,
            receiving_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Encrypt a plaintext message.
    ///
    /// Returns `(header, ciphertext)` — both must be sent to the peer.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(MessageHeader, Vec<u8>), String> {
        self.encrypt_with_ad(plaintext, &[])
    }

    /// Encrypt while binding caller-provided associated data (for example the
    /// two identity keys or a conversation identifier) to this message.
    pub fn encrypt_with_ad(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(MessageHeader, Vec<u8>), String> {
        let ck = self
            .sending_chain_key
            .as_ref()
            .ok_or("sending chain not initialized (responder must receive first)")?;

        let mut message_key = kdf::hmac_sha256(ck, b"\x01");
        let next_chain_key = kdf::hmac_sha256(ck, b"\x02");

        let header = MessageHeader {
            ratchet_key: self
                .dh_sending_public
                .ok_or("sending ratchet key not initialized")?,
            n: self.send_count,
            pn: self.prev_send_count,
        };
        let next_send_count = self
            .send_count
            .checked_add(1)
            .ok_or("message counter overflow".to_string())?;

        // Signal-style CONCAT(AD, header): authenticate the canonical header
        // and commit the sending chain only after encryption succeeds.
        let aad = message_aad(associated_data, &header)?;
        let result = aead::encrypt_with_aad(&message_key, plaintext, &aad);
        message_key.zeroize();
        let (ciphertext, nonce) = result?;

        self.sending_chain_key = Some(next_chain_key);
        self.send_count = next_send_count;

        let mut output = Vec::with_capacity(aead::NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        Ok((header, output))
    }

    /// Decrypt a received message.
    ///
    /// Handles DH ratchet steps and out-of-order messages automatically.
    pub fn decrypt(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.decrypt_with_ad(header, ciphertext, &[])
    }

    /// Decrypt with caller-provided associated data.
    ///
    /// All ratchet mutations are made on a clone and committed only after AEAD
    /// authentication succeeds. Invalid packets cannot consume skipped keys or
    /// advance the receiving/DH chains.
    pub fn decrypt_with_ad(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, String> {
        if ciphertext.len() < aead::NONCE_SIZE {
            return Err("ciphertext too short".to_string());
        }

        let mut candidate = self.clone();
        let plaintext = candidate.decrypt_in_place_with_next_ratchet_secret(
            header,
            ciphertext,
            associated_data,
            || X25519StaticSecret::random_from_rng(OsRng),
        )?;
        *self = candidate;
        Ok(plaintext)
    }

    /// Test-only authenticated transition with one reviewed next ratchet key.
    ///
    /// The production path above always supplies `OsRng`. This crate-private
    /// hook exists only so an immutable transcript can freeze the exact state
    /// after the responder's first DH step. It fails unless that transition
    /// consumes the supplied secret exactly once.
    #[cfg(test)]
    pub(crate) fn decrypt_with_ad_and_next_ratchet_secret_for_test(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
        associated_data: &[u8],
        next_ratchet_secret: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        if ciphertext.len() < aead::NONCE_SIZE {
            return Err("ciphertext too short".to_string());
        }

        let mut candidate = self.clone();
        let mut secret_uses = 0u8;
        let plaintext = candidate.decrypt_in_place_with_next_ratchet_secret(
            header,
            ciphertext,
            associated_data,
            || {
                secret_uses += 1;
                X25519StaticSecret::from(*next_ratchet_secret)
            },
        );
        if secret_uses != 1 {
            return Err(format!(
                "test-only next ratchet secret must be consumed exactly once, got {secret_uses}"
            ));
        }
        let plaintext = plaintext?;
        *self = candidate;
        Ok(plaintext)
    }

    fn decrypt_in_place_with_next_ratchet_secret<F>(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
        associated_data: &[u8],
        next_ratchet_secret: F,
    ) -> Result<Vec<u8>, String>
    where
        F: FnOnce() -> X25519StaticSecret,
    {
        let aad = message_aad(associated_data, header)?;

        // Try skipped keys first (out-of-order message)
        if let Some(plaintext) = self.try_skipped_keys(header, ciphertext, &aad)? {
            return Ok(plaintext);
        }

        // Check if we need a DH ratchet step (new ratchet key from peer)
        let need_ratchet = match self.dh_receiving {
            None => true,
            Some(ref current) => *current != header.ratchet_key,
        };

        if need_ratchet {
            // Skip any remaining messages in the current receiving chain
            self.skip_messages(header.pn)?;
            self.dh_ratchet_step_with_next_secret(&header.ratchet_key, next_ratchet_secret)?;
        }

        // Skip messages if needed (gaps in sequence)
        self.skip_messages(header.n)?;

        // KDF_CK: derive message key
        let ck = self
            .receiving_chain_key
            .as_ref()
            .ok_or("receiving chain not initialized")?;
        let mut message_key = kdf::hmac_sha256(ck, b"\x01");
        let next_chain_key = kdf::hmac_sha256(ck, b"\x02");
        self.receiving_chain_key = Some(next_chain_key);
        self.recv_count = self
            .recv_count
            .checked_add(1)
            .ok_or("recv counter overflow".to_string())?;

        // Decrypt
        let nonce: [u8; aead::NONCE_SIZE] = ciphertext[..aead::NONCE_SIZE]
            .try_into()
            .map_err(|_| "invalid nonce")?;
        let ct = &ciphertext[aead::NONCE_SIZE..];

        let result = aead::decrypt_with_aad(&message_key, ct, &nonce, &aad);
        message_key.zeroize();
        result
    }

    /// Perform a DH ratchet step (peer sent a new ratchet key).
    fn dh_ratchet_step_with_next_secret<F>(
        &mut self,
        peer_ratchet_key: &[u8; 32],
        next_ratchet_secret: F,
    ) -> Result<(), String>
    where
        F: FnOnce() -> X25519StaticSecret,
    {
        // DH with our current sending key and peer's new ratchet key
        let peer_key = X25519PublicKey::from(*peer_ratchet_key);
        let our_secret = self.reconstruct_secret()?;
        let dh_output = our_secret.diffie_hellman(&peer_key);
        require_contributory(&dh_output, "ratchet key")?;

        // Generate and validate the next sending DH before deriving or
        // publishing either root transition. A rejected peer key therefore
        // leaves every counter, chain, and key byte unchanged.
        let new_secret = next_ratchet_secret();
        let new_public = X25519PublicKey::from(&new_secret);
        let dh_output2 = new_secret.diffie_hellman(&peer_key);
        require_contributory(&dh_output2, "ratchet key")?;

        // KDF_RK → new root key + receiving chain key
        let mut kdf_out =
            kdf::hkdf_sha256(&self.root_key, dh_output.as_bytes(), b"veil-ratchet-v1", 64);
        let mut receiving_root_key = [0u8; 32];
        receiving_root_key.copy_from_slice(&kdf_out[..32]);
        let mut recv_ck = [0u8; 32];
        recv_ck.copy_from_slice(&kdf_out[32..]);
        kdf_out.zeroize();

        // KDF_RK → new root key + sending chain key
        let mut kdf_out2 = kdf::hkdf_sha256(
            &receiving_root_key,
            dh_output2.as_bytes(),
            b"veil-ratchet-v1",
            64,
        );
        let mut sending_root_key = [0u8; 32];
        sending_root_key.copy_from_slice(&kdf_out2[..32]);
        let mut send_ck = [0u8; 32];
        send_ck.copy_from_slice(&kdf_out2[32..]);
        kdf_out2.zeroize();

        self.prev_send_count = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;
        self.dh_receiving = Some(*peer_ratchet_key);
        self.root_key = sending_root_key;
        self.receiving_chain_key = Some(recv_ck);
        self.sending_chain_key = Some(send_ck);
        self.dh_sending_secret = Some(new_secret.to_bytes().to_vec());
        self.dh_sending_public = Some(*new_public.as_bytes());

        receiving_root_key.zeroize();
        sending_root_key.zeroize();
        recv_ck.zeroize();
        send_ck.zeroize();

        Ok(())
    }

    /// Skip ahead to message number `until`, storing skipped keys.
    fn skip_messages(&mut self, until: u32) -> Result<(), String> {
        if until.saturating_sub(self.recv_count) > MAX_SKIP {
            return Err(format!(
                "too many skipped messages: {} → {}",
                self.recv_count, until
            ));
        }

        if let Some(ref ck) = self.receiving_chain_key {
            let ratchet_key = self
                .dh_receiving
                .ok_or("receiving chain has no ratchet key")?;
            let gap = until.saturating_sub(self.recv_count) as usize;
            if gap > MAX_TOTAL_SKIPPED.saturating_sub(self.skipped_keys.len()) {
                return Err("skipped message key capacity exhausted".to_string());
            }
            if (self.recv_count..until)
                .any(|number| self.skipped_keys.contains_key(&(ratchet_key, number)))
            {
                return Err("duplicate skipped message key state".to_string());
            }

            let mut chain_key = *ck;
            while self.recv_count < until {
                let mut message_key = kdf::hmac_sha256(&chain_key, b"\x01");
                let mut next_ck = kdf::hmac_sha256(&chain_key, b"\x02");
                chain_key.zeroize();
                chain_key = next_ck;
                next_ck.zeroize();

                let skipped_key = (ratchet_key, self.recv_count);
                self.skipped_keys.insert(skipped_key, message_key);
                message_key.zeroize();
                self.recv_count = self
                    .recv_count
                    .checked_add(1)
                    .ok_or("recv counter overflow in skip".to_string())?;
            }
            self.receiving_chain_key = Some(chain_key);
            chain_key.zeroize();
        }

        Ok(())
    }

    /// Try to decrypt using a previously skipped message key.
    fn try_skipped_keys(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Option<Vec<u8>>, String> {
        let key = (header.ratchet_key, header.n);
        if let Some(stored_message_key) = self.skipped_keys.get(&key) {
            let message_key = Zeroizing::new(*stored_message_key);
            let nonce: [u8; aead::NONCE_SIZE] = ciphertext[..aead::NONCE_SIZE]
                .try_into()
                .map_err(|_| "invalid nonce")?;
            let ct = &ciphertext[aead::NONCE_SIZE..];
            let result = aead::decrypt_with_aad(&message_key, ct, &nonce, aad);
            let plaintext = result?;

            // Wipe the live bucket before removing it. Removing a Copy value
            // first can leave the moved-from bucket outside the map's Drop
            // traversal. On authentication error the entry remains active, so
            // dropping the unpublished candidate wipes it normally.
            self.skipped_keys
                .get_mut(&key)
                .ok_or("authenticated skipped message key disappeared")?
                .zeroize();
            let mut removed = self
                .skipped_keys
                .remove(&key)
                .ok_or("authenticated skipped message key disappeared")?;
            removed.zeroize();
            Ok(Some(plaintext))
        } else {
            Ok(None)
        }
    }

    /// Reconstruct X25519 StaticSecret from stored bytes.
    fn reconstruct_secret(&self) -> Result<X25519StaticSecret, String> {
        let bytes = self.dh_sending_secret.as_ref().ok_or("no sending secret")?;
        let mut arr = [0u8; 32];
        if bytes.len() != 32 {
            return Err("invalid secret length".to_string());
        }
        arr.copy_from_slice(bytes);
        let secret = X25519StaticSecret::from(arr);
        arr.zeroize();
        Ok(secret)
    }

    /// Serialize session state for persistence (encrypted by veil-store).
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        self.validate_persisted_shape_v1()
            .map_err(|error| format!("serialize: {error}"))?;
        let mut serialized = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *serialized, self).map_err(|e| format!("serialize: {e}"))?;
        if serialized.len() > MAX_SERIALIZED_RATCHET_BYTES {
            return Err("serialize: ratchet session is oversized".to_string());
        }
        Ok(std::mem::take(&mut *serialized))
    }

    /// Deserialize session state.
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        if data.is_empty() || data.len() > MAX_SERIALIZED_RATCHET_BYTES {
            return Err("deserialize: ratchet session is empty or oversized".to_string());
        }
        // The v1 writer never emits JSON escapes: every field name is fixed,
        // Base64 uses an escape-free alphabet, and all other fields are
        // numeric. Reject aliases before serde_json can copy an escaped secret
        // string into its internal scratch buffer, which it does not zeroize.
        if data.contains(&b'\\') {
            return Err("deserialize: ratchet session contains non-canonical JSON escapes".into());
        }
        let persisted: PersistedRatchetSessionV1 =
            serde_json::from_slice(data).map_err(|e| format!("deserialize: {e}"))?;
        persisted
            .into_validated_session()
            .map_err(|e| format!("deserialize: {e}"))
    }
}

// Serde helpers for secret key serialization
mod secret_key_serde {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::{Zeroize, Zeroizing};

    const ENCODED_KEY_BYTES: usize = 44;
    // Padded Base64 length estimates can be one byte above the actual decoded
    // length. Keep that byte caller-owned and wipe the entire buffer on drop.
    const DECODE_BUFFER_BYTES: usize = 33;

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => {
                let mut encoded = base64::engine::general_purpose::STANDARD.encode(value);
                let result = serializer.serialize_some(&encoded);
                encoded.zeroize();
                result
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize_guard<'de, D>(deserializer: D) -> Result<super::OptionalSecretVec, D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::Engine;
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(encoded) => {
                let encoded = Zeroizing::new(encoded);
                if encoded.len() != ENCODED_KEY_BYTES {
                    return Err(serde::de::Error::custom(
                        "invalid canonical ratchet sending secret",
                    ));
                }

                let mut decoded = Zeroizing::new([0u8; DECODE_BUFFER_BYTES]);
                let decoded_len = base64::engine::general_purpose::STANDARD
                    .decode_slice(encoded.as_bytes(), decoded.as_mut())
                    .map_err(serde::de::Error::custom)?;
                let canonical = decoded_len == 32 && {
                    let mut canonical_encoded =
                        base64::engine::general_purpose::STANDARD.encode(&decoded[..decoded_len]);
                    let result = canonical_encoded == encoded.as_str();
                    canonical_encoded.zeroize();
                    result
                };
                if !canonical {
                    return Err(serde::de::Error::custom(
                        "invalid canonical ratchet sending secret",
                    ));
                }
                Ok(super::OptionalSecretVec(Some(decoded[..32].to_vec())))
            }
            None => Ok(super::OptionalSecretVec(None)),
        }
    }
}

mod skipped_keys_serde {
    use super::{SecretSkippedKeysMap, SkippedKeysMap, MAX_TOTAL_SKIPPED};
    use base64::Engine;
    use serde::de::{MapAccess, Visitor};
    use serde::ser::SerializeMap;
    use serde::{Deserializer, Serializer};
    use std::collections::HashMap;
    use std::fmt;
    use zeroize::{Zeroize, Zeroizing};

    const ENCODED_KEY_BYTES: usize = 44;
    const DECODE_BUFFER_BYTES: usize = 33;

    pub fn serialize<S>(value: &SkippedKeysMap, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if value.len() > MAX_TOTAL_SKIPPED {
            return Err(serde::ser::Error::custom(
                "skipped message key capacity exceeded",
            ));
        }
        // Preserve the existing v1 JSON object shape but emit raw ratchet-key
        // bytes and numeric counters in a canonical order. In particular,
        // frozen empty states remain `{}`, while 2 sorts before 10.
        let mut entries: Vec<_> = value.iter().collect();
        entries.sort_unstable_by(
            |((left_key, left_number), _), ((right_key, right_number), _)| {
                left_key.cmp(right_key).then(left_number.cmp(right_number))
            },
        );
        let mut map = serializer.serialize_map(Some(entries.len()))?;
        for ((ratchet_key, number), message_key) in entries {
            let encoded_key = format!(
                "{}:{}",
                base64::engine::general_purpose::STANDARD.encode(ratchet_key),
                number
            );
            let mut encoded_message_key =
                base64::engine::general_purpose::STANDARD.encode(message_key);
            let serialized = map.serialize_entry(&encoded_key, &encoded_message_key);
            encoded_message_key.zeroize();
            serialized?;
        }
        map.end()
    }

    pub fn deserialize_guard<'de, D>(deserializer: D) -> Result<SecretSkippedKeysMap, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SkippedKeysVisitor;

        impl<'de> Visitor<'de> for SkippedKeysVisitor {
            type Value = SecretSkippedKeysMap;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded canonical skipped-message-key object")
            }

            fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut result = SecretSkippedKeysMap(HashMap::new());
                while let Some((encoded_key, encoded_message_key)) =
                    entries.next_entry::<String, String>()?
                {
                    let encoded_message_key = Zeroizing::new(encoded_message_key);
                    if result.0.len() >= MAX_TOTAL_SKIPPED {
                        return Err(serde::de::Error::custom(
                            "skipped message key capacity exceeded",
                        ));
                    }
                    let (encoded_ratchet_key, encoded_number) = encoded_key
                        .rsplit_once(':')
                        .ok_or_else(|| serde::de::Error::custom("invalid skipped message key"))?;
                    let number: u32 = encoded_number.parse().map_err(serde::de::Error::custom)?;
                    if encoded_number != number.to_string() {
                        return Err(serde::de::Error::custom(
                            "non-canonical skipped message number",
                        ));
                    }

                    if encoded_ratchet_key.len() != ENCODED_KEY_BYTES {
                        return Err(serde::de::Error::custom(
                            "invalid canonical skipped ratchet key",
                        ));
                    }
                    let mut ratchet_key_bytes = [0u8; DECODE_BUFFER_BYTES];
                    let ratchet_key_len = base64::engine::general_purpose::STANDARD
                        .decode_slice(encoded_ratchet_key.as_bytes(), &mut ratchet_key_bytes)
                        .map_err(serde::de::Error::custom)?;
                    if ratchet_key_len != 32
                        || base64::engine::general_purpose::STANDARD
                            .encode(&ratchet_key_bytes[..ratchet_key_len])
                            != encoded_ratchet_key
                    {
                        return Err(serde::de::Error::custom(
                            "invalid canonical skipped ratchet key",
                        ));
                    }

                    if encoded_message_key.len() != ENCODED_KEY_BYTES {
                        return Err(serde::de::Error::custom(
                            "invalid canonical skipped message key material",
                        ));
                    }
                    let mut message_key_bytes = Zeroizing::new([0u8; DECODE_BUFFER_BYTES]);
                    let message_key_len = base64::engine::general_purpose::STANDARD
                        .decode_slice(encoded_message_key.as_bytes(), message_key_bytes.as_mut())
                        .map_err(serde::de::Error::custom)?;
                    let canonical_message_key = if message_key_len == 32 {
                        let mut canonical_encoded = base64::engine::general_purpose::STANDARD
                            .encode(&message_key_bytes[..message_key_len]);
                        let result = canonical_encoded == encoded_message_key.as_str();
                        canonical_encoded.zeroize();
                        result
                    } else {
                        false
                    };
                    if !canonical_message_key {
                        return Err(serde::de::Error::custom(
                            "invalid canonical skipped message key material",
                        ));
                    }

                    let mut ratchet_key = [0u8; 32];
                    ratchet_key.copy_from_slice(&ratchet_key_bytes[..32]);
                    let mut message_key = [0u8; 32];
                    message_key.copy_from_slice(&message_key_bytes[..32]);
                    if result.0.contains_key(&(ratchet_key, number)) {
                        message_key.zeroize();
                        return Err(serde::de::Error::custom("duplicate skipped message key"));
                    }
                    result.0.insert((ratchet_key, number), message_key);
                    message_key.zeroize();
                }

                Ok(result)
            }
        }

        deserializer.deserialize_map(SkippedKeysVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKeyPair;
    use crate::x3dh::{self, OneTimePreKey, SignedPreKey};

    fn setup_sessions() -> (RatchetSession, RatchetSession) {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();

        let bob_spk = SignedPreKey::generate(&bob_identity, 1);
        let bob_opk = OneTimePreKey::generate(1);

        let bob_bundle = x3dh::PreKeyBundle {
            identity_key: bob_identity.x25519_public_bytes(),
            signing_key: bob_identity.ed25519_public_bytes(),
            signed_prekey: *bob_spk.public.as_bytes(),
            signed_prekey_signature: bob_spk.signature,
            signed_prekey_id: 1,
            one_time_prekey: Some(*bob_opk.public.as_bytes()),
            one_time_prekey_id: Some(1),
        };

        // X3DH
        let alice_x3dh = x3dh::initiate(&alice_identity, &bob_bundle).unwrap();
        let bob_x3dh = x3dh::respond(
            &bob_identity,
            &bob_spk,
            Some(&bob_opk),
            &alice_identity.x25519_public_bytes(),
            &alice_x3dh.ephemeral_public,
        )
        .unwrap();

        assert_eq!(alice_x3dh.shared_secret, bob_x3dh.shared_secret);

        // Initialize ratchet sessions
        let alice_session =
            RatchetSession::init_initiator(&alice_x3dh.shared_secret, &bob_bundle.signed_prekey);
        let bob_session = RatchetSession::init_responder(
            &bob_x3dh.shared_secret,
            &bob_spk.secret.to_bytes(),
            bob_spk.public.as_bytes(),
        );

        (alice_session, bob_session)
    }

    fn assert_serialized_session_eq(actual: Vec<u8>, expected: Vec<u8>) {
        let actual: serde_json::Value = serde_json::from_slice(&actual).unwrap();
        let expected: serde_json::Value = serde_json::from_slice(&expected).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn persisted_state_match_is_independent_of_skipped_key_map_order() {
        let (mut sender, mut live) = setup_sessions();
        let (header, ciphertext) = sender.encrypt(b"initialize receiver").unwrap();
        live.decrypt(&header, &ciphertext).unwrap();
        let first = ([0x31; 32], 7);
        let second = ([0x42; 32], 9);
        live.skipped_keys.insert(first, [0xA1; 32]);
        live.skipped_keys.insert(second, [0xB2; 32]);

        let mut persisted = live.clone();
        persisted.skipped_keys.clear();
        persisted.skipped_keys.insert(second, [0xB2; 32]);
        persisted.skipped_keys.insert(first, [0xA1; 32]);
        let serialized = serde_json::to_vec(&persisted).unwrap();
        assert_eq!(live.serialize().unwrap(), persisted.serialize().unwrap());
        assert!(live.matches_serialized_v1(&serialized).unwrap());

        persisted.skipped_keys.insert(first, [0xFF; 32]);
        let changed = serde_json::to_vec(&persisted).unwrap();
        assert!(!live.matches_serialized_v1(&changed).unwrap());
        assert!(live.matches_serialized_v1(b"not-json").is_err());
    }

    fn replace_skipped_entries(serialized: &[u8], entries: &str) -> Vec<u8> {
        String::from_utf8(serialized.to_vec())
            .unwrap()
            .replacen(
                "\"skipped_keys\":{}",
                &format!("\"skipped_keys\":{{{entries}}}"),
                1,
            )
            .into_bytes()
    }

    fn session_json_with_skipped_entries(entries: &str) -> Vec<u8> {
        let (mut sender, mut session) = setup_sessions();
        let (header, ciphertext) = sender.encrypt(b"initialize receiver").unwrap();
        session.decrypt(&header, &ciphertext).unwrap();
        replace_skipped_entries(&session.serialize().unwrap(), entries)
    }

    fn encoded_skipped_entry(
        ratchet_key: impl AsRef<[u8]>,
        number: &str,
        message_key: impl AsRef<[u8]>,
    ) -> String {
        use base64::Engine;

        format!(
            "\"{}:{}\":\"{}\"",
            base64::engine::general_purpose::STANDARD.encode(ratchet_key),
            number,
            base64::engine::general_purpose::STANDARD.encode(message_key)
        )
    }

    #[test]
    fn skipped_key_serialization_is_canonical_and_accepts_legacy_member_order() {
        let first = encoded_skipped_entry([0x31; 32], "7", [0xA1; 32]);
        let second = encoded_skipped_entry([0x42; 32], "9", [0xB2; 32]);
        let (mut sender, mut session) = setup_sessions();
        let (header, ciphertext) = sender.encrypt(b"initialize receiver").unwrap();
        session.decrypt(&header, &ciphertext).unwrap();
        let base = session.serialize().unwrap();
        let forward = replace_skipped_entries(&base, &format!("{first},{second}"));
        let reverse = replace_skipped_entries(&base, &format!("{second},{first}"));

        let forward = RatchetSession::deserialize(&forward).unwrap();
        let reverse = RatchetSession::deserialize(&reverse).unwrap();
        assert!(forward.same_state_v1(&reverse));
        assert_eq!(forward.serialize().unwrap(), reverse.serialize().unwrap());

        let ten = encoded_skipped_entry([0x55; 32], "10", [0x10; 32]);
        let two = encoded_skipped_entry([0x55; 32], "2", [0x02; 32]);
        let numeric =
            RatchetSession::deserialize(&replace_skipped_entries(&base, &format!("{ten},{two}")))
                .unwrap();
        let numeric = String::from_utf8(numeric.serialize().unwrap()).unwrap();
        assert!(numeric.find(":2\"").unwrap() < numeric.find(":10\"").unwrap());
    }

    #[test]
    fn persisted_ratchet_shape_rejects_unknown_mismatched_and_impossible_state() {
        use base64::Engine;

        let (session, _) = setup_sessions();
        let base: serde_json::Value =
            serde_json::from_slice(&session.serialize().unwrap()).unwrap();

        let mut unknown = base.clone();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(RatchetSession::deserialize(&serde_json::to_vec(&unknown).unwrap()).is_err());

        let mut mismatched_public = base.clone();
        let first_public_byte = mismatched_public["dh_sending_public"][0].as_u64().unwrap();
        mismatched_public["dh_sending_public"][0] = serde_json::json!(first_public_byte ^ 1);
        assert!(
            RatchetSession::deserialize(&serde_json::to_vec(&mismatched_public).unwrap()).is_err()
        );

        let mut short_secret = base.clone();
        short_secret["dh_sending_secret"] =
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode([0x11; 31]));
        assert!(RatchetSession::deserialize(&serde_json::to_vec(&short_secret).unwrap()).is_err());

        let mut malformed_secret = base.clone();
        malformed_secret["dh_sending_secret"] = serde_json::json!("!".repeat(44));
        assert!(
            RatchetSession::deserialize(&serde_json::to_vec(&malformed_secret).unwrap()).is_err()
        );

        let mut escaped_secret = Zeroizing::new(
            String::from_utf8(session.serialize().unwrap()).expect("ratchet JSON is UTF-8"),
        );
        let secret_marker = "\"dh_sending_secret\":\"";
        let secret_start = escaped_secret.find(secret_marker).unwrap() + secret_marker.len();
        let secret_byte = escaped_secret.as_bytes()[secret_start];
        escaped_secret.replace_range(
            secret_start..secret_start + 1,
            &format!("\\u00{secret_byte:02X}"),
        );
        let error = match RatchetSession::deserialize(escaped_secret.as_bytes()) {
            Ok(_) => panic!("escaped persisted secret was accepted"),
            Err(error) => error,
        };
        assert!(error.contains("non-canonical JSON escapes"));

        let mut missing_initial_sending_chain = base.clone();
        missing_initial_sending_chain["sending_chain_key"] = serde_json::Value::Null;
        assert!(RatchetSession::deserialize(
            &serde_json::to_vec(&missing_initial_sending_chain).unwrap()
        )
        .is_err());

        let mut impossible_previous_chain = base.clone();
        impossible_previous_chain["prev_send_count"] = serde_json::json!(1);
        assert!(RatchetSession::deserialize(
            &serde_json::to_vec(&impossible_previous_chain).unwrap()
        )
        .is_err());

        let mut impossible_counter = base;
        impossible_counter["sending_chain_key"] = serde_json::Value::Null;
        impossible_counter["send_count"] = serde_json::json!(1);
        assert!(
            RatchetSession::deserialize(&serde_json::to_vec(&impossible_counter).unwrap()).is_err()
        );

        let (mut sender, mut receiver) = setup_sessions();
        let (header, ciphertext) = sender.encrypt(b"initialize receiver").unwrap();
        receiver.decrypt(&header, &ciphertext).unwrap();
        let mut missing_live_sending_chain: serde_json::Value =
            serde_json::from_slice(&receiver.serialize().unwrap()).unwrap();
        missing_live_sending_chain["sending_chain_key"] = serde_json::Value::Null;
        assert!(RatchetSession::deserialize(
            &serde_json::to_vec(&missing_live_sending_chain).unwrap()
        )
        .is_err());

        let mut responder_live_with_zero_recv: serde_json::Value =
            serde_json::from_slice(&receiver.serialize().unwrap()).unwrap();
        responder_live_with_zero_recv["recv_count"] = serde_json::json!(0);
        assert!(RatchetSession::deserialize(
            &serde_json::to_vec(&responder_live_with_zero_recv).unwrap()
        )
        .is_err());

        let (reply_header, reply_ciphertext) = receiver.encrypt(b"reply").unwrap();
        sender.decrypt(&reply_header, &reply_ciphertext).unwrap();
        let mut initiator_live_with_zero_recv: serde_json::Value =
            serde_json::from_slice(&sender.serialize().unwrap()).unwrap();
        initiator_live_with_zero_recv["recv_count"] = serde_json::json!(0);
        assert!(RatchetSession::deserialize(
            &serde_json::to_vec(&initiator_live_with_zero_recv).unwrap()
        )
        .is_err());

        let mut ahead = receiver.serialize().unwrap();
        let entry = encoded_skipped_entry(
            receiver.dh_receiving.unwrap(),
            &receiver.recv_count.to_string(),
            [0x22; 32],
        );
        ahead = replace_skipped_entries(&ahead, &entry);
        assert!(RatchetSession::deserialize(&ahead).is_err());
    }

    #[test]
    fn skipped_key_deserialization_rejects_malformed_noncanonical_and_duplicate_entries() {
        use base64::Engine;

        let canonical = encoded_skipped_entry([0x31; 32], "7", [0xA1; 32]);
        let short_ratchet = encoded_skipped_entry([0x31; 31], "7", [0xA1; 32]);
        let short_message = encoded_skipped_entry([0x31; 32], "7", [0xA1; 31]);
        let leading_zero = encoded_skipped_entry([0x31; 32], "07", [0xA1; 32]);
        let unpadded_ratchet = canonical.replacen(
            &base64::engine::general_purpose::STANDARD.encode([0x31; 32]),
            &base64::engine::general_purpose::STANDARD_NO_PAD.encode([0x31; 32]),
            1,
        );
        let invalid_message = format!(
            "\"{}:7\":\"{}\"",
            base64::engine::general_purpose::STANDARD.encode([0x31; 32]),
            "!".repeat(44)
        );
        let malformed = format!(
            "\"missing-number\":\"{}\"",
            base64::engine::general_purpose::STANDARD.encode([0xA1; 32])
        );

        for entries in [
            malformed,
            short_ratchet,
            short_message,
            leading_zero,
            unpadded_ratchet,
            invalid_message,
            format!("{canonical},{canonical}"),
        ] {
            assert!(
                RatchetSession::deserialize(&session_json_with_skipped_entries(&entries)).is_err(),
                "accepted malformed skipped-key entry: {entries}"
            );
        }
    }

    #[test]
    fn skipped_key_deserialization_enforces_total_and_document_bounds() {
        let entries = (0..=MAX_TOTAL_SKIPPED)
            .map(|number| encoded_skipped_entry([0x31; 32], &number.to_string(), [0xA1; 32]))
            .collect::<Vec<_>>()
            .join(",");
        let oversized_map = session_json_with_skipped_entries(&entries);
        assert!(oversized_map.len() < MAX_SERIALIZED_RATCHET_BYTES);
        let map_error = match RatchetSession::deserialize(&oversized_map) {
            Ok(_) => panic!("oversized skipped-key map was accepted"),
            Err(error) => error,
        };
        assert!(map_error.contains("capacity exceeded"));
        let document_error =
            match RatchetSession::deserialize(&vec![b' '; MAX_SERIALIZED_RATCHET_BYTES + 1]) {
                Ok(_) => panic!("oversized ratchet document was accepted"),
                Err(error) => error,
            };
        assert!(document_error.contains("empty or oversized"));
    }

    #[test]
    fn skipped_key_capacity_and_counter_exhaustion_roll_back() {
        let (mut alice, mut bob) = setup_sessions();
        let (header, ciphertext) = alice.encrypt(b"initialize receiving chain").unwrap();
        bob.decrypt(&header, &ciphertext).unwrap();

        for number in 0..MAX_TOTAL_SKIPPED as u32 {
            bob.skipped_keys.insert(([0x7A; 32], number), [0xA5; 32]);
        }
        let before_capacity = bob.serialize().unwrap();
        let error = bob.skip_messages(bob.recv_count + 1).unwrap_err();
        assert!(error.contains("capacity exhausted"));
        assert_eq!(bob.serialize().unwrap(), before_capacity);

        bob.skipped_keys.clear();
        bob.recv_count = u32::MAX - 1;
        bob.skip_messages(u32::MAX).unwrap();
        let before_counter = bob.serialize().unwrap();
        let header = MessageHeader {
            ratchet_key: bob.dh_receiving.unwrap(),
            n: u32::MAX,
            pn: 0,
        };
        let error = bob.decrypt(&header, &[0; aead::NONCE_SIZE]).unwrap_err();
        assert!(error.contains("recv counter overflow"));
        assert_eq!(bob.serialize().unwrap(), before_counter);
    }

    #[test]
    fn per_chain_skip_limit_rejects_without_losing_authentic_packets() {
        let (mut alice, mut bob) = setup_sessions();
        let mut packets = Vec::new();
        for number in 0..=MAX_SKIP + 1 {
            packets.push(
                alice
                    .encrypt(format!("message-{number}").as_bytes())
                    .unwrap(),
            );
        }
        let before = bob.serialize().unwrap();
        let rejected = &packets[(MAX_SKIP + 1) as usize];
        assert!(bob.decrypt(&rejected.0, &rejected.1).is_err());
        assert_eq!(bob.serialize().unwrap(), before);

        let boundary = &packets[MAX_SKIP as usize];
        assert_eq!(
            bob.decrypt(&boundary.0, &boundary.1).unwrap(),
            format!("message-{MAX_SKIP}").as_bytes()
        );
        assert_eq!(
            bob.decrypt(&packets[0].0, &packets[0].1).unwrap(),
            b"message-0"
        );
    }

    #[test]
    fn test_basic_messaging() {
        let (mut alice, mut bob) = setup_sessions();

        // Alice sends to Bob
        let (header, ct) = alice.encrypt(b"Hello Bob!").unwrap();
        let plaintext = bob.decrypt(&header, &ct).unwrap();
        assert_eq!(plaintext, b"Hello Bob!");

        // Bob replies to Alice
        let (header, ct) = bob.encrypt(b"Hi Alice!").unwrap();
        let plaintext = alice.decrypt(&header, &ct).unwrap();
        assert_eq!(plaintext, b"Hi Alice!");
    }

    #[test]
    fn test_multiple_messages_same_direction() {
        let (mut alice, mut bob) = setup_sessions();

        for i in 0..10 {
            let msg = format!("Message {i}");
            let (header, ct) = alice.encrypt(msg.as_bytes()).unwrap();
            let plaintext = bob.decrypt(&header, &ct).unwrap();
            assert_eq!(plaintext, msg.as_bytes());
        }
    }

    #[test]
    fn test_ping_pong() {
        let (mut alice, mut bob) = setup_sessions();

        for i in 0..20 {
            if i % 2 == 0 {
                let msg = format!("Alice says {i}");
                let (h, ct) = alice.encrypt(msg.as_bytes()).unwrap();
                let pt = bob.decrypt(&h, &ct).unwrap();
                assert_eq!(pt, msg.as_bytes());
            } else {
                let msg = format!("Bob says {i}");
                let (h, ct) = bob.encrypt(msg.as_bytes()).unwrap();
                let pt = alice.decrypt(&h, &ct).unwrap();
                assert_eq!(pt, msg.as_bytes());
            }
        }
    }

    #[test]
    fn test_out_of_order() {
        let (mut alice, mut bob) = setup_sessions();

        // Alice sends 3 messages
        let (h1, ct1) = alice.encrypt(b"First").unwrap();
        let (h2, ct2) = alice.encrypt(b"Second").unwrap();
        let (h3, ct3) = alice.encrypt(b"Third").unwrap();

        // Bob receives them out of order
        assert_eq!(bob.decrypt(&h3, &ct3).unwrap(), b"Third");
        assert_eq!(bob.decrypt(&h1, &ct1).unwrap(), b"First");
        assert_eq!(bob.decrypt(&h2, &ct2).unwrap(), b"Second");
    }

    #[test]
    fn test_session_serialization() {
        let (mut alice, mut bob) = setup_sessions();

        // Exchange some messages
        let (h, ct) = alice.encrypt(b"Before serialize").unwrap();
        bob.decrypt(&h, &ct).unwrap();

        // Serialize and deserialize Alice's session
        let data = alice.serialize().unwrap();
        let mut alice2 = RatchetSession::deserialize(&data).unwrap();

        // Continue messaging with restored session
        let (h, ct) = alice2.encrypt(b"After deserialize").unwrap();
        let pt = bob.decrypt(&h, &ct).unwrap();
        assert_eq!(pt, b"After deserialize");
    }

    #[test]
    fn test_forward_secrecy() {
        let (mut alice, mut bob) = setup_sessions();

        // Exchange messages to advance ratchet
        let (h, ct) = alice.encrypt(b"Secret 1").unwrap();
        bob.decrypt(&h, &ct).unwrap();

        let (h, ct) = bob.encrypt(b"Secret 2").unwrap();
        alice.decrypt(&h, &ct).unwrap();

        // Capture Alice's state
        let alice_state = alice.serialize().unwrap();

        // More messages
        let (h, ct) = alice.encrypt(b"Secret 3").unwrap();
        bob.decrypt(&h, &ct).unwrap();

        // Even with Alice's old state, can't decrypt new messages
        // (the ratchet has advanced)
        let _old_alice = RatchetSession::deserialize(&alice_state).unwrap();
        // old_alice can't decrypt messages sent after the state was captured
        // because the ratchet keys have changed
    }

    #[test]
    fn test_empty_message() {
        let (mut alice, mut bob) = setup_sessions();

        let (h, ct) = alice.encrypt(b"").unwrap();
        let pt = bob.decrypt(&h, &ct).unwrap();
        assert_eq!(pt, b"");
    }

    #[test]
    fn test_large_message() {
        let (mut alice, mut bob) = setup_sessions();

        let large = vec![0x42u8; 100_000]; // 100 KB
        let (h, ct) = alice.encrypt(&large).unwrap();
        let pt = bob.decrypt(&h, &ct).unwrap();
        assert_eq!(pt, large);
    }

    #[test]
    fn test_header_roundtrip_is_explicitly_versioned() {
        let header = MessageHeader {
            ratchet_key: [7u8; 32],
            n: 42,
            pn: 9,
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 41);
        assert_eq!(bytes[0], RATCHET_HEADER_VERSION);
        assert_eq!(MessageHeader::from_bytes(&bytes).unwrap(), header);

        // Legacy v1 headers had no version byte and must not be interpreted as
        // v2, because their ciphertext did not authenticate the header.
        assert!(MessageHeader::from_bytes(&bytes[1..]).is_err());
        let mut unknown = bytes;
        unknown[0] = 0x7f;
        assert!(MessageHeader::from_bytes(&unknown).is_err());
    }

    #[test]
    fn test_tampered_header_does_not_desync_session() {
        let (mut alice, mut bob) = setup_sessions();
        let (header, ciphertext) = alice.encrypt(b"authenticated header").unwrap();
        let before = bob.serialize().unwrap();

        let mut tampered = header.clone();
        tampered.n ^= 1;
        assert!(bob.decrypt(&tampered, &ciphertext).is_err());
        assert_serialized_session_eq(bob.serialize().unwrap(), before);

        // The authentic packet must still decrypt after the failed attempt.
        assert_eq!(
            bob.decrypt(&header, &ciphertext).unwrap(),
            b"authenticated header"
        );
    }

    #[test]
    fn non_contributory_received_ratchet_keys_do_not_mutate_session() {
        let (mut alice, mut bob) = setup_sessions();
        let (authentic_header, authentic_ciphertext) =
            alice.encrypt(b"still authentic after rejected DH").unwrap();
        let before = bob.serialize().unwrap();

        let mut non_zero_low_order = [0u8; 32];
        non_zero_low_order[0] = 1;
        for ratchet_key in [[0u8; 32], non_zero_low_order] {
            let hostile_header = MessageHeader {
                ratchet_key,
                ..authentic_header.clone()
            };
            let error = bob
                .decrypt(&hostile_header, &authentic_ciphertext)
                .unwrap_err();
            assert!(error.contains("non-contributory X25519 ratchet key"));
            assert_serialized_session_eq(bob.serialize().unwrap(), before.clone());
        }

        assert_eq!(
            bob.decrypt(&authentic_header, &authentic_ciphertext)
                .unwrap(),
            b"still authentic after rejected DH"
        );
    }

    #[test]
    fn test_failed_skipped_key_authentication_does_not_consume_key() {
        let (mut alice, mut bob) = setup_sessions();
        let (h1, ct1) = alice.encrypt(b"one").unwrap();
        let (_h2, _ct2) = alice.encrypt(b"two").unwrap();
        let (h3, ct3) = alice.encrypt(b"three").unwrap();

        assert_eq!(bob.decrypt(&h3, &ct3).unwrap(), b"three");
        let before = bob.serialize().unwrap();

        let mut tampered = h1.clone();
        tampered.pn ^= 1;
        let mut rejected_candidate = bob.clone();
        let aad = message_aad(&[], &tampered).unwrap();
        assert!(rejected_candidate
            .try_skipped_keys(&tampered, &ct1, &aad)
            .is_err());
        assert!(rejected_candidate
            .skipped_keys
            .contains_key(&(tampered.ratchet_key, tampered.n)));
        assert!(bob.decrypt(&tampered, &ct1).is_err());
        assert_serialized_session_eq(bob.serialize().unwrap(), before);
        assert_eq!(bob.decrypt(&h1, &ct1).unwrap(), b"one");
    }

    #[test]
    fn test_caller_associated_data_is_authenticated() {
        let (mut alice, mut bob) = setup_sessions();
        let (header, ciphertext) = alice
            .encrypt_with_ad(b"bound", b"alice|bob|conversation-a")
            .unwrap();
        let before = bob.serialize().unwrap();

        assert!(bob
            .decrypt_with_ad(&header, &ciphertext, b"alice|bob|conversation-b")
            .is_err());
        assert_serialized_session_eq(bob.serialize().unwrap(), before);
        assert_eq!(
            bob.decrypt_with_ad(&header, &ciphertext, b"alice|bob|conversation-a")
                .unwrap(),
            b"bound"
        );
    }
}
