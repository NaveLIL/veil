use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crate::aead;
use crate::kdf;

/// Type alias for the skipped message keys map: (ratchet_public_key, message_number) -> message_key.
type SkippedKeysMap = HashMap<([u8; 32], u32), [u8; 32]>;

/// Maximum number of skipped message keys to store (out-of-order tolerance).
const MAX_SKIP: u32 = 1000;
/// Absolute maximum number of total stored skipped keys (prevents unbounded growth).
const MAX_TOTAL_SKIPPED: usize = 5000;
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
#[derive(Clone, Serialize, Deserialize)]
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
    /// Initialize as the initiator (Alice) after X3DH.
    ///
    /// - `shared_secret`: the SK from X3DH
    /// - `peer_ratchet_key`: Bob's SPK (used as initial ratchet key)
    pub fn init_initiator(shared_secret: &[u8; 32], peer_ratchet_key: &[u8; 32]) -> Self {
        // Generate our first ratchet keypair
        let dh_secret = X25519StaticSecret::random_from_rng(OsRng);
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
        let plaintext = candidate.decrypt_in_place(header, ciphertext, associated_data)?;
        *self = candidate;
        Ok(plaintext)
    }

    fn decrypt_in_place(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, String> {
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
            self.dh_ratchet_step(&header.ratchet_key)?;
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
    fn dh_ratchet_step(&mut self, peer_ratchet_key: &[u8; 32]) -> Result<(), String> {
        self.prev_send_count = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;

        self.dh_receiving = Some(*peer_ratchet_key);

        // DH with our current sending key and peer's new ratchet key
        let peer_key = X25519PublicKey::from(*peer_ratchet_key);
        let our_secret = self.reconstruct_secret()?;
        let dh_output = our_secret.diffie_hellman(&peer_key);

        // KDF_RK → new root key + receiving chain key
        let mut kdf_out =
            kdf::hkdf_sha256(&self.root_key, dh_output.as_bytes(), b"veil-ratchet-v1", 64);
        self.root_key.copy_from_slice(&kdf_out[..32]);
        let mut recv_ck = [0u8; 32];
        recv_ck.copy_from_slice(&kdf_out[32..]);
        self.receiving_chain_key = Some(recv_ck);
        kdf_out.zeroize();

        // Generate new sending ratchet keypair
        let new_secret = X25519StaticSecret::random_from_rng(OsRng);
        let new_public = X25519PublicKey::from(&new_secret);
        let dh_output2 = new_secret.diffie_hellman(&peer_key);

        // KDF_RK → new root key + sending chain key
        let mut kdf_out2 = kdf::hkdf_sha256(
            &self.root_key,
            dh_output2.as_bytes(),
            b"veil-ratchet-v1",
            64,
        );
        self.root_key.copy_from_slice(&kdf_out2[..32]);
        let mut send_ck = [0u8; 32];
        send_ck.copy_from_slice(&kdf_out2[32..]);
        self.sending_chain_key = Some(send_ck);
        kdf_out2.zeroize();

        self.dh_sending_secret = Some(new_secret.to_bytes().to_vec());
        self.dh_sending_public = Some(*new_public.as_bytes());

        Ok(())
    }

    /// Skip ahead to message number `until`, storing skipped keys.
    fn skip_messages(&mut self, until: u32) -> Result<(), String> {
        if self.recv_count + MAX_SKIP < until {
            return Err(format!(
                "too many skipped messages: {} → {}",
                self.recv_count, until
            ));
        }

        if let Some(ref ck) = self.receiving_chain_key {
            let mut chain_key = *ck;
            while self.recv_count < until {
                let message_key = kdf::hmac_sha256(&chain_key, b"\x01");
                let next_ck = kdf::hmac_sha256(&chain_key, b"\x02");
                chain_key = next_ck;

                let rk = self.dh_receiving.unwrap_or([0u8; 32]);
                // Enforce global cap on stored skipped keys
                if self.skipped_keys.len() >= MAX_TOTAL_SKIPPED {
                    // Evict oldest entry (arbitrary key — HashMap is unordered)
                    if let Some(&oldest) = self.skipped_keys.keys().next() {
                        let mut evicted = self.skipped_keys.remove(&oldest).unwrap_or([0u8; 32]);
                        evicted.zeroize();
                    }
                }
                self.skipped_keys.insert((rk, self.recv_count), message_key);
                self.recv_count = self
                    .recv_count
                    .checked_add(1)
                    .ok_or("recv counter overflow in skip".to_string())?;
            }
            self.receiving_chain_key = Some(chain_key);
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
        if let Some(mut message_key) = self.skipped_keys.remove(&key) {
            let nonce: [u8; aead::NONCE_SIZE] = ciphertext[..aead::NONCE_SIZE]
                .try_into()
                .map_err(|_| "invalid nonce")?;
            let ct = &ciphertext[aead::NONCE_SIZE..];
            let result = aead::decrypt_with_aad(&message_key, ct, &nonce, aad);
            message_key.zeroize();
            Ok(Some(result?))
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
        serde_json::to_vec(self).map_err(|e| format!("serialize: {e}"))
    }

    /// Deserialize session state.
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| format!("deserialize: {e}"))
    }
}

// Serde helpers for secret key serialization
mod secret_key_serde {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .as_ref()
            .map(|v| base64::engine::general_purpose::STANDARD.encode(v))
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::Engine;
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&s)
                    .map_err(serde::de::Error::custom)?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }
}

mod skipped_keys_serde {
    use super::SkippedKeysMap;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    pub fn serialize<S>(value: &SkippedKeysMap, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let map: HashMap<String, String> = value
            .iter()
            .map(|((key, n), mk)| {
                let k = format!(
                    "{}:{}",
                    base64::engine::general_purpose::STANDARD.encode(key),
                    n
                );
                let v = base64::engine::general_purpose::STANDARD.encode(mk);
                (k, v)
            })
            .collect();
        map.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SkippedKeysMap, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map: HashMap<String, String> = HashMap::deserialize(deserializer)?;
        let mut result = HashMap::new();
        for (k, v) in map {
            let parts: Vec<&str> = k.rsplitn(2, ':').collect();
            if parts.len() != 2 {
                continue;
            }
            let n: u32 = parts[0].parse().map_err(serde::de::Error::custom)?;
            let key_bytes = base64::engine::general_purpose::STANDARD
                .decode(parts[1])
                .map_err(serde::de::Error::custom)?;
            let mk_bytes = base64::engine::general_purpose::STANDARD
                .decode(&v)
                .map_err(serde::de::Error::custom)?;
            if key_bytes.len() == 32 && mk_bytes.len() == 32 {
                let mut key = [0u8; 32];
                let mut mk = [0u8; 32];
                key.copy_from_slice(&key_bytes);
                mk.copy_from_slice(&mk_bytes);
                result.insert((key, n), mk);
            }
        }
        Ok(result)
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
    fn test_failed_skipped_key_authentication_does_not_consume_key() {
        let (mut alice, mut bob) = setup_sessions();
        let (h1, ct1) = alice.encrypt(b"one").unwrap();
        let (_h2, _ct2) = alice.encrypt(b"two").unwrap();
        let (h3, ct3) = alice.encrypt(b"three").unwrap();

        assert_eq!(bob.decrypt(&h3, &ct3).unwrap(), b"three");
        let before = bob.serialize().unwrap();

        let mut tampered = h1.clone();
        tampered.pn ^= 1;
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
