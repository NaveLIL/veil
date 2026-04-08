use std::collections::HashMap;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crate::aead;
use crate::kdf;

/// Maximum number of skipped message keys to store (out-of-order tolerance).
const MAX_SKIP: u32 = 1000;

/// Header attached to each ratchet message (sent alongside ciphertext).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let mut bytes = Vec::with_capacity(32 + 4 + 4);
        bytes.extend_from_slice(&self.ratchet_key);
        bytes.extend_from_slice(&self.n.to_be_bytes());
        bytes.extend_from_slice(&self.pn.to_be_bytes());
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 40 {
            return Err("header too short".to_string());
        }
        let mut ratchet_key = [0u8; 32];
        ratchet_key.copy_from_slice(&data[..32]);
        let n = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
        let pn = u32::from_be_bytes([data[36], data[37], data[38], data[39]]);
        Ok(Self { ratchet_key, n, pn })
    }
}

/// A Double Ratchet session between two parties.
///
/// Provides forward secrecy: each message is encrypted with a unique key.
/// Even if a session state is compromised, past messages cannot be decrypted.
#[derive(Serialize, Deserialize)]
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
        for (_, key) in self.skipped_keys.iter_mut() {
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
        let mut kdf_output = kdf::hkdf_sha256(shared_secret, dh_output.as_bytes(), b"veil-ratchet-v1", 64);

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
        let ck = self.sending_chain_key.as_ref()
            .ok_or("sending chain not initialized (responder must receive first)")?;

        // KDF_CK: derive message key and next chain key
        let message_key = kdf::hmac_sha256(ck, b"\x01");
        let next_chain_key = kdf::hmac_sha256(ck, b"\x02");

        self.sending_chain_key = Some(next_chain_key);

        let header = MessageHeader {
            ratchet_key: self.dh_sending_public.unwrap_or([0u8; 32]),
            n: self.send_count,
            pn: self.prev_send_count,
        };

        self.send_count = self.send_count.checked_add(1)
            .ok_or("message counter overflow".to_string())?;

        // Encrypt with message key
        let (ciphertext, nonce) = aead::encrypt(&message_key, plaintext)?;

        // Prepend nonce to ciphertext for transport
        let mut output = Vec::with_capacity(aead::NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        Ok((header, output))
    }

    /// Decrypt a received message.
    ///
    /// Handles DH ratchet steps and out-of-order messages automatically.
    pub fn decrypt(&mut self, header: &MessageHeader, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < aead::NONCE_SIZE {
            return Err("ciphertext too short".to_string());
        }

        // Try skipped keys first (out-of-order message)
        if let Some(plaintext) = self.try_skipped_keys(header, ciphertext)? {
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
        let ck = self.receiving_chain_key.as_ref()
            .ok_or("receiving chain not initialized")?;
        let message_key = kdf::hmac_sha256(ck, b"\x01");
        let next_chain_key = kdf::hmac_sha256(ck, b"\x02");
        self.receiving_chain_key = Some(next_chain_key);
        self.recv_count += 1;

        // Decrypt
        let nonce: [u8; aead::NONCE_SIZE] = ciphertext[..aead::NONCE_SIZE]
            .try_into()
            .map_err(|_| "invalid nonce")?;
        let ct = &ciphertext[aead::NONCE_SIZE..];

        aead::decrypt(&message_key, ct, &nonce)
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
        let mut kdf_out = kdf::hkdf_sha256(&self.root_key, dh_output.as_bytes(), b"veil-ratchet-v1", 64);
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
        let mut kdf_out2 = kdf::hkdf_sha256(&self.root_key, dh_output2.as_bytes(), b"veil-ratchet-v1", 64);
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
                self.skipped_keys.insert((rk, self.recv_count), message_key);
                self.recv_count += 1;
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
    ) -> Result<Option<Vec<u8>>, String> {
        let key = (header.ratchet_key, header.n);
        if let Some(message_key) = self.skipped_keys.remove(&key) {
            let nonce: [u8; aead::NONCE_SIZE] = ciphertext[..aead::NONCE_SIZE]
                .try_into()
                .map_err(|_| "invalid nonce")?;
            let ct = &ciphertext[aead::NONCE_SIZE..];
            let plaintext = aead::decrypt(&message_key, ct, &nonce)?;
            Ok(Some(plaintext))
        } else {
            Ok(None)
        }
    }

    /// Reconstruct X25519 StaticSecret from stored bytes.
    fn reconstruct_secret(&self) -> Result<X25519StaticSecret, String> {
        let bytes = self.dh_sending_secret.as_ref()
            .ok_or("no sending secret")?;
        let mut arr = [0u8; 32];
        if bytes.len() != 32 {
            return Err("invalid secret length".to_string());
        }
        arr.copy_from_slice(bytes);
        Ok(X25519StaticSecret::from(arr))
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
    where S: Serializer {
        value.as_ref().map(|v| base64::engine::general_purpose::STANDARD.encode(v))
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where D: Deserializer<'de> {
        use base64::Engine;
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = base64::engine::general_purpose::STANDARD.decode(&s)
                    .map_err(serde::de::Error::custom)?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }
}

mod skipped_keys_serde {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    pub fn serialize<S>(
        value: &HashMap<([u8; 32], u32), [u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let map: HashMap<String, String> = value.iter().map(|((key, n), mk)| {
            let k = format!("{}:{}", base64::engine::general_purpose::STANDARD.encode(key), n);
            let v = base64::engine::general_purpose::STANDARD.encode(mk);
            (k, v)
        }).collect();
        map.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<([u8; 32], u32), [u8; 32]>, D::Error>
    where D: Deserializer<'de> {
        let map: HashMap<String, String> = HashMap::deserialize(deserializer)?;
        let mut result = HashMap::new();
        for (k, v) in map {
            let parts: Vec<&str> = k.rsplitn(2, ':').collect();
            if parts.len() != 2 {
                continue;
            }
            let n: u32 = parts[0].parse().map_err(serde::de::Error::custom)?;
            let key_bytes = base64::engine::general_purpose::STANDARD.decode(parts[1])
                .map_err(serde::de::Error::custom)?;
            let mk_bytes = base64::engine::general_purpose::STANDARD.decode(&v)
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
        ).unwrap();

        assert_eq!(alice_x3dh.shared_secret, bob_x3dh.shared_secret);

        // Initialize ratchet sessions
        let alice_session = RatchetSession::init_initiator(
            &alice_x3dh.shared_secret,
            &bob_bundle.signed_prekey,
        );
        let bob_session = RatchetSession::init_responder(
            &bob_x3dh.shared_secret,
            &bob_spk.secret.to_bytes(),
            bob_spk.public.as_bytes(),
        );

        (alice_session, bob_session)
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
}
