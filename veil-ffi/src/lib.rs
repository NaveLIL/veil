use std::sync::{Arc, Mutex};
use veil_crypto::{
    aead, fingerprint, kdf, keys, ratchet, share, signature, x3dh,
    IdentityKeyPair, RatchetSession,
};

uniffi::setup_scaffolding!();

// ── Error type ──────────────────────────────────────────────

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VeilError {
    #[error("Crypto error: {msg}")]
    Crypto { msg: String },
    #[error("Invalid input: {msg}")]
    InvalidInput { msg: String },
    #[error("Session error: {msg}")]
    Session { msg: String },
}

// ── Record types (plain data, serialized across FFI) ────────

#[derive(uniffi::Record)]
pub struct AeadResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct FingerprintResult {
    pub emoji: String,
    pub hex: String,
}

#[derive(uniffi::Record)]
pub struct RatchetMessage {
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct ShareBundle {
    pub ciphertext: Vec<u8>,
    pub content_key: Vec<u8>,
    pub wrapped_key: Option<Vec<u8>>,
    pub salt: Option<Vec<u8>>,
}

#[derive(uniffi::Record)]
pub struct X3dhResultData {
    pub shared_secret: Vec<u8>,
    pub ephemeral_public: Vec<u8>,
    pub associated_data: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct KeyBundleData {
    pub identity_key: Vec<u8>,
    pub signing_key: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct PreKeyBundleData {
    pub identity_key: Vec<u8>,
    pub signing_key: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub signed_prekey_id: u32,
    pub one_time_prekey: Option<Vec<u8>>,
    pub one_time_prekey_id: Option<u32>,
}

// ── VeilIdentity (opaque object) ────────────────────────────

#[derive(uniffi::Object)]
pub struct VeilIdentity {
    inner: IdentityKeyPair,
}

#[uniffi::export]
impl VeilIdentity {
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        Arc::new(Self {
            inner: IdentityKeyPair::generate(),
        })
    }

    #[uniffi::constructor]
    pub fn from_mnemonic(mnemonic: String) -> Result<Arc<Self>, VeilError> {
        let kp = IdentityKeyPair::from_mnemonic(&mnemonic)
            .map_err(|e| VeilError::Crypto { msg: e })?;
        Ok(Arc::new(Self { inner: kp }))
    }

    pub fn identity_key(&self) -> Vec<u8> {
        self.inner.x25519_public_bytes().to_vec()
    }

    pub fn signing_key(&self) -> Vec<u8> {
        self.inner.ed25519_public_bytes().to_vec()
    }

    pub fn sign(&self, message: Vec<u8>) -> Vec<u8> {
        signature::sign(&self.inner, &message).to_vec()
    }

    pub fn to_key_bundle(&self) -> KeyBundleData {
        KeyBundleData {
            identity_key: self.inner.x25519_public_bytes().to_vec(),
            signing_key: self.inner.ed25519_public_bytes().to_vec(),
        }
    }
}

// ── VeilRatchet (opaque object wrapping mutable RatchetSession) ──

#[derive(uniffi::Object)]
pub struct VeilRatchet {
    session: Mutex<RatchetSession>,
}

#[uniffi::export]
impl VeilRatchet {
    #[uniffi::constructor]
    pub fn init_initiator(shared_secret: Vec<u8>, peer_ratchet_key: Vec<u8>) -> Result<Arc<Self>, VeilError> {
        let ss = to_32(&shared_secret)?;
        let prk = to_32(&peer_ratchet_key)?;
        Ok(Arc::new(Self {
            session: Mutex::new(RatchetSession::init_initiator(&ss, &prk)),
        }))
    }

    #[uniffi::constructor]
    pub fn init_responder(shared_secret: Vec<u8>, our_spk_secret: Vec<u8>, our_spk_public: Vec<u8>) -> Result<Arc<Self>, VeilError> {
        let ss = to_32(&shared_secret)?;
        let pub_key = to_32(&our_spk_public)?;
        Ok(Arc::new(Self {
            session: Mutex::new(RatchetSession::init_responder(&ss, &our_spk_secret, &pub_key)),
        }))
    }

    #[uniffi::constructor]
    pub fn deserialize(json: String) -> Result<Arc<Self>, VeilError> {
        let session: RatchetSession = serde_json::from_str(&json)
            .map_err(|e| VeilError::Session { msg: e.to_string() })?;
        Ok(Arc::new(Self {
            session: Mutex::new(session),
        }))
    }

    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<RatchetMessage, VeilError> {
        let mut s = self.session.lock()
            .map_err(|e| VeilError::Session { msg: e.to_string() })?;
        let (header, ciphertext) = s.encrypt(&plaintext)
            .map_err(|e| VeilError::Crypto { msg: e })?;
        Ok(RatchetMessage {
            header: header.to_bytes(),
            ciphertext,
        })
    }

    pub fn decrypt(&self, header_bytes: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, VeilError> {
        let header = ratchet::MessageHeader::from_bytes(&header_bytes)
            .map_err(|e| VeilError::InvalidInput { msg: e })?;
        let mut s = self.session.lock()
            .map_err(|e| VeilError::Session { msg: e.to_string() })?;
        s.decrypt(&header, &ciphertext)
            .map_err(|e| VeilError::Crypto { msg: e })
    }

    pub fn serialize(&self) -> Result<String, VeilError> {
        let s = self.session.lock()
            .map_err(|e| VeilError::Session { msg: e.to_string() })?;
        serde_json::to_string(&*s)
            .map_err(|e| VeilError::Session { msg: e.to_string() })
    }
}

// ── Free functions ──────────────────────────────────────────

#[uniffi::export]
pub fn generate_mnemonic() -> String {
    keys::generate_mnemonic().to_string()
}

#[uniffi::export]
pub fn validate_mnemonic(mnemonic: String) -> bool {
    keys::validate_mnemonic(&mnemonic)
}

#[uniffi::export]
pub fn aead_encrypt(key: Vec<u8>, plaintext: Vec<u8>) -> Result<AeadResult, VeilError> {
    let k = to_32(&key)?;
    let (ct, nonce) = aead::encrypt(&k, &plaintext)
        .map_err(|e| VeilError::Crypto { msg: e })?;
    Ok(AeadResult {
        ciphertext: ct,
        nonce: nonce.to_vec(),
    })
}

#[uniffi::export]
pub fn aead_decrypt(key: Vec<u8>, ciphertext: Vec<u8>, nonce: Vec<u8>) -> Result<Vec<u8>, VeilError> {
    let k = to_32(&key)?;
    let n = to_24(&nonce)?;
    aead::decrypt(&k, &ciphertext, &n)
        .map_err(|e| VeilError::Crypto { msg: e })
}

#[uniffi::export]
pub fn ed25519_verify(public_key: Vec<u8>, message: Vec<u8>, sig: Vec<u8>) -> Result<bool, VeilError> {
    let pk = to_32(&public_key)?;
    let s = to_64(&sig)?;
    Ok(signature::verify(&pk, &message, &s))
}

#[uniffi::export]
pub fn generate_fingerprint(key_a: Vec<u8>, key_b: Vec<u8>) -> Result<FingerprintResult, VeilError> {
    let a = to_32(&key_a)?;
    let b = to_32(&key_b)?;
    let (emoji, hex) = fingerprint::generate(&a, &b);
    Ok(FingerprintResult { emoji, hex })
}

#[uniffi::export]
pub fn derive_key_from_pin(pin: String, salt: Vec<u8>) -> Result<Vec<u8>, VeilError> {
    let s = to_32(&salt)?;
    let key = kdf::derive_key_from_pin(&pin, &s)
        .map_err(|e| VeilError::Crypto { msg: e })?;
    Ok(key.to_vec())
}

#[uniffi::export]
pub fn derive_key_from_password(password: String, salt: Vec<u8>) -> Result<Vec<u8>, VeilError> {
    let s = to_32(&salt)?;
    let key = kdf::derive_key_from_password(&password, &s)
        .map_err(|e| VeilError::Crypto { msg: e })?;
    Ok(key.to_vec())
}

#[uniffi::export]
pub fn encrypt_share(payload: Vec<u8>, password: Option<String>) -> Result<ShareBundle, VeilError> {
    let bundle = share::encrypt_share(&payload, password.as_deref())
        .map_err(|e| VeilError::Crypto { msg: e })?;
    Ok(ShareBundle {
        ciphertext: bundle.ciphertext.clone(),
        content_key: bundle.content_key.to_vec(),
        wrapped_key: bundle.wrapped_key.clone(),
        salt: bundle.salt.map(|s| s.to_vec()),
    })
}

#[uniffi::export]
pub fn decrypt_share(
    ciphertext: Vec<u8>,
    content_key: Option<Vec<u8>>,
    password: Option<String>,
    wrapped_key: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
) -> Result<Vec<u8>, VeilError> {
    let ck: Option<[u8; 32]> = match content_key {
        Some(ref v) => Some(to_32(v)?),
        None => None,
    };
    let s: Option<[u8; 32]> = match salt {
        Some(ref sv) => Some(to_32(sv)?),
        None => None,
    };
    share::decrypt_share(
        &ciphertext,
        ck.as_ref(),
        password.as_deref(),
        wrapped_key.as_deref(),
        s.as_ref(),
    )
    .map_err(|e| VeilError::Crypto { msg: e })
}

#[uniffi::export]
pub fn x3dh_initiate(
    identity: &VeilIdentity,
    peer_bundle: PreKeyBundleData,
) -> Result<X3dhResultData, VeilError> {
    let bundle = x3dh::PreKeyBundle {
        identity_key: to_32(&peer_bundle.identity_key)?,
        signing_key: to_32(&peer_bundle.signing_key)?,
        signed_prekey: to_32(&peer_bundle.signed_prekey)?,
        signed_prekey_signature: to_64(&peer_bundle.signed_prekey_signature)?,
        signed_prekey_id: peer_bundle.signed_prekey_id,
        one_time_prekey: match peer_bundle.one_time_prekey {
            Some(ref k) => Some(to_32(k)?),
            None => None,
        },
        one_time_prekey_id: peer_bundle.one_time_prekey_id,
    };

    let result = x3dh::initiate(&identity.inner, &bundle)
        .map_err(|e| VeilError::Crypto { msg: e })?;

    Ok(X3dhResultData {
        shared_secret: result.shared_secret.to_vec(),
        ephemeral_public: result.ephemeral_public.to_vec(),
        associated_data: result.associated_data.to_vec(),
    })
}

// ── Helpers ─────────────────────────────────────────────────

fn to_32(data: &[u8]) -> Result<[u8; 32], VeilError> {
    data.try_into().map_err(|_| VeilError::InvalidInput {
        msg: format!("expected 32 bytes, got {}", data.len()),
    })
}

fn to_24(data: &[u8]) -> Result<[u8; 24], VeilError> {
    data.try_into().map_err(|_| VeilError::InvalidInput {
        msg: format!("expected 24 bytes, got {}", data.len()),
    })
}

fn to_64(data: &[u8]) -> Result<[u8; 64], VeilError> {
    data.try_into().map_err(|_| VeilError::InvalidInput {
        msg: format!("expected 64 bytes, got {}", data.len()),
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_validate_mnemonic() {
        let m = generate_mnemonic();
        assert!(validate_mnemonic(m));
    }

    #[test]
    fn test_identity_roundtrip() {
        let id = VeilIdentity::generate();
        assert_eq!(id.identity_key().len(), 32);
        assert_eq!(id.signing_key().len(), 32);
    }

    #[test]
    fn test_aead_roundtrip() {
        let key = vec![42u8; 32];
        let plain = b"hello veil".to_vec();
        let enc = aead_encrypt(key.clone(), plain.clone()).unwrap();
        let dec = aead_decrypt(key, enc.ciphertext, enc.nonce).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_sign_verify() {
        let id = VeilIdentity::generate();
        let msg = b"test message".to_vec();
        let sig = id.sign(msg.clone());
        assert!(ed25519_verify(id.signing_key(), msg, sig).unwrap());
    }

    #[test]
    fn test_fingerprint() {
        let a = vec![1u8; 32];
        let b = vec![2u8; 32];
        let fp = generate_fingerprint(a, b).unwrap();
        assert!(!fp.emoji.is_empty());
        assert!(!fp.hex.is_empty());
    }
}
