use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use veil_crypto::{
    aead, fingerprint, kdf, keys, ratchet, share, signature, x3dh, IdentityKeyPair, RatchetSession,
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

#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobileAuthenticatedBinding {
    pub canonical_server_origin: String,
    pub user_id: String,
}

#[derive(uniffi::Record)]
pub struct RestSignatureData {
    pub user_id: String,
    pub timestamp_ms: String,
    pub signature_base64: String,
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
        let kp =
            IdentityKeyPair::from_mnemonic(&mnemonic).map_err(|e| VeilError::Crypto { msg: e })?;
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

// ── VeilMobileSession (native account/origin binding) ──────

/// Native mobile session backed by the same SQLCipher/per-device engine as
/// desktop. Account authentication and request signatures never cross into
/// JavaScript; Kotlin receives only bounded public binding metadata.
#[derive(uniffi::Object)]
pub struct VeilMobileSession {
    client: Mutex<veil_client::api::VeilClient>,
    runtime: tokio::runtime::Runtime,
    binding: Mutex<Option<MobileAuthenticatedBinding>>,
    last_rest_timestamp_ms: AtomicI64,
}

#[uniffi::export]
impl VeilMobileSession {
    #[uniffi::constructor]
    pub fn from_mnemonic(mnemonic: String, database_path: String) -> Result<Arc<Self>, VeilError> {
        if database_path.is_empty() || database_path.len() > 4096 {
            return Err(VeilError::InvalidInput {
                msg: "mobile database path is empty or oversized".to_string(),
            });
        }
        let path = PathBuf::from(database_path);
        if !path.is_absolute() {
            return Err(VeilError::InvalidInput {
                msg: "mobile database path must be absolute".to_string(),
            });
        }
        let mut client = veil_client::api::VeilClient::new();
        client
            .init_with_mnemonic(&mnemonic, &path)
            .map_err(|msg| VeilError::Session { msg })?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .thread_name("veil-mobile-native")
            .build()
            .map_err(|error| VeilError::Session {
                msg: format!("create mobile native runtime: {error}"),
            })?;
        Ok(Arc::new(Self {
            client: Mutex::new(client),
            runtime,
            binding: Mutex::new(None),
            last_rest_timestamp_ms: AtomicI64::new(0),
        }))
    }

    pub fn connect(
        &self,
        websocket_url: String,
        canonical_server_origin: String,
    ) -> Result<MobileAuthenticatedBinding, VeilError> {
        validate_mobile_endpoint_pair(&websocket_url, &canonical_server_origin)?;
        let mut client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;
        let user_id = self
            .runtime
            .block_on(client.connect_with_device_name(&websocket_url, "veil-android"))
            .map_err(|msg| VeilError::Session { msg })?;
        require_canonical_user_id("authenticated mobile user ID", &user_id)?;
        let identity_key = client
            .identity_key()
            .map_err(|msg| VeilError::Session { msg })?;
        let signing_key = client
            .signing_key()
            .map_err(|msg| VeilError::Session { msg })?;
        if let Err(msg) = client
            .db()
            .ok_or_else(|| "mobile SQLCipher database is unavailable".to_string())
            .and_then(|database| {
                database.bind_authenticated_self(
                    &canonical_server_origin,
                    &user_id,
                    &identity_key,
                    &signing_key,
                )
            })
        {
            client.disconnect();
            return Err(VeilError::Session { msg });
        }
        let binding = MobileAuthenticatedBinding {
            canonical_server_origin,
            user_id,
        };
        *self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })? = Some(binding.clone());
        Ok(binding)
    }

    pub fn authenticated_binding(&self) -> Result<MobileAuthenticatedBinding, VeilError> {
        self.binding
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile binding: {error}"),
            })?
            .clone()
            .ok_or_else(|| VeilError::Session {
                msg: "mobile account is not authenticated".to_string(),
            })
    }

    pub fn sign_rest_request(
        &self,
        canonical_server_origin: String,
        method: String,
        request_target: String,
        body: Vec<u8>,
    ) -> Result<RestSignatureData, VeilError> {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let origin = require_canonical_server_origin(&canonical_server_origin)?;
        let binding = self.authenticated_binding()?;
        if binding.canonical_server_origin != origin {
            return Err(VeilError::Session {
                msg: "REST origin differs from the authenticated mobile binding".to_string(),
            });
        }
        let method = require_rest_method(&method)?;
        require_rest_target(&request_target)?;
        if body.len() > 64 * 1024 {
            return Err(VeilError::InvalidInput {
                msg: "REST request body exceeds the mobile signing limit".to_string(),
            });
        }
        let timestamp_ms = self.next_rest_timestamp_ms()?;
        let authority = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .ok_or_else(|| VeilError::InvalidInput {
                msg: "canonical origin has no supported scheme".to_string(),
            })?;
        let canonical = format!(
            "veil-rest-v1\n{method}\n{authority}\n{request_target}\n{timestamp_ms}\n{}",
            hex::encode(Sha256::digest(&body)),
        );
        let signature = self
            .client
            .lock()
            .map_err(|error| VeilError::Session {
                msg: format!("lock mobile client: {error}"),
            })?
            .sign_message(canonical.as_bytes())
            .map_err(|msg| VeilError::Session { msg })?;
        // Re-check after signing so a concurrent disconnect cannot publish a
        // signature from an invalidated account/origin epoch.
        if self.authenticated_binding()? != binding {
            return Err(VeilError::Session {
                msg: "mobile binding changed while signing REST request".to_string(),
            });
        }
        Ok(RestSignatureData {
            user_id: binding.user_id,
            timestamp_ms: timestamp_ms.to_string(),
            signature_base64: base64::engine::general_purpose::STANDARD.encode(signature),
        })
    }

    pub fn disconnect(&self) -> Result<(), VeilError> {
        let mut client = self.client.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile client: {error}"),
        })?;
        client.disconnect();
        *self.binding.lock().map_err(|error| VeilError::Session {
            msg: format!("lock mobile binding: {error}"),
        })? = None;
        Ok(())
    }
}

impl VeilMobileSession {
    fn next_rest_timestamp_ms(&self) -> Result<i64, VeilError> {
        let now: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VeilError::Session {
                msg: "system clock is before Unix epoch".to_string(),
            })?
            .as_millis()
            .try_into()
            .map_err(|_| VeilError::Session {
                msg: "system clock exceeds signed millisecond range".to_string(),
            })?;
        let mut previous = self.last_rest_timestamp_ms.load(Ordering::Acquire);
        loop {
            let next = now.max(previous.checked_add(1).ok_or_else(|| VeilError::Session {
                msg: "REST timestamp allocator exhausted".to_string(),
            })?);
            match self.last_rest_timestamp_ms.compare_exchange_weak(
                previous,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(next),
                Err(actual) => previous = actual,
            }
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
    pub fn init_initiator(
        shared_secret: Vec<u8>,
        peer_ratchet_key: Vec<u8>,
    ) -> Result<Arc<Self>, VeilError> {
        let ss = to_32(&shared_secret)?;
        let prk = to_32(&peer_ratchet_key)?;
        Ok(Arc::new(Self {
            session: Mutex::new(RatchetSession::init_initiator(&ss, &prk)),
        }))
    }

    #[uniffi::constructor]
    pub fn init_responder(
        shared_secret: Vec<u8>,
        our_spk_secret: Vec<u8>,
        our_spk_public: Vec<u8>,
    ) -> Result<Arc<Self>, VeilError> {
        let ss = to_32(&shared_secret)?;
        let pub_key = to_32(&our_spk_public)?;
        Ok(Arc::new(Self {
            session: Mutex::new(RatchetSession::init_responder(
                &ss,
                &our_spk_secret,
                &pub_key,
            )),
        }))
    }

    #[uniffi::constructor]
    pub fn deserialize(json: String) -> Result<Arc<Self>, VeilError> {
        let session: RatchetSession =
            serde_json::from_str(&json).map_err(|e| VeilError::Session { msg: e.to_string() })?;
        Ok(Arc::new(Self {
            session: Mutex::new(session),
        }))
    }

    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<RatchetMessage, VeilError> {
        let mut s = self
            .session
            .lock()
            .map_err(|e| VeilError::Session { msg: e.to_string() })?;
        let (header, ciphertext) = s
            .encrypt(&plaintext)
            .map_err(|e| VeilError::Crypto { msg: e })?;
        Ok(RatchetMessage {
            header: header.to_bytes(),
            ciphertext,
        })
    }

    pub fn decrypt(
        &self,
        header_bytes: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, VeilError> {
        let header = ratchet::MessageHeader::from_bytes(&header_bytes)
            .map_err(|e| VeilError::InvalidInput { msg: e })?;
        let mut s = self
            .session
            .lock()
            .map_err(|e| VeilError::Session { msg: e.to_string() })?;
        s.decrypt(&header, &ciphertext)
            .map_err(|e| VeilError::Crypto { msg: e })
    }

    pub fn serialize(&self) -> Result<String, VeilError> {
        let s = self
            .session
            .lock()
            .map_err(|e| VeilError::Session { msg: e.to_string() })?;
        serde_json::to_string(&*s).map_err(|e| VeilError::Session { msg: e.to_string() })
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
    let (ct, nonce) = aead::encrypt(&k, &plaintext).map_err(|e| VeilError::Crypto { msg: e })?;
    Ok(AeadResult {
        ciphertext: ct,
        nonce: nonce.to_vec(),
    })
}

#[uniffi::export]
pub fn aead_decrypt(
    key: Vec<u8>,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<Vec<u8>, VeilError> {
    let k = to_32(&key)?;
    let n = to_24(&nonce)?;
    aead::decrypt(&k, &ciphertext, &n).map_err(|e| VeilError::Crypto { msg: e })
}

#[uniffi::export]
pub fn ed25519_verify(
    public_key: Vec<u8>,
    message: Vec<u8>,
    sig: Vec<u8>,
) -> Result<bool, VeilError> {
    let pk = to_32(&public_key)?;
    let s = to_64(&sig)?;
    Ok(signature::verify(&pk, &message, &s))
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn generate_account_fingerprint_v2(
    canonical_server_origin: String,
    user_id_a: String,
    identity_key_a: Vec<u8>,
    signing_key_a: Vec<u8>,
    user_id_b: String,
    identity_key_b: Vec<u8>,
    signing_key_b: Vec<u8>,
) -> Result<FingerprintResult, VeilError> {
    let origin = require_canonical_server_origin(&canonical_server_origin)?;
    let user_a = require_canonical_user_id("first account user ID", &user_id_a)?;
    let user_b = require_canonical_user_id("second account user ID", &user_id_b)?;
    let (identity_a, signing_a) =
        require_account_key_pair("first account", &identity_key_a, &signing_key_a)?;
    let (identity_b, signing_b) =
        require_account_key_pair("second account", &identity_key_b, &signing_key_b)?;
    let (emoji, hex) = fingerprint::generate_account_v2(
        &origin,
        fingerprint::AccountFingerprintTuple {
            user_id: &user_a,
            identity_key: &identity_a,
            signing_key: &signing_a,
        },
        fingerprint::AccountFingerprintTuple {
            user_id: &user_b,
            identity_key: &identity_b,
            signing_key: &signing_b,
        },
    );
    Ok(FingerprintResult { emoji, hex })
}

#[uniffi::export]
pub fn derive_key_from_pin(pin: String, salt: Vec<u8>) -> Result<Vec<u8>, VeilError> {
    let s = to_32(&salt)?;
    let key = kdf::derive_key_from_pin(&pin, &s).map_err(|e| VeilError::Crypto { msg: e })?;
    Ok(key.to_vec())
}

#[uniffi::export]
pub fn derive_key_from_password(password: String, salt: Vec<u8>) -> Result<Vec<u8>, VeilError> {
    let s = to_32(&salt)?;
    let key =
        kdf::derive_key_from_password(&password, &s).map_err(|e| VeilError::Crypto { msg: e })?;
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

    let result =
        x3dh::initiate(&identity.inner, &bundle).map_err(|e| VeilError::Crypto { msg: e })?;

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

fn require_canonical_user_id(label: &str, value: &str) -> Result<String, VeilError> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| VeilError::InvalidInput {
        msg: format!("{label} must be a canonical lowercase UUID"),
    })?;
    let canonical = parsed.hyphenated().to_string();
    if parsed.is_nil() || canonical != value {
        return Err(VeilError::InvalidInput {
            msg: format!("{label} must be a non-nil canonical lowercase UUID"),
        });
    }
    Ok(canonical)
}

fn require_account_key_pair(
    label: &str,
    identity_key: &[u8],
    signing_key: &[u8],
) -> Result<([u8; 32], [u8; 32]), VeilError> {
    let identity_key = to_32(identity_key)?;
    let signing_key = to_32(signing_key)?;
    if identity_key == [0u8; 32]
        || !veil_crypto::public_key::valid_ed25519_public_key(&signing_key)
        || identity_key == signing_key
    {
        return Err(VeilError::InvalidInput {
            msg: format!(
                "{label} keys must contain a non-zero X25519 key and a valid, type-distinct Ed25519 key"
            ),
        });
    }
    Ok((identity_key, signing_key))
}

fn require_canonical_server_origin(value: &str) -> Result<String, VeilError> {
    if value.is_empty() || value.len() > 512 {
        return Err(VeilError::InvalidInput {
            msg: "server origin is empty or oversized".to_string(),
        });
    }
    let parsed = url::Url::parse(value).map_err(|error| VeilError::InvalidInput {
        msg: format!("invalid canonical server origin: {error}"),
    })?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(VeilError::InvalidInput {
            msg: "server origin must not contain credentials, path, query, or fragment".to_string(),
        });
    }
    match parsed.scheme() {
        "https" => {}
        "http" => match parsed.host_str() {
            Some("localhost" | "127.0.0.1" | "::1" | "[::1]") => {}
            _ => {
                return Err(VeilError::InvalidInput {
                    msg: "insecure http:// is allowed only for localhost/loopback".to_string(),
                });
            }
        },
        _ => {
            return Err(VeilError::InvalidInput {
                msg: "server origin must use https:// or loopback http://".to_string(),
            });
        }
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| VeilError::InvalidInput {
            msg: "server origin is missing a host".to_string(),
        })?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| VeilError::InvalidInput {
            msg: "server origin has no effective port".to_string(),
        })?;
    let canonical = format!(
        "{}://{}:{}",
        parsed.scheme().to_ascii_lowercase(),
        authority,
        port
    );
    if canonical != value {
        return Err(VeilError::InvalidInput {
            msg: "server origin is not canonical".to_string(),
        });
    }
    Ok(canonical)
}

fn validate_mobile_endpoint_pair(
    websocket_url: &str,
    canonical_server_origin: &str,
) -> Result<(), VeilError> {
    let canonical_origin = require_canonical_server_origin(canonical_server_origin)?;
    let rest = url::Url::parse(&canonical_origin).map_err(|error| VeilError::InvalidInput {
        msg: format!("invalid canonical REST origin: {error}"),
    })?;
    let websocket = url::Url::parse(websocket_url).map_err(|error| VeilError::InvalidInput {
        msg: format!("invalid mobile WebSocket URL: {error}"),
    })?;
    if !websocket.username().is_empty()
        || websocket.password().is_some()
        || websocket.query().is_some()
        || websocket.fragment().is_some()
        || websocket.path() != "/ws"
    {
        return Err(VeilError::InvalidInput {
            msg: "mobile WebSocket URL must be an exact /ws endpoint without credentials, query, or fragment"
                .to_string(),
        });
    }
    let expected_scheme = match rest.scheme() {
        "https" => "wss",
        "http" => "ws",
        _ => unreachable!("canonical origin already checked"),
    };
    if websocket.scheme() != expected_scheme
        || websocket.host_str().map(str::to_ascii_lowercase)
            != rest.host_str().map(str::to_ascii_lowercase)
        || websocket.port_or_known_default() != rest.port_or_known_default()
    {
        return Err(VeilError::InvalidInput {
            msg: "mobile WebSocket and REST endpoints must share one secure origin".to_string(),
        });
    }
    Ok(())
}

fn require_rest_method(method: &str) -> Result<&str, VeilError> {
    match method {
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" => Ok(method),
        _ => Err(VeilError::InvalidInput {
            msg: "unsupported REST method".to_string(),
        }),
    }
}

fn require_rest_target(target: &str) -> Result<(), VeilError> {
    if target.is_empty()
        || target.len() > 2048
        || !target.starts_with('/')
        || target.starts_with("//")
        || target.contains('#')
        || target.chars().any(|character| {
            character.is_control() || character.is_whitespace() || !character.is_ascii()
        })
    {
        return Err(VeilError::InvalidInput {
            msg: "REST request target is invalid".to_string(),
        });
    }
    let parsed = url::Url::parse(&format!("https://veil.invalid{target}")).map_err(|_| {
        VeilError::InvalidInput {
            msg: "REST request target is invalid".to_string(),
        }
    })?;
    let canonical = match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_string(),
    };
    if canonical != target {
        return Err(VeilError::InvalidInput {
            msg: "REST request target is not canonical".to_string(),
        });
    }
    Ok(())
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
    fn test_account_fingerprint_v2() {
        let account_a = VeilIdentity::generate();
        let account_b = VeilIdentity::generate();
        let identity_a = account_a.identity_key();
        let signing_a = account_a.signing_key();
        let identity_b = account_b.identity_key();
        let signing_b = account_b.signing_key();
        let fp_ab = generate_account_fingerprint_v2(
            "https://chat.example.test:443".to_string(),
            "550e8400-e29b-41d4-a716-446655440001".to_string(),
            identity_a.clone(),
            signing_a.clone(),
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            identity_b.clone(),
            signing_b.clone(),
        )
        .unwrap();
        let fp_ba = generate_account_fingerprint_v2(
            "https://chat.example.test:443".to_string(),
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            identity_b,
            signing_b,
            "550e8400-e29b-41d4-a716-446655440001".to_string(),
            identity_a,
            signing_a,
        )
        .unwrap();
        assert!(!fp_ab.emoji.is_empty());
        assert_eq!(fp_ab.hex.len(), 64);
        assert_eq!(fp_ab.hex, fp_ba.hex);
    }

    #[test]
    fn account_fingerprint_v2_rejects_ambiguous_scope() {
        let account_a = VeilIdentity::generate();
        let account_b = VeilIdentity::generate();
        let identity_a = account_a.identity_key();
        let signing_a = account_a.signing_key();
        let identity_b = account_b.identity_key();
        let signing_b = account_b.signing_key();
        assert!(generate_account_fingerprint_v2(
            "https://chat.example.test".to_string(),
            "550e8400-e29b-41d4-a716-446655440001".to_string(),
            identity_a.clone(),
            signing_a.clone(),
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            identity_b.clone(),
            signing_b.clone(),
        )
        .is_err());
        assert!(generate_account_fingerprint_v2(
            "https://chat.example.test:443".to_string(),
            "550E8400-E29B-41D4-A716-446655440001".to_string(),
            identity_a.clone(),
            signing_a.clone(),
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            identity_b.clone(),
            signing_b.clone(),
        )
        .is_err());
        assert!(generate_account_fingerprint_v2(
            "https://chat.example.test:443".to_string(),
            "550e8400-e29b-41d4-a716-446655440001".to_string(),
            vec![0u8; 32],
            signing_a,
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            identity_b,
            signing_b,
        )
        .is_err());
        assert!(generate_account_fingerprint_v2(
            "https://chat.example.test:443".to_string(),
            "550e8400-e29b-41d4-a716-446655440001".to_string(),
            vec![7u8; 32],
            vec![7u8; 32],
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            vec![3u8; 32],
            vec![4u8; 32],
        )
        .is_err());
    }

    #[test]
    fn account_fingerprint_v2_accepts_canonical_ipv6_loopback_origin() {
        let account_a = VeilIdentity::generate();
        let account_b = VeilIdentity::generate();
        assert!(generate_account_fingerprint_v2(
            "http://[::1]:80".to_string(),
            "550e8400-e29b-41d4-a716-446655440001".to_string(),
            account_a.identity_key(),
            account_a.signing_key(),
            "550e8400-e29b-41d4-a716-446655440002".to_string(),
            account_b.identity_key(),
            account_b.signing_key(),
        )
        .is_ok());
    }

    #[test]
    fn mobile_endpoint_pair_is_exact_origin_scoped() {
        assert!(validate_mobile_endpoint_pair(
            "wss://chat.example.test/ws",
            "https://chat.example.test:443",
        )
        .is_ok());
        assert!(
            validate_mobile_endpoint_pair("ws://127.0.0.1:9080/ws", "http://127.0.0.1:9080",)
                .is_ok()
        );
        for websocket in [
            "wss://other.example.test/ws",
            "wss://chat.example.test/other",
            "wss://chat.example.test/ws?origin=other",
            "ws://chat.example.test/ws",
        ] {
            assert!(
                validate_mobile_endpoint_pair(websocket, "https://chat.example.test:443",).is_err()
            );
        }
    }

    #[test]
    fn mobile_rest_signing_inputs_are_canonical_and_bounded() {
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
            assert!(require_rest_method(method).is_ok());
        }
        assert!(require_rest_method("get").is_err());
        assert!(require_rest_target("/v1/push/vapid-key").is_ok());
        assert!(require_rest_target("/v1/push/subscriptions/7/confirm").is_ok());
        for target in [
            "v1/push/vapid-key",
            "//other.example.test/v1/push",
            "/v1/push#fragment",
            "/v1/push\nforged",
            "/v1/пуш",
        ] {
            assert!(require_rest_target(target).is_err());
        }
    }
}
