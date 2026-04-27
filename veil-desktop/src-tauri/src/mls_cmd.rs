//! Tauri-facing surface for Phase 6 OpenMLS.
//!
//! Strategy:
//!
//! * [`MlsState`] holds a single `MlsClient<InMemoryStore>` keyed off the
//!   user's identity. The signer blob is mirrored into SQLCipher
//!   (`mls_signer` table) so a future `restore` path can rehydrate the
//!   identity across restarts. Group state itself currently lives inside
//!   openmls' in-memory storage — persisting that is tracked in the
//!   roadmap as the next milestone.
//! * REST traffic uses the existing `signed_request` helper in
//!   `lib.rs`. Frontend code calls these commands; the JS side never
//!   sees raw MLS blobs (everything is base64 strings).
//! * Failure mode: every command returns `Result<…, String>` so Tauri
//!   surfaces it as a JS exception; UI must handle it.

use std::sync::Mutex;

use base64::Engine;
use tauri::State;
use veil_mls::{
    CommitBlob, InMemoryStore, KeyPackageBlob, LeafIdentity, MlsCiphertext, MlsClient, MlsGroupId,
    MlsKeyStore, SignerBlob, WelcomeBlob,
};

/// Container kept in `AppState`. The inner `Option` is `Some` only
/// after `mls_init` has been called for the current session.
#[derive(Default)]
pub struct MlsState {
    inner: Mutex<Option<MlsClient<InMemoryStore>>>,
    /// The leaf identity bytes of the currently-loaded client. Cached
    /// here so the auto-snapshot helper can address the SQLCipher row
    /// without re-deriving the hash on every mutating command.
    leaf: Mutex<Option<Vec<u8>>>,
}

impl MlsState {
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(
        &self,
        f: impl FnOnce(&MlsClient<InMemoryStore>) -> Result<R, String>,
    ) -> Result<R, String> {
        let guard = self.inner.lock().map_err(|e| e.to_string())?;
        let client = guard
            .as_ref()
            .ok_or_else(|| "mls: not initialized — call mls_init first".to_string())?;
        f(client)
    }

    /// Run a closure with the active client and afterwards persist a
    /// fresh snapshot to SQLCipher. Used by every mutating command so
    /// MLS group state survives a restart.
    fn with_persist<R>(
        &self,
        state: &crate::AppState,
        f: impl FnOnce(&MlsClient<InMemoryStore>) -> Result<R, String>,
    ) -> Result<R, String> {
        let guard = self.inner.lock().map_err(|e| e.to_string())?;
        let client = guard
            .as_ref()
            .ok_or_else(|| "mls: not initialized — call mls_init first".to_string())?;
        let result = f(client)?;
        let snapshot = client
            .snapshot()
            .map_err(|e| format!("snapshot: {e}"))?;
        // Drop the client guard before grabbing the wider Veil DB lock to
        // keep lock acquisition order consistent (mls -> client).
        drop(guard);
        let leaf_guard = self.leaf.lock().map_err(|e| e.to_string())?;
        if let Some(leaf) = leaf_guard.as_ref() {
            let client_guard = state.client.lock().map_err(|e| e.to_string())?;
            if let Some(db) = client_guard.db() {
                db.mls_save_snapshot(leaf, &snapshot)?;
            }
        }
        Ok(result)
    }
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn decode_b64(s: &str) -> Result<Vec<u8>, String> {
    b64().decode(s).map_err(|e| format!("base64 decode: {e}"))
}

fn decode_group_id(s: &str) -> Result<MlsGroupId, String> {
    // Group IDs travel as hex strings (the conversation UUID).
    hex::decode(s)
        .map(MlsGroupId)
        .map_err(|e| format!("group_id hex decode: {e}"))
}

/// Initialise (or restore) the MLS client for the current session.
///
/// `leaf_identity` is the per-device handle — the caller is expected to
/// pass the blake3-hashed `user_id::device_label`. If the SQLCipher
/// database holds a previously-persisted signer + snapshot for this
/// leaf, the client is rehydrated; otherwise a fresh identity is
/// generated and immediately persisted.
///
/// Returns the hex-encoded signature public key (stable across restarts).
#[tauri::command]
pub fn mls_init(
    state: State<'_, crate::AppState>,
    leaf_identity_hex: &str,
) -> Result<String, String> {
    let leaf_bytes =
        hex::decode(leaf_identity_hex).map_err(|e| format!("leaf_identity hex: {e}"))?;
    if leaf_bytes.is_empty() {
        return Err("leaf_identity must be non-empty".into());
    }
    let leaf = LeafIdentity::new(leaf_bytes.clone());

    // Pull any persisted material from SQLCipher.
    let (signer_blob, snapshot_blob) = {
        let client_guard = state.client.lock().map_err(|e| e.to_string())?;
        match client_guard.db() {
            Some(db) => (
                db.mls_load_signer(&leaf_bytes)?,
                db.mls_load_snapshot(&leaf_bytes)?,
            ),
            None => (None, None),
        }
    };

    let mut store = InMemoryStore::default();
    if let Some(blob) = signer_blob.clone() {
        store.save_signer(&leaf_bytes, SignerBlob(blob))?;
    }

    let client = match (signer_blob.is_some(), snapshot_blob) {
        // Full restore (signer + group state).
        (true, Some(snap)) => MlsClient::restore_with_snapshot(leaf, store, &snap)
            .map_err(|e| format!("mls restore_with_snapshot: {e}"))?,
        // Signer only — recover identity but no groups yet.
        (true, None) => {
            MlsClient::restore(leaf, store).map_err(|e| format!("mls restore: {e}"))?
        }
        // Brand-new identity. `MlsClient::create` already persists the
        // signer into `store`; we then mirror it into SQLCipher.
        _ => {
            let c = MlsClient::create(leaf, store).map_err(|e| format!("mls create: {e}"))?;
            let blob = c
                .store()
                .load_signer(&leaf_bytes)
                .map_err(|e| format!("read fresh signer: {e}"))?
                .ok_or_else(|| "fresh signer missing".to_string())?;
            let client_guard = state.client.lock().map_err(|e| e.to_string())?;
            if let Some(db) = client_guard.db() {
                db.mls_save_signer(&leaf_bytes, &blob.0)?;
            }
            c
        }
    };

    let pubkey = hex::encode(client.signature_public());
    {
        let mut guard = state.mls.inner.lock().map_err(|e| e.to_string())?;
        *guard = Some(client);
    }
    {
        let mut leaf_guard = state.mls.leaf.lock().map_err(|e| e.to_string())?;
        *leaf_guard = Some(leaf_bytes);
    }
    Ok(pubkey)
}

/// `true` if `mls_init` has been called.
#[tauri::command]
pub fn mls_ready(state: State<'_, crate::AppState>) -> Result<bool, String> {
    let guard = state.mls.inner.lock().map_err(|e| e.to_string())?;
    Ok(guard.is_some())
}

/// Generate a batch of fresh KeyPackages (returned as base64 blobs).
/// Frontend uploads them via `signed_request` to `POST /v1/mls/keypackages`.
#[tauri::command]
pub fn mls_generate_key_packages(
    state: State<'_, crate::AppState>,
    count: u32,
) -> Result<Vec<String>, String> {
    if count == 0 || count > 100 {
        return Err("count must be between 1 and 100".into());
    }
    // Generating key packages mutates openmls' encryption-key store, so
    // we persist a fresh snapshot afterwards or peers' Welcomes would
    // fail to decrypt after a restart.
    state.mls.with_persist(&state, |client| {
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let kp: KeyPackageBlob = client
                .generate_key_package()
                .map_err(|e| format!("kp: {e}"))?;
            out.push(b64().encode(kp.0));
        }
        Ok(out)
    })
}

/// Create a fresh MLS group identified by the conversation UUID
/// (encoded as hex bytes).
#[tauri::command]
pub fn mls_create_group(
    state: State<'_, crate::AppState>,
    group_id_hex: &str,
) -> Result<u64, String> {
    let group_id = decode_group_id(group_id_hex)?;
    state.mls.with_persist(&state, |client| {
        client
            .create_group(&group_id)
            .map_err(|e| format!("create_group: {e}"))?;
        client
            .epoch(&group_id)
            .map_err(|e| format!("epoch: {e}"))
    })
}

/// Add a member by consuming their (server-fetched) KeyPackage. Returns
/// the commit and welcome blobs (base64) the caller must publish via
/// the REST endpoints.
#[derive(serde::Serialize)]
pub struct AddMemberResult {
    pub commit_b64: String,
    pub welcome_b64: String,
    pub epoch: u64,
}

#[tauri::command]
pub fn mls_add_member(
    state: State<'_, crate::AppState>,
    group_id_hex: &str,
    key_package_b64: &str,
) -> Result<AddMemberResult, String> {
    let group_id = decode_group_id(group_id_hex)?;
    let kp_bytes = decode_b64(key_package_b64)?;
    state.mls.with_persist(&state, |client| {
        let (commit, welcome) = client
            .add_member(&group_id, &KeyPackageBlob(kp_bytes))
            .map_err(|e| format!("add_member: {e}"))?;
        let epoch = client
            .epoch(&group_id)
            .map_err(|e| format!("epoch: {e}"))?;
        Ok(AddMemberResult {
            commit_b64: b64().encode(commit.0),
            welcome_b64: b64().encode(welcome.0),
            epoch,
        })
    })
}

/// Process a Welcome we just pulled from the server. Returns the new
/// group's hex ID for confirmation.
#[tauri::command]
pub fn mls_process_welcome(
    state: State<'_, crate::AppState>,
    welcome_b64: &str,
) -> Result<String, String> {
    let bytes = decode_b64(welcome_b64)?;
    state.mls.with_persist(&state, |client| {
        let gid = client
            .process_welcome(&WelcomeBlob(bytes))
            .map_err(|e| format!("process_welcome: {e}"))?;
        Ok(hex::encode(gid.0))
    })
}

/// Apply a commit pulled from `GET /v1/mls/commits/{conv}?after_epoch=N`.
/// Returns the new local epoch.
#[tauri::command]
pub fn mls_process_commit(
    state: State<'_, crate::AppState>,
    group_id_hex: &str,
    commit_b64: &str,
) -> Result<u64, String> {
    let group_id = decode_group_id(group_id_hex)?;
    let bytes = decode_b64(commit_b64)?;
    state.mls.with_persist(&state, |client| {
        client
            .process_commit(&group_id, &CommitBlob(bytes))
            .map_err(|e| format!("process_commit: {e}"))?;
        client
            .epoch(&group_id)
            .map_err(|e| format!("epoch: {e}"))
    })
}

/// Encrypt UTF-8 text → base64 ciphertext blob.
#[tauri::command]
pub fn mls_encrypt(
    state: State<'_, crate::AppState>,
    group_id_hex: &str,
    plaintext: &str,
) -> Result<String, String> {
    let group_id = decode_group_id(group_id_hex)?;
    // Encryption advances the application secret tree, so we snapshot too.
    state.mls.with_persist(&state, |client| {
        let ct = client
            .encrypt(&group_id, plaintext.as_bytes())
            .map_err(|e| format!("encrypt: {e}"))?;
        Ok(b64().encode(ct.0))
    })
}

/// Decrypt a base64 ciphertext → UTF-8 string.
#[tauri::command]
pub fn mls_decrypt(
    state: State<'_, crate::AppState>,
    group_id_hex: &str,
    ciphertext_b64: &str,
) -> Result<String, String> {
    let group_id = decode_group_id(group_id_hex)?;
    let bytes = decode_b64(ciphertext_b64)?;
    // Decryption ratchets the application secret tree forward.
    state.mls.with_persist(&state, |client| {
        let pt = client
            .decrypt(&group_id, &MlsCiphertext(bytes))
            .map_err(|e| format!("decrypt: {e}"))?;
        String::from_utf8(pt).map_err(|e| format!("plaintext utf-8: {e}"))
    })
}

/// Current epoch (cheap UI helper for showing the "MLS active" badge).
#[tauri::command]
pub fn mls_epoch(state: State<'_, crate::AppState>, group_id_hex: &str) -> Result<u64, String> {
    let group_id = decode_group_id(group_id_hex)?;
    state.mls.with(|client| {
        client
            .epoch(&group_id)
            .map_err(|e| format!("epoch: {e}"))
    })
}

/// Derive a secret bound to the current epoch (for Phase 7 LiveKit etc).
#[tauri::command]
pub fn mls_export_secret(
    state: State<'_, crate::AppState>,
    group_id_hex: &str,
    context_b64: &str,
    length: u32,
) -> Result<String, String> {
    if length == 0 || length > 1024 {
        return Err("length must be between 1 and 1024".into());
    }
    let group_id = decode_group_id(group_id_hex)?;
    let context = decode_b64(context_b64)?;
    state.mls.with(|client| {
        let secret = client
            .export_secret(&group_id, &context, length as usize)
            .map_err(|e| format!("export_secret: {e}"))?;
        Ok(b64().encode(secret))
    })
}
