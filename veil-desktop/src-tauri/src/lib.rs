use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use subtle::ConstantTimeEq;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_notification::NotificationExt;
use veil_client::api::VeilClient;
use veil_client::connection::ConnectionEvent;
use veil_search::{Indexer, SearchHit};
use veil_store::keychain;
use zeroize::{Zeroize, Zeroizing};

mod pin_throttle;
use pin_throttle::PinThrottle;

struct AppState {
    client: Mutex<VeilClient>,
    /// Serializes lock/unlock transitions with native event publication. This
    /// prevents a stale pending lock event from firing after a successful PIN
    /// unlock and orders live events before the lock that destroys their keys.
    session_transition: Mutex<()>,
    /// Prevent overlapping reconnect workflows from rebinding the signed REST
    /// authority underneath an authenticated backlog sync.
    connect_transition: Mutex<()>,
    /// Exact REST origin paired with the currently authenticated WebSocket.
    /// Every signed REST request is checked against this native binding.
    authenticated_rest_origin: Mutex<Option<RestBinding>>,
    rest_binding_generation: AtomicU64,
    /// Native security boundary. Sensitive commands also require an
    /// initialized client, but this flag prevents reopening the keychain/DB
    /// through IPC while the PIN screen is active.
    unlocked: AtomicBool,
    /// A single app-lifetime dispatcher follows whichever authenticated
    /// connection is currently installed in `client`. Reconnects must not
    /// create competing consumers for the same event queue.
    event_poller_started: AtomicBool,
    /// Live WebSocket events must not overtake the authenticated REST backlog:
    /// both Double Ratchet and Sender Keys require strict message ordering.
    /// A failed sync leaves the dispatcher paused until a clean reconnect.
    offline_sync_ready: AtomicBool,
    /// Expiry discovered on an IPC path still has to clear renderer plaintext;
    /// the watchdog consumes this flag and emits the native lock event.
    lock_event_pending: AtomicBool,
    /// Native, process-local brute-force and concurrency guard shared by
    /// every command that verifies the application PIN.
    pin_throttle: Mutex<PinThrottle>,
    runtime: tokio::runtime::Runtime,
    last_activity: Mutex<Instant>,
    db_dir: PathBuf,
    /// Shared HTTP client — reuses TCP/TLS connections + HTTP/2 streams across
    /// all REST calls. Eliminates per-request handshake overhead, the main
    /// cause of the perceived "server tab is slow / hangs" UX.
    http: reqwest::Client,
    /// Decrypted full-text index kept in process memory only. Rebuilt from the
    /// SQLCipher database after unlock and cleared before key material drops.
    indexer: Arc<Indexer>,
}

const KEYCHAIN_ACCOUNT: &str = "veil-default";
const PIN_MATERIAL_ACCOUNT: &str = "veil-pin-material-v2";
// Read-only compatibility with builds that stored the hash and salt as two
// credentials. New writes use one credential so a partial update cannot pair
// a new salt with an old hash and lock the user out.
const PIN_HASH_ACCOUNT: &str = "veil-pin-hash";
const PIN_SALT_ACCOUNT: &str = "veil-pin-salt";
const PIN_THROTTLE_ACCOUNT: &str = "veil-pin-throttle-v1";
const AUTO_LOCK_ACCOUNT: &str = "veil-auto-lock-seconds";
const DEFAULT_AUTO_LOCK_SECONDS: u64 = 5 * 60;
static LAST_REST_TIMESTAMP_MS: AtomicI64 = AtomicI64::new(0);
const MAX_REST_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct RestOrigin {
    scheme: String,
    host: String,
    port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RestBinding {
    origin: RestOrigin,
    generation: u64,
}

// ─── Identity ─────────────────────────────────────────

#[tauri::command]
fn generate_mnemonic() -> String {
    veil_crypto::keys::generate_mnemonic().to_string()
}

#[tauri::command]
fn validate_mnemonic_cmd(mnemonic: String) -> bool {
    let mnemonic = Zeroizing::new(mnemonic);
    veil_crypto::keys::validate_mnemonic(&mnemonic)
}

#[tauri::command]
fn init_identity(state: State<'_, AppState>, mnemonic: String) -> Result<String, String> {
    let mnemonic = Zeroizing::new(mnemonic);
    if keychain::has_seed(KEYCHAIN_ACCOUNT)? {
        require_unlocked(&state)?;
        let stored = Zeroizing::new(keychain::get_seed(KEYCHAIN_ACCOUNT)?);
        let requested_key =
            veil_crypto::keys::IdentityKeyPair::from_mnemonic(&mnemonic)?.x25519_public_bytes();
        let stored_key =
            veil_crypto::keys::IdentityKeyPair::from_mnemonic(&stored)?.x25519_public_bytes();
        if requested_key.ct_eq(&stored_key).unwrap_u8() != 1 {
            return Err(
                "a different identity already exists; refusing to replace its encrypted database"
                    .into(),
            );
        }
        let _transition = state.session_transition.lock().map_err(|e| e.to_string())?;
        if !state.unlocked.load(Ordering::Acquire) {
            return Err("application locked while initializing identity".to_string());
        }
        return initialize_client(&state, &stored);
    }

    let _transition = state.session_transition.lock().map_err(|e| e.to_string())?;
    if !state.unlocked.load(Ordering::Acquire) {
        return Err("application locked while initializing identity".to_string());
    }
    let key = initialize_client(&state, &mnemonic)?;
    publish_unlocked_session(&state.lock_event_pending, &state.unlocked);
    Ok(key)
}

#[tauri::command]
fn get_identity_key(state: State<'_, AppState>) -> Result<String, String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let key = client.identity_key()?;
    require_session_still_unlocked(&state)?;
    Ok(hex::encode(key))
}

#[tauri::command]
fn fingerprint_peer(
    state: State<'_, AppState>,
    peer_identity_key: String,
) -> Result<String, String> {
    require_unlocked(&state)?;
    let peer: [u8; 32] = hex::decode(peer_identity_key.trim())
        .map_err(|_| "peer identity key must be 32-byte hex")?
        .try_into()
        .map_err(|_| "peer identity key must be 32-byte hex")?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let (_, hex_fingerprint) = client.fingerprint(&peer)?;
    require_session_still_unlocked(&state)?;
    Ok(hex_fingerprint)
}

#[tauri::command]
fn store_seed(state: State<'_, AppState>, mnemonic: String) -> Result<(), String> {
    let mnemonic = Zeroizing::new(mnemonic);
    require_unlocked(&state)?;
    let expected =
        veil_crypto::keys::IdentityKeyPair::from_mnemonic(&mnemonic)?.x25519_public_bytes();
    let actual = state
        .client
        .lock()
        .map_err(|e| e.to_string())?
        .identity_key()?;
    if expected.ct_eq(&actual).unwrap_u8() != 1 {
        return Err("refusing to store a seed that does not match the active identity".into());
    }
    keychain::store_seed(KEYCHAIN_ACCOUNT, &mnemonic)
}

#[tauri::command]
fn has_stored_identity() -> Result<bool, String> {
    keychain::has_seed(KEYCHAIN_ACCOUNT)
}

fn require_unlocked(state: &AppState) -> Result<(), String> {
    if !state.unlocked.load(Ordering::SeqCst) {
        return Err("application is locked".into());
    }
    let expired = has_pin_material()?
        && state
            .last_activity
            .lock()
            .map_err(|e| e.to_string())?
            .elapsed()
            .as_secs()
            >= get_auto_lock_seconds();
    if expired {
        reset_sensitive_state(state)?;
        return Err("application auto-locked due to inactivity".into());
    }
    Ok(())
}

/// Final non-blocking guard for commands that still hold the client/DB mutex.
/// A lock transition sets this flag before waiting for that mutex, so checking
/// it immediately before producing IPC output closes the read-vs-lock race
/// without recursively trying to reset the client while its mutex is held.
fn require_session_still_unlocked(state: &AppState) -> Result<(), String> {
    if state.unlocked.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err("application locked while processing the request".to_string())
    }
}

fn require_live_transport_ready(state: &AppState) -> Result<(), String> {
    require_unlocked(state)?;
    if state.offline_sync_ready.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err("authenticated directory refresh is required before sending".to_string())
    }
}

fn consume_pending_lock_event(pending: &AtomicBool, unlocked: &AtomicBool) -> bool {
    pending.swap(false, Ordering::AcqRel) && !unlocked.load(Ordering::Acquire)
}

/// Publish a successfully initialized session while the caller holds
/// `session_transition`. Clearing first prevents an older lock request from
/// being emitted after the new session becomes visible.
fn publish_unlocked_session(pending: &AtomicBool, unlocked: &AtomicBool) {
    pending.store(false, Ordering::Release);
    unlocked.store(true, Ordering::SeqCst);
}

fn reset_sensitive_state(state: &AppState) -> Result<(), String> {
    let _transition = state.session_transition.lock().map_err(|e| e.to_string())?;
    reset_sensitive_state_locked(state)
}

/// Reset body for callers already holding `session_transition`.
fn reset_sensitive_state_locked(state: &AppState) -> Result<(), String> {
    state.unlocked.store(false, Ordering::SeqCst);
    state.offline_sync_ready.store(false, Ordering::SeqCst);
    state.lock_event_pending.store(true, Ordering::Release);
    *state
        .authenticated_rest_origin
        .lock()
        .map_err(|e| e.to_string())? = None;
    // The client mutex is the linearization point: operations already holding
    // it finish first; every later operation observes an empty client.
    *state.client.lock().map_err(|e| e.to_string())? = VeilClient::new();
    state.indexer.clear().map_err(|e| e.to_string())
}

fn initialize_client(state: &AppState, mnemonic: &str) -> Result<String, String> {
    let db_path = state.db_dir.join("veil.db");
    let mut fresh = VeilClient::new();
    fresh.init_with_mnemonic(mnemonic, &db_path)?;
    fresh.set_indexer(state.indexer.clone());
    let key = hex::encode(fresh.identity_key()?);
    *state.client.lock().map_err(|e| e.to_string())? = fresh;
    Ok(key)
}

fn verify_pin_material(pin: &str, stored_hash: &str, stored_salt: &str) -> Result<bool, String> {
    let salt_bytes = hex::decode(stored_salt).map_err(|e| e.to_string())?;
    let salt: [u8; 32] = salt_bytes
        .try_into()
        .map_err(|_| "invalid PIN salt length".to_string())?;
    let expected_bytes = hex::decode(stored_hash).map_err(|e| e.to_string())?;
    let mut expected: [u8; 32] = expected_bytes
        .try_into()
        .map_err(|_| "invalid PIN hash length".to_string())?;
    let mut actual = veil_crypto::kdf::derive_key_from_pin(pin, &salt)?;
    let matches = actual.ct_eq(&expected).unwrap_u8() == 1;
    actual.zeroize();
    expected.zeroize();
    Ok(matches)
}

fn has_pin_material() -> Result<bool, String> {
    Ok(keychain::has_seed(PIN_MATERIAL_ACCOUNT)? || keychain::has_seed(PIN_HASH_ACCOUNT)?)
}

fn load_pin_material() -> Result<(String, String), String> {
    if keychain::has_seed(PIN_MATERIAL_ACCOUNT)? {
        let mut material = keychain::get_seed(PIN_MATERIAL_ACCOUNT)?;
        let parsed = (|| {
            let mut fields = material.split(':');
            let version = fields.next();
            let salt = fields.next();
            let hash = fields.next();
            if version != Some("v2") || fields.next().is_some() {
                return Err("invalid PIN material format".to_string());
            }
            Ok((
                hash.ok_or("PIN material is missing its hash")?.to_string(),
                salt.ok_or("PIN material is missing its salt")?.to_string(),
            ))
        })();
        material.zeroize();
        return parsed;
    }

    Ok((
        keychain::get_seed(PIN_HASH_ACCOUNT)?,
        keychain::get_seed(PIN_SALT_ACCOUNT)?,
    ))
}

#[derive(Default)]
struct PersistentPinThrottle {
    failures: u32,
    blocked_until_ms: u64,
}

fn unix_time_ms() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch".to_string())?
        .as_millis()
        .try_into()
        .map_err(|_| "system clock exceeds millisecond range".to_string())
}

fn load_persistent_pin_throttle() -> Result<PersistentPinThrottle, String> {
    if !keychain::has_seed(PIN_THROTTLE_ACCOUNT)? {
        return Ok(PersistentPinThrottle::default());
    }
    let mut encoded = keychain::get_seed(PIN_THROTTLE_ACCOUNT)?;
    let parsed = (|| {
        let mut fields = encoded.split(':');
        if fields.next() != Some("v1") {
            return Err("invalid persistent PIN throttle version".to_string());
        }
        let failures = fields
            .next()
            .ok_or("persistent PIN throttle is missing failure count")?
            .parse::<u32>()
            .map_err(|_| "invalid persistent PIN failure count".to_string())?;
        let blocked_until_ms = fields
            .next()
            .ok_or("persistent PIN throttle is missing deadline")?
            .parse::<u64>()
            .map_err(|_| "invalid persistent PIN throttle deadline".to_string())?;
        if fields.next().is_some() {
            return Err("invalid persistent PIN throttle format".to_string());
        }
        Ok(PersistentPinThrottle {
            failures,
            blocked_until_ms,
        })
    })();
    encoded.zeroize();
    parsed
}

fn persist_pin_failure(previous_failures: u32) -> Result<(), String> {
    let failures = previous_failures.saturating_add(1);
    let shift = failures.saturating_sub(1).min(20);
    let delay_ms = 500u64.saturating_mul(1u64 << shift).min(5 * 60 * 1000);
    let blocked_until_ms = unix_time_ms()?.saturating_add(delay_ms);
    let mut encoded = format!("v1:{failures}:{blocked_until_ms}");
    let result = keychain::store_seed(PIN_THROTTLE_ACCOUNT, &encoded);
    encoded.zeroize();
    result
}

fn clear_persistent_pin_throttle() -> Result<(), String> {
    if keychain::has_seed(PIN_THROTTLE_ACCOUNT)? {
        keychain::delete_seed(PIN_THROTTLE_ACCOUNT)?;
    }
    Ok(())
}

async fn verify_pin_throttled(state: &AppState, pin: String) -> Result<bool, String> {
    // Read keychain material before reserving a permit so an OS keychain
    // failure cannot strand the single verification slot.
    let persistent = load_persistent_pin_throttle()?;
    let now_ms = unix_time_ms()?;
    if persistent.blocked_until_ms > now_ms {
        return Err(format!(
            "PIN verification is rate-limited; retry in {} ms",
            persistent.blocked_until_ms - now_ms
        ));
    }
    let (mut stored_hash, mut stored_salt) = load_pin_material()?;
    let permit = state
        .pin_throttle
        .lock()
        .map_err(|e| e.to_string())?
        .begin_attempt(Instant::now())
        .map_err(|e| e.to_string())?;

    let mut pin = pin;
    let verification = match tokio::task::spawn_blocking(move || {
        let result = verify_pin_material(&pin, &stored_hash, &stored_salt);
        pin.zeroize();
        stored_hash.zeroize();
        stored_salt.zeroize();
        result
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(format!("PIN verification worker failed: {error}")),
    };

    let mut throttle = state.pin_throttle.lock().map_err(|e| e.to_string())?;
    match verification {
        Ok(true) => {
            throttle
                .record_success(permit, Instant::now())
                .map_err(|e| e.to_string())?;
            clear_persistent_pin_throttle()?;
            Ok(true)
        }
        Ok(false) => {
            throttle
                .record_failure(permit, Instant::now())
                .map_err(|e| e.to_string())?;
            persist_pin_failure(persistent.failures)?;
            Ok(false)
        }
        Err(error) => {
            throttle
                .record_failure(permit, Instant::now())
                .map_err(|e| e.to_string())?;
            persist_pin_failure(persistent.failures)?;
            Err(error)
        }
    }
}

// ─── PIN Lock ─────────────────────────────────────────

#[tauri::command]
async fn set_pin(
    state: State<'_, AppState>,
    pin: String,
    current_pin: Option<String>,
) -> Result<(), String> {
    require_unlocked(&state)?;
    if pin.len() < 6 || pin.len() > 12 || !pin.bytes().all(|b| b.is_ascii_digit()) {
        return Err("new PIN must contain 6 to 12 digits".into());
    }
    if has_pin_material()? {
        let current = current_pin.ok_or("current PIN is required")?;
        let valid = verify_pin_throttled(&state, current).await?;
        if !valid {
            return Err("current PIN is incorrect".into());
        }
        require_unlocked(&state)?;
    }

    let (hash_hex, salt_hex) = tokio::task::spawn_blocking(move || {
        use rand::RngCore;

        let mut pin = pin;
        let mut salt = [0u8; 32];
        let result = (|| {
            rand::rngs::OsRng
                .try_fill_bytes(&mut salt)
                .map_err(|e| format!("RNG failed: {e}"))?;
            let mut hash = veil_crypto::kdf::derive_key_from_pin(&pin, &salt)?;
            let encoded = (hex::encode(hash), hex::encode(salt));
            hash.zeroize();
            Ok::<_, String>(encoded)
        })();
        pin.zeroize();
        salt.zeroize();
        result
    })
    .await
    .map_err(|e| e.to_string())??;
    require_unlocked(&state)?;

    let hash_hex = Zeroizing::new(hash_hex);
    let salt_hex = Zeroizing::new(salt_hex);
    let material = Zeroizing::new(format!("v2:{}:{}", salt_hex.as_str(), hash_hex.as_str()));
    // Credential mutation is a native session transition. Serialize it with
    // lock/watchdog teardown, then follow the canonical transition -> client
    // order so a successful async verification cannot race an auto-lock.
    let _transition = state.session_transition.lock().map_err(|e| e.to_string())?;
    if !state.unlocked.load(Ordering::Acquire) {
        return Err("application locked while changing PIN".to_string());
    }
    let _client_guard = state.client.lock().map_err(|e| e.to_string())?;
    if !state.unlocked.load(Ordering::Acquire) {
        return Err("application locked while changing PIN".to_string());
    }
    let store_result = keychain::store_seed(PIN_MATERIAL_ACCOUNT, &material);
    store_result?;
    // Best-effort cleanup after the new atomic credential is durable. A
    // cleanup failure is harmless because reads always prefer v2.
    let _ = keychain::delete_seed(PIN_HASH_ACCOUNT);
    let _ = keychain::delete_seed(PIN_SALT_ACCOUNT);
    clear_persistent_pin_throttle()?;
    state
        .pin_throttle
        .lock()
        .map_err(|e| e.to_string())?
        .reset();
    Ok(())
}

#[tauri::command]
async fn verify_pin(state: State<'_, AppState>, pin: String) -> Result<bool, String> {
    // Run Argon2id off the main thread under the shared native throttle so
    // parallel IPC calls cannot multiply brute-force throughput.
    let matches = verify_pin_throttled(&state, pin).await?;

    if matches {
        let mnemonic = Zeroizing::new(keychain::get_seed(KEYCHAIN_ACCOUNT)?);
        let _transition = state.session_transition.lock().map_err(|e| e.to_string())?;
        if let Err(e) = initialize_client(&state, &mnemonic) {
            return match reset_sensitive_state_locked(&state) {
                Ok(()) => Err(e),
                Err(reset_error) => Err(format!(
                    "{e}; failed to reset native session after unlock error: {reset_error}"
                )),
            };
        }
        if let Err(error) = state.indexer.clear().map_err(|e| e.to_string()) {
            let reset = reset_sensitive_state_locked(&state);
            return Err(reset.err().map_or(error.clone(), |reset_error| {
                format!("{error}; unlock reset also failed: {reset_error}")
            }));
        }
        if let Err(error) = state
            .last_activity
            .lock()
            .map(|mut last| *last = Instant::now())
            .map_err(|e| e.to_string())
        {
            let reset = reset_sensitive_state_locked(&state);
            return Err(reset.err().map_or(error.clone(), |reset_error| {
                format!("{error}; unlock reset also failed: {reset_error}")
            }));
        }
        // Clear a lock notification created by a command-side expiry before
        // publishing the unlocked state, under the same transition mutex used
        // by the watchdog's check-and-emit path.
        publish_unlocked_session(&state.lock_event_pending, &state.unlocked);
    }

    Ok(matches)
}

#[tauri::command]
fn has_pin() -> Result<bool, String> {
    has_pin_material()
}

#[tauri::command]
async fn clear_pin(state: State<'_, AppState>, current_pin: String) -> Result<(), String> {
    require_unlocked(&state)?;
    let valid = verify_pin_throttled(&state, current_pin).await?;
    if !valid {
        return Err("current PIN is incorrect".into());
    }
    require_unlocked(&state)?;
    // Keep credential deletion linearized with reset_sensitive_state. In
    // particular, the watchdog cannot lock and destroy the client between the
    // successful verification and removal of the last usable PIN credential.
    let _transition = state.session_transition.lock().map_err(|e| e.to_string())?;
    if !state.unlocked.load(Ordering::Acquire) {
        return Err("application locked while clearing PIN".to_string());
    }
    let _client_guard = state.client.lock().map_err(|e| e.to_string())?;
    if !state.unlocked.load(Ordering::Acquire) {
        return Err("application locked while clearing PIN".to_string());
    }
    if keychain::has_seed(PIN_MATERIAL_ACCOUNT)? {
        // Remove stale legacy credentials first while the authoritative v2
        // credential still guarantees that an interrupted cleanup is usable.
        if keychain::has_seed(PIN_HASH_ACCOUNT)? {
            keychain::delete_seed(PIN_HASH_ACCOUNT)?;
        }
        if keychain::has_seed(PIN_SALT_ACCOUNT)? {
            keychain::delete_seed(PIN_SALT_ACCOUNT)?;
        }
        keychain::delete_seed(PIN_MATERIAL_ACCOUNT)?;
    } else {
        keychain::delete_seed(PIN_HASH_ACCOUNT)?;
        keychain::delete_seed(PIN_SALT_ACCOUNT)?;
    }
    state
        .pin_throttle
        .lock()
        .map_err(|e| e.to_string())?
        .reset();
    Ok(())
}

#[tauri::command]
async fn reveal_recovery_phrase(state: State<'_, AppState>, pin: String) -> Result<String, String> {
    require_unlocked(&state)?;
    if !has_pin_material()? {
        return Err("set a PIN before revealing the recovery phrase".into());
    }
    let valid = verify_pin_throttled(&state, pin).await?;
    if !valid {
        return Err("incorrect PIN".into());
    }
    require_unlocked(&state)?;
    let _client_guard = state.client.lock().map_err(|e| e.to_string())?;
    if !state.unlocked.load(Ordering::Acquire) {
        return Err("application locked while revealing recovery phrase".to_string());
    }
    let phrase = Zeroizing::new(keychain::get_seed(KEYCHAIN_ACCOUNT)?);
    require_session_still_unlocked(&state)?;
    // The returned IPC string is unavoidable, but keep the keychain-owned
    // intermediate zeroizing so a concurrent-lock error scrubs it on drop.
    Ok(phrase.as_str().to_owned())
}

#[tauri::command]
fn lock_app(state: State<'_, AppState>) -> Result<(), String> {
    if !has_pin_material()? {
        return Err("configure a PIN before locking the application".into());
    }
    let result = reset_sensitive_state(&state);
    // Renderer-initiated lock already cleared its own state.
    if let Ok(_transition) = state.session_transition.lock() {
        if !state.unlocked.load(Ordering::Acquire) {
            state.lock_event_pending.store(false, Ordering::Release);
        }
    }
    result
}

#[tauri::command]
fn touch_activity(state: State<'_, AppState>) {
    if state.unlocked.load(Ordering::SeqCst) {
        if let Ok(mut t) = state.last_activity.lock() {
            *t = Instant::now();
        }
    }
}

/// Returns seconds since last user activity.
#[tauri::command]
fn idle_seconds(state: State<'_, AppState>) -> u64 {
    state
        .last_activity
        .lock()
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0)
}

fn valid_auto_lock_seconds(seconds: u64) -> bool {
    matches!(seconds, 60 | 300 | 900 | 1800 | 3600)
}

#[tauri::command]
fn get_auto_lock_seconds() -> u64 {
    keychain::get_seed(AUTO_LOCK_ACCOUNT)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|seconds| valid_auto_lock_seconds(*seconds))
        .unwrap_or(DEFAULT_AUTO_LOCK_SECONDS)
}

#[tauri::command]
fn set_auto_lock_seconds(state: State<'_, AppState>, seconds: u64) -> Result<(), String> {
    require_unlocked(&state)?;
    if !valid_auto_lock_seconds(seconds) {
        return Err("auto-lock must be 1, 5, 15, 30 or 60 minutes".to_string());
    }
    keychain::store_seed(AUTO_LOCK_ACCOUNT, &seconds.to_string())
}

// ─── DB Persistence ───────────────────────────────────

/// Re-initialize client from stored seed (called after PIN unlock on restart).
/// Async so the heavy Argon2id work runs off the main thread.
#[tauri::command]
async fn init_from_seed(state: State<'_, AppState>) -> Result<String, String> {
    if has_pin_material()? {
        require_unlocked(&state)?;
    }
    let mnemonic = Zeroizing::new(keychain::get_seed(KEYCHAIN_ACCOUNT)?);
    let _transition = state.session_transition.lock().map_err(|e| e.to_string())?;
    if !state.unlocked.load(Ordering::Acquire) {
        return Err("application locked while restoring identity".to_string());
    }
    let key = initialize_client(&state, &mnemonic)?;
    publish_unlocked_session(&state.lock_event_pending, &state.unlocked);
    Ok(key)
}

/// Get persisted conversations from the encrypted DB.
#[tauri::command]
fn get_conversations(state: State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("database not initialized")?;
    let convs = db.get_conversations()?;
    let result = convs
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "type": match c.conv_type {
                    veil_store::models::ConversationType::DM => "dm",
                    veil_store::models::ConversationType::Group => "group",
                    veil_store::models::ConversationType::Channel => "channel",
                },
                "name": c.name.unwrap_or_default(),
                "peerKey": c.peer_identity_key.map(hex::encode),
                "lastMessageAt": c.last_message_at,
            })
        })
        .collect();
    require_session_still_unlocked(&state)?;
    Ok(result)
}

/// Get persisted messages for a conversation.
#[tauri::command]
fn get_messages(
    state: State<'_, AppState>,
    conversation_id: String,
    limit: Option<u32>,
) -> Result<Vec<serde_json::Value>, String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("database not initialized")?;
    let msgs = db.get_messages(&conversation_id, limit.unwrap_or(200))?;
    let result = msgs
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "id": m.id,
                "conversationId": m.conversation_id,
                "senderKey": hex::encode(&m.sender_key),
                "text": m.plaintext,
                "isOwn": m.is_outgoing,
                "pending": m.status == veil_store::models::MessageStatus::Sending,
                "timestamp": m.server_timestamp.unwrap_or(0),
                "createdAt": m.created_at,
                "replyToId": m.reply_to_id,
            })
        })
        .collect();
    require_session_still_unlocked(&state)?;
    Ok(result)
}

/// Generate and upload prekeys for X3DH key exchange.
#[tauri::command]
fn upload_prekeys(state: State<'_, AppState>, server_http_url: String) -> Result<(), String> {
    require_unlocked(&state)?;
    let (user_id, device_id, identity_key) = {
        let client = state.client.lock().map_err(|e| e.to_string())?;
        (
            client.authenticated_user_id()?,
            hex::encode(client.device_id()),
            hex::encode(client.identity_key()?),
        )
    };

    // Avoid generating an unbounded SPK/OPK batch on every reconnect. Count is
    // private and signed; a missing/malformed current-device entry fails closed
    // instead of silently growing local_prekeys forever.
    let count_response = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::GET,
        rest_api_url(&server_http_url, &["v1", "prekeys", &identity_key, "count"])?,
        &user_id,
        None,
    ))?;
    let devices = count_response
        .get("devices")
        .and_then(serde_json::Value::as_array)
        .ok_or("prekey count response is missing devices")?;
    let mut matching_counts = devices
        .iter()
        .filter(|device| {
            device.get("device_id").and_then(serde_json::Value::as_str) == Some(device_id.as_str())
        })
        .map(|device| device.get("remaining").and_then(serde_json::Value::as_i64));
    let remaining = matching_counts
        .next()
        .ok_or("prekey count response is missing the authenticated device")?
        .ok_or("prekey count remaining value is invalid")?;
    if matching_counts.next().is_some() || remaining < 0 {
        return Err("prekey count response contains invalid duplicate/device data".to_string());
    }
    if remaining >= 10 {
        return Ok(());
    }

    // Generate only after the authenticated server count crosses the low-water
    // mark, then release the client lock before the signed upload request.
    let prekey_set = state
        .client
        .lock()
        .map_err(|e| e.to_string())?
        .generate_prekeys()?;

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let otks: Vec<serde_json::Value> = prekey_set
        .otk_publics
        .iter()
        .map(|(key, id)| {
            serde_json::json!({
                "key_id": id,
                "public_key": b64.encode(key),
            })
        })
        .collect();

    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        rest_api_url(&server_http_url, &["v1", "prekeys"])?,
        &user_id,
        Some(serde_json::json!({
            "device_id": device_id,
            "signed_prekey": {
                "key_id": prekey_set.spk_id,
                "public_key": b64.encode(prekey_set.spk_public),
                "signature": b64.encode(prekey_set.spk_signature),
            },
            "one_time_prekeys": otks,
        })),
    ))?;

    Ok(())
}

#[derive(serde::Deserialize)]
struct PreKeyBundleResponse {
    identity_key: String,
    signing_key: String,
    signed_prekey: String,
    signed_prekey_signature: String,
    signed_prekey_id: u32,
    one_time_prekey: Option<String>,
    one_time_prekey_id: Option<u32>,
}

fn decode_b64_array<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| format!("decode {field}: {e}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("invalid {field} length: expected {N}, got {}", v.len()))
}

fn parse_prekey_bundle(
    value: serde_json::Value,
    expected_identity_key: &[u8; 32],
) -> Result<veil_crypto::x3dh::PreKeyBundle, String> {
    let response: PreKeyBundleResponse =
        serde_json::from_value(value).map_err(|e| format!("parse prekey bundle: {e}"))?;
    let identity_key = decode_b64_array::<32>("identity_key", &response.identity_key)?;
    if &identity_key != expected_identity_key {
        return Err("prekey bundle identity does not match requested peer".to_string());
    }

    let one_time_prekey = response
        .one_time_prekey
        .as_deref()
        .map(|value| decode_b64_array::<32>("one_time_prekey", value))
        .transpose()?;
    if one_time_prekey.is_some() != response.one_time_prekey_id.is_some() {
        return Err("incomplete one-time prekey in server response".to_string());
    }

    Ok(veil_crypto::x3dh::PreKeyBundle {
        identity_key,
        signing_key: decode_b64_array::<32>("signing_key", &response.signing_key)?,
        signed_prekey: decode_b64_array::<32>("signed_prekey", &response.signed_prekey)?,
        signed_prekey_signature: decode_b64_array::<64>(
            "signed_prekey_signature",
            &response.signed_prekey_signature,
        )?,
        signed_prekey_id: response.signed_prekey_id,
        one_time_prekey,
        one_time_prekey_id: response.one_time_prekey_id,
    })
}

fn establish_session_for_peer(
    state: &AppState,
    server_http_url: &str,
    peer_identity_key: [u8; 32],
    expected_signing_key: Option<[u8; 32]>,
) -> Result<(), String> {
    let user_id = state
        .client
        .lock()
        .map_err(|e| e.to_string())?
        .authenticated_user_id()?;
    let value = state.runtime.block_on(rest_send_json(
        state,
        reqwest::Method::GET,
        rest_api_url(
            server_http_url,
            &["v1", "prekeys", &hex::encode(peer_identity_key)],
        )?,
        &user_id,
        None,
    ))?;
    let bundle = parse_prekey_bundle(value, &peer_identity_key)?;
    if let Some(expected) = expected_signing_key {
        if bundle.signing_key != expected {
            return Err("prekey signing key does not match the authenticated DM peer".to_string());
        }
    }
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    client.pin_peer_signing_key(peer_identity_key, bundle.signing_key)?;
    client.establish_session(&peer_identity_key, &bundle)
}

/// Fetch a peer's prekey bundle and establish an encrypted session.
#[tauri::command]
fn establish_session(
    state: State<'_, AppState>,
    server_http_url: String,
    peer_identity_key: String,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let peer_identity_key: [u8; 32] = hex::decode(peer_identity_key.trim())
        .map_err(|e| format!("decode peer identity key: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("peer identity key must be 32 bytes, got {}", v.len()))?;
    establish_session_for_peer(&state, &server_http_url, peer_identity_key, None)
}

// ─── Connection ───────────────────────────────────────

const OFFLINE_SYNC_PAGE_LIMIT: usize = 100;
const OFFLINE_SYNC_MAX_PAGES: usize = 10_000;
const MAX_SYNC_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MAX_SYNC_HEADER_BYTES: usize = 512;
const MAX_SYNC_SENDER_KEY_RECIPIENTS: usize = 3_500;

#[derive(serde::Deserialize)]
struct SyncConversationPage {
    conversations: Vec<SyncConversation>,
    count: usize,
    #[serde(default)]
    next_cursor: Option<String>,
}

#[derive(serde::Deserialize)]
struct SyncConversation {
    id: String,
    conv_type: u8,
    name: Option<String>,
    server_id: Option<String>,
    created_at: String,
    members: Vec<SyncDirectoryMember>,
}

#[derive(serde::Deserialize)]
struct SyncDirectoryMember {
    user_id: String,
    username: String,
    identity_key: String,
    signing_key: String,
}

#[derive(Clone)]
struct PinnedDirectoryMember {
    username: String,
    identity_key: [u8; 32],
    signing_key: [u8; 32],
}

#[derive(serde::Deserialize)]
struct SyncMessagePage {
    messages: Vec<SyncMessage>,
    count: usize,
    #[serde(default)]
    next_cursor: Option<String>,
}

#[derive(serde::Deserialize)]
struct SyncMessage {
    id: String,
    conversation_id: String,
    sender_id: String,
    sender_identity_key: String,
    sender_signing_key: String,
    ciphertext: String,
    header: String,
    #[serde(default)]
    reply_to_id: Option<String>,
    server_timestamp: i64,
    #[serde(default, rename = "edited_at")]
    _edited_at: Option<String>,
    is_deleted: bool,
    is_expired: bool,
    revision_timestamp: i64,
    #[serde(default)]
    reactions: Vec<SyncReaction>,
}

#[derive(serde::Deserialize)]
struct SyncReaction {
    emoji: String,
    user_id: String,
    username: String,
}

#[derive(Default)]
struct OfflineSyncStats {
    conversations: usize,
    messages: usize,
    duplicates: usize,
    unavailable_history: usize,
    retained_sender_keys: usize,
    edits: usize,
    tombstones: usize,
}

fn decode_lower_hex_32(field: &str, value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must be exactly 32-byte lowercase hex"));
    }
    hex::decode(value)
        .map_err(|e| format!("decode {field}: {e}"))?
        .try_into()
        .map_err(|_| format!("{field} must be exactly 32 bytes"))
}

fn decode_lower_hex_bytes(field: &str, value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must be non-empty lowercase hex"));
    }
    hex::decode(value).map_err(|e| format!("decode {field}: {e}"))
}

/// Build an API URL by appending each untrusted identifier as one encoded path
/// segment. This prevents `/`, `%2f`, `..`, query and fragment injection from
/// changing which signed route the native command authorizes.
fn rest_api_url(server_http_url: &str, segments: &[&str]) -> Result<String, String> {
    let mut url =
        reqwest::Url::parse(server_http_url).map_err(|e| format!("invalid REST base URL: {e}"))?;
    validate_rest_url(&url)?;
    if url.query().is_some() || url.fragment().is_some() || !url.path().trim_matches('/').is_empty()
    {
        return Err("REST base URL must be an exact origin without path or query".to_string());
    }
    let mut path = url
        .path_segments_mut()
        .map_err(|_| "REST URL cannot be a base URL".to_string())?;
    path.clear();
    for segment in segments {
        if segment.is_empty()
            || segment.len() > 256
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err("REST path segment is empty, too long, or non-canonical".to_string());
        }
        path.push(segment);
    }
    drop(path);
    Ok(url.to_string())
}

fn validate_invite_code(code: &str) -> Result<(), String> {
    if code.len() == 8
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        Ok(())
    } else {
        Err("invite code must be 8 URL-safe characters".to_string())
    }
}

fn offline_sync_url(
    server_http_url: &str,
    path: &[&str],
    cursor: Option<&str>,
) -> Result<String, String> {
    let mut url = reqwest::Url::parse(&rest_api_url(server_http_url, path)?)
        .map_err(|e| format!("invalid offline sync URL: {e}"))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("limit", &OFFLINE_SYNC_PAGE_LIMIT.to_string());
        if let Some(cursor) = cursor {
            if cursor.is_empty() {
                return Err("offline sync cursor must not be empty".to_string());
            }
            query.append_pair("cursor", cursor);
        }
    }
    Ok(url.to_string())
}

fn validate_next_cursor(
    current: Option<&str>,
    next: Option<&str>,
    item_count: usize,
) -> Result<(), String> {
    if let Some(next) = next {
        if next.is_empty() {
            return Err("server returned an empty offline sync cursor".to_string());
        }
        if current == Some(next) {
            return Err("server repeated an offline sync cursor".to_string());
        }
        if item_count == 0 {
            return Err("server returned a cursor for an empty sync page".to_string());
        }
    }
    Ok(())
}

fn pin_and_persist_sync_conversation(
    state: &AppState,
    authenticated_user_id: &str,
    conversation: &SyncConversation,
) -> Result<std::collections::HashMap<String, PinnedDirectoryMember>, String> {
    if conversation.id.is_empty() || conversation.created_at.is_empty() {
        return Err("server returned an incomplete conversation directory entry".to_string());
    }
    if conversation.conv_type > 2 {
        return Err(format!(
            "conversation {} has unsupported type {}",
            conversation.id, conversation.conv_type
        ));
    }
    if conversation.server_id.as_deref().is_some_and(str::is_empty) {
        return Err(format!(
            "conversation {} has an empty server id",
            conversation.id
        ));
    }
    if conversation.members.is_empty() || conversation.members.len() > 1_024 {
        return Err(format!(
            "conversation {} has an invalid authenticated member count",
            conversation.id
        ));
    }

    let mut directory = std::collections::HashMap::new();
    let mut identity_owners = std::collections::HashMap::new();
    for member in &conversation.members {
        if member.user_id.is_empty() || member.username.is_empty() {
            return Err(format!(
                "conversation {} contains an incomplete member",
                conversation.id
            ));
        }
        let identity_key = decode_lower_hex_32("member identity_key", &member.identity_key)?;
        let signing_key = decode_lower_hex_32("member signing_key", &member.signing_key)?;
        if directory.contains_key(&member.user_id) {
            return Err(format!(
                "conversation {} repeats member {}",
                conversation.id, member.user_id
            ));
        }
        if let Some(owner) = identity_owners.insert(identity_key, member.user_id.clone()) {
            return Err(format!(
                "conversation {} maps one identity to users {} and {}",
                conversation.id, owner, member.user_id
            ));
        }
        directory.insert(
            member.user_id.clone(),
            PinnedDirectoryMember {
                username: member.username.clone(),
                identity_key,
                signing_key,
            },
        );
    }

    let our_member = directory.get(authenticated_user_id).ok_or_else(|| {
        format!(
            "authenticated user is absent from conversation {} directory",
            conversation.id
        )
    })?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    if our_member.identity_key != client.identity_key()?
        || our_member.signing_key != client.signing_key()?
    {
        return Err(format!(
            "server directory returned substituted local identity keys for conversation {}",
            conversation.id
        ));
    }

    let (name, peer_identity_key) = if conversation.conv_type == 0 {
        if directory.len() != 2 {
            return Err(format!(
                "DM conversation {} must contain exactly two members",
                conversation.id
            ));
        }
        let peer = directory
            .iter()
            .find(|(user_id, _)| user_id.as_str() != authenticated_user_id)
            .map(|(_, member)| member)
            .ok_or_else(|| format!("DM conversation {} has no peer", conversation.id))?;
        (
            conversation
                .name
                .as_deref()
                .filter(|name| !name.is_empty())
                .unwrap_or(&peer.username),
            Some(peer.identity_key),
        )
    } else {
        (conversation.name.as_deref().unwrap_or_default(), None)
    };

    // Only after the complete entry has passed structural/self-key checks do
    // we commit TOFU pins learned from this authenticated directory page.
    for (user_id, member) in &directory {
        client.remember_user_identity(user_id, member.identity_key);
        client.pin_peer_signing_key(member.identity_key, member.signing_key)?;
    }
    client.replace_authorized_conversation_senders(
        &conversation.id,
        directory.values().map(|member| member.identity_key),
    )?;
    {
        let db = client.db().ok_or("database not initialized")?;
        db.upsert_directory_conversation(
            &conversation.id,
            conversation.conv_type,
            Some(name),
            peer_identity_key.as_ref().map(<[u8; 32]>::as_slice),
            conversation.server_id.as_deref(),
            &conversation.created_at,
        )?;
    }

    if let Some(peer_identity_key) = peer_identity_key {
        client.bind_dm_conversation(&conversation.id, peer_identity_key);
    } else {
        // Group/channel history is Sender-Key ciphertext. Marking first blocks
        // outgoing sends until a fresh distribution, while hydration restores
        // the incoming ratchets required for the backlog.
        client.mark_channel_conversation(&conversation.id);
        client.hydrate_channel_sender_keys(&conversation.id)?;
    }
    Ok(directory)
}

fn sync_conversation_messages(
    state: &AppState,
    server_http_url: &str,
    authenticated_user_id: &str,
    conversation_id: &str,
    directory: &std::collections::HashMap<String, PinnedDirectoryMember>,
    stats: &mut OfflineSyncStats,
) -> Result<(), String> {
    let mut cursor: Option<String> = None;
    for _ in 0..OFFLINE_SYNC_MAX_PAGES {
        let url = offline_sync_url(
            server_http_url,
            &["v1", "messages", conversation_id],
            cursor.as_deref(),
        )?;
        let value = state.runtime.block_on(rest_send_json(
            state,
            reqwest::Method::GET,
            url,
            authenticated_user_id,
            None,
        ))?;
        let page: SyncMessagePage = serde_json::from_value(value)
            .map_err(|e| format!("invalid message sync response: {e}"))?;
        if page.count != page.messages.len() {
            return Err(format!(
                "message sync count mismatch for conversation {conversation_id}"
            ));
        }
        if page.messages.len() > OFFLINE_SYNC_PAGE_LIMIT {
            return Err(format!(
                "message sync page exceeds client limit for conversation {conversation_id}"
            ));
        }
        validate_next_cursor(
            cursor.as_deref(),
            page.next_cursor.as_deref(),
            page.messages.len(),
        )?;

        let mut page_message_ids = std::collections::HashSet::new();
        for message in &page.messages {
            if message.id.is_empty() || !page_message_ids.insert(message.id.as_str()) {
                return Err(format!(
                    "message sync returned an empty or repeated UUID for conversation {conversation_id}"
                ));
            }
            if message.conversation_id != conversation_id {
                return Err(format!(
                    "message {} escaped its authenticated conversation scope",
                    message.id
                ));
            }

            let response_identity =
                decode_lower_hex_32("message sender_identity_key", &message.sender_identity_key)?;
            let response_signing =
                decode_lower_hex_32("message sender_signing_key", &message.sender_signing_key)?;
            if message.server_timestamp < 0 || message.revision_timestamp < message.server_timestamp
            {
                return Err(format!(
                    "message {} has an invalid server revision timestamp",
                    message.id
                ));
            }
            let reactions: Vec<veil_store::models::RemoteReaction> = message
                .reactions
                .iter()
                .map(|reaction| veil_store::models::RemoteReaction {
                    emoji: reaction.emoji.clone(),
                    user_id: reaction.user_id.clone(),
                    username: reaction.username.clone(),
                })
                .collect();
            let metadata = veil_client::api::RemoteMessageMetadata {
                revision_ms: message.revision_timestamp,
                reactions: Some(&reactions),
            };
            let remote_state = if message.is_deleted {
                veil_store::models::RemoteMessageStateKind::Deleted
            } else if message.is_expired {
                veil_store::models::RemoteMessageStateKind::Expired
            } else {
                veil_store::models::RemoteMessageStateKind::Active
            };

            let mut client = state.client.lock().map_err(|e| e.to_string())?;
            let mut sender_is_usable = true;
            if let Some(pinned_sender) = directory.get(&message.sender_id) {
                if response_identity != pinned_sender.identity_key
                    || response_signing != pinned_sender.signing_key
                    || client.known_user_identity(&message.sender_id) != Some(response_identity)
                {
                    return Err(format!(
                        "message {} sender keys do not match the pinned server directory",
                        message.id
                    ));
                }
            } else {
                // Removed members are absent from the current member list. We
                // may decrypt their history only if this exact X->Ed binding
                // was already durably pinned while they were a member. A new
                // device is not entitled to unavailable pre-join Sender-Key
                // history, so first-seen former senders are skipped explicitly
                // instead of blocking later backlog pages.
                if !client.peer_signing_key_is_pinned(&response_identity, &response_signing) {
                    sender_is_usable = false;
                }
                if client
                    .known_user_identity(&message.sender_id)
                    .is_some_and(|known| known != response_identity)
                {
                    return Err(format!(
                        "message {} former sender conflicts with a known user identity",
                        message.id
                    ));
                }
            }

            if !sender_is_usable
                && remote_state == veil_store::models::RemoteMessageStateKind::Active
            {
                client.reconcile_remote_message_metadata(
                    &message.id,
                    conversation_id,
                    &response_identity,
                    &metadata,
                    veil_store::models::RemoteMessageStateKind::Unavailable,
                )?;
                stats.unavailable_history += 1;
                continue;
            }

            let action = client.reconcile_remote_message_metadata(
                &message.id,
                conversation_id,
                &response_identity,
                &metadata,
                remote_state,
            )?;
            match action {
                veil_client::api::RemoteReconcileAction::Deleted => {
                    stats.tombstones += 1;
                    continue;
                }
                veil_client::api::RemoteReconcileAction::Unchanged
                | veil_client::api::RemoteReconcileAction::SelfStateOnly => {
                    stats.duplicates += 1;
                    continue;
                }
                veil_client::api::RemoteReconcileAction::Unavailable => {
                    stats.unavailable_history += 1;
                    continue;
                }
                veil_client::api::RemoteReconcileAction::NeedsInitialCiphertext
                    if message.sender_id == authenticated_user_id =>
                {
                    client.reconcile_remote_message_metadata(
                        &message.id,
                        conversation_id,
                        &response_identity,
                        &metadata,
                        veil_store::models::RemoteMessageStateKind::Unavailable,
                    )?;
                    stats.unavailable_history += 1;
                    continue;
                }
                veil_client::api::RemoteReconcileAction::NeedsEncryptedEdit
                    if message.sender_id == authenticated_user_id =>
                {
                    return Err(format!(
                        "self-authored message {} requires ciphertext decryption",
                        message.id
                    ));
                }
                _ => {}
            }

            if message.header.len() > MAX_SYNC_HEADER_BYTES * 2
                || message.ciphertext.len() > MAX_SYNC_CIPHERTEXT_BYTES * 2
            {
                return Err(format!(
                    "message {} exceeds the E2E wire size limit",
                    message.id
                ));
            }
            let header = decode_lower_hex_bytes("message header", &message.header)?;
            let ciphertext = decode_lower_hex_bytes("message ciphertext", &message.ciphertext)?;
            let sender_key_mode = client.is_channel_conversation(conversation_id);
            match action {
                veil_client::api::RemoteReconcileAction::NeedsInitialCiphertext => {
                    match client.receive_and_persist_message(
                        &message.id,
                        conversation_id,
                        &response_identity,
                        sender_key_mode,
                        None,
                        &header,
                        &ciphertext,
                        Some(message.server_timestamp),
                        message.reply_to_id.as_deref(),
                        Some(&metadata),
                    )? {
                        veil_client::api::ReceiveMessageResult::Stored { .. } => {
                            stats.messages += 1;
                        }
                        veil_client::api::ReceiveMessageResult::Duplicate => {
                            stats.duplicates += 1;
                        }
                    }
                }
                veil_client::api::RemoteReconcileAction::NeedsEncryptedEdit => {
                    client.receive_and_persist_edit(
                        &message.id,
                        conversation_id,
                        &response_identity,
                        sender_key_mode,
                        &header,
                        &ciphertext,
                        Some(&metadata),
                    )?;
                    stats.edits += 1;
                }
                _ => {
                    return Err(format!(
                        "unexpected reconciliation action for message {}",
                        message.id
                    ));
                }
            }
        }

        // Advance only after every non-duplicate record in the page was
        // authenticated, decrypted and durably persisted.
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(()),
        }
    }
    Err(format!(
        "message sync exceeded {} pages for conversation {conversation_id}",
        OFFLINE_SYNC_MAX_PAGES
    ))
}

fn sync_offline_state(
    state: &AppState,
    server_http_url: &str,
    authenticated_user_id: &str,
) -> Result<OfflineSyncStats, String> {
    let mut stats = OfflineSyncStats::default();
    let mut cursor: Option<String> = None;
    let mut seen_conversations = std::collections::HashSet::new();
    let mut directories = Vec::new();
    let mut finished = false;

    for _ in 0..OFFLINE_SYNC_MAX_PAGES {
        let url = offline_sync_url(server_http_url, &["v1", "conversations"], cursor.as_deref())?;
        let value = state.runtime.block_on(rest_send_json(
            state,
            reqwest::Method::GET,
            url,
            authenticated_user_id,
            None,
        ))?;
        let page: SyncConversationPage = serde_json::from_value(value)
            .map_err(|e| format!("invalid conversation sync response: {e}"))?;
        if page.count != page.conversations.len() {
            return Err("conversation sync count mismatch".to_string());
        }
        if page.conversations.len() > OFFLINE_SYNC_PAGE_LIMIT {
            return Err("conversation sync page exceeds client limit".to_string());
        }
        validate_next_cursor(
            cursor.as_deref(),
            page.next_cursor.as_deref(),
            page.conversations.len(),
        )?;

        for conversation in &page.conversations {
            if !seen_conversations.insert(conversation.id.clone()) {
                return Err(format!(
                    "conversation directory repeated {} across pages",
                    conversation.id
                ));
            }
            let directory =
                pin_and_persist_sync_conversation(state, authenticated_user_id, conversation)?;
            directories.push((conversation.id.clone(), directory));
            stats.conversations += 1;
        }

        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => {
                finished = true;
                break;
            }
        }
    }
    if !finished {
        return Err(format!(
            "conversation sync exceeded {} pages",
            OFFLINE_SYNC_MAX_PAGES
        ));
    }

    // AuthResult is a FIFO barrier: all retained SKDM envelopes were buffered
    // before it. Install them only now, after every signed member directory is
    // pinned, and before any group ciphertext consumes Sender-Key state.
    stats.retained_sender_keys = state
        .client
        .lock()
        .map_err(|e| e.to_string())?
        .process_retained_sender_keys_before_sync()?;

    // All identities are pinned and all FK parents/groups are installed before
    // consuming any ratchet state from the ciphertext backlog.
    for (conversation_id, directory) in &directories {
        sync_conversation_messages(
            state,
            server_http_url,
            authenticated_user_id,
            conversation_id,
            directory,
            &mut stats,
        )?;
    }

    // The current roster may have changed while this client was offline and
    // membership events are not durable. After all historical ciphertext has
    // been consumed with its old receive keys, rotate every group/channel
    // outgoing generation and distribute only to the freshly authenticated
    // directory. Sending stays blocked until every server ACK is processed by
    // the live dispatcher.
    let our_identity = state
        .client
        .lock()
        .map_err(|e| e.to_string())?
        .identity_key()?;
    let mut total_recipients = 0usize;
    for (conversation_id, directory) in &directories {
        let sender_key_mode = state
            .client
            .lock()
            .map_err(|e| e.to_string())?
            .is_channel_conversation(conversation_id);
        if sender_key_mode {
            total_recipients = total_recipients
                .checked_add(
                    directory
                        .values()
                        .filter(|member| member.identity_key != our_identity)
                        .count(),
                )
                .ok_or_else(|| "sender-key recipient count overflow".to_string())?;
        }
    }
    if total_recipients > MAX_SYNC_SENDER_KEY_RECIPIENTS {
        return Err(format!(
            "offline sender-key refresh exceeds {MAX_SYNC_SENDER_KEY_RECIPIENTS} recipients"
        ));
    }
    for (conversation_id, directory) in directories {
        let sender_key_mode = state
            .client
            .lock()
            .map_err(|e| e.to_string())?
            .is_channel_conversation(&conversation_id);
        if !sender_key_mode {
            continue;
        }
        let recipients = directory
            .values()
            .map(|member| (hex::encode(member.identity_key), member.identity_key));
        distribute_pinned_sender_key(state, &conversation_id, recipients, true)?;
    }
    Ok(stats)
}

#[tauri::command]
fn connect_to_server(
    state: State<'_, AppState>,
    app: AppHandle,
    server_url: String,
    server_http_url: String,
) -> Result<String, String> {
    require_unlocked(&state)?;
    validate_server_endpoint_pair(&server_url, &server_http_url)?;
    let requested_rest_url =
        reqwest::Url::parse(&server_http_url).map_err(|e| format!("invalid REST URL: {e}"))?;
    let requested_rest_origin = rest_origin(&requested_rest_url)?;
    let _connect_transition = state.connect_transition.lock().map_err(|e| e.to_string())?;
    require_unlocked(&state)?;
    let previous_generation = state
        .rest_binding_generation
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map_err(|_| "REST binding generation exhausted".to_string())?;
    let requested_rest_binding = RestBinding {
        origin: requested_rest_origin,
        generation: previous_generation + 1,
    };
    // Pauses an already-running dispatcher during reconnect as well as the
    // first connection. It is enabled only after the complete keyset backlog
    // has been authenticated, decrypted and persisted.
    state.offline_sync_ready.store(false, Ordering::SeqCst);
    *state
        .authenticated_rest_origin
        .lock()
        .map_err(|e| e.to_string())? = None;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    client.clear_all_authorized_conversation_senders();
    let result = state.runtime.block_on(client.connect(&server_url))?;
    drop(client);

    // Bind REST only after successful WS authentication, serialized against a
    // concurrent native lock. A reconnect starts with no binding, so an old
    // authenticated origin cannot authorize requests for the new session.
    {
        let session_transition = state.session_transition.lock().map_err(|e| e.to_string())?;
        if !state.unlocked.load(Ordering::Acquire) {
            return Err("application locked while authenticating".to_string());
        }
        let expired = has_pin_material()?
            && state
                .last_activity
                .lock()
                .map_err(|e| e.to_string())?
                .elapsed()
                .as_secs()
                >= get_auto_lock_seconds();
        if expired {
            drop(session_transition);
            reset_sensitive_state(&state)?;
            return Err("application auto-locked while authenticating".to_string());
        }
        *state
            .authenticated_rest_origin
            .lock()
            .map_err(|e| e.to_string())? = Some(requested_rest_binding.clone());
    }

    let sync_stats = match sync_offline_state(&state, &server_http_url, &result) {
        Ok(stats) => stats,
        Err(error) => {
            let mut bound = state
                .authenticated_rest_origin
                .lock()
                .map_err(|e| e.to_string())?;
            if bound.as_ref() == Some(&requested_rest_binding) {
                *bound = None;
            }
            return Err(format!("authenticated offline sync failed: {error}"));
        }
    };
    {
        // Publish readiness and its UI notification in the same ordered
        // session transition as lock/unlock. Otherwise a watchdog reset could
        // land after require_unlocked but before this store and resurrect a
        // stale connection as ready while the native session is locked.
        let _session_transition = state.session_transition.lock().map_err(|e| e.to_string())?;
        if !state.unlocked.load(Ordering::Acquire) {
            return Err("application locked while completing offline sync".to_string());
        }
        let binding_matches = state
            .authenticated_rest_origin
            .lock()
            .map_err(|e| e.to_string())?
            .as_ref()
            == Some(&requested_rest_binding);
        if !binding_matches {
            return Err("authenticated REST binding changed during offline sync".to_string());
        }
        state.offline_sync_ready.store(true, Ordering::SeqCst);
        let _ = app.emit(
            "veil://sync-complete",
            serde_json::json!({
                "conversations": sync_stats.conversations,
                "messages": sync_stats.messages,
                "duplicates": sync_stats.duplicates,
                "unavailableHistory": sync_stats.unavailable_history,
                "retainedSenderKeys": sync_stats.retained_sender_keys,
                "edits": sync_stats.edits,
                "tombstones": sync_stats.tombstones,
            }),
        );
    }

    // Start exactly one background event polling loop for the app lifetime.
    if state
        .event_poller_started
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        let app_handle = app.clone();
        std::thread::spawn(move || {
            let state_inner = app_handle.state::<AppState>();
            loop {
                std::thread::sleep(std::time::Duration::from_millis(50));
                if !state_inner.offline_sync_ready.load(Ordering::Acquire) {
                    continue;
                }
                let _session_transition = match state_inner.session_transition.lock() {
                    Ok(guard) => guard,
                    Err(_) => break,
                };
                if !state_inner.unlocked.load(Ordering::Acquire)
                    || !state_inner.offline_sync_ready.load(Ordering::Acquire)
                {
                    continue;
                }
                let mut client = match state_inner.client.lock() {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let event = match state_inner.runtime.block_on(client.poll_event()) {
                    Ok(event) => event,
                    Err(error) => {
                        drop(client);
                        let _ = app_handle.emit(
                            "veil://error",
                            serde_json::json!({
                                "code": 5001,
                                "message": format!("failed to reconcile server event: {error}"),
                            }),
                        );
                        continue;
                    }
                };

                if let Some(evt) = event {
                    match evt {
                        ConnectionEvent::MessageReceived {
                            message_id,
                            conversation_id,
                            sender_identity_key,
                            sender_username,
                            ciphertext,
                            header,
                            server_timestamp,
                            reply_to_id,
                        } => {
                            // Decrypt strictly; invalid or legacy plaintext network
                            // frames are rejected below.
                            let sender_key: [u8; 32] = match sender_identity_key
                                .as_slice()
                                .try_into()
                            {
                                Ok(key) => key,
                                Err(_) => {
                                    drop(client);
                                    let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 4001,
                                        "message": "message rejected: sender identity key must be 32 bytes",
                                    }),
                                );
                                    continue;
                                }
                            };

                            if let Err(error) = client
                                .require_currently_authorized_sender(&conversation_id, &sender_key)
                            {
                                state_inner
                                    .offline_sync_ready
                                    .store(false, Ordering::Release);
                                drop(client);
                                let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 4003,
                                        "message": format!("live message authorization rejected: {error}"),
                                    }),
                                );
                                let _ = app_handle.emit(
                                    "veil://membership-refresh-required",
                                    serde_json::json!({ "conversationId": conversation_id }),
                                );
                                continue;
                            }

                            let sender_key_mode = client.is_channel_conversation(&conversation_id);
                            let ts_ms = (server_timestamp / 1_000_000) as i64;
                            let text = match client.receive_and_persist_live_message(
                                &message_id,
                                &conversation_id,
                                &sender_key,
                                sender_key_mode,
                                Some(&sender_username),
                                &header,
                                &ciphertext,
                                Some(ts_ms),
                                reply_to_id.as_deref(),
                                None,
                            ) {
                                Ok(veil_client::api::ReceiveMessageResult::Stored {
                                    plaintext,
                                }) => plaintext,
                                Ok(veil_client::api::ReceiveMessageResult::Duplicate) => {
                                    drop(client);
                                    continue;
                                }
                                Err(error) => {
                                    // Crypto state, FK parent and plaintext row
                                    // were rolled back together by the client.
                                    drop(client);
                                    let _ = app_handle.emit(
                                        "veil://error",
                                        serde_json::json!({
                                            "code": 4001,
                                            "message": format!("message transaction rejected: {error}"),
                                        }),
                                    );
                                    continue;
                                }
                            };
                            drop(client); // Release lock before emitting

                            let _ = app_handle.emit(
                                "veil://message",
                                serde_json::json!({
                                    "messageId": message_id,
                                    "conversationId": conversation_id,
                                    "senderKey": hex::encode(&sender_identity_key),
                                    "senderName": sender_username,
                                    "text": text,
                                    "timestamp": server_timestamp / 1_000_000,
                                    "replyToId": reply_to_id,
                                }),
                            );

                            // Desktop notification
                            let _ = app_handle
                                .notification()
                                .builder()
                                .title("Veil")
                                .body("New encrypted message")
                                .show();
                        }
                        ConnectionEvent::MessageAcked {
                            message_id,
                            server_timestamp,
                            ref_seq,
                            local_message_id,
                            mutation,
                        } => {
                            drop(client);
                            let _ = app_handle.emit(
                                "veil://message-ack",
                                serde_json::json!({
                                    "messageId": message_id.clone(),
                                    "localMessageId": local_message_id,
                                    "refSeq": ref_seq,
                                }),
                            );
                            match mutation {
                                Some(veil_client::connection::ConfirmedMutation::Edit {
                                    message_id,
                                    conversation_id,
                                    mut new_text,
                                }) => {
                                    let mut payload = serde_json::json!({
                                        "messageId": message_id,
                                        "conversationId": conversation_id,
                                        "newText": &new_text,
                                        "editTimestamp": server_timestamp / 1_000_000,
                                    });
                                    let _ = app_handle.emit("veil://message-edited", &payload);
                                    new_text.zeroize();
                                    if let Some(serde_json::Value::String(text)) =
                                        payload.get_mut("newText")
                                    {
                                        text.zeroize();
                                    }
                                }
                                Some(veil_client::connection::ConfirmedMutation::Delete {
                                    message_id,
                                    conversation_id,
                                }) => {
                                    let _ = app_handle.emit(
                                        "veil://message-deleted",
                                        serde_json::json!({
                                            "messageId": message_id,
                                            "conversationId": conversation_id,
                                        }),
                                    );
                                }
                                Some(veil_client::connection::ConfirmedMutation::Reaction {
                                    message_id,
                                    conversation_id,
                                    emoji,
                                    user_id,
                                    add,
                                }) => {
                                    let _ = app_handle.emit(
                                        "veil://reaction",
                                        serde_json::json!({
                                            "messageId": message_id,
                                            "conversationId": conversation_id,
                                            "emoji": emoji,
                                            "userId": user_id,
                                            "username": "You",
                                            "add": add,
                                        }),
                                    );
                                }
                                None => {}
                            }
                        }
                        ConnectionEvent::MessageEdited {
                            message_id,
                            conversation_id,
                            sender_identity_key,
                            ciphertext,
                            header,
                            edit_timestamp,
                        } => {
                            let sender_key: [u8; 32] = match sender_identity_key
                                .as_slice()
                                .try_into()
                            {
                                Ok(key) => key,
                                Err(_) => {
                                    drop(client);
                                    let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 4001,
                                        "message": "edit rejected: sender identity key must be 32 bytes",
                                    }),
                                );
                                    continue;
                                }
                            };

                            if let Err(error) = client
                                .require_currently_authorized_sender(&conversation_id, &sender_key)
                            {
                                state_inner
                                    .offline_sync_ready
                                    .store(false, Ordering::Release);
                                drop(client);
                                let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 4003,
                                        "message": format!("live edit authorization rejected: {error}"),
                                    }),
                                );
                                let _ = app_handle.emit(
                                    "veil://membership-refresh-required",
                                    serde_json::json!({ "conversationId": conversation_id }),
                                );
                                continue;
                            }

                            let sender_key_mode = client.is_channel_conversation(&conversation_id);
                            let revision_ms = match i64::try_from(edit_timestamp / 1_000_000) {
                                Ok(timestamp) => timestamp,
                                Err(_) => {
                                    drop(client);
                                    continue;
                                }
                            };
                            let metadata = veil_client::api::RemoteMessageMetadata {
                                revision_ms,
                                reactions: None,
                            };
                            match client.reconcile_remote_message_metadata(
                                &message_id,
                                &conversation_id,
                                &sender_key,
                                &metadata,
                                veil_store::models::RemoteMessageStateKind::Active,
                            ) {
                                Ok(veil_client::api::RemoteReconcileAction::Unchanged)
                                | Ok(veil_client::api::RemoteReconcileAction::SelfStateOnly) => {
                                    drop(client);
                                    continue;
                                }
                                Ok(veil_client::api::RemoteReconcileAction::NeedsEncryptedEdit) => {
                                }
                                Ok(_) => {
                                    drop(client);
                                    continue;
                                }
                                Err(error) => {
                                    drop(client);
                                    let _ = app_handle.emit(
                                        "veil://error",
                                        serde_json::json!({
                                            "code": 4001,
                                            "message": format!("message edit reconciliation rejected: {error}"),
                                        }),
                                    );
                                    continue;
                                }
                            }
                            let new_text = match client.receive_and_persist_live_edit(
                                &message_id,
                                &conversation_id,
                                &sender_key,
                                sender_key_mode,
                                &header,
                                &ciphertext,
                                Some(&metadata),
                            ) {
                                Ok(plaintext) => plaintext,
                                Err(error) => {
                                    drop(client);
                                    let _ = app_handle.emit(
                                        "veil://error",
                                        serde_json::json!({
                                            "code": 4001,
                                            "message": format!("message edit rejected: {error}"),
                                        }),
                                    );
                                    continue;
                                }
                            };

                            drop(client);

                            let _ = app_handle.emit(
                                "veil://message-edited",
                                serde_json::json!({
                                    "messageId": message_id,
                                    "conversationId": conversation_id,
                                    "newText": new_text,
                                    "editTimestamp": edit_timestamp / 1_000_000,
                                }),
                            );
                        }
                        ConnectionEvent::MessageDeleted {
                            message_id,
                            conversation_id,
                            sender_identity_key,
                            delete_timestamp,
                        } => {
                            let sender_key: [u8; 32] = match sender_identity_key.try_into() {
                                Ok(sender) => sender,
                                Err(_) => {
                                    drop(client);
                                    continue;
                                }
                            };

                            // A durable identity pin proves who signed the event,
                            // but it does not prove that the sender is still a
                            // member of this conversation. Apply the same live
                            // directory guard as NEW/EDIT before a tombstone can
                            // mutate local history.
                            if let Err(error) = client
                                .require_currently_authorized_sender(&conversation_id, &sender_key)
                            {
                                state_inner
                                    .offline_sync_ready
                                    .store(false, Ordering::Release);
                                drop(client);
                                let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 4003,
                                        "message": format!("live delete authorization rejected: {error}"),
                                    }),
                                );
                                let _ = app_handle.emit(
                                    "veil://membership-refresh-required",
                                    serde_json::json!({ "conversationId": conversation_id }),
                                );
                                continue;
                            }

                            let revision_ms = match i64::try_from(delete_timestamp / 1_000_000) {
                                Ok(timestamp) => timestamp,
                                Err(_) => {
                                    drop(client);
                                    continue;
                                }
                            };
                            let metadata = veil_client::api::RemoteMessageMetadata {
                                revision_ms,
                                reactions: None,
                            };
                            if let Err(error) = client.reconcile_remote_message_metadata(
                                &message_id,
                                &conversation_id,
                                &sender_key,
                                &metadata,
                                veil_store::models::RemoteMessageStateKind::Deleted,
                            ) {
                                drop(client);
                                let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 5001,
                                        "message": format!("message delete persistence failed: {error}"),
                                    }),
                                );
                                continue;
                            }
                            drop(client);

                            let _ = app_handle.emit(
                                "veil://message-deleted",
                                serde_json::json!({
                                    "messageId": message_id,
                                    "conversationId": conversation_id,
                                }),
                            );
                        }
                        ConnectionEvent::Disconnected { reason } => {
                            drop(client);
                            let _ = app_handle.emit(
                                "veil://disconnected",
                                serde_json::json!({ "reason": reason }),
                            );
                            continue;
                        }
                        ConnectionEvent::Error {
                            code,
                            message,
                            local_message_id,
                            ..
                        } => {
                            drop(client);
                            let _ = app_handle.emit(
                                "veil://error",
                                serde_json::json!({
                                    "code": code,
                                    "message": message,
                                    "localMessageId": local_message_id,
                                }),
                            );
                        }
                        ConnectionEvent::TypingEvent {
                            conversation_id,
                            identity_key,
                            started,
                        } => {
                            drop(client);
                            let _ = app_handle.emit(
                                "veil://typing",
                                serde_json::json!({
                                    "conversationId": conversation_id,
                                    "identityKey": hex::encode(&identity_key),
                                    "started": started,
                                }),
                            );
                        }
                        ConnectionEvent::ReactionEvent {
                            message_id,
                            conversation_id,
                            emoji,
                            user_id,
                            username,
                            add,
                        } => {
                            // Persist to local DB
                            let persistence = if add {
                                client.add_local_reaction(&message_id, &user_id, &emoji, &username)
                            } else {
                                client.remove_local_reaction(&message_id, &user_id, &emoji)
                            };
                            if let Err(error) = persistence {
                                drop(client);
                                let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 5001,
                                        "message": format!("reaction persistence failed: {error}"),
                                    }),
                                );
                                continue;
                            }
                            drop(client);
                            let _ = app_handle.emit(
                                "veil://reaction",
                                serde_json::json!({
                                    "messageId": message_id,
                                    "conversationId": conversation_id,
                                    "emoji": emoji,
                                    "userId": user_id,
                                    "username": username,
                                    "add": add,
                                }),
                            );
                        }
                        ConnectionEvent::PresenceUpdate {
                            identity_key,
                            status,
                            status_text,
                            last_seen,
                        } => {
                            drop(client);
                            let _ = app_handle.emit(
                                "veil://presence",
                                serde_json::json!({
                                    "identityKey": hex::encode(&identity_key),
                                    "status": status,
                                    "statusText": status_text,
                                    "lastSeen": last_seen,
                                }),
                            );
                        }
                        ConnectionEvent::FriendRequestReceived {
                            request_id,
                            from_user_id,
                            from_username,
                            message,
                            timestamp,
                        } => {
                            drop(client);
                            let _ = app_handle.emit(
                                "veil://friend-request",
                                serde_json::json!({
                                    "requestId": request_id,
                                    "fromUserId": from_user_id,
                                    "fromUsername": from_username,
                                    "message": message,
                                    "timestamp": timestamp,
                                }),
                            );
                            let _ = app_handle
                                .notification()
                                .builder()
                                .title("Veil")
                                .body("New friend request")
                                .show();
                        }
                        ConnectionEvent::FriendAccepted { user_id, username } => {
                            drop(client);
                            let _ = app_handle.emit(
                                "veil://friend-accepted",
                                serde_json::json!({
                                    "userId": user_id,
                                    "username": username,
                                }),
                            );
                        }
                        ConnectionEvent::FriendRemoved { user_id } => {
                            drop(client);
                            let _ = app_handle.emit(
                                "veil://friend-removed",
                                serde_json::json!({ "userId": user_id }),
                            );
                        }
                        ConnectionEvent::FriendListReceived {
                            friends,
                            pending_requests,
                        } => {
                            drop(client);
                            let _ = app_handle.emit(
                            "veil://friend-list",
                            serde_json::json!({
                                "friends": friends.iter().map(|f| serde_json::json!({
                                    "userId": f.user_id,
                                    "username": f.username,
                                    "status": f.status,
                                    "lastSeen": f.last_seen,
                                })).collect::<Vec<_>>(),
                                "pendingRequests": pending_requests.iter().map(|r| serde_json::json!({
                                    "requestId": r.request_id,
                                    "fromUserId": r.from_user_id,
                                    "fromUsername": r.from_username,
                                    "message": r.message,
                                    "timestamp": r.timestamp,
                                    "outgoing": r.outgoing,
                                })).collect::<Vec<_>>(),
                            }),
                        );
                        }
                        ConnectionEvent::ServerEvent {
                            event_type,
                            server_id,
                            server_info,
                            member_info,
                            role_info,
                        } => {
                            // Server deletion (2) invalidates cached channel
                            // authorization just as strongly as membership and
                            // role changes (3..=9). Metadata-only create/update
                            // events (0/1) do not require key rotation.
                            let roster_changed = matches!(event_type, 2..=9);
                            if roster_changed {
                                // Membership and role changes invalidate every
                                // channel roster. Clear live authorization and
                                // rotate/block before pausing the dispatcher;
                                // old incoming keys remain only for historical
                                // backlog decryption during the forced reconnect.
                                let conversation_ids: Vec<String> = client
                                    .db()
                                    .and_then(|db| db.list_channels(&server_id).ok())
                                    .unwrap_or_default()
                                    .into_iter()
                                    .filter_map(|channel| channel.conversation_id)
                                    .collect();
                                for conversation_id in conversation_ids {
                                    client.clear_authorized_conversation_senders(&conversation_id);
                                    client.mark_channel_conversation(&conversation_id);
                                    // Even if persistence fails, clear_authorized
                                    // and mark_channel keep live receive/send blocked.
                                    let _ = client.rotate_sender_key(&conversation_id);
                                }
                                state_inner
                                    .offline_sync_ready
                                    .store(false, Ordering::Release);
                            }
                            drop(client);
                            let _ = app_handle.emit(
                                "veil://server-event",
                                serde_json::json!({
                                    "eventType": event_type,
                                    "serverId": server_id.clone(),
                                    "serverInfo": server_info.map(|si| serde_json::json!({
                                        "id": si.id,
                                        "name": si.name,
                                        "iconUrl": si.icon_url,
                                        "ownerIdentityKey": hex::encode(&si.owner_identity_key),
                                    })),
                                    "memberInfo": member_info.map(|mi| serde_json::json!({
                                        "identityKey": hex::encode(&mi.identity_key),
                                        "username": mi.username,
                                        "roleIds": mi.role_ids,
                                        "reason": mi.reason,
                                    })),
                                    "roleInfo": role_info.map(|ri| serde_json::json!({
                                        "id": ri.id,
                                        "name": ri.name,
                                        "permissions": ri.permissions,
                                        "position": ri.position,
                                        "color": ri.color,
                                    })),
                                }),
                            );
                            if roster_changed {
                                let _ = app_handle.emit(
                                    "veil://membership-refresh-required",
                                    serde_json::json!({ "serverId": server_id }),
                                );
                            }
                        }
                        ConnectionEvent::ChannelEvent {
                            event_type,
                            server_id,
                            channel,
                        } => {
                            let conversation_ids: Vec<String> = client
                                .db()
                                .and_then(|db| db.list_channels(&server_id).ok())
                                .unwrap_or_default()
                                .into_iter()
                                .filter_map(|cached| cached.conversation_id)
                                .collect();
                            for conversation_id in conversation_ids {
                                client.clear_authorized_conversation_senders(&conversation_id);
                                client.mark_channel_conversation(&conversation_id);
                                let _ = client.rotate_sender_key(&conversation_id);
                            }
                            state_inner
                                .offline_sync_ready
                                .store(false, Ordering::Release);
                            drop(client);
                            let _ = app_handle.emit(
                                "veil://channel-event",
                                serde_json::json!({
                                    "eventType": event_type,
                                    "serverId": server_id.clone(),
                                    "channel": {
                                        "id": channel.id,
                                        "serverId": channel.server_id,
                                        "name": channel.name,
                                        "channelType": channel.channel_type,
                                        "categoryId": channel.category_id,
                                        "position": channel.position,
                                        "topic": channel.topic,
                                    },
                                }),
                            );
                            let _ = app_handle.emit(
                                "veil://membership-refresh-required",
                                serde_json::json!({ "serverId": server_id }),
                            );
                        }
                        ConnectionEvent::SenderKeyDist {
                            conversation_id,
                            sender_key_message,
                            generation,
                            ..
                        } => match client.process_sealed_skdm(
                            &sender_key_message,
                            &conversation_id,
                            generation,
                        ) {
                            Ok(()) => {
                                drop(client);
                                let _ = app_handle.emit(
                                    "veil://sender-key-received",
                                    serde_json::json!({
                                        "conversationId": conversation_id,
                                    }),
                                );
                            }
                            Err(e) => {
                                state_inner
                                    .offline_sync_ready
                                    .store(false, Ordering::Release);
                                drop(client);
                                let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 4002,
                                        "message": format!("sender-key distribution rejected: {e}"),
                                    }),
                                );
                                let _ = app_handle.emit(
                                    "veil://membership-refresh-required",
                                    serde_json::json!({ "conversationId": conversation_id }),
                                );
                            }
                        },
                        _ => {}
                    }
                }
            }
        });
    }

    Ok(result)
}

// ─── Messaging ────────────────────────────────────────

#[tauri::command]
fn send_message(
    state: State<'_, AppState>,
    conversation_id: String,
    text: String,
    reply_to_id: Option<String>,
) -> Result<u64, String> {
    require_live_transport_ready(&state)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    state
        .runtime
        .block_on(client.send_message(&conversation_id, &text, reply_to_id.as_deref()))
}

#[tauri::command]
fn edit_message(
    state: State<'_, AppState>,
    message_id: String,
    conversation_id: String,
    new_text: String,
) -> Result<u64, String> {
    require_live_transport_ready(&state)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    state
        .runtime
        .block_on(client.edit_message(&message_id, &conversation_id, &new_text))
}

#[tauri::command]
fn delete_message(
    state: State<'_, AppState>,
    message_id: String,
    conversation_id: String,
) -> Result<u64, String> {
    require_live_transport_ready(&state)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    state
        .runtime
        .block_on(client.delete_message(&message_id, &conversation_id))
}

#[tauri::command]
fn send_typing(
    state: State<'_, AppState>,
    conversation_id: String,
    started: bool,
) -> Result<(), String> {
    require_live_transport_ready(&state)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    state
        .runtime
        .block_on(client.send_typing(&conversation_id, started))
}

#[tauri::command]
fn toggle_reaction(
    state: State<'_, AppState>,
    message_id: String,
    conversation_id: String,
    emoji: String,
    user_id: String,
    add: bool,
) -> Result<(), String> {
    require_live_transport_ready(&state)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    if user_id != client.authenticated_user_id()? {
        return Err("reaction user id does not match authenticated session".to_string());
    }
    state
        .runtime
        .block_on(client.send_reaction(&message_id, &conversation_id, &emoji, add))
}

#[tauri::command]
fn get_reactions(
    state: State<'_, AppState>,
    message_id: String,
) -> Result<Vec<(String, String, String)>, String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let result = client.get_local_reactions(&message_id)?;
    require_session_still_unlocked(&state)?;
    Ok(result)
}

/// Create a DM conversation via the Go REST API.
/// Returns the conversation_id.
#[tauri::command]
fn create_dm(
    state: State<'_, AppState>,
    server_http_url: String,
    our_user_id: String,
    peer_user_id: String,
) -> Result<String, String> {
    require_unlocked(&state)?;
    let authenticated_user_id = {
        let client = state.client.lock().map_err(|e| e.to_string())?;
        let authenticated_user_id = client.authenticated_user_id()?;
        if !our_user_id.is_empty() && our_user_id != authenticated_user_id {
            return Err("UI user id does not match the authenticated session".to_string());
        }
        authenticated_user_id
    };

    let body = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        rest_api_url(&server_http_url, &["v1", "conversations", "dm"])?,
        &authenticated_user_id,
        Some(serde_json::json!({
            "peer_user_id": peer_user_id,
        })),
    ))?;

    let conversation_id = body["conversation_id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "no conversation_id in response".to_string())?;
    let created = body["created"]
        .as_bool()
        .ok_or_else(|| "DM response missing created state".to_string())?;
    let peer_identity_key = decode_b64_array::<32>(
        "peer_identity_key",
        body["peer_identity_key"]
            .as_str()
            .ok_or_else(|| "DM response missing peer_identity_key".to_string())?,
    )?;
    let peer_signing_key = decode_b64_array::<32>(
        "peer_signing_key",
        body["peer_signing_key"]
            .as_str()
            .ok_or_else(|| "DM response missing peer_signing_key".to_string())?,
    )?;

    // Reopening an existing deterministic DM must never replace a healthy
    // Double Ratchet with a fresh one. Pin the directory response first; only
    // fetch/consume a new prekey bundle when no session exists locally.
    let session_exists = {
        let mut client = state.client.lock().map_err(|e| e.to_string())?;
        client.pin_peer_signing_key(peer_identity_key, peer_signing_key)?;
        client.remember_user_identity(&peer_user_id, peer_identity_key);
        let our_identity_key = client.identity_key()?;
        client.replace_authorized_conversation_senders(
            &conversation_id,
            [our_identity_key, peer_identity_key],
        )?;
        let exists = client.has_session(&peer_identity_key);
        if exists {
            client.bind_dm_conversation(&conversation_id, peer_identity_key);
        }
        exists
    };
    if !session_exists && created {
        // A new DM is not usable until X3DH succeeds. If this fails, return the
        // error rather than creating a conversation that silently sends.
        establish_session_for_peer(
            &state,
            &server_http_url,
            peer_identity_key,
            Some(peer_signing_key),
        )?;
        state
            .client
            .lock()
            .map_err(|e| e.to_string())?
            .bind_dm_conversation(&conversation_id, peer_identity_key);
    } else if !session_exists {
        // The concurrent creator is responsible for the initial X3DH packet.
        // Cross-initiating here would install two incompatible sessions. Bind
        // the authenticated conversation and wait fail-closed for peer INITIAL;
        // send_message reports the missing session until that arrives.
        state
            .client
            .lock()
            .map_err(|e| e.to_string())?
            .bind_dm_conversation(&conversation_id, peer_identity_key);
    }

    Ok(conversation_id)
}

#[tauri::command]
fn is_connected(state: State<'_, AppState>) -> Result<bool, String> {
    require_unlocked(&state)?;
    let client = state.client.lock().unwrap_or_else(|e| e.into_inner());
    let result = client.is_connected();
    require_session_still_unlocked(&state)?;
    Ok(result)
}

// ─── Groups ───────────────────────────────────────────

/// Create a new group on the server. Returns the conversation_id.
#[tauri::command]
fn create_group(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    name: String,
) -> Result<String, String> {
    let resp = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        rest_api_url(&server_http_url, &["v1", "groups"])?,
        &user_id,
        Some(serde_json::json!({ "name": name })),
    ))?;

    let conv_id = resp["conversation_id"]
        .as_str()
        .ok_or("no conversation_id")?
        .to_string();

    // Persist locally
    let client = state.client.lock().map_err(|e| e.to_string())?;
    if let Some(db) = client.db() {
        let _ = db.insert_conversation(&conv_id, 1, Some(&name), None, None);
    }

    Ok(conv_id)
}

/// Add a member to a group via the server.
#[tauri::command]
fn add_group_member(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    group_id: String,
    target_user_id: String,
) -> Result<(), String> {
    state
        .runtime
        .block_on(rest_send_json(
            &state,
            reqwest::Method::POST,
            rest_api_url(&server_http_url, &["v1", "groups", &group_id, "members"])?,
            &user_id,
            Some(serde_json::json!({ "user_id": target_user_id })),
        ))
        .map(|_| ())
}

/// Remove a member from a group (or leave).
#[tauri::command]
fn remove_group_member(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    group_id: String,
    target_user_id: String,
) -> Result<(), String> {
    state
        .runtime
        .block_on(rest_send_json(
            &state,
            reqwest::Method::DELETE,
            rest_api_url(
                &server_http_url,
                &["v1", "groups", &group_id, "members", &target_user_id],
            )?,
            &user_id,
            None,
        ))
        .map(|_| ())
}

/// Get group members from the server.
fn pin_directory_member_keys(
    client: &mut VeilClient,
    members: &[serde_json::Value],
) -> Result<(), String> {
    for member in members {
        let identity: [u8; 32] = hex::decode(
            member["identity_key"]
                .as_str()
                .ok_or_else(|| "member directory entry missing identity_key".to_string())?,
        )
        .map_err(|e| format!("invalid member identity_key: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("member identity_key must be 32 bytes, got {}", v.len()))?;
        let signing: [u8; 32] = hex::decode(
            member["signing_key"]
                .as_str()
                .ok_or_else(|| "member directory entry missing signing_key".to_string())?,
        )
        .map_err(|e| format!("invalid member signing_key: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("member signing_key must be 32 bytes, got {}", v.len()))?;
        client.pin_peer_signing_key(identity, signing)?;
    }
    Ok(())
}

fn fetch_authorized_conversation_directory(
    state: &AppState,
    server_http_url: &str,
    user_id: &str,
    conversation_id: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let response = state.runtime.block_on(rest_send_json(
        state,
        reqwest::Method::GET,
        rest_api_url(
            server_http_url,
            &["v1", "conversations", conversation_id, "members"],
        )?,
        user_id,
        None,
    ))?;
    if response
        .get("conversation_id")
        .and_then(serde_json::Value::as_str)
        != Some(conversation_id)
    {
        return Err("conversation directory response changed its conversation id".to_string());
    }
    let members = response
        .get("members")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .ok_or("conversation directory response is missing members")?;
    if members.is_empty() || members.len() > 1_024 {
        return Err("conversation directory member count is outside client limits".to_string());
    }

    let mut validated = Vec::with_capacity(members.len());
    let mut user_ids = std::collections::HashSet::new();
    let mut identities = std::collections::HashSet::new();
    for member in &members {
        let member_user_id = member
            .get("user_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("conversation directory member is missing user_id")?;
        let username = member
            .get("username")
            .and_then(serde_json::Value::as_str)
            .ok_or("conversation directory member is missing username")?;
        if member_user_id.is_empty()
            || username.is_empty()
            || !user_ids.insert(member_user_id.to_string())
        {
            return Err("conversation directory contains an invalid duplicate member".to_string());
        }
        let identity = decode_lower_hex_32(
            "conversation member identity_key",
            member
                .get("identity_key")
                .and_then(serde_json::Value::as_str)
                .ok_or("conversation directory member is missing identity_key")?,
        )?;
        let signing = decode_lower_hex_32(
            "conversation member signing_key",
            member
                .get("signing_key")
                .and_then(serde_json::Value::as_str)
                .ok_or("conversation directory member is missing signing_key")?,
        )?;
        if !identities.insert(identity) {
            return Err("conversation directory maps one identity to multiple users".to_string());
        }
        validated.push((member_user_id.to_string(), identity, signing));
    }

    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    let authenticated_user_id = client.authenticated_user_id()?;
    if user_id != authenticated_user_id {
        return Err("conversation directory user differs from authenticated session".into());
    }
    let our_identity = client.identity_key()?;
    let our_signing = client.signing_key()?;
    if !validated.iter().any(|(member_user_id, identity, signing)| {
        member_user_id == user_id && *identity == our_identity && *signing == our_signing
    }) {
        return Err("authenticated identity is absent from conversation directory".to_string());
    }
    for (member_user_id, identity, signing) in &validated {
        client.remember_user_identity(member_user_id, *identity);
        client.pin_peer_signing_key(*identity, *signing)?;
    }
    client.replace_authorized_conversation_senders(
        conversation_id,
        validated.iter().map(|(_, identity, _)| *identity),
    )?;
    require_session_still_unlocked(state)?;
    Ok(members)
}

#[tauri::command]
fn get_conversation_members(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    conversation_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    require_unlocked(&state)?;
    fetch_authorized_conversation_directory(&state, &server_http_url, &user_id, &conversation_id)
}

#[tauri::command]
fn get_group_members(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    group_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    require_unlocked(&state)?;
    let members =
        fetch_authorized_conversation_directory(&state, &server_http_url, &user_id, &group_id)?;

    // Also persist members locally
    let client = state.client.lock().map_err(|e| e.to_string())?;
    if let Some(db) = client.db() {
        for m in &members {
            if let (Some(ik_hex), Some(role)) = (m["identity_key"].as_str(), m["role"].as_i64()) {
                if let Ok(ik) = hex::decode(ik_hex) {
                    let _ = db.insert_group_member(&group_id, &ik, role as u8);
                }
            }
        }
    }

    require_session_still_unlocked(&state)?;
    Ok(members)
}

// ─── Servers / Channels / Roles / Invites ─────────────

/// Helper: parse a JSON error body and produce a String.
fn rest_err(body: &serde_json::Value, fallback: &str) -> String {
    body.get("error")
        .and_then(|v| v.as_str())
        .unwrap_or(fallback)
        .to_string()
}

fn validate_rest_url(url: &reqwest::Url) -> Result<(), String> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err("REST URLs must not contain userinfo or passwords".to_string());
    }
    if url.fragment().is_some() {
        return Err("REST URLs must not contain fragments".to_string());
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" => match url.host_str() {
            Some("localhost" | "127.0.0.1" | "::1" | "[::1]") => Ok(()),
            _ => Err("insecure http:// is allowed only for localhost/loopback".to_string()),
        },
        scheme => Err(format!(
            "unsupported REST URL scheme {scheme:?}; use https://"
        )),
    }
}

fn rest_origin(url: &reqwest::Url) -> Result<RestOrigin, String> {
    validate_rest_url(url)?;
    Ok(RestOrigin {
        scheme: url.scheme().to_ascii_lowercase(),
        host: url
            .host_str()
            .ok_or_else(|| "REST URL is missing a host".to_string())?
            .to_ascii_lowercase(),
        port: url
            .port_or_known_default()
            .ok_or_else(|| "REST URL has no effective port".to_string())?,
    })
}

fn require_authenticated_rest_origin(
    state: &AppState,
    url: &reqwest::Url,
) -> Result<RestBinding, String> {
    let requested = rest_origin(url)?;
    let bound = state
        .authenticated_rest_origin
        .lock()
        .map_err(|e| e.to_string())?
        .clone()
        .ok_or_else(|| "no REST origin is bound to an authenticated WebSocket".to_string())?;
    if requested != bound.origin {
        return Err("REST request origin differs from the authenticated WebSocket origin".into());
    }
    Ok(bound)
}

fn require_same_rest_binding(
    state: &AppState,
    url: &reqwest::Url,
    expected: &RestBinding,
) -> Result<(), String> {
    let current = require_authenticated_rest_origin(state, url)?;
    if &current != expected {
        return Err("authenticated REST session changed while the request was in flight".into());
    }
    Ok(())
}

fn validate_server_endpoint_pair(ws_raw: &str, rest_raw: &str) -> Result<(), String> {
    let ws = reqwest::Url::parse(ws_raw).map_err(|e| format!("invalid WebSocket URL: {e}"))?;
    let rest = reqwest::Url::parse(rest_raw).map_err(|e| format!("invalid REST URL: {e}"))?;
    validate_rest_url(&rest)?;
    if !ws.username().is_empty()
        || ws.password().is_some()
        || ws.query().is_some()
        || ws.fragment().is_some()
    {
        return Err("WebSocket URL must not contain userinfo, query or fragment".to_string());
    }
    if rest.query().is_some()
        || rest.fragment().is_some()
        || !rest.path().trim_matches('/').is_empty()
    {
        return Err("REST base URL must contain only scheme and authority".to_string());
    }
    let expected_rest_scheme = match ws.scheme() {
        "wss" => "https",
        "ws" => {
            if !matches!(
                ws.host_str(),
                Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
            ) {
                return Err("cleartext WebSocket is allowed only on loopback".to_string());
            }
            "http"
        }
        scheme => return Err(format!("unsupported WebSocket scheme {scheme:?}")),
    };
    if rest.scheme() != expected_rest_scheme {
        return Err("WebSocket and REST transport schemes do not match".to_string());
    }
    if ws.host_str().map(str::to_ascii_lowercase) != rest.host_str().map(str::to_ascii_lowercase)
        || ws.port_or_known_default() != rest.port_or_known_default()
    {
        return Err("WebSocket and REST endpoints must use the same host and port".to_string());
    }
    Ok(())
}

fn explicit_url_port(raw_url: &str) -> Result<Option<u16>, String> {
    let (_, remainder) = raw_url
        .split_once("://")
        .ok_or_else(|| "REST URL is missing a scheme separator".to_string())?;
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let port = if authority.starts_with('[') {
        let close = authority
            .find(']')
            .ok_or_else(|| "invalid bracketed IPv6 authority".to_string())?;
        let suffix = &authority[close + 1..];
        if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or_else(|| "invalid IPv6 authority suffix".to_string())?,
            )
        }
    } else {
        authority
            .rsplit_once(':')
            .and_then(|(_, port)| port.chars().all(|c| c.is_ascii_digit()).then_some(port))
    };
    port.map(|value| {
        value
            .parse::<u16>()
            .map_err(|_| "invalid REST URL port".to_string())
    })
    .transpose()
}

fn rest_authority(url: &reqwest::Url, raw_url: &str) -> Result<String, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "REST URL is missing a host".to_string())?;
    let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    let mut authority = if unbracketed.contains(':') {
        format!("[{}]", unbracketed.to_ascii_lowercase())
    } else {
        unbracketed.to_ascii_lowercase()
    };
    if let Some(port) = explicit_url_port(raw_url)? {
        authority.push(':');
        authority.push_str(&port.to_string());
    }
    Ok(authority)
}

fn rest_request_target(url: &reqwest::Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

fn rest_canonical(
    method: &reqwest::Method,
    authority: &str,
    request_target: &str,
    timestamp_ms: i64,
    body_hash_hex: &str,
) -> String {
    format!(
        "veil-rest-v1\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        authority,
        request_target,
        timestamp_ms,
        body_hash_hex
    )
}

fn next_rest_timestamp_ms() -> Result<i64, String> {
    let now: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch".to_string())?
        .as_millis()
        .try_into()
        .map_err(|_| "system clock exceeds signed millisecond range".to_string())?;
    let mut previous = LAST_REST_TIMESTAMP_MS.load(Ordering::Acquire);
    loop {
        let next = now.max(
            previous
                .checked_add(1)
                .ok_or_else(|| "REST timestamp allocator exhausted".to_string())?,
        );
        match LAST_REST_TIMESTAMP_MS.compare_exchange_weak(
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

async fn read_bounded_response(
    mut response: reqwest::Response,
) -> Result<(reqwest::StatusCode, Vec<u8>), String> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_REST_RESPONSE_BYTES as u64)
    {
        return Err(format!(
            "HTTP response exceeds {} bytes",
            MAX_REST_RESPONSE_BYTES
        ));
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(MAX_REST_RESPONSE_BYTES as u64) as usize,
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("read response body: {e}"))?
    {
        let new_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| "HTTP response length overflow".to_string())?;
        if new_len > MAX_REST_RESPONSE_BYTES {
            return Err(format!(
                "HTTP response exceeds {} bytes",
                MAX_REST_RESPONSE_BYTES
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

async fn rest_send_json(
    state: &AppState,
    method: reqwest::Method,
    url: String,
    user_id: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    require_unlocked(state)?;
    let parsed_url = reqwest::Url::parse(&url).map_err(|e| format!("invalid REST URL: {e}"))?;
    let rest_binding = require_authenticated_rest_origin(state, &parsed_url)?;
    let authenticated_user_id = {
        let client = state.client.lock().map_err(|e| e.to_string())?;
        client.authenticated_user_id()?.to_string()
    };
    if user_id != authenticated_user_id {
        return Err("REST user id does not match the authenticated WebSocket session".into());
    }

    // 1. Compute body bytes + hash up-front (so signing covers the wire body).
    let body_bytes: Vec<u8> = match body.as_ref() {
        Some(b) => serde_json::to_vec(b).map_err(|e| format!("serialize body: {e}"))?,
        None => Vec::new(),
    };
    let body_hash = Sha256::digest(&body_bytes);

    // 2. Canonical request context. Query parameters and authority are signed
    // so authenticated requests cannot be redirected across users/origins.
    let authority = rest_authority(&parsed_url, &url)?;
    let request_target = rest_request_target(&parsed_url);
    let ts_ms = next_rest_timestamp_ms()?;

    let canonical = rest_canonical(
        &method,
        &authority,
        &request_target,
        ts_ms,
        &hex::encode(body_hash),
    );

    // 3. Sign — short-lived client lock, dropped before async send.
    //    Signing is REQUIRED: the server's allowUnsigned bypass has been
    //    removed, so a missing signature would 401 every request anyway.
    let sig_b64 = {
        let client = state.client.lock().map_err(|e| e.to_string())?;
        client
            .sign_message(canonical.as_bytes())
            .map(|sig| base64::engine::general_purpose::STANDARD.encode(sig))
            .map_err(|e| format!("identity not initialized — cannot sign request: {e}"))?
    };

    // 4. Build & send request via shared HTTP client (connection pooling).
    let mut req = state
        .http
        .request(method, parsed_url.clone())
        .header(reqwest::header::HOST, &authority)
        .header("X-Veil-User", &authenticated_user_id)
        .header("X-Veil-Timestamp", ts_ms.to_string())
        .header("X-Veil-Signature", sig_b64);
    if !body_bytes.is_empty() {
        req = req
            .header("Content-Type", "application/json")
            .body(body_bytes);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("http request failed: {e}"))?;
    // Bound chunked and Content-Length responses alike before parsing JSON.
    let (status, body_bytes) = read_bounded_response(resp).await?;
    // The request was in flight without the client lock, so an explicit lock
    // or inactivity expiry may have happened while waiting for the network.
    // Do not return response data to a renderer that is no longer unlocked.
    require_unlocked(state)?;
    require_same_rest_binding(state, &parsed_url, &rest_binding)?;
    let json: serde_json::Value = if body_bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null)
    };
    require_session_still_unlocked(state)?;
    require_same_rest_binding(state, &parsed_url, &rest_binding)?;
    if !status.is_success() {
        let fallback = if json.is_null() {
            let snippet = String::from_utf8_lossy(&body_bytes);
            let truncated: String = snippet.chars().take(200).collect();
            format!("HTTP {}: {}", status.as_u16(), truncated)
        } else {
            format!("HTTP {}", status.as_u16())
        };
        require_session_still_unlocked(state)?;
        require_same_rest_binding(state, &parsed_url, &rest_binding)?;
        return Err(rest_err(&json, &fallback));
    }
    require_session_still_unlocked(state)?;
    require_same_rest_binding(state, &parsed_url, &rest_binding)?;
    Ok(json)
}

fn pause_server_sender_keys(state: &AppState, server_id: &str) -> Result<(), String> {
    state.offline_sync_ready.store(false, Ordering::Release);
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    let conversation_ids: Vec<String> = client
        .db()
        .map(|db| db.list_channels(server_id))
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .filter_map(|channel| channel.conversation_id)
        .collect();
    for conversation_id in conversation_ids {
        client.clear_authorized_conversation_senders(&conversation_id);
        client.mark_channel_conversation(&conversation_id);
        // The pending flag above is the security boundary; rotation errors are
        // returned so callers cannot report the role/member mutation as fully
        // reconciled while continuing on the old generation.
        client.rotate_sender_key(&conversation_id)?;
    }
    Ok(())
}

fn emit_membership_refresh_required(app: &AppHandle, server_id: &str) {
    let _ = app.emit(
        "veil://membership-refresh-required",
        serde_json::json!({ "serverId": server_id }),
    );
}

#[tauri::command]
fn create_server(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    name: String,
) -> Result<serde_json::Value, String> {
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        rest_api_url(&server_http_url, &["v1", "servers"])?,
        &user_id,
        Some(serde_json::json!({ "name": name })),
    ))
}

#[tauri::command]
fn list_servers(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let resp = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::GET,
        rest_api_url(&server_http_url, &["v1", "servers"])?,
        &user_id,
        None,
    ))?;
    Ok(resp["servers"].as_array().cloned().unwrap_or_default())
}

#[tauri::command]
fn get_server(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
) -> Result<serde_json::Value, String> {
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::GET,
        rest_api_url(&server_http_url, &["v1", "servers", &server_id])?,
        &user_id,
        None,
    ))
}

#[tauri::command]
fn update_server(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
    name: Option<String>,
    description: Option<String>,
    icon_url: Option<String>,
) -> Result<(), String> {
    let mut body = serde_json::Map::new();
    if let Some(v) = name {
        body.insert("name".into(), v.into());
    }
    if let Some(v) = description {
        body.insert("description".into(), v.into());
    }
    if let Some(v) = icon_url {
        body.insert("icon_url".into(), v.into());
    }
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::PATCH,
        rest_api_url(&server_http_url, &["v1", "servers", &server_id])?,
        &user_id,
        Some(serde_json::Value::Object(body)),
    ))?;
    Ok(())
}

#[tauri::command]
fn delete_server(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
) -> Result<(), String> {
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::DELETE,
        rest_api_url(&server_http_url, &["v1", "servers", &server_id])?,
        &user_id,
        None,
    ))?;
    Ok(())
}

#[tauri::command]
fn leave_server(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
) -> Result<(), String> {
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        rest_api_url(&server_http_url, &["v1", "servers", &server_id, "leave"])?,
        &user_id,
        None,
    ))?;
    Ok(())
}

#[tauri::command]
fn list_server_members(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let resp = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::GET,
        rest_api_url(&server_http_url, &["v1", "servers", &server_id, "members"])?,
        &user_id,
        None,
    ))?;
    let members = resp["members"].as_array().cloned().unwrap_or_default();
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    pin_directory_member_keys(&mut client, &members)?;
    require_session_still_unlocked(&state)?;
    Ok(members)
}

#[tauri::command]
fn kick_server_member(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
    target_user_id: String,
    reason: Option<String>,
) -> Result<(), String> {
    let body = reason.map(|r| serde_json::json!({ "reason": r }));
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::DELETE,
        rest_api_url(
            &server_http_url,
            &["v1", "servers", &server_id, "members", &target_user_id],
        )?,
        &user_id,
        body,
    ))?;
    Ok(())
}

#[tauri::command]
fn list_channels(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let resp = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::GET,
        rest_api_url(&server_http_url, &["v1", "servers", &server_id, "channels"])?,
        &user_id,
        None,
    ))?;
    Ok(resp["channels"].as_array().cloned().unwrap_or_default())
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri IPC fields intentionally stay explicit.
fn create_channel(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
    name: String,
    channel_type: i16,
    category_id: Option<String>,
    topic: Option<String>,
) -> Result<serde_json::Value, String> {
    let mut body = serde_json::json!({
        "name": name,
        "channel_type": channel_type,
    });
    if let Some(v) = category_id {
        body["category_id"] = v.into();
    }
    if let Some(v) = topic {
        body["topic"] = v.into();
    }
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        rest_api_url(&server_http_url, &["v1", "servers", &server_id, "channels"])?,
        &user_id,
        Some(body),
    ))
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri IPC fields intentionally stay explicit.
fn update_channel(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    channel_id: String,
    name: Option<String>,
    topic: Option<String>,
    nsfw: Option<bool>,
    slowmode_secs: Option<i32>,
) -> Result<(), String> {
    let mut body = serde_json::Map::new();
    if let Some(v) = name {
        body.insert("name".into(), v.into());
    }
    if let Some(v) = topic {
        body.insert("topic".into(), v.into());
    }
    if let Some(v) = nsfw {
        body.insert("nsfw".into(), v.into());
    }
    if let Some(v) = slowmode_secs {
        body.insert("slowmode_secs".into(), v.into());
    }
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::PATCH,
        rest_api_url(&server_http_url, &["v1", "channels", &channel_id])?,
        &user_id,
        Some(serde_json::Value::Object(body)),
    ))?;
    Ok(())
}

#[tauri::command]
fn delete_channel(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    channel_id: String,
) -> Result<(), String> {
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::DELETE,
        rest_api_url(&server_http_url, &["v1", "channels", &channel_id])?,
        &user_id,
        None,
    ))?;
    Ok(())
}

#[tauri::command]
fn reorder_channels(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
    items: Vec<serde_json::Value>,
) -> Result<(), String> {
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        rest_api_url(
            &server_http_url,
            &["v1", "servers", &server_id, "channels", "reorder"],
        )?,
        &user_id,
        Some(serde_json::json!({ "items": items })),
    ))?;
    Ok(())
}

#[tauri::command]
fn list_roles(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let resp = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::GET,
        rest_api_url(&server_http_url, &["v1", "servers", &server_id, "roles"])?,
        &user_id,
        None,
    ))?;
    Ok(resp["roles"].as_array().cloned().unwrap_or_default())
}

#[tauri::command]
fn create_role(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
    name: String,
    permissions: u64,
    color: Option<i32>,
) -> Result<serde_json::Value, String> {
    let mut body = serde_json::json!({
        "name": name,
        "permissions": permissions,
    });
    if let Some(c) = color {
        body["color"] = c.into();
    }
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        rest_api_url(&server_http_url, &["v1", "servers", &server_id, "roles"])?,
        &user_id,
        Some(body),
    ))
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri IPC fields intentionally stay explicit.
fn update_role(
    state: State<'_, AppState>,
    app: AppHandle,
    server_http_url: String,
    user_id: String,
    server_id: String,
    role_id: String,
    name: Option<String>,
    permissions: Option<u64>,
    color: Option<i32>,
) -> Result<(), String> {
    let mut body = serde_json::Map::new();
    if let Some(v) = name {
        body.insert("name".into(), v.into());
    }
    if let Some(v) = permissions {
        body.insert("permissions".into(), v.into());
    }
    if let Some(v) = color {
        body.insert("color".into(), v.into());
    }
    if let Err(error) = pause_server_sender_keys(&state, &server_id) {
        emit_membership_refresh_required(&app, &server_id);
        return Err(error);
    }
    let result = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::PATCH,
        rest_api_url(
            &server_http_url,
            &["v1", "servers", &server_id, "roles", &role_id],
        )?,
        &user_id,
        Some(serde_json::Value::Object(body)),
    ));
    emit_membership_refresh_required(&app, &server_id);
    result.map(|_| ())
}

#[tauri::command]
fn delete_role(
    state: State<'_, AppState>,
    app: AppHandle,
    server_http_url: String,
    user_id: String,
    server_id: String,
    role_id: String,
) -> Result<(), String> {
    if let Err(error) = pause_server_sender_keys(&state, &server_id) {
        emit_membership_refresh_required(&app, &server_id);
        return Err(error);
    }
    let result = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::DELETE,
        rest_api_url(
            &server_http_url,
            &["v1", "servers", &server_id, "roles", &role_id],
        )?,
        &user_id,
        None,
    ));
    emit_membership_refresh_required(&app, &server_id);
    result.map(|_| ())
}

#[tauri::command]
fn assign_role(
    state: State<'_, AppState>,
    app: AppHandle,
    server_http_url: String,
    user_id: String,
    server_id: String,
    target_user_id: String,
    role_id: String,
) -> Result<(), String> {
    if let Err(error) = pause_server_sender_keys(&state, &server_id) {
        emit_membership_refresh_required(&app, &server_id);
        return Err(error);
    }
    let result = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::PUT,
        rest_api_url(
            &server_http_url,
            &[
                "v1",
                "servers",
                &server_id,
                "members",
                &target_user_id,
                "roles",
                &role_id,
            ],
        )?,
        &user_id,
        None,
    ));
    emit_membership_refresh_required(&app, &server_id);
    result.map(|_| ())
}

#[tauri::command]
fn unassign_role(
    state: State<'_, AppState>,
    app: AppHandle,
    server_http_url: String,
    user_id: String,
    server_id: String,
    target_user_id: String,
    role_id: String,
) -> Result<(), String> {
    if let Err(error) = pause_server_sender_keys(&state, &server_id) {
        emit_membership_refresh_required(&app, &server_id);
        return Err(error);
    }
    let result = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::DELETE,
        rest_api_url(
            &server_http_url,
            &[
                "v1",
                "servers",
                &server_id,
                "members",
                &target_user_id,
                "roles",
                &role_id,
            ],
        )?,
        &user_id,
        None,
    ));
    emit_membership_refresh_required(&app, &server_id);
    result.map(|_| ())
}

#[tauri::command]
fn create_invite(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
    max_uses: i32,
    expires_in_secs: i64,
) -> Result<serde_json::Value, String> {
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        rest_api_url(&server_http_url, &["v1", "servers", &server_id, "invites"])?,
        &user_id,
        Some(serde_json::json!({
            "max_uses": max_uses,
            "expires_in_secs": expires_in_secs,
        })),
    ))
}

#[tauri::command]
fn list_invites(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let resp = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::GET,
        rest_api_url(&server_http_url, &["v1", "servers", &server_id, "invites"])?,
        &user_id,
        None,
    ))?;
    Ok(resp["invites"].as_array().cloned().unwrap_or_default())
}

#[tauri::command]
fn revoke_invite(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    code: String,
) -> Result<(), String> {
    validate_invite_code(&code)?;
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::DELETE,
        rest_api_url(&server_http_url, &["v1", "invites", &code])?,
        &user_id,
        None,
    ))?;
    Ok(())
}

#[tauri::command]
fn preview_invite(
    state: State<'_, AppState>,
    server_http_url: String,
    code: String,
) -> Result<serde_json::Value, String> {
    require_unlocked(&state)?;
    validate_invite_code(&code)?;
    let mut url = reqwest::Url::parse(server_http_url.trim_end_matches('/'))
        .map_err(|e| format!("invalid invite server URL: {e}"))?;
    let rest_binding = require_authenticated_rest_origin(&state, &url)?;
    if url.query().is_some() || url.fragment().is_some() || !url.path().trim_matches('/').is_empty()
    {
        return Err(
            "invite server URL must be an exact origin without a path or query".to_string(),
        );
    }
    url.path_segments_mut()
        .map_err(|()| "invite server URL cannot be a base URL".to_string())?
        .pop_if_empty()
        .extend(["v1", "invites", code.as_str()]);

    state.runtime.block_on(async {
        let resp = state
            .http
            .get(url.clone())
            .send()
            .await
            .map_err(|e| format!("preview: {e}"))?;
        let (status, body) = read_bounded_response(resp).await?;
        require_unlocked(&state)?;
        require_same_rest_binding(&state, &url, &rest_binding)?;
        let json: serde_json::Value = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body)
                .map_err(|e| format!("invalid invite preview response: {e}"))?
        };
        require_session_still_unlocked(&state)?;
        require_same_rest_binding(&state, &url, &rest_binding)?;
        if !status.is_success() {
            return Err(rest_err(&json, &format!("HTTP {}", status.as_u16())));
        }
        Ok(json)
    })
}

#[tauri::command]
fn use_invite(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    code: String,
) -> Result<serde_json::Value, String> {
    validate_invite_code(&code)?;
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        rest_api_url(&server_http_url, &["v1", "invites", &code, "use"])?,
        &user_id,
        None,
    ))
}

// ─── Server / Channel local cache (offline-first) ─────
//
// Source of truth is the gateway. The cache exists so the UI can render the
// server rail and channel tree instantly on app start, before REST returns.
// The frontend is expected to (a) call load_cached_* on mount,
// (b) call save_cached_* with the freshly-fetched payload on successful REST,
// (c) listen to veil://server-event / veil://channel-event and refetch.

fn cached_server_from_json(
    v: &serde_json::Value,
    position: i32,
) -> Option<veil_store::models::CachedServer> {
    Some(veil_store::models::CachedServer {
        id: v.get("id")?.as_str()?.to_string(),
        name: v.get("name")?.as_str()?.to_string(),
        description: v
            .get("description")
            .and_then(|x| x.as_str())
            .map(String::from),
        icon_url: v.get("icon_url").and_then(|x| x.as_str()).map(String::from),
        owner_id: v.get("owner_id")?.as_str()?.to_string(),
        position,
        created_at: v
            .get("created_at")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

fn cached_channel_from_json(
    server_id: &str,
    v: &serde_json::Value,
) -> Option<veil_store::models::CachedChannel> {
    Some(veil_store::models::CachedChannel {
        id: v.get("id")?.as_str()?.to_string(),
        server_id: server_id.to_string(),
        conversation_id: v
            .get("conversation_id")
            .and_then(|x| x.as_str())
            .map(String::from),
        name: v.get("name")?.as_str()?.to_string(),
        channel_type: v.get("channel_type").and_then(|x| x.as_i64()).unwrap_or(0) as i16,
        category_id: v
            .get("category_id")
            .and_then(|x| x.as_str())
            .map(String::from),
        position: v.get("position").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
        topic: v.get("topic").and_then(|x| x.as_str()).map(String::from),
        nsfw: v.get("nsfw").and_then(|x| x.as_bool()).unwrap_or(false),
        slowmode_secs: v.get("slowmode_secs").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
    })
}

fn cached_role_from_json(
    server_id: &str,
    v: &serde_json::Value,
) -> Option<veil_store::models::CachedRole> {
    Some(veil_store::models::CachedRole {
        id: v.get("id")?.as_str()?.to_string(),
        server_id: server_id.to_string(),
        name: v.get("name")?.as_str()?.to_string(),
        permissions: v.get("permissions").and_then(|x| x.as_u64()).unwrap_or(0),
        position: v.get("position").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
        color: v.get("color").and_then(|x| x.as_i64()).map(|c| c as i32),
        is_default: v
            .get("is_default")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
        hoist: v.get("hoist").and_then(|x| x.as_bool()).unwrap_or(false),
        mentionable: v
            .get("mentionable")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
    })
}

fn cached_member_from_json(
    server_id: &str,
    v: &serde_json::Value,
) -> Option<veil_store::models::CachedServerMember> {
    let role_ids = v
        .get("role_ids")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Some(veil_store::models::CachedServerMember {
        server_id: server_id.to_string(),
        user_id: v.get("user_id")?.as_str()?.to_string(),
        username: v
            .get("username")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        nickname: v.get("nickname").and_then(|x| x.as_str()).map(String::from),
        role_ids,
        joined_at: v
            .get("joined_at")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

#[tauri::command]
fn cache_load_servers(state: State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("db not initialized")?;
    let servers = db.list_servers()?;
    let result = servers
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "name": s.name,
                "description": s.description,
                "icon_url": s.icon_url,
                "owner_id": s.owner_id,
                "position": s.position,
                "created_at": s.created_at,
            })
        })
        .collect();
    require_session_still_unlocked(&state)?;
    Ok(result)
}

#[tauri::command]
fn cache_save_servers(
    state: State<'_, AppState>,
    servers: Vec<serde_json::Value>,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db_mut().ok_or("db not initialized")?;
    let cached: Vec<_> = servers
        .iter()
        .enumerate()
        .filter_map(|(i, v)| cached_server_from_json(v, i as i32))
        .collect();
    db.replace_servers(&cached)
}

#[tauri::command]
fn cache_delete_server(state: State<'_, AppState>, server_id: String) -> Result<(), String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("db not initialized")?;
    db.delete_server(&server_id)
}

#[tauri::command]
fn cache_load_channels(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("db not initialized")?;
    let chans = db.list_channels(&server_id)?;
    let result = chans
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "server_id": c.server_id,
                "conversation_id": c.conversation_id,
                "name": c.name,
                "channel_type": c.channel_type,
                "category_id": c.category_id,
                "position": c.position,
                "topic": c.topic,
                "nsfw": c.nsfw,
                "slowmode_secs": c.slowmode_secs,
            })
        })
        .collect();
    require_session_still_unlocked(&state)?;
    Ok(result)
}

#[tauri::command]
fn cache_save_channels(
    state: State<'_, AppState>,
    server_id: String,
    channels: Vec<serde_json::Value>,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db_mut().ok_or("db not initialized")?;
    let cached: Vec<_> = channels
        .iter()
        .filter_map(|v| cached_channel_from_json(&server_id, v))
        .collect();
    db.replace_channels(&server_id, &cached)
}

#[tauri::command]
fn cache_delete_channel(state: State<'_, AppState>, channel_id: String) -> Result<(), String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("db not initialized")?;
    db.delete_channel(&channel_id)
}

#[tauri::command]
fn cache_load_roles(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("db not initialized")?;
    let roles = db.list_roles(&server_id)?;
    let result = roles
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "server_id": r.server_id,
                "name": r.name,
                "permissions": r.permissions,
                "position": r.position,
                "color": r.color,
                "is_default": r.is_default,
                "hoist": r.hoist,
                "mentionable": r.mentionable,
            })
        })
        .collect();
    require_session_still_unlocked(&state)?;
    Ok(result)
}

#[tauri::command]
fn cache_save_roles(
    state: State<'_, AppState>,
    server_id: String,
    roles: Vec<serde_json::Value>,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db_mut().ok_or("db not initialized")?;
    let cached: Vec<_> = roles
        .iter()
        .filter_map(|v| cached_role_from_json(&server_id, v))
        .collect();
    db.replace_roles(&server_id, &cached)
}

#[tauri::command]
fn cache_load_server_members(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("db not initialized")?;
    let members = db.list_server_members(&server_id)?;
    let result = members
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "server_id": m.server_id,
                "user_id": m.user_id,
                "username": m.username,
                "nickname": m.nickname,
                "role_ids": m.role_ids,
                "joined_at": m.joined_at,
            })
        })
        .collect();
    require_session_still_unlocked(&state)?;
    Ok(result)
}

#[tauri::command]
fn cache_save_server_members(
    state: State<'_, AppState>,
    server_id: String,
    members: Vec<serde_json::Value>,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db_mut().ok_or("db not initialized")?;
    let cached: Vec<_> = members
        .iter()
        .filter_map(|v| cached_member_from_json(&server_id, v))
        .collect();
    db.replace_server_members(&server_id, &cached)
}

// ─── Sender Keys (Phase E) ────────────────────────────

/// Mark a conversation as a channel — outgoing messages are encrypted with
/// per-group sender keys and incoming messages are decrypted via SenderKeyStore.
#[tauri::command]
fn mark_channel_conversation(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    client.mark_channel_conversation(&conversation_id);
    Ok(())
}

/// Hydrate sender keys (outgoing + all incoming) for a channel from the local DB.
#[tauri::command]
fn hydrate_channel_sender_keys(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    client.hydrate_channel_sender_keys(&conversation_id)
}

/// Distribute our outgoing sender key to a list of channel members
/// (sealed envelope per recipient identity key, sent via SenderKeyDist envelope).
fn distribute_pinned_sender_key(
    state: &AppState,
    conversation_id: &str,
    recipients: impl IntoIterator<Item = (String, [u8; 32])>,
    force_rotate: bool,
) -> Result<u32, String> {
    require_unlocked(state)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    client.mark_channel_conversation(conversation_id);
    if force_rotate {
        client.rotate_sender_key(conversation_id)?;
    }
    if !client.begin_sender_key_distribution(conversation_id)? {
        return Ok(0);
    }

    let our_ik = client.identity_key()?;
    let mut seen = std::collections::HashSet::new();
    let mut sent = 0u32;
    let started = Instant::now();
    client.buffer_connection_events_during_sync();
    for (label, peer_ik) in recipients {
        if peer_ik == our_ik || !seen.insert(peer_ik) {
            continue;
        }
        if !client.is_currently_authorized_sender(conversation_id, &peer_ik) {
            client.mark_sender_key_distribution_failed(conversation_id);
            return Err("refusing to distribute a sender key outside the current roster".into());
        }
        if started.elapsed() >= std::time::Duration::from_secs(20)
            || !state.unlocked.load(Ordering::Acquire)
        {
            client.mark_sender_key_distribution_failed(conversation_id);
            return Err("sender-key distribution timed out or the application locked".to_string());
        }
        if let Err(error) = state
            .runtime
            .block_on(client.send_sender_key_to(conversation_id, &peer_ik))
        {
            client.mark_sender_key_distribution_failed(conversation_id);
            return Err(format!("sender-key delivery to {label} failed: {error}"));
        }
        sent += 1;
        if sent.is_multiple_of(128) {
            client.buffer_connection_events_during_sync();
        }
    }
    if sent == 0 {
        client.mark_sender_key_distributed(conversation_id)?;
    }
    Ok(sent)
}

#[tauri::command]
fn distribute_sender_key(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    conversation_id: String,
) -> Result<u32, String> {
    require_unlocked(&state)?;
    // The renderer never chooses recipients. Fetch the signed, permission-
    // filtered directory for this exact conversation and pin it first.
    let members = fetch_authorized_conversation_directory(
        &state,
        &server_http_url,
        &user_id,
        &conversation_id,
    )?;
    let mut recipients = Vec::new();
    for member in &members {
        let hex_key = member
            .get("identity_key")
            .and_then(serde_json::Value::as_str)
            .ok_or("authorized directory member is missing identity_key")?;
        let peer_ik = decode_lower_hex_32("authorized member identity_key", hex_key)?;
        recipients.push((hex_key.to_string(), peer_ik));
    }
    distribute_pinned_sender_key(&state, &conversation_id, recipients, false)
}

/// Force-rotate our outgoing sender key for a channel (e.g. on member kick).
#[tauri::command]
fn rotate_sender_key(state: State<'_, AppState>, conversation_id: String) -> Result<(), String> {
    require_unlocked(&state)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    client.rotate_sender_key(&conversation_id)
}

// ─── Phase 6: per-conversation crypto mode ───────────

// ─── Friends & Presence ───────────────────────────────

#[tauri::command]
fn send_friend_request(
    state: State<'_, AppState>,
    target_user_id: String,
    message: Option<String>,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    state
        .runtime
        .block_on(client.send_friend_request(&target_user_id, message.as_deref()))
}

#[tauri::command]
fn respond_friend_request(
    state: State<'_, AppState>,
    request_id: String,
    accept: bool,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    state
        .runtime
        .block_on(client.respond_friend_request(&request_id, accept))
}

#[tauri::command]
fn remove_friend(state: State<'_, AppState>, user_id: String) -> Result<(), String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    state.runtime.block_on(client.remove_friend(&user_id))
}

#[tauri::command]
fn request_friend_list(state: State<'_, AppState>) -> Result<(), String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    state.runtime.block_on(client.request_friend_list())
}

#[tauri::command]
fn send_presence(
    state: State<'_, AppState>,
    status: i32,
    status_text: Option<String>,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    state
        .runtime
        .block_on(client.send_presence(status, status_text.as_deref()))
}

/// Search for a user by username via the server REST API.
#[tauri::command]
fn search_user(
    state: State<'_, AppState>,
    server_http_url: String,
    username: String,
) -> Result<serde_json::Value, String> {
    require_unlocked(&state)?;
    let user_id = state
        .client
        .lock()
        .map_err(|e| e.to_string())?
        .authenticated_user_id()?;
    let mut url = reqwest::Url::parse(&rest_api_url(&server_http_url, &["v1", "users", "search"])?)
        .map_err(|e| format!("invalid server URL: {e}"))?;
    url.query_pairs_mut().append_pair("username", &username);

    let result = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::GET,
        url.to_string(),
        &user_id,
        None,
    ))?;

    let peer_user_id = result["user_id"]
        .as_str()
        .ok_or_else(|| "directory response missing user_id".to_string())?;
    let peer_identity_key: [u8; 32] = hex::decode(
        result["identity_key"]
            .as_str()
            .ok_or_else(|| "directory response missing identity_key".to_string())?,
    )
    .map_err(|e| format!("invalid directory identity_key: {e}"))?
    .try_into()
    .map_err(|v: Vec<u8>| format!("directory identity_key must be 32 bytes, got {}", v.len()))?;
    state
        .client
        .lock()
        .map_err(|e| e.to_string())?
        .remember_user_identity(peer_user_id, peer_identity_key);
    require_session_still_unlocked(&state)?;
    Ok(result)
}

// ─── Local search ─────────────────────────────────────

#[derive(serde::Serialize)]
struct SearchHitDto {
    id: String,
    #[serde(rename = "conversationId")]
    conversation_id: String,
    sender: String,
    body: String,
    ts: i64,
    score: f32,
}

impl From<SearchHit> for SearchHitDto {
    fn from(h: SearchHit) -> Self {
        Self {
            id: h.id,
            conversation_id: h.conversation_id,
            sender: h.sender,
            body: h.body,
            ts: h.ts,
            score: h.score,
        }
    }
}

#[tauri::command]
fn search_messages(
    state: State<'_, AppState>,
    query: String,
    conversation_id: Option<String>,
    limit: Option<usize>,
) -> Result<Vec<SearchHitDto>, String> {
    require_unlocked(&state)?;
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.len() > 1_024 {
        return Err("search query exceeds 1024 UTF-8 bytes".to_string());
    }
    if conversation_id
        .as_deref()
        .is_some_and(|id| id.is_empty() || id.len() > 256)
    {
        return Err("search conversation id is invalid".to_string());
    }
    let limit = limit.unwrap_or(50).clamp(1, 500);
    let hits = state
        .indexer
        .search(trimmed, conversation_id.as_deref(), limit)
        .map_err(|e| e.to_string())?;
    let result = hits.into_iter().map(SearchHitDto::from).collect();
    require_session_still_unlocked(&state)?;
    Ok(result)
}

#[tauri::command]
fn clear_search_index(state: State<'_, AppState>) -> Result<(), String> {
    require_unlocked(&state)?;
    state.indexer.clear().map_err(|e| e.to_string())
}

#[tauri::command]
fn rebuild_search_index(state: State<'_, AppState>) -> Result<usize, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    require_unlocked(&state)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("database not initialized")?;
    state.indexer.clear().map_err(|e| e.to_string())?;
    let convs = db.get_conversations()?;
    let mut indexed = 0usize;
    for conv in convs {
        if let Err(error) = require_session_still_unlocked(&state) {
            let _ = state.indexer.clear();
            return Err(error);
        }
        let msgs = db.get_messages(&conv.id, 100_000)?;
        for m in msgs {
            if indexed.is_multiple_of(64) {
                if let Err(error) = require_session_still_unlocked(&state) {
                    let _ = state.indexer.clear();
                    return Err(error);
                }
            }
            let ts = m.server_timestamp.unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0)
            });
            if state
                .indexer
                .index_message(
                    &m.id,
                    &conv.id,
                    &hex::encode(&m.sender_key),
                    &m.plaintext,
                    ts,
                )
                .is_ok()
            {
                indexed += 1;
            }
        }
    }
    require_session_still_unlocked(&state)?;
    Ok(indexed)
}

/// Rebuild the process-memory-only search index after each unlock.
#[tauri::command]
fn ensure_search_backfill(state: State<'_, AppState>) -> Result<usize, String> {
    require_unlocked(&state)?;
    rebuild_search_index(state)
}

// ─── App ──────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // A second instance tried to start — focus the existing window instead.
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
                let _ = win.unminimize();
            }
        }))
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| PathBuf::from("."));
            std::fs::create_dir_all(&data_dir).ok();

            // Remove the legacy persistent Tantivy index because it contained
            // decrypted message bodies outside SQLCipher. Search is now kept
            // only in process memory and rebuilt after each unlock.
            let legacy_index_dir = data_dir.join("search").join("v1");
            if legacy_index_dir.exists() {
                std::fs::remove_dir_all(&legacy_index_dir)?;
            }
            let indexer =
                Arc::new(Indexer::in_memory().expect("failed to create in-memory search index"));
            let pin_configured = has_pin_material().map_err(std::io::Error::other)?;

            app.manage(AppState {
                client: Mutex::new(VeilClient::new()),
                session_transition: Mutex::new(()),
                connect_transition: Mutex::new(()),
                authenticated_rest_origin: Mutex::new(None),
                rest_binding_generation: AtomicU64::new(0),
                unlocked: AtomicBool::new(!pin_configured),
                event_poller_started: AtomicBool::new(false),
                offline_sync_ready: AtomicBool::new(false),
                lock_event_pending: AtomicBool::new(false),
                pin_throttle: Mutex::new(PinThrottle::default()),
                runtime: tokio::runtime::Runtime::new().expect("failed to create tokio runtime"),
                last_activity: Mutex::new(Instant::now()),
                db_dir: data_dir,
                http: reqwest::Client::builder()
                    // Redirects could escape the validated HTTPS/loopback
                    // origin and leak signed headers or turn the client into
                    // an SSRF primitive. Callers must opt into a new URL and
                    // sign that authority explicitly instead.
                    .redirect(reqwest::redirect::Policy::none())
                    .pool_idle_timeout(std::time::Duration::from_secs(30))
                    .pool_max_idle_per_host(8)
                    .timeout(std::time::Duration::from_secs(20))
                    .build()
                    .expect("reqwest client"),
                indexer,
            });
            let watchdog_app = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let state = watchdog_app.state::<AppState>();
                if let Ok(_transition) = state.session_transition.lock() {
                    if consume_pending_lock_event(&state.lock_event_pending, &state.unlocked) {
                        let _ = watchdog_app.emit("veil://locked", serde_json::json!({}));
                    }
                }
                if !state.unlocked.load(Ordering::Acquire) {
                    continue;
                }
                let expired = has_pin_material().unwrap_or(true)
                    && state
                        .last_activity
                        .lock()
                        .map(|last| last.elapsed().as_secs() >= get_auto_lock_seconds())
                        .unwrap_or(true);
                if expired && reset_sensitive_state(&state).is_ok() {
                    if let Ok(_transition) = state.session_transition.lock() {
                        if !state.unlocked.load(Ordering::Acquire) {
                            state.lock_event_pending.store(false, Ordering::Release);
                            let _ = watchdog_app.emit("veil://locked", serde_json::json!({}));
                        }
                    }
                }
            });
            // System tray with menu
            let show = MenuItem::with_id(app, "show", "Show Veil", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;

            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().cloned().unwrap())
                .tooltip("Veil — Encrypted Messenger")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::DoubleClick { .. } = event {
                        let app = tray.app_handle();
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                })
                .build(app)?;

            // Minimize to tray on close (instead of quitting)
            if let Some(window) = app.get_webview_window("main") {
                let w = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let app_handle = w.app_handle().clone();
                        let state = app_handle.state::<AppState>();
                        match state.session_transition.lock() {
                            Ok(_transition) => {
                                // PIN changes use this same transition, so the
                                // policy check and possible lock are atomic
                                // with clear_pin/set_pin.
                                match has_pin_material() {
                                    Ok(true) => {
                                        // Clear native plaintext/key state and
                                        // renderer plaintext in one ordered
                                        // transition before hiding to tray.
                                        let reset = reset_sensitive_state_locked(&state);
                                        state.lock_event_pending.store(false, Ordering::Release);
                                        let _ =
                                            app_handle.emit("veil://locked", serde_json::json!({}));
                                        if let Err(error) = reset {
                                            let _ = app_handle.emit(
                                                "veil://error",
                                                serde_json::json!({
                                                    "code": 5001,
                                                    "message": format!(
                                                        "close-to-tray cleanup failed: {error}"
                                                    ),
                                                }),
                                            );
                                        }
                                        let _ = w.hide();
                                    }
                                    Ok(false) => {
                                        let _ = w.hide();
                                    }
                                    Err(error) => {
                                        // A keychain failure means we cannot
                                        // know that hiding an unlocked window
                                        // is safe.
                                        let _ = app_handle.emit(
                                            "veil://error",
                                            serde_json::json!({
                                                "code": 5001,
                                                "message": format!(
                                                    "could not determine close-to-tray lock policy: {error}"
                                                ),
                                            }),
                                        );
                                    }
                                }
                            }
                            Err(error) => {
                                // Keep the window visible when the security
                                // transition cannot be made.
                                let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 5001,
                                        "message": format!(
                                            "close-to-tray lock failed: {error}"
                                        ),
                                    }),
                                );
                            }
                        };
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            generate_mnemonic,
            validate_mnemonic_cmd,
            init_identity,
            get_identity_key,
            fingerprint_peer,
            store_seed,
            has_stored_identity,
            set_pin,
            verify_pin,
            has_pin,
            clear_pin,
            reveal_recovery_phrase,
            lock_app,
            touch_activity,
            idle_seconds,
            get_auto_lock_seconds,
            set_auto_lock_seconds,
            init_from_seed,
            get_conversations,
            get_messages,
            upload_prekeys,
            establish_session,
            connect_to_server,
            send_message,
            edit_message,
            delete_message,
            send_typing,
            toggle_reaction,
            get_reactions,
            create_dm,
            is_connected,
            search_messages,
            clear_search_index,
            rebuild_search_index,
            ensure_search_backfill,
            create_group,
            add_group_member,
            remove_group_member,
            get_group_members,
            get_conversation_members,
            send_friend_request,
            respond_friend_request,
            remove_friend,
            request_friend_list,
            send_presence,
            search_user,
            create_server,
            list_servers,
            get_server,
            update_server,
            delete_server,
            leave_server,
            list_server_members,
            kick_server_member,
            list_channels,
            create_channel,
            update_channel,
            reorder_channels,
            delete_channel,
            list_roles,
            create_role,
            update_role,
            delete_role,
            assign_role,
            unassign_role,
            create_invite,
            list_invites,
            revoke_invite,
            preview_invite,
            use_invite,
            cache_load_servers,
            cache_save_servers,
            cache_delete_server,
            cache_load_channels,
            cache_save_channels,
            cache_delete_channel,
            cache_load_roles,
            cache_save_roles,
            cache_load_server_members,
            cache_save_server_members,
            mark_channel_conversation,
            hydrate_channel_sender_keys,
            distribute_sender_key,
            rotate_sender_key,
        ])
        .run(tauri::generate_context!())
        .expect("error while running veil");
}

#[cfg(test)]
mod e2ee_rest_tests {
    use super::{
        consume_pending_lock_event, offline_sync_url, parse_prekey_bundle,
        publish_unlocked_session, rest_api_url, rest_authority, rest_canonical, rest_origin,
        rest_request_target, validate_next_cursor, validate_rest_url,
        validate_server_endpoint_pair,
    };
    use base64::Engine;

    #[test]
    fn prekey_bundle_requires_base64_lengths_and_requested_identity() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let expected_identity = [1u8; 32];
        let value = serde_json::json!({
            "identity_key": b64.encode(expected_identity),
            "signing_key": b64.encode([2u8; 32]),
            "signed_prekey": b64.encode([3u8; 32]),
            "signed_prekey_signature": b64.encode([4u8; 64]),
            "signed_prekey_id": 7,
            "one_time_prekey": b64.encode([5u8; 32]),
            "one_time_prekey_id": 9,
        });

        let bundle = parse_prekey_bundle(value.clone(), &expected_identity).unwrap();
        assert_eq!(bundle.signed_prekey_id, 7);
        assert_eq!(bundle.one_time_prekey_id, Some(9));
        assert!(parse_prekey_bundle(value, &[8u8; 32]).is_err());
    }

    #[test]
    fn rest_transport_rejects_remote_cleartext() {
        assert!(
            validate_rest_url(&reqwest::Url::parse("https://chat.example.test/v1").unwrap())
                .is_ok()
        );
        assert!(
            validate_rest_url(&reqwest::Url::parse("http://127.0.0.1:9080/v1").unwrap()).is_ok()
        );
        assert!(
            validate_rest_url(&reqwest::Url::parse("http://chat.example.test/v1").unwrap())
                .is_err()
        );
        assert!(
            validate_rest_url(&reqwest::Url::parse("https://user@example.test/v1").unwrap())
                .is_err()
        );
        assert!(validate_rest_url(
            &reqwest::Url::parse("https://example.test/v1#fragment").unwrap()
        )
        .is_err());
    }

    #[test]
    fn websocket_and_rest_endpoints_must_share_a_secure_origin() {
        assert!(validate_server_endpoint_pair(
            "wss://chat.example.test:9443/ws",
            "https://chat.example.test:9443"
        )
        .is_ok());
        assert!(
            validate_server_endpoint_pair("ws://127.0.0.1:9080/ws", "http://127.0.0.1:9080/")
                .is_ok()
        );

        assert!(validate_server_endpoint_pair(
            "wss://chat.example.test/ws",
            "https://evil.example.test"
        )
        .is_err());
        assert!(validate_server_endpoint_pair(
            "wss://chat.example.test:9443/ws",
            "https://chat.example.test:8443"
        )
        .is_err());
        assert!(validate_server_endpoint_pair(
            "ws://chat.example.test/ws",
            "http://chat.example.test"
        )
        .is_err());
        assert!(validate_server_endpoint_pair(
            "wss://chat.example.test/ws?token=secret",
            "https://chat.example.test"
        )
        .is_err());
        assert!(validate_server_endpoint_pair(
            "wss://chat.example.test/ws",
            "https://chat.example.test/api"
        )
        .is_err());
    }

    #[test]
    fn signed_rest_routes_reject_noncanonical_untrusted_segments() {
        let url = rest_api_url(
            "https://chat.example.test",
            &["v1", "servers", "550e8400-e29b-41d4-a716-446655440000"],
        )
        .unwrap();
        let parsed = reqwest::Url::parse(&url).unwrap();
        assert_eq!(
            parsed.path(),
            "/v1/servers/550e8400-e29b-41d4-a716-446655440000"
        );
        assert!(rest_api_url(
            "https://chat.example.test",
            &["v1", "servers", "id/with?delimiters#fragment"]
        )
        .is_err());
        assert!(rest_api_url("https://chat.example.test", &["v1", ".."]).is_err());
        assert!(rest_api_url("https://chat.example.test/base", &["v1"]).is_err());

        let bound =
            rest_origin(&reqwest::Url::parse("https://chat.example.test").unwrap()).unwrap();
        let same =
            rest_origin(&reqwest::Url::parse("https://CHAT.example.test:443").unwrap()).unwrap();
        let other = rest_origin(&reqwest::Url::parse("https://api.example.test").unwrap()).unwrap();
        assert_eq!(bound, same);
        assert_ne!(bound, other);
    }

    #[test]
    fn successful_unlock_suppresses_a_stale_pending_lock_event() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let pending = AtomicBool::new(true);
        let unlocked = AtomicBool::new(false);
        // All identity-init/unlock paths call this while holding the same
        // transition mutex as the watchdog's consume/check/emit operation.
        publish_unlocked_session(&pending, &unlocked);
        assert!(!consume_pending_lock_event(&pending, &unlocked));

        pending.store(true, Ordering::Release);
        unlocked.store(false, Ordering::Release);
        assert!(consume_pending_lock_event(&pending, &unlocked));
    }

    #[test]
    fn rest_canonical_matches_server_vector_and_signs_query() {
        let raw = "https://Example.COM:0443/v1/prekeys?device=7";
        let url = reqwest::Url::parse(raw).unwrap();
        let authority = rest_authority(&url, raw).unwrap();
        let target = rest_request_target(&url);
        let canonical = rest_canonical(
            &reqwest::Method::POST,
            &authority,
            &target,
            1_700_000_000_123,
            "5041bf1f713df204784353e82f6a4a535931cb64f1f4b4a5aeaffcb720918b22",
        );
        assert_eq!(authority, "example.com:443");
        assert_eq!(target, "/v1/prekeys?device=7");
        assert_eq!(
            canonical,
            "veil-rest-v1\nPOST\nexample.com:443\n/v1/prekeys?device=7\n1700000000123\n5041bf1f713df204784353e82f6a4a535931cb64f1f4b4a5aeaffcb720918b22"
        );
    }

    #[test]
    fn offline_sync_cursor_is_opaque_and_conversation_path_is_escaped() {
        let url = offline_sync_url(
            "https://chat.example.test",
            &["v1", "messages", "550e8400-e29b-41d4-a716-446655440000"],
            Some("opaque+/=_cursor"),
        )
        .unwrap();
        let parsed = reqwest::Url::parse(&url).unwrap();
        assert_eq!(
            parsed.path(),
            "/v1/messages/550e8400-e29b-41d4-a716-446655440000"
        );
        let query: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(query.get("limit").map(String::as_str), Some("100"));
        assert_eq!(
            query.get("cursor").map(String::as_str),
            Some("opaque+/=_cursor")
        );
        assert!(offline_sync_url(
            "https://chat.example.test",
            &["v1", "messages", "conversation/escape"],
            None,
        )
        .is_err());
    }

    #[test]
    fn offline_sync_rejects_non_progressing_keyset_pages() {
        assert!(validate_next_cursor(Some("same"), Some("same"), 1).is_err());
        assert!(validate_next_cursor(None, Some("next"), 0).is_err());
        assert!(validate_next_cursor(Some("old"), Some("next"), 1).is_ok());
        assert!(validate_next_cursor(Some("last"), None, 0).is_ok());
    }
}
