use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use subtle::ConstantTimeEq;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_notification::NotificationExt;
use veil_client::api::{
    DeviceBindingCandidateV1, DeviceRosterCandidateV1, DeviceRosterEntryV1,
    MessageSecurityContextV1, OfflineSenderKeyRefresh, SenderKeyMessageSecurityContextV1,
    VeilClient,
};
use veil_client::connection::ConnectionEvent;
use veil_search::{Indexer, SearchHit};
use veil_store::keychain;
use veil_store::models::{
    AccountSnapshot, AccountSnapshotSource, LocalIdentityVerification, NetworkProfile,
    ProfileLocator,
};
use zeroize::{Zeroize, Zeroizing};

mod appearance;
mod pin_throttle;
use pin_throttle::PinThrottle;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ConversationCryptoDiagnostic {
    conversation_id: String,
    code: String,
    detail: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkProfileResponse {
    user_id: String,
    username: String,
    display_name: Option<String>,
    about: String,
    profile_version: u64,
    profile_updated_at: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkProfileView {
    canonical_server_origin: String,
    user_id: String,
    identity_key: String,
    username: String,
    display_name: Option<String>,
    about: String,
    profile_version: String,
    profile_updated_at: String,
    observed_at: String,
    proof_state: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityVerificationView {
    canonical_server_origin: String,
    user_id: String,
    identity_key: String,
    fingerprint_hex: String,
    fingerprint_emoji: String,
    proof_state: String,
}

#[derive(Default)]
struct ConversationSyncIsolation {
    blocked: std::collections::BTreeMap<String, ConversationCryptoDiagnostic>,
}

impl ConversationSyncIsolation {
    fn block(&mut self, conversation_id: &str, code: &str, detail: &str) {
        self.blocked
            .entry(conversation_id.to_string())
            .or_insert_with(|| ConversationCryptoDiagnostic {
                conversation_id: conversation_id.to_string(),
                code: code.to_string(),
                detail: bounded_diagnostic_detail(detail),
            });
    }

    fn is_blocked(&self, conversation_id: &str) -> bool {
        self.blocked.contains_key(conversation_id)
    }

    fn into_diagnostics(self) -> Vec<ConversationCryptoDiagnostic> {
        self.blocked.into_values().collect()
    }
}

struct AppState {
    client: Mutex<VeilClient>,
    /// Serializes lock/unlock transitions with native event publication. This
    /// prevents a stale pending lock event from firing after a successful PIN
    /// unlock and orders live events before the lock that destroys their keys.
    session_transition: Mutex<()>,
    /// Monotonic native session identity. Commands that cross an async boundary
    /// must reject work captured before any intervening lock or unlock.
    session_epoch: AtomicU64,
    /// Prevent overlapping reconnect workflows from rebinding the signed REST
    /// authority underneath an authenticated backlog sync.
    connect_transition: Mutex<()>,
    /// Exact REST origin paired with the currently authenticated WebSocket.
    /// Every signed REST request is checked against this native binding.
    authenticated_rest_origin: Mutex<Option<RestBinding>>,
    /// Exact native binding explicitly confirmed by the renderer after it has
    /// published the matching UI namespace and prekeys. Renderer-initiated
    /// live mutations are forbidden until this equals the transport binding.
    renderer_confirmed_rest_binding: Mutex<Option<RestBinding>>,
    rest_binding_generation: AtomicU64,
    /// Native security boundary. Sensitive commands also require an
    /// initialized client, but this flag prevents reopening the keychain/DB
    /// through IPC while the PIN screen is active.
    unlocked: AtomicBool,
    /// Process-local PIN policy loaded from secure storage at setup and
    /// changed only by serialized, durable PIN mutations.
    pin_configured: AtomicBool,
    /// A single app-lifetime dispatcher follows whichever authenticated
    /// connection is currently installed in `client`. Reconnects must not
    /// create competing consumers for the same event queue.
    event_poller_started: AtomicBool,
    /// Live WebSocket events must not overtake the authenticated REST backlog:
    /// both Double Ratchet and Sender Keys require strict message ordering.
    /// A failed sync leaves the dispatcher paused until a clean reconnect.
    offline_sync_ready: AtomicBool,
    /// Conversation-scoped crypto quarantine. A missing historical generation
    /// or an unready device roster must not turn one bad group into a global DM
    /// outage, but every native send/live-mutation path still fails closed for
    /// the affected conversation until a complete authenticated reconnect.
    unavailable_conversations:
        Mutex<std::collections::HashMap<String, ConversationCryptoDiagnostic>>,
    /// Expiry discovered on an IPC path still has to clear renderer plaintext;
    /// the watchdog consumes this flag and emits the native lock event.
    lock_event_pending: AtomicBool,
    /// Native, process-local brute-force and concurrency guard shared by
    /// every command that verifies the application PIN.
    pin_throttle: Mutex<PinThrottle>,
    runtime: tokio::runtime::Runtime,
    /// Validated auto-lock policy loaded once from secure storage. Runtime
    /// expiry checks must never perform blocking keychain I/O.
    auto_lock_seconds: AtomicU64,
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
const PROJECT_REPOSITORY_URL: &str = "https://github.com/NaveLIL/veil";
const LEGACY_MIN_PIN_LEN: usize = 4;
const MAX_PIN_LEN: usize = 12;

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

/// Authenticated namespace published to the renderer only after the complete
/// WS-authenticated REST backlog has passed the origin and continuity gates.
/// The generation is serialized as text so JavaScript can never lose u64
/// precision and accidentally treat two native bindings as the same session.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatedSessionScope {
    user_id: String,
    canonical_server_origin: String,
    binding_generation: String,
}

fn validate_authenticated_binding_commit(
    session_unlocked: bool,
    expected_user_id: &str,
    current_user_id: &str,
    expected_identity_key: &[u8; 32],
    current_identity_key: &[u8; 32],
    expected_signing_key: &[u8; 32],
    current_signing_key: &[u8; 32],
) -> Result<(), String> {
    if !session_unlocked {
        return Err("application locked before durable account binding".to_string());
    }
    if current_user_id != expected_user_id
        || current_identity_key != expected_identity_key
        || current_signing_key != expected_signing_key
    {
        return Err("authenticated client changed before durable account binding".to_string());
    }
    Ok(())
}

fn authenticated_event_payload<T: serde::Serialize>(
    binding: &RestBinding,
    event: &str,
    payload: T,
) -> Result<serde_json::Value, String> {
    let mut payload = serde_json::to_value(payload)
        .map_err(|error| format!("serialize authenticated event {event}: {error}"))?;
    let object = payload
        .as_object_mut()
        .ok_or_else(|| format!("authenticated event {event} payload must be an object"))?;
    // Insert after serializing the event body so a future payload field can
    // never override the native scope which authorized this exact event.
    object.insert(
        "serverScopeOrigin".to_string(),
        binding.origin.canonical_server_origin().into(),
    );
    object.insert(
        "serverBindingGeneration".to_string(),
        binding.generation.to_string().into(),
    );
    Ok(payload)
}

fn invalidate_disconnected_binding(
    current: &mut Option<RestBinding>,
    disconnected: &RestBinding,
) -> bool {
    if current.as_ref() != Some(disconnected) {
        return false;
    }
    *current = None;
    true
}

/// App handle bound to the exact authenticated generation which produced an
/// event. It deliberately does not look up the current binding during `emit`:
/// a delayed old-socket event must keep its old generation tag and can never
/// masquerade as an event from a replacement connection.
#[derive(Clone)]
struct AuthenticatedEventAppHandle {
    app: AppHandle,
    binding: RestBinding,
}

impl AuthenticatedEventAppHandle {
    fn new(app: AppHandle, binding: RestBinding) -> Self {
        Self { app, binding }
    }

    fn for_current(app: &AppHandle) -> Result<Self, String> {
        let state = app.state::<AppState>();
        Ok(Self::new(app.clone(), authenticated_rest_binding(&state)?))
    }

    fn raw_app(&self) -> &AppHandle {
        &self.app
    }
}

impl AuthenticatedEventAppHandle {
    fn emit<T: serde::Serialize>(&self, event: &str, payload: T) -> Result<(), String> {
        let payload = authenticated_event_payload(&self.binding, event, payload)?;
        self.app
            .emit(event, payload)
            .map_err(|error| format!("emit authenticated event {event}: {error}"))
    }
}

impl RestOrigin {
    fn canonical_server_origin(&self) -> String {
        let host = self.host.trim_start_matches('[').trim_end_matches(']');
        let authority = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        format!("{}://{}:{}", self.scheme, authority, self.port)
    }
}

fn identity_observed_at() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
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
    publish_unlocked_session(
        &state.lock_event_pending,
        &state.unlocked,
        &state.session_epoch,
    );
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

#[tauri::command]
fn open_project_repository() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        std::process::Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", PROJECT_REPOSITORY_URL])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| format!("open project repository: {e}"))?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(PROJECT_REPOSITORY_URL)
            .spawn()
            .map_err(|e| format!("open project repository: {e}"))?;
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(PROJECT_REPOSITORY_URL)
            .spawn()
            .map_err(|e| format!("open project repository: {e}"))?;
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err("opening the project repository is unsupported on this platform".to_string())
}

fn configured_auto_lock_seconds(state: &AppState) -> u64 {
    state.auto_lock_seconds.load(Ordering::Acquire)
}

fn configured_pin(state: &AppState) -> bool {
    state.pin_configured.load(Ordering::Acquire)
}

fn inactivity_expired(state: &AppState) -> Result<bool, String> {
    if !configured_pin(state) {
        return Ok(false);
    }
    Ok(state
        .last_activity
        .lock()
        .map_err(|e| e.to_string())?
        .elapsed()
        .as_secs()
        >= configured_auto_lock_seconds(state))
}

/// Validate the native security boundary while the caller holds
/// `session_transition`. Expiry and sensitive-state reset are one transition,
/// so a concurrent policy update or activity touch cannot land between them.
fn require_unlocked_locked(state: &AppState) -> Result<(), String> {
    if !state.unlocked.load(Ordering::SeqCst) {
        return Err("application is locked".into());
    }
    if inactivity_expired(state)? {
        reset_sensitive_state_locked(state)?;
        return Err("application auto-locked due to inactivity".into());
    }
    Ok(())
}

fn require_unlocked(state: &AppState) -> Result<(), String> {
    let _transition = state.session_transition.lock().map_err(|e| e.to_string())?;
    require_unlocked_locked(state)
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

/// Re-check the live-send barrier after acquiring `state.client`. This variant
/// must stay non-blocking: `require_unlocked` may reset the client on idle
/// expiry and therefore cannot be called while the client mutex is held.
fn require_live_transport_still_ready(state: &AppState) -> Result<(), String> {
    require_session_still_unlocked(state)?;
    if state.offline_sync_ready.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err("authenticated directory refresh started while preparing the send".to_string())
    }
}

fn authenticated_rest_binding(state: &AppState) -> Result<RestBinding, String> {
    state
        .authenticated_rest_origin
        .lock()
        .map_err(|error| error.to_string())?
        .clone()
        .ok_or_else(|| "no server origin is bound to the authenticated session".to_string())
}

fn exact_confirmed_live_action_binding(
    authenticated: Option<&RestBinding>,
    renderer_confirmed: Option<&RestBinding>,
    offline_sync_ready: bool,
    expected: Option<&RestBinding>,
) -> Result<RestBinding, String> {
    if !offline_sync_ready {
        return Err("authenticated transport is not ready for renderer live actions".to_string());
    }
    let authenticated =
        authenticated.ok_or("no server origin is bound to the authenticated session")?;
    if renderer_confirmed != Some(authenticated) {
        return Err(
            "renderer has not confirmed the exact authenticated server binding".to_string(),
        );
    }
    if expected.is_some_and(|expected| expected != authenticated) {
        return Err("authenticated server binding changed during the live action".to_string());
    }
    Ok(authenticated.clone())
}

/// Capture the exact renderer-confirmed generation before acquiring the client
/// mutex. Commands must re-check it after acquiring that mutex so a queued old
/// action cannot mutate a replacement client session.
fn capture_confirmed_live_action_binding(state: &AppState) -> Result<RestBinding, String> {
    require_live_transport_ready(state)?;
    let authenticated = state
        .authenticated_rest_origin
        .lock()
        .map_err(|error| error.to_string())?
        .clone();
    let renderer_confirmed = state
        .renderer_confirmed_rest_binding
        .lock()
        .map_err(|error| error.to_string())?
        .clone();
    exact_confirmed_live_action_binding(
        authenticated.as_ref(),
        renderer_confirmed.as_ref(),
        state.offline_sync_ready.load(Ordering::Acquire),
        None,
    )
}

/// Non-blocking half of the live-action gate for callers already holding
/// `state.client`. Never call `require_unlocked` here because expiry reset also
/// needs the client mutex.
fn require_confirmed_live_action_binding_current(
    state: &AppState,
    expected: &RestBinding,
) -> Result<(), String> {
    require_session_still_unlocked(state)?;
    let authenticated = state
        .authenticated_rest_origin
        .lock()
        .map_err(|error| error.to_string())?
        .clone();
    let renderer_confirmed = state
        .renderer_confirmed_rest_binding
        .lock()
        .map_err(|error| error.to_string())?
        .clone();
    exact_confirmed_live_action_binding(
        authenticated.as_ref(),
        renderer_confirmed.as_ref(),
        state.offline_sync_ready.load(Ordering::Acquire),
        Some(expected),
    )
    .map(|_| ())
}

fn validate_expected_live_action_binding(
    binding: &RestBinding,
    expected_server_origin: &str,
    expected_binding_generation: &str,
) -> Result<(), String> {
    let expected_generation = expected_binding_generation
        .parse::<u64>()
        .map_err(|_| "expected binding generation is invalid".to_string())?;
    if expected_generation == 0 || expected_generation.to_string() != expected_binding_generation {
        return Err("expected binding generation is non-canonical".to_string());
    }
    if binding.origin.canonical_server_origin() != expected_server_origin
        || binding.generation != expected_generation
    {
        return Err("renderer live action belongs to another server binding".to_string());
    }
    Ok(())
}

fn capture_expected_live_action_binding(
    state: &AppState,
    expected_server_origin: &str,
    expected_binding_generation: &str,
) -> Result<RestBinding, String> {
    let binding = capture_confirmed_live_action_binding(state)?;
    validate_expected_live_action_binding(
        &binding,
        expected_server_origin,
        expected_binding_generation,
    )?;
    Ok(binding)
}

fn validate_live_action_rest_origin(
    binding: &RestBinding,
    request_url: &str,
) -> Result<(), String> {
    let parsed_url =
        reqwest::Url::parse(request_url).map_err(|error| format!("invalid REST URL: {error}"))?;
    if rest_origin(&parsed_url)? != binding.origin {
        return Err(
            "renderer live action REST origin differs from its authenticated binding".to_string(),
        );
    }
    Ok(())
}

fn validate_expected_rest_binding(
    current: &RestBinding,
    expected: Option<&RestBinding>,
) -> Result<(), String> {
    if expected.is_some_and(|expected| expected != current) {
        return Err("authenticated REST binding changed before the live action".to_string());
    }
    Ok(())
}

/// Validate a renderer-visible scope while the caller holds
/// `session_transition`. This is the final publication check after native
/// backlog sync and again after renderer-side prekey publication.
fn validate_authenticated_session_scope(
    state: &AppState,
    user_id: &str,
    canonical_server_origin: &str,
    binding_generation: u64,
) -> Result<(), String> {
    require_session_still_unlocked(state)?;
    if !state.offline_sync_ready.load(Ordering::Acquire) {
        return Err("authenticated transport is no longer ready".to_string());
    }
    let binding = authenticated_rest_binding(state)?;
    if binding.generation != binding_generation
        || binding.origin.canonical_server_origin() != canonical_server_origin
    {
        return Err("authenticated server scope changed before publication".to_string());
    }
    let client = state.client.lock().map_err(|error| error.to_string())?;
    if client.authenticated_user_id()? != user_id {
        return Err("authenticated user changed before scope publication".to_string());
    }
    Ok(())
}

/// Temporary Phase 4D boundary while legacy conversation/ratchet tables still
/// use bare UUID primary keys. A conversation from another self-hosted origin
/// must never advance local crypto state through the active transport.
fn require_authenticated_conversation_origin(
    state: &AppState,
    client: &VeilClient,
    conversation_id: &str,
) -> Result<(), String> {
    let binding = authenticated_rest_binding(state)?;
    let expected_origin = binding.origin.canonical_server_origin();
    let conversation = client
        .db()
        .ok_or("database not initialized")?
        .get_conversations()?
        .into_iter()
        .find(|conversation| conversation.id == conversation_id)
        .ok_or("conversation is absent from the encrypted local directory")?;
    if conversation.server_origin.as_deref() != Some(expected_origin.as_str()) {
        return Err(
            "conversation belongs to another or unknown authenticated server origin".to_string(),
        );
    }
    if authenticated_rest_binding(state)? != binding {
        return Err("authenticated server origin changed while resolving conversation".to_string());
    }
    Ok(())
}

fn validate_persisted_message_conversation(
    persisted_conversation_id: Option<&str>,
    expected_conversation_id: &str,
) -> Result<(), String> {
    match persisted_conversation_id {
        Some(persisted) if persisted == expected_conversation_id => Ok(()),
        Some(_) => Err("message belongs to another conversation".to_string()),
        None => Err("message is absent from encrypted local storage".to_string()),
    }
}

fn require_persisted_message_conversation(
    client: &VeilClient,
    message_id: &str,
    expected_conversation_id: &str,
) -> Result<(), String> {
    let binding = client
        .db()
        .ok_or("database not initialized")?
        .get_message_binding(message_id)?;
    validate_persisted_message_conversation(
        binding.as_ref().map(|binding| binding.0.as_str()),
        expected_conversation_id,
    )
}

fn bounded_diagnostic_detail(detail: &str) -> String {
    let sanitized: String = detail
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(512)
        .collect();
    let sanitized = sanitized.trim();
    if sanitized.is_empty() {
        "cryptographic state is unavailable".to_string()
    } else {
        sanitized.to_string()
    }
}

fn conversation_crypto_diagnostic(
    state: &AppState,
    conversation_id: &str,
) -> Result<Option<ConversationCryptoDiagnostic>, String> {
    Ok(state
        .unavailable_conversations
        .lock()
        .map_err(|error| error.to_string())?
        .get(conversation_id)
        .cloned())
}

fn require_conversation_crypto_available(
    state: &AppState,
    conversation_id: &str,
) -> Result<(), String> {
    if let Some(diagnostic) = conversation_crypto_diagnostic(state, conversation_id)? {
        return Err(format!(
            "conversation cryptography is unavailable ({}): {}",
            diagnostic.code, diagnostic.detail
        ));
    }
    Ok(())
}

fn conversation_is_quarantined_fail_closed(state: &AppState, conversation_id: &str) -> bool {
    !matches!(
        conversation_crypto_diagnostic(state, conversation_id),
        Ok(None)
    )
}

fn quarantine_conversation_state(
    state: &AppState,
    conversation_id: &str,
    code: &str,
    detail: &str,
) -> Result<ConversationCryptoDiagnostic, String> {
    let mut unavailable = state
        .unavailable_conversations
        .lock()
        .map_err(|error| error.to_string())?;
    Ok(unavailable
        .entry(conversation_id.to_string())
        .or_insert_with(|| ConversationCryptoDiagnostic {
            conversation_id: conversation_id.to_string(),
            code: code.to_string(),
            detail: bounded_diagnostic_detail(detail),
        })
        .clone())
}

fn emit_authenticated_conversation_crypto_unavailable(
    app: &AuthenticatedEventAppHandle,
    diagnostic: &ConversationCryptoDiagnostic,
) {
    let _ = app.emit("veil://conversation-crypto-unavailable", diagnostic);
}

fn quarantine_runtime_conversation(
    state: &AppState,
    conversation_id: &str,
    sender_key_mode: bool,
) -> Result<(), String> {
    if !sender_key_mode {
        return Ok(());
    }
    let mut client = state.client.lock().map_err(|error| error.to_string())?;
    client.invalidate_device_roster_v1(conversation_id);
    client.mark_channel_conversation(conversation_id);
    Ok(())
}

fn quarantine_live_conversation(
    state: &AppState,
    app: &AuthenticatedEventAppHandle,
    client: &mut VeilClient,
    conversation_id: &str,
    sender_key_mode: bool,
    code: &str,
    detail: &str,
) -> Result<(), String> {
    if sender_key_mode {
        client.invalidate_device_roster_v1(conversation_id);
        client.mark_channel_conversation(conversation_id);
    }
    let diagnostic = quarantine_conversation_state(state, conversation_id, code, detail)?;
    emit_authenticated_conversation_crypto_unavailable(app, &diagnostic);
    Ok(())
}

/// Reject every conversation-scoped live event whose bare UUID does not map
/// to the current authenticated origin in SQLCipher. Runtime authorization is
/// necessary but cannot by itself disambiguate equal UUIDs across self-hosted
/// instances.
fn live_conversation_origin_is_current(
    state: &AppState,
    app: &AuthenticatedEventAppHandle,
    client: &mut VeilClient,
    conversation_id: &str,
) -> bool {
    if let Err(error) = require_authenticated_conversation_origin(state, client, conversation_id) {
        let sender_key_mode = client.is_channel_conversation(conversation_id);
        let detail = format!("live event origin rejected: {error}");
        let _ = quarantine_live_conversation(
            state,
            app,
            client,
            conversation_id,
            sender_key_mode,
            "live_origin_rejected",
            &detail,
        );
        let _ = app.emit(
            "veil://error",
            serde_json::json!({
                "code": 4003,
                "message": detail,
            }),
        );
        return false;
    }
    true
}

fn consume_pending_lock_event(pending: &AtomicBool, unlocked: &AtomicBool) -> bool {
    pending.swap(false, Ordering::AcqRel) && !unlocked.load(Ordering::Acquire)
}

/// Publish a successfully initialized session while the caller holds
/// `session_transition`. Clearing first prevents an older lock request from
/// being emitted after the new session becomes visible.
fn publish_unlocked_session(pending: &AtomicBool, unlocked: &AtomicBool, epoch: &AtomicU64) {
    epoch.fetch_add(1, Ordering::SeqCst);
    pending.store(false, Ordering::Release);
    unlocked.store(true, Ordering::SeqCst);
}

/// Reset body for callers already holding `session_transition`.
fn reset_sensitive_state_locked(state: &AppState) -> Result<(), String> {
    state.session_epoch.fetch_add(1, Ordering::SeqCst);
    state.unlocked.store(false, Ordering::SeqCst);
    state.offline_sync_ready.store(false, Ordering::SeqCst);
    state.lock_event_pending.store(true, Ordering::Release);
    *state
        .authenticated_rest_origin
        .lock()
        .map_err(|e| e.to_string())? = None;
    *state
        .renderer_confirmed_rest_binding
        .lock()
        .map_err(|e| e.to_string())? = None;
    state
        .unavailable_conversations
        .lock()
        .map_err(|e| e.to_string())?
        .clear();
    // The client mutex is the linearization point: operations already holding
    // it finish first; every later operation observes an empty client.
    *state.client.lock().map_err(|e| e.to_string())? = VeilClient::new();
    state.indexer.clear().map_err(|e| e.to_string())
}

fn account_database_path(state: &AppState, mnemonic: &str) -> Result<PathBuf, String> {
    let identity = veil_crypto::keys::IdentityKeyPair::from_mnemonic(mnemonic)?;
    let accounts_dir = state.db_dir.join("accounts");
    std::fs::create_dir_all(&accounts_dir).map_err(|e| format!("create account vault: {e}"))?;
    let identity_name = hex::encode(identity.x25519_public_bytes());
    let scoped = accounts_dir.join(format!("{identity_name}.db"));

    // Pre-release builds used one global path. Move that file exactly once
    // when opening the identity that owns it; never copy it into another
    // account namespace.
    let legacy = state.db_dir.join("veil.db");
    if !scoped.exists() && legacy.exists() {
        for source in [
            legacy.clone(),
            legacy.with_extension("db-wal"),
            legacy.with_extension("db-shm"),
        ] {
            if !source.exists() {
                continue;
            }
            let suffix = source
                .extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or("db");
            let target = if suffix == "db" {
                scoped.clone()
            } else {
                scoped.with_extension(suffix)
            };
            std::fs::rename(&source, &target)
                .map_err(|e| format!("move legacy account database: {e}"))?;
        }
    }
    Ok(scoped)
}

fn initialize_client(state: &AppState, mnemonic: &str) -> Result<String, String> {
    let db_path = account_database_path(state, mnemonic)?;
    let mut fresh = VeilClient::new();
    fresh.init_with_mnemonic(mnemonic, &db_path)?;
    fresh.set_indexer(state.indexer.clone());
    let identity_key = fresh.identity_key()?;
    let key = hex::encode(identity_key);
    *state.client.lock().map_err(|e| e.to_string())? = fresh;
    state
        .unavailable_conversations
        .lock()
        .map_err(|e| e.to_string())?
        .clear();
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

fn valid_unlock_pin(pin: &str) -> bool {
    (LEGACY_MIN_PIN_LEN..=MAX_PIN_LEN).contains(&pin.len())
        && pin.bytes().all(|byte| byte.is_ascii_digit())
}

async fn verify_pin_throttled(state: &AppState, mut pin: String) -> Result<bool, String> {
    if !valid_unlock_pin(&pin) {
        pin.zeroize();
        return Err("PIN must contain 4 to 12 digits (4–5 only for legacy PINs)".to_string());
    }
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
    if configured_pin(&state) {
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
    // Installing or changing the PIN starts a fresh inactivity window. Lock
    // every fallible in-process guard and clear the durable throttle before
    // the PIN write. Once the new credential is durable, the command has no
    // remaining fallible step that could report failure while the PIN is
    // actually active.
    let mut last_activity = state.last_activity.lock().map_err(|e| e.to_string())?;
    let mut throttle = state.pin_throttle.lock().map_err(|e| e.to_string())?;
    clear_persistent_pin_throttle()?;
    keychain::store_seed(PIN_MATERIAL_ACCOUNT, &material)?;
    state.pin_configured.store(true, Ordering::Release);
    *last_activity = Instant::now();
    throttle.reset();
    drop(last_activity);
    // Best-effort cleanup after the new atomic credential is durable. A
    // cleanup failure is harmless because reads always prefer v2.
    let _ = keychain::delete_seed(PIN_HASH_ACCOUNT);
    let _ = keychain::delete_seed(PIN_SALT_ACCOUNT);
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
        publish_unlocked_session(
            &state.lock_event_pending,
            &state.unlocked,
            &state.session_epoch,
        );
    }

    Ok(matches)
}

#[tauri::command]
fn has_pin(state: State<'_, AppState>) -> bool {
    configured_pin(&state)
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
    // Acquire every fallible in-process guard before deleting credentials so
    // a successful deletion has no later mutex failure before cache update.
    let mut throttle = state.pin_throttle.lock().map_err(|e| e.to_string())?;
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
    throttle.reset();
    state.pin_configured.store(false, Ordering::Release);
    Ok(())
}

#[tauri::command]
async fn reveal_recovery_phrase(state: State<'_, AppState>, pin: String) -> Result<String, String> {
    require_unlocked(&state)?;
    if !configured_pin(&state) {
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
    let _transition = state.session_transition.lock().map_err(|e| e.to_string())?;
    if !configured_pin(&state) {
        return Err("configure a PIN before locking the application".into());
    }
    let result = reset_sensitive_state_locked(&state);
    // Renderer-initiated lock already cleared its own state.
    if !state.unlocked.load(Ordering::Acquire) {
        state.lock_event_pending.store(false, Ordering::Release);
    }
    result
}

/// Remove the active account from this device without touching the server.
/// The account-scoped SQLCipher vault remains on disk and can be reopened
/// with its recovery phrase; only the keychain seed and app PIN are removed.
#[tauri::command]
fn sign_out(state: State<'_, AppState>) -> Result<(), String> {
    let _transition = state.session_transition.lock().map_err(|e| e.to_string())?;
    require_unlocked_locked(&state)?;
    if !keychain::has_seed(KEYCHAIN_ACCOUNT)? {
        return Err("no stored identity is available to sign out".to_string());
    }

    // Remove the PIN policy before the seed. If keychain access fails, the
    // operation aborts while the active account is still recoverable.
    if keychain::has_seed(PIN_MATERIAL_ACCOUNT)? {
        keychain::delete_seed(PIN_MATERIAL_ACCOUNT)?;
    }
    if keychain::has_seed(PIN_HASH_ACCOUNT)? {
        keychain::delete_seed(PIN_HASH_ACCOUNT)?;
    }
    if keychain::has_seed(PIN_SALT_ACCOUNT)? {
        keychain::delete_seed(PIN_SALT_ACCOUNT)?;
    }
    if keychain::has_seed(PIN_THROTTLE_ACCOUNT)? {
        keychain::delete_seed(PIN_THROTTLE_ACCOUNT)?;
    }
    keychain::delete_seed(KEYCHAIN_ACCOUNT)?;

    reset_sensitive_state_locked(&state)?;
    state.pin_configured.store(false, Ordering::Release);
    state.lock_event_pending.store(false, Ordering::Release);
    state
        .pin_throttle
        .lock()
        .map_err(|e| e.to_string())?
        .reset();
    // No identity/PIN remains, so onboarding is intentionally allowed to
    // initialize the next account without passing through a lock screen.
    publish_unlocked_session(
        &state.lock_event_pending,
        &state.unlocked,
        &state.session_epoch,
    );
    Ok(())
}

#[tauri::command]
fn touch_activity(state: State<'_, AppState>) {
    // Keep activity refresh ordered with the watchdog's expiry check/reset.
    let Ok(_transition) = state.session_transition.lock() else {
        return;
    };
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

fn resolve_auto_lock_seconds(stored: Result<Option<String>, String>) -> Result<u64, String> {
    let Some(value) = stored? else {
        return Ok(DEFAULT_AUTO_LOCK_SECONDS);
    };
    let seconds = value
        .parse::<u64>()
        .map_err(|_| "stored auto-lock setting is not a valid number of seconds".to_string())?;
    if !valid_auto_lock_seconds(seconds) {
        return Err(
            "stored auto-lock setting must be 60, 300, 900, 1800 or 3600 seconds".to_string(),
        );
    }
    Ok(seconds)
}

fn load_auto_lock_seconds() -> Result<u64, String> {
    resolve_auto_lock_seconds(keychain::get_optional_seed(AUTO_LOCK_ACCOUNT))
}

#[tauri::command]
fn get_auto_lock_seconds(state: State<'_, AppState>) -> u64 {
    configured_auto_lock_seconds(&state)
}

#[tauri::command]
fn set_auto_lock_seconds(state: State<'_, AppState>, seconds: u64) -> Result<(), String> {
    let _transition = state.session_transition.lock().map_err(|e| e.to_string())?;
    require_unlocked_locked(&state)?;
    if !valid_auto_lock_seconds(seconds) {
        return Err("auto-lock must be 1, 5, 15, 30 or 60 minutes".to_string());
    }
    let mut last_activity = state.last_activity.lock().map_err(|e| e.to_string())?;
    keychain::store_seed(AUTO_LOCK_ACCOUNT, &seconds.to_string())?;
    state.auto_lock_seconds.store(seconds, Ordering::Release);
    *last_activity = Instant::now();
    Ok(())
}

// ─── DB Persistence ───────────────────────────────────

/// Re-initialize client from stored seed (called after PIN unlock on restart).
/// Async so the heavy Argon2id work runs off the main thread.
#[tauri::command]
async fn init_from_seed(state: State<'_, AppState>) -> Result<String, String> {
    if configured_pin(&state) {
        require_unlocked(&state)?;
    }
    let mnemonic = Zeroizing::new(keychain::get_seed(KEYCHAIN_ACCOUNT)?);
    let _transition = state.session_transition.lock().map_err(|e| e.to_string())?;
    if !state.unlocked.load(Ordering::Acquire) {
        return Err("application locked while restoring identity".to_string());
    }
    let key = initialize_client(&state, &mnemonic)?;
    publish_unlocked_session(
        &state.lock_event_pending,
        &state.unlocked,
        &state.session_epoch,
    );
    Ok(key)
}

/// Get persisted conversations from the encrypted DB.
#[tauri::command]
fn get_conversations(state: State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    require_unlocked(&state)?;
    let binding = state
        .authenticated_rest_origin
        .lock()
        .map_err(|error| error.to_string())?
        .clone();
    let Some(binding) = binding else {
        // A bare renderer endpoint is not an identity namespace. The complete
        // list is refreshed after authenticated WS+REST binding succeeds.
        return Ok(Vec::new());
    };
    let canonical_server_origin = binding.origin.canonical_server_origin();
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("database not initialized")?;
    let convs = db.get_conversations()?;
    let result = convs
        .into_iter()
        .filter(|conversation| {
            conversation.server_origin.as_deref() == Some(canonical_server_origin.as_str())
        })
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
                "peerUserId": c.peer_user_id,
                "serverOrigin": c.server_origin,
                "lastMessageAt": c.last_message_at,
            })
        })
        .collect();
    if authenticated_rest_binding(&state)? != binding {
        return Err("authenticated server origin changed while listing conversations".to_string());
    }
    require_session_still_unlocked(&state)?;
    Ok(result)
}

/// Return conversation-scoped crypto quarantine without hiding locally stored
/// plaintext. The renderer can render a blocked island and a reconnect action
/// while unrelated DMs/groups remain fully usable.
#[tauri::command]
fn get_conversation_crypto_diagnostics(
    state: State<'_, AppState>,
) -> Result<Vec<ConversationCryptoDiagnostic>, String> {
    require_unlocked(&state)?;
    let mut diagnostics: Vec<_> = state
        .unavailable_conversations
        .lock()
        .map_err(|error| error.to_string())?
        .values()
        .cloned()
        .collect();
    diagnostics.sort_by(|left, right| left.conversation_id.cmp(&right.conversation_id));
    require_session_still_unlocked(&state)?;
    Ok(diagnostics)
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
    require_authenticated_conversation_origin(&state, &client, &conversation_id)?;
    let db = client.db().ok_or("database not initialized")?;
    let msgs = db.get_messages(&conversation_id, limit.unwrap_or(200))?;
    let result = msgs
        .into_iter()
        .map(|m| {
            let author_name = m.author.as_ref().and_then(|author| {
                author
                    .display_name
                    .as_ref()
                    .or(author.username.as_ref())
                    .cloned()
            });
            serde_json::json!({
                "id": m.id,
                "conversationId": m.conversation_id,
                "senderKey": hex::encode(&m.sender_key),
                "senderName": author_name,
                "senderUserId": m.author.as_ref().map(|author| &author.locator.user_id),
                "senderSigningKey": m.author.as_ref().map(|author| hex::encode(author.signing_key)),
                "senderProfileVersion": m.author.as_ref().and_then(|author| author.profile_version),
                "senderProfileOrigin": m.author.as_ref().map(|author| &author.profile_origin),
                "senderOrigin": m.author.as_ref().map(|author| &author.locator.canonical_server_origin),
                "text": m.plaintext,
                "isOwn": m.is_outgoing,
                "pending": m.is_outgoing && m.status == veil_store::models::MessageStatus::Sending,
                "failed": m.is_outgoing && m.status == veil_store::models::MessageStatus::Failed,
                "deliveryUnknown": m.is_outgoing && m.status == veil_store::models::MessageStatus::Unknown,
                "timestamp": m.server_timestamp.unwrap_or(0),
                "createdAt": m.created_at,
                "replyToId": m.reply_to_id,
            })
        })
        .collect();
    require_authenticated_conversation_origin(&state, &client, &conversation_id)?;
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
    live_action_binding: &RestBinding,
) -> Result<(), String> {
    let user_id = {
        let client = state.client.lock().map_err(|e| e.to_string())?;
        require_confirmed_live_action_binding_current(state, live_action_binding)?;
        client.authenticated_user_id()?
    };
    let value = state.runtime.block_on(rest_send_json_for_binding(
        state,
        reqwest::Method::GET,
        rest_api_url(
            server_http_url,
            &["v1", "prekeys", &hex::encode(peer_identity_key)],
        )?,
        &user_id,
        None,
        live_action_binding,
    ))?;
    let bundle = parse_prekey_bundle(value, &peer_identity_key)?;
    if let Some(expected) = expected_signing_key {
        if bundle.signing_key != expected {
            return Err("prekey signing key does not match the authenticated DM peer".to_string());
        }
    }
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(state, live_action_binding)?;
    client.pin_peer_signing_key(peer_identity_key, bundle.signing_key)?;
    client.establish_session(&peer_identity_key, &bundle)
}

// ─── Connection ───────────────────────────────────────

const OFFLINE_SYNC_PAGE_LIMIT: usize = 100;
const OFFLINE_SYNC_MAX_PAGES: usize = 10_000;
const MAX_SYNC_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MAX_SYNC_HEADER_BYTES: usize = 512;
const MAX_SYNC_SENDER_KEY_RECIPIENTS: usize = 3_500;
const MAX_SYNC_ATTACHMENTS: usize = 64;
const MAX_SYNC_ATTACHMENT_KEY_BYTES: usize = 4_096;
const MAX_SYNC_ATTACHMENT_NONCE_BYTES: usize = 64;
const MAX_DEVICE_DIRECTORY_MEMBERS: usize = 1_024;
const MAX_DEVICE_DIRECTORY_DEVICES: usize = 3_500;
const MAX_DIRECTORY_USERNAME_BYTES: usize = 128;
const MAX_DIRECTORY_DEVICE_NAME_BYTES: usize = 256;
const MAX_DIRECTORY_REASON_BYTES: usize = 128;

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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceDirectoryWire {
    conversation_id: String,
    roster_version: String,
    roster_commitment: String,
    ready: bool,
    #[serde(default)]
    reason: Option<String>,
    required_capabilities: String,
    member_user_ids: Vec<String>,
    devices: Vec<DeviceDirectoryEntryWire>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceDirectoryEntryWire {
    user_id: String,
    username: String,
    account_identity_key: String,
    account_signing_key: String,
    device_id: String,
    device_name: String,
    #[serde(default)]
    binding: Option<DeviceBindingWire>,
    status: u8,
    eligible: bool,
    #[serde(default)]
    exclusion_reason: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceBindingWire {
    device_id: String,
    device_identity_key: String,
    device_signing_key: String,
    version: String,
    capabilities: String,
    status: u8,
    account_signature: String,
    created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedDeviceBinding {
    device_id: [u8; 16],
    device_identity_key: [u8; 32],
    device_signing_key: [u8; 32],
    version: u64,
    capabilities: u64,
    status: u8,
    account_signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedDeviceRosterEntry {
    user_id: [u8; 16],
    account_identity_key: [u8; 32],
    account_signing_key: [u8; 32],
    device_id: [u8; 16],
    binding: Option<ParsedDeviceBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedDeviceRoster {
    conversation_id: String,
    roster_version: u64,
    roster_commitment: [u8; 32],
    required_capabilities: u64,
    ready: bool,
    unavailable_reason: Option<String>,
    member_user_ids: Vec<[u8; 16]>,
    devices: Vec<ParsedDeviceRosterEntry>,
}

impl From<ParsedDeviceBinding> for DeviceBindingCandidateV1 {
    fn from(binding: ParsedDeviceBinding) -> Self {
        Self {
            device_id: binding.device_id,
            device_identity_key: binding.device_identity_key,
            device_signing_key: binding.device_signing_key,
            version: binding.version,
            capabilities: binding.capabilities,
            status: binding.status,
            account_signature: binding.account_signature,
        }
    }
}

impl From<ParsedDeviceRosterEntry> for DeviceRosterEntryV1 {
    fn from(entry: ParsedDeviceRosterEntry) -> Self {
        Self {
            user_id: entry.user_id,
            account_identity_key: entry.account_identity_key,
            account_signing_key: entry.account_signing_key,
            device_id: entry.device_id,
            binding: entry.binding.map(Into::into),
        }
    }
}

impl From<ParsedDeviceRoster> for DeviceRosterCandidateV1 {
    fn from(roster: ParsedDeviceRoster) -> Self {
        Self {
            conversation_id: roster.conversation_id,
            roster_version: roster.roster_version,
            roster_commitment: roster.roster_commitment,
            required_capabilities: roster.required_capabilities,
            ready: roster.ready,
            member_user_ids: roster.member_user_ids,
            devices: roster.devices.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone)]
struct PinnedDirectoryMember {
    username: String,
    identity_key: [u8; 32],
    signing_key: [u8; 32],
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncMessagePage {
    messages: Vec<SyncMessage>,
    count: usize,
    #[serde(default)]
    next_cursor: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncMessage {
    id: String,
    conversation_id: String,
    sender_id: String,
    sender_identity_key: String,
    sender_signing_key: String,
    ciphertext: String,
    header: String,
    msg_type: i16,
    #[serde(default)]
    reply_to_id: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    edited_at: Option<String>,
    server_timestamp: i64,
    created_at: String,
    is_deleted: bool,
    is_expired: bool,
    revision_timestamp: i64,
    #[serde(default)]
    reactions: Vec<SyncReaction>,
    #[serde(default)]
    attachments: Vec<SyncAttachment>,
    crypto_profile: String,
    #[serde(default)]
    crypto_era: Option<String>,
    #[serde(default)]
    roster_version: Option<String>,
    #[serde(default)]
    roster_commitment: Option<String>,
    #[serde(default)]
    sender_device_id: Option<String>,
    #[serde(default)]
    sender_binding_version: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncReaction {
    emoji: String,
    user_id: String,
    username: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncAttachment {
    media_id: String,
    encrypted_key: String,
    nonce: String,
    size: i64,
    content_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedMessageCryptoContext {
    LegacyUnknown,
    SenderKeyV5 {
        roster_version: u64,
        roster_commitment: [u8; 32],
        sender_device_id: [u8; 16],
        sender_binding_version: u64,
    },
}

#[derive(Default)]
struct OfflineSyncStats {
    conversations: usize,
    messages: usize,
    duplicates: usize,
    unavailable_history: usize,
    unavailable_conversations: Vec<ConversationCryptoDiagnostic>,
    retained_sender_keys: usize,
    edits: usize,
    tombstones: usize,
}

fn decode_lower_hex_32(field: &str, value: &str) -> Result<[u8; 32], String> {
    decode_lower_hex_fixed(field, value)
}

fn parse_expected_dm_peer_identity_key(value: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    value
        .map(|value| decode_lower_hex_32("expected DM peer identity key", value))
        .transpose()
}

fn validate_expected_dm_peer_identity_key(
    expected: Option<&[u8; 32]>,
    authenticated: &[u8; 32],
) -> Result<(), String> {
    if expected.is_some_and(|expected| expected != authenticated) {
        return Err(
            "authenticated DM peer identity key does not match the requested identity".to_string(),
        );
    }
    Ok(())
}

fn validate_created_dm_account_directory<'a>(
    directory: &'a std::collections::HashMap<String, PinnedDirectoryMember>,
    authenticated_user_id: &str,
    local_identity_key: &[u8; 32],
    local_signing_key: &[u8; 32],
    peer_user_id: &str,
    peer_identity_key: &[u8; 32],
    peer_signing_key: &[u8; 32],
) -> Result<&'a PinnedDirectoryMember, String> {
    if peer_user_id == authenticated_user_id {
        return Err("DM peer must differ from the authenticated account".to_string());
    }
    if directory.len() != 2 {
        return Err("created DM directory must contain exactly two accounts".to_string());
    }
    validate_pinned_directory_self(
        directory,
        authenticated_user_id,
        local_identity_key,
        local_signing_key,
    )?;
    let peer = directory
        .get(peer_user_id)
        .ok_or("created DM directory is missing the requested peer")?;
    if peer.identity_key != *peer_identity_key || peer.signing_key != *peer_signing_key {
        return Err(
            "created DM response conflicts with its authenticated member directory".to_string(),
        );
    }
    Ok(peer)
}

fn decode_lower_hex_fixed<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must be exactly {N}-byte lowercase hex"));
    }
    hex::decode(value)
        .map_err(|e| format!("decode {field}: {e}"))?
        .try_into()
        .map_err(|_| format!("{field} must be exactly {N} bytes"))
}

fn decode_canonical_base64<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    use base64::Engine;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| format!("{field} must be canonical standard base64"))?;
    if decoded.len() != N || base64::engine::general_purpose::STANDARD.encode(&decoded) != value {
        return Err(format!(
            "{field} must be canonical standard base64 for exactly {N} bytes"
        ));
    }
    decoded
        .try_into()
        .map_err(|_| format!("{field} must decode to exactly {N} bytes"))
}

fn validate_canonical_base64_bytes(
    field: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), String> {
    use base64::Engine;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| format!("{field} must be canonical standard base64"))?;
    if decoded.is_empty()
        || decoded.len() > max_bytes
        || base64::engine::general_purpose::STANDARD.encode(&decoded) != value
    {
        return Err(format!(
            "{field} must be bounded non-empty canonical standard base64"
        ));
    }
    Ok(())
}

fn parse_decimal_u63(field: &str, value: &str, allow_zero: bool) -> Result<u64, String> {
    if value.is_empty()
        || value.len() > 19
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("{field} must be canonical unsigned decimal"));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{field} is outside the unsigned 63-bit range"))?;
    if parsed > i64::MAX as u64 || (!allow_zero && parsed == 0) {
        return Err(format!("{field} is outside the unsigned 63-bit range"));
    }
    Ok(parsed)
}

fn parse_message_crypto_context(
    profile: &str,
    era: Option<&str>,
    roster_version: Option<&str>,
    roster_commitment: Option<&str>,
    sender_device_id: Option<&str>,
    sender_binding_version: Option<&str>,
) -> Result<ParsedMessageCryptoContext, String> {
    let all_absent = era.is_none()
        && roster_version.is_none()
        && roster_commitment.is_none()
        && sender_device_id.is_none()
        && sender_binding_version.is_none();
    match profile {
        "legacy_unknown" if all_absent => Ok(ParsedMessageCryptoContext::LegacyUnknown),
        "legacy_unknown" => {
            Err("legacy message crypto profile carries a partial modern context".to_string())
        }
        "sender_key_v5" => {
            let era = parse_decimal_u63(
                "message crypto_era",
                era.ok_or("sender-key message is missing crypto_era")?,
                false,
            )?;
            if era != 1 {
                return Err("sender-key message has an unsupported crypto era".to_string());
            }
            let sender_device_id = decode_lower_hex_fixed::<16>(
                "message sender_device_id",
                sender_device_id.ok_or("sender-key message is missing sender_device_id")?,
            )?;
            if sender_device_id == [0u8; 16] {
                return Err("sender-key message has an invalid zero sender device id".to_string());
            }
            Ok(ParsedMessageCryptoContext::SenderKeyV5 {
                roster_version: parse_decimal_u63(
                    "message roster_version",
                    roster_version.ok_or("sender-key message is missing roster_version")?,
                    false,
                )?,
                roster_commitment: decode_lower_hex_fixed::<32>(
                    "message roster_commitment",
                    roster_commitment.ok_or("sender-key message is missing roster_commitment")?,
                )?,
                sender_device_id,
                sender_binding_version: parse_decimal_u63(
                    "message sender_binding_version",
                    sender_binding_version
                        .ok_or("sender-key message is missing sender_binding_version")?,
                    false,
                )?,
            })
        }
        _ => Err("message has an unknown crypto profile".to_string()),
    }
}

fn client_message_security_context(
    parsed: ParsedMessageCryptoContext,
    target_device_id: [u8; 16],
) -> Option<MessageSecurityContextV1> {
    match parsed {
        ParsedMessageCryptoContext::LegacyUnknown => None,
        ParsedMessageCryptoContext::SenderKeyV5 {
            roster_version,
            roster_commitment,
            sender_device_id,
            sender_binding_version,
        } => Some(MessageSecurityContextV1::SenderKeyV5(
            SenderKeyMessageSecurityContextV1 {
                roster_version,
                roster_commitment,
                sender_device_id,
                target_device_id,
                sender_binding_version,
            },
        )),
    }
}

fn validate_live_message_security_context(
    sender_key_mode: bool,
    context: Option<&MessageSecurityContextV1>,
) -> Result<(), String> {
    match (sender_key_mode, context) {
        (false, None) | (true, Some(MessageSecurityContextV1::SenderKeyV5(_))) => Ok(()),
        (false, Some(_)) => Err("DM message carries a Sender-Key security context".to_string()),
        (true, None) => {
            Err("group/channel message is missing its Sender-Key v5 context".to_string())
        }
    }
}

fn decode_canonical_uuid(field: &str, value: &str) -> Result<[u8; 16], String> {
    if value.len() != 36
        || value.as_bytes().get(8) != Some(&b'-')
        || value.as_bytes().get(13) != Some(&b'-')
        || value.as_bytes().get(18) != Some(&b'-')
        || value.as_bytes().get(23) != Some(&b'-')
    {
        return Err(format!("{field} must be a canonical lowercase UUID"));
    }
    let compact: String = value
        .chars()
        .filter(|character| *character != '-')
        .collect();
    let decoded = decode_lower_hex_fixed(field, &compact)
        .map_err(|_| format!("{field} must be a canonical lowercase UUID"))?;
    if decoded == [0u8; 16] {
        return Err(format!("{field} must not be the nil UUID"));
    }
    Ok(decoded)
}

fn validate_directory_text(
    field: &str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), String> {
    if value.len() > max_bytes
        || (!allow_empty && value.is_empty())
        || value.chars().any(char::is_control)
    {
        return Err(format!("{field} is empty, oversized, or contains controls"));
    }
    Ok(())
}

fn contains_bidi_override(value: &str) -> bool {
    value.chars().any(|character| {
        matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
    })
}

fn validate_profile_text(
    field: &str,
    value: &str,
    max_bytes: usize,
    allow_line_feed: bool,
) -> Result<(), String> {
    if value.len() > max_bytes
        || contains_bidi_override(value)
        || value
            .chars()
            .any(|character| character.is_control() && !(allow_line_feed && character == '\n'))
    {
        return Err(format!("{field} is oversized or contains unsafe controls"));
    }
    Ok(())
}

fn canonical_profile_version(value: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| "profile version is invalid".to_string())?;
    if parsed.to_string() != value {
        return Err("profile version is non-canonical".to_string());
    }
    Ok(parsed)
}

fn parse_network_profile_response(
    value: serde_json::Value,
    expected_user_id: &str,
) -> Result<NetworkProfileResponse, String> {
    let profile: NetworkProfileResponse = serde_json::from_value(value)
        .map_err(|error| format!("invalid network profile response: {error}"))?;
    decode_canonical_uuid("network profile user id", &profile.user_id)?;
    if profile.user_id != expected_user_id {
        return Err("network profile response changed its user id".to_string());
    }
    validate_profile_text("network profile username", &profile.username, 256, false)?;
    if profile.username.is_empty() {
        return Err("network profile username is empty".to_string());
    }
    if let Some(display_name) = profile.display_name.as_deref() {
        validate_profile_text("network profile display name", display_name, 512, false)?;
    }
    validate_profile_text("network profile about", &profile.about, 2048, true)?;
    validate_utc_rfc3339_nano(
        "network profile updated timestamp",
        &profile.profile_updated_at,
    )?;
    Ok(profile)
}

fn network_profile_view(
    profile: &NetworkProfile,
    proof: LocalIdentityVerification,
    is_self: bool,
) -> NetworkProfileView {
    let proof_state = if is_self {
        "current_account"
    } else {
        local_identity_verification_token(proof)
    };
    NetworkProfileView {
        canonical_server_origin: profile.locator.canonical_server_origin.clone(),
        user_id: profile.locator.user_id.clone(),
        identity_key: hex::encode(profile.locator.identity_key),
        username: profile.username.clone(),
        display_name: profile.display_name.clone(),
        about: profile.about.clone(),
        profile_version: profile.profile_version.to_string(),
        profile_updated_at: profile.profile_updated_at.clone(),
        observed_at: profile.observed_at.clone(),
        proof_state: proof_state.to_string(),
    }
}

fn local_identity_verification_token(proof: LocalIdentityVerification) -> &'static str {
    match proof {
        LocalIdentityVerification::NotCompared => "not_compared",
        LocalIdentityVerification::VerifiedOnThisDevice => "verified_on_this_device",
        LocalIdentityVerification::IdentityChanged => "identity_changed",
    }
}

fn validate_directory_reason(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_DIRECTORY_REASON_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(format!("{field} must be a bounded canonical reason token"));
    }
    Ok(())
}

fn validate_utc_rfc3339_nano(field: &str, value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let fixed_layout = bytes.len() >= 20
        && bytes.len() <= 30
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes.last() == Some(&b'Z');
    if !fixed_layout {
        return Err(format!("{field} must be canonical UTC RFC3339Nano"));
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        if matches!(index, 4 | 7 | 10 | 13 | 16) || index == bytes.len() - 1 {
            continue;
        }
        if index == 19 && bytes.len() > 20 {
            if byte != b'.' {
                return Err(format!("{field} must be canonical UTC RFC3339Nano"));
            }
            continue;
        }
        if !byte.is_ascii_digit() {
            return Err(format!("{field} must be canonical UTC RFC3339Nano"));
        }
    }
    let parse_u8_component = |range: std::ops::Range<usize>| -> Result<u8, String> {
        std::str::from_utf8(&bytes[range])
            .ok()
            .and_then(|part| part.parse::<u8>().ok())
            .ok_or_else(|| format!("{field} must be canonical UTC RFC3339Nano"))
    };
    let year = std::str::from_utf8(&bytes[0..4])
        .ok()
        .and_then(|part| part.parse::<u16>().ok())
        .ok_or_else(|| format!("{field} must be canonical UTC RFC3339Nano"))?;
    let month = parse_u8_component(5..7)?;
    let day = parse_u8_component(8..10)?;
    let hour = parse_u8_component(11..13)?;
    let minute = parse_u8_component(14..16)?;
    let second = parse_u8_component(17..19)?;
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => 0,
    };
    let fractional_is_canonical = bytes.len() == 20
        || (bytes.len() >= 22
            && bytes.len() <= 30
            && bytes[19] == b'.'
            // Go's RFC3339Nano formatter removes trailing fractional zeros.
            // Accepting them would give the signed directory more than one
            // wire representation for the same timestamp.
            && bytes[bytes.len() - 2] != b'0');
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month
        || hour > 23
        || minute > 59
        || second > 59
        || !fractional_is_canonical
    {
        return Err(format!("{field} must be canonical UTC RFC3339Nano"));
    }
    Ok(())
}

fn parse_device_directory(
    value: serde_json::Value,
    expected_conversation_id: &str,
) -> Result<ParsedDeviceRoster, String> {
    let wire: DeviceDirectoryWire = serde_json::from_value(value)
        .map_err(|error| format!("invalid device directory response: {error}"))?;
    let expected_conversation_uuid = decode_canonical_uuid(
        "expected device directory conversation_id",
        expected_conversation_id,
    )?;
    let conversation_uuid =
        decode_canonical_uuid("device directory conversation_id", &wire.conversation_id)?;
    if conversation_uuid != expected_conversation_uuid
        || wire.conversation_id != expected_conversation_id
    {
        return Err("device directory response changed its conversation id".to_string());
    }
    let roster_version = parse_decimal_u63(
        "device directory roster_version",
        &wire.roster_version,
        false,
    )?;
    let roster_commitment = decode_lower_hex_fixed::<32>(
        "device directory roster_commitment",
        &wire.roster_commitment,
    )?;
    let required_capabilities = parse_decimal_u63(
        "device directory required_capabilities",
        &wire.required_capabilities,
        false,
    )?;
    if let Some(reason) = wire.reason.as_deref() {
        validate_directory_reason("device directory reason", reason)?;
    }
    if wire.ready == wire.reason.is_some() {
        return Err("device directory ready/reason fields contradict each other".to_string());
    }
    if wire.member_user_ids.is_empty()
        || wire.member_user_ids.len() > MAX_DEVICE_DIRECTORY_MEMBERS
        || wire.devices.len() > MAX_DEVICE_DIRECTORY_DEVICES
    {
        return Err("device directory member or device count is outside client limits".to_string());
    }

    let mut member_user_ids = Vec::with_capacity(wire.member_user_ids.len());
    let mut member_set = std::collections::HashSet::new();
    for user_id in &wire.member_user_ids {
        let decoded = decode_canonical_uuid("device directory member user_id", user_id)?;
        if member_user_ids
            .last()
            .is_some_and(|previous| previous >= &decoded)
            || !member_set.insert(decoded)
        {
            return Err("device directory members are duplicated or non-canonical".to_string());
        }
        member_user_ids.push(decoded);
    }

    let mut devices = Vec::with_capacity(wire.devices.len());
    let mut device_ids = std::collections::HashSet::new();
    let mut account_keys = std::collections::HashMap::new();
    let mut account_names = std::collections::HashMap::new();
    let mut account_identity_owners = std::collections::HashMap::new();
    let mut account_signing_owners = std::collections::HashMap::new();
    let mut eligible_by_member = std::collections::HashMap::<[u8; 16], usize>::new();
    let mut previous_device_order: Option<([u8; 16], [u8; 16])> = None;
    let mut has_legacy = false;
    let mut has_missing_capabilities = false;

    for entry in wire.devices {
        validate_directory_text(
            "device directory username",
            &entry.username,
            MAX_DIRECTORY_USERNAME_BYTES,
            false,
        )?;
        validate_directory_text(
            "device directory device_name",
            &entry.device_name,
            MAX_DIRECTORY_DEVICE_NAME_BYTES,
            true,
        )?;
        let user_id = decode_canonical_uuid("device directory device user_id", &entry.user_id)?;
        if !member_set.contains(&user_id) {
            return Err("device directory contains a device for a non-member".to_string());
        }
        match account_names.insert(user_id, entry.username.clone()) {
            Some(previous) if previous != entry.username => {
                return Err("device directory changed username within one member".to_string());
            }
            _ => {}
        }
        let account_identity_key = decode_canonical_base64::<32>(
            "device directory account_identity_key",
            &entry.account_identity_key,
        )?;
        let account_signing_key = decode_canonical_base64::<32>(
            "device directory account_signing_key",
            &entry.account_signing_key,
        )?;
        match account_keys.insert(user_id, (account_identity_key, account_signing_key)) {
            Some(previous) if previous != (account_identity_key, account_signing_key) => {
                return Err("device directory changed account keys within one member".to_string());
            }
            _ => {}
        }
        if let Some(previous_owner) = account_identity_owners.insert(account_identity_key, user_id)
        {
            if previous_owner != user_id {
                return Err(
                    "device directory maps one account identity to multiple users".to_string(),
                );
            }
        }
        if let Some(previous_owner) = account_signing_owners.insert(account_signing_key, user_id) {
            if previous_owner != user_id {
                return Err(
                    "device directory maps one account signing key to multiple users".to_string(),
                );
            }
        }
        let device_id =
            decode_lower_hex_fixed::<16>("device directory device_id", &entry.device_id)?;
        if device_id == [0u8; 16] || !device_ids.insert(device_id) {
            return Err("device directory repeats a protocol device id".to_string());
        }
        let order = (user_id, device_id);
        if previous_device_order
            .as_ref()
            .is_some_and(|previous| previous >= &order)
        {
            return Err("device directory devices are not in canonical order".to_string());
        }
        previous_device_order = Some(order);

        let (binding, expected_status, expected_eligible, expected_exclusion_reason) =
            if let Some(binding) = entry.binding {
                let binding_device_id =
                    decode_lower_hex_fixed::<16>("device binding device_id", &binding.device_id)?;
                if binding_device_id != device_id {
                    return Err("device binding id differs from its directory device".to_string());
                }
                let version = parse_decimal_u63("device binding version", &binding.version, false)?;
                let capabilities =
                    parse_decimal_u63("device binding capabilities", &binding.capabilities, true)?;
                if !matches!(binding.status, 1..=3) {
                    return Err("device binding has an invalid signed status".to_string());
                }
                validate_utc_rfc3339_nano("device binding created_at", &binding.created_at)?;
                let eligible = binding.status == 1
                    && capabilities & required_capabilities == required_capabilities;
                let exclusion_reason = match (binding.status, eligible) {
                    (_, true) => None,
                    (1, false) => Some("missing_required_capabilities"),
                    (2, false) => Some("explicitly_excluded"),
                    (3, false) => Some("revoked"),
                    _ => unreachable!(),
                };
                let parsed = ParsedDeviceBinding {
                    device_id: binding_device_id,
                    device_identity_key: decode_canonical_base64::<32>(
                        "device binding device_identity_key",
                        &binding.device_identity_key,
                    )?,
                    device_signing_key: decode_canonical_base64::<32>(
                        "device binding device_signing_key",
                        &binding.device_signing_key,
                    )?,
                    version,
                    capabilities,
                    status: binding.status,
                    account_signature: decode_canonical_base64::<64>(
                        "device binding account_signature",
                        &binding.account_signature,
                    )?,
                };
                (Some(parsed), binding.status, eligible, exclusion_reason)
            } else {
                (None, 4, false, Some("legacy_unbound"))
            };
        if entry.status != expected_status
            || entry.eligible != expected_eligible
            || entry.exclusion_reason.as_deref() != expected_exclusion_reason
        {
            return Err(
                "device directory status, eligibility, or exclusion reason is inconsistent"
                    .to_string(),
            );
        }
        if let Some(reason) = entry.exclusion_reason.as_deref() {
            validate_directory_reason("device directory exclusion_reason", reason)?;
        }
        if expected_eligible {
            *eligible_by_member.entry(user_id).or_default() += 1;
        }
        has_legacy |= expected_status == 4;
        has_missing_capabilities |= expected_status == 1 && !expected_eligible;
        devices.push(ParsedDeviceRosterEntry {
            user_id,
            account_identity_key,
            account_signing_key,
            device_id,
            binding,
        });
    }

    let member_without_eligible_device = member_user_ids
        .iter()
        .any(|member| eligible_by_member.get(member).copied().unwrap_or_default() == 0);
    let derived_reason = if has_legacy {
        Some("legacy_unbound_device")
    } else if has_missing_capabilities {
        Some("active_device_missing_required_capabilities")
    } else if member_without_eligible_device {
        Some("member_has_no_eligible_active_device")
    } else {
        None
    };
    if wire.ready != derived_reason.is_none() || wire.reason.as_deref() != derived_reason {
        return Err(
            "device directory readiness does not match its canonical device set".to_string(),
        );
    }

    Ok(ParsedDeviceRoster {
        conversation_id: wire.conversation_id,
        roster_version,
        roster_commitment,
        required_capabilities,
        ready: wire.ready,
        unavailable_reason: wire.reason,
        member_user_ids,
        devices,
    })
}

fn verify_device_directory_account_keys(
    roster: &ParsedDeviceRoster,
    account_directory: &std::collections::HashMap<String, PinnedDirectoryMember>,
) -> Result<(), String> {
    if roster.member_user_ids.len() != account_directory.len() {
        return Err("device and account directories disagree on the member set".to_string());
    }
    let mut pinned_by_user = std::collections::HashMap::with_capacity(account_directory.len());
    for (user_id, member) in account_directory {
        let user_id = decode_canonical_uuid("account directory member user_id", user_id)?;
        if pinned_by_user.insert(user_id, member).is_some() {
            return Err("account directory repeats a canonical member id".to_string());
        }
    }
    if roster
        .member_user_ids
        .iter()
        .any(|user_id| !pinned_by_user.contains_key(user_id))
    {
        return Err("device and account directories disagree on a member id".to_string());
    }
    for device in &roster.devices {
        let member = pinned_by_user
            .get(&device.user_id)
            .ok_or("device directory contains an account outside the pinned member set")?;
        if member.identity_key != device.account_identity_key
            || member.signing_key != device.account_signing_key
        {
            return Err("device directory substituted pinned account keys".to_string());
        }
    }
    Ok(())
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
    canonical_server_origin: &str,
    conversation: &SyncConversation,
) -> Result<
    (
        std::collections::HashMap<String, PinnedDirectoryMember>,
        Option<OfflineSenderKeyRefresh>,
    ),
    String,
> {
    decode_canonical_uuid("conversation directory id", &conversation.id)?;
    validate_utc_rfc3339_nano(
        "conversation directory created_at",
        &conversation.created_at,
    )?;
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
    if let Some(server_id) = conversation.server_id.as_deref() {
        decode_canonical_uuid("conversation directory server_id", server_id)?;
    }
    if (conversation.conv_type == 2) != conversation.server_id.is_some() {
        return Err(format!(
            "conversation {} has a server scope inconsistent with its type",
            conversation.id
        ));
    }
    if let Some(name) = conversation.name.as_deref() {
        validate_directory_text("conversation directory name", name, 256, false)?;
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
        decode_canonical_uuid("conversation directory member user_id", &member.user_id)?;
        validate_directory_text(
            "conversation directory member username",
            &member.username,
            MAX_DIRECTORY_USERNAME_BYTES,
            false,
        )?;
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

    let (name, peer_user_id, peer_identity_key) = if conversation.conv_type == 0 {
        if directory.len() != 2 {
            return Err(format!(
                "DM conversation {} must contain exactly two members",
                conversation.id
            ));
        }
        let (peer_user_id, peer) = directory
            .iter()
            .find(|(user_id, _)| user_id.as_str() != authenticated_user_id)
            .ok_or_else(|| format!("DM conversation {} has no peer", conversation.id))?;
        (
            conversation
                .name
                .as_deref()
                .filter(|name| !name.is_empty())
                .unwrap_or(&peer.username),
            Some(peer_user_id.as_str()),
            Some(peer.identity_key),
        )
    } else {
        (conversation.name.as_deref().unwrap_or_default(), None, None)
    };

    // SQLCipher is the authoritative origin boundary. Presentation metadata
    // and the canonical conversation scope must be accepted before any
    // process-local lookup, signing pin, or live sender authorization is
    // published.
    {
        let db = client.db().ok_or("database not initialized")?;
        let observed_at = identity_observed_at();
        let snapshots: Vec<AccountSnapshot> = directory
            .iter()
            .map(|(user_id, member)| AccountSnapshot {
                locator: ProfileLocator {
                    canonical_server_origin: canonical_server_origin.to_string(),
                    user_id: user_id.clone(),
                    identity_key: member.identity_key,
                },
                signing_key: member.signing_key,
                username: Some(member.username.clone()),
                display_name: None,
                profile_version: None,
                profile_origin: canonical_server_origin.to_string(),
                source: AccountSnapshotSource::AuthenticatedConversationDirectory,
                observed_at: observed_at.clone(),
            })
            .collect();
        db.upsert_identity_directory(&snapshots)?;
        db.upsert_directory_conversation(
            &conversation.id,
            conversation.conv_type,
            canonical_server_origin,
            Some(name),
            peer_user_id,
            peer_identity_key.as_ref().map(<[u8; 32]>::as_slice),
            conversation.server_id.as_deref(),
            &conversation.created_at,
        )?;
    }

    // Only after durable origin validation succeeds do we commit TOFU pins
    // learned from this authenticated directory page.
    for (user_id, member) in &directory {
        client.ensure_user_identity_binding_compatible(user_id, member.identity_key)?;
        client.ensure_peer_signing_key_compatible(member.identity_key, member.signing_key)?;
    }
    for (user_id, member) in &directory {
        client.remember_user_identity(user_id, member.identity_key)?;
        client.pin_peer_signing_key(member.identity_key, member.signing_key)?;
    }
    client.replace_authorized_conversation_senders(
        &conversation.id,
        directory.values().map(|member| member.identity_key),
    )?;

    let sender_key_refresh = if let Some(peer_identity_key) = peer_identity_key {
        client.bind_dm_conversation(&conversation.id, peer_identity_key)?;
        None
    } else {
        // Group/channel history is Sender-Key ciphertext. Marking first blocks
        // outgoing sends until a fresh distribution, while hydration restores
        // the incoming ratchets required for the backlog.
        client.mark_channel_conversation(&conversation.id);
        Some(client.hydrate_channel_sender_keys(&conversation.id)?)
    };
    Ok((directory, sender_key_refresh))
}

fn sync_conversation_messages(
    state: &AppState,
    server_http_url: &str,
    authenticated_user_id: &str,
    canonical_server_origin: &str,
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
            decode_canonical_uuid("message sync id", &message.id)?;
            decode_canonical_uuid("message sync conversation_id", &message.conversation_id)?;
            decode_canonical_uuid("message sync sender_id", &message.sender_id)?;
            if let Some(reply_to_id) = message.reply_to_id.as_deref() {
                decode_canonical_uuid("message sync reply_to_id", reply_to_id)?;
            }
            validate_utc_rfc3339_nano("message sync created_at", &message.created_at)?;
            if let Some(edited_at) = message.edited_at.as_deref() {
                validate_utc_rfc3339_nano("message sync edited_at", edited_at)?;
            }
            if let Some(expires_at) = message.expires_at.as_deref() {
                validate_utc_rfc3339_nano("message sync expires_at", expires_at)?;
            }
            if !(0..=5).contains(&message.msg_type) || !page_message_ids.insert(message.id.as_str())
            {
                return Err(format!(
                    "message sync returned an invalid type or repeated UUID for conversation {conversation_id}"
                ));
            }
            if message.attachments.len() > MAX_SYNC_ATTACHMENTS
                || ((message.is_deleted || message.is_expired) && !message.attachments.is_empty())
            {
                return Err(format!(
                    "message {} has an invalid attachment count for its state",
                    message.id
                ));
            }
            for attachment in &message.attachments {
                validate_directory_text(
                    "message attachment media_id",
                    &attachment.media_id,
                    256,
                    false,
                )?;
                validate_canonical_base64_bytes(
                    "message attachment encrypted_key",
                    &attachment.encrypted_key,
                    MAX_SYNC_ATTACHMENT_KEY_BYTES,
                )?;
                validate_canonical_base64_bytes(
                    "message attachment nonce",
                    &attachment.nonce,
                    MAX_SYNC_ATTACHMENT_NONCE_BYTES,
                )?;
                if attachment.size < 0 {
                    return Err(format!(
                        "message {} has a negative attachment size",
                        message.id
                    ));
                }
                validate_directory_text(
                    "message attachment content_type",
                    &attachment.content_type,
                    256,
                    false,
                )?;
            }
            if message.conversation_id != conversation_id {
                return Err(format!(
                    "message {} escaped its authenticated conversation scope",
                    message.id
                ));
            }
            let crypto_context = parse_message_crypto_context(
                &message.crypto_profile,
                message.crypto_era.as_deref(),
                message.roster_version.as_deref(),
                message.roster_commitment.as_deref(),
                message.sender_device_id.as_deref(),
                message.sender_binding_version.as_deref(),
            )?;

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
            let encrypted_wire =
                if remote_state == veil_store::models::RemoteMessageStateKind::Active {
                    if message.header.len() > MAX_SYNC_HEADER_BYTES * 2
                        || message.ciphertext.len() > MAX_SYNC_CIPHERTEXT_BYTES * 2
                    {
                        return Err(format!(
                            "message {} exceeds the E2E wire size limit",
                            message.id
                        ));
                    }
                    Some((
                        decode_lower_hex_bytes("message header", &message.header)?,
                        decode_lower_hex_bytes("message ciphertext", &message.ciphertext)?,
                    ))
                } else {
                    if !message.header.is_empty() || !message.ciphertext.is_empty() {
                        return Err(format!(
                            "message {} exposes ciphertext for a terminal tombstone",
                            message.id
                        ));
                    }
                    None
                };

            let mut client = state.client.lock().map_err(|e| e.to_string())?;
            let sender_key_mode = client.is_channel_conversation(conversation_id);
            let message_security_context =
                client_message_security_context(crypto_context, client.device_id());
            if let Some((header, _)) = encrypted_wire.as_ref() {
                let valid_header = if sender_key_mode {
                    header.as_slice() == [0x05]
                } else {
                    matches!(header.first(), Some(0x01 | 0x02))
                };
                if !valid_header {
                    return Err(format!(
                        "message {} E2E header conflicts with its pinned conversation mode",
                        message.id
                    ));
                }
            }
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
                // may decrypt their history only after the ciphertext resolves
                // through an exact retained account-signed device proof below.
                // An existing IK->Ed conflict stays fatal. A first observation
                // is deliberately service-mediated TOFU: it establishes device
                // continuity, never a user-visible "Verified" attribution.
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

            match (sender_key_mode, crypto_context) {
                (false, ParsedMessageCryptoContext::LegacyUnknown) => {}
                (false, ParsedMessageCryptoContext::SenderKeyV5 { .. }) => {
                    return Err(format!(
                        "DM message {} carries a sender-key security context",
                        message.id
                    ));
                }
                (true, ParsedMessageCryptoContext::LegacyUnknown)
                    if remote_state == veil_store::models::RemoteMessageStateKind::Active =>
                {
                    let has_local_plaintext = client
                        .db()
                        .ok_or("database not initialized")?
                        .message_exists(&message.id)?;
                    if has_local_plaintext {
                        // Migration 018 labels pre-context rows explicitly as
                        // legacy_unknown. An already-decrypted local row is
                        // still trustworthy at the same authenticated
                        // revision: preserve its plaintext/index and reconcile
                        // reactions as Active. A newer encrypted edit cannot
                        // be applied, so retain the old local body while
                        // recording only the newer remote revision as
                        // unavailable.
                        match client.reconcile_remote_message_metadata(
                            &message.id,
                            conversation_id,
                            &response_identity,
                            &metadata,
                            veil_store::models::RemoteMessageStateKind::Active,
                        )? {
                            veil_client::api::RemoteReconcileAction::Unchanged
                            | veil_client::api::RemoteReconcileAction::SelfStateOnly => {
                                stats.duplicates += 1;
                                continue;
                            }
                            veil_client::api::RemoteReconcileAction::NeedsEncryptedEdit => {}
                            unexpected => {
                                return Err(format!(
                                    "legacy message {} produced unexpected local reconciliation {unexpected:?}",
                                    message.id
                                ));
                            }
                        }
                    }
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
                (true, ParsedMessageCryptoContext::LegacyUnknown) => {}
                (true, ParsedMessageCryptoContext::SenderKeyV5 { .. }) => {
                    if remote_state == veil_store::models::RemoteMessageStateKind::Active {
                        let existing_local_self = message.sender_id == authenticated_user_id
                            && client
                                .db()
                                .ok_or("database not initialized")?
                                .message_exists(&message.id)?;
                        if !existing_local_self {
                            let (_, ciphertext) = encrypted_wire
                                .as_ref()
                                .ok_or("active Sender-Key message has no ciphertext")?;
                            client.validate_sender_key_message_context_v1(
                                conversation_id,
                                &response_identity,
                                ciphertext,
                                message_security_context
                                    .as_ref()
                                    .ok_or("Sender-Key message context conversion failed")?,
                            )?;
                            if !client
                                .peer_signing_key_is_pinned(&response_identity, &response_signing)
                            {
                                return Err(format!(
                                    "message {} sender signing key is absent from its current or retained continuity pin",
                                    message.id
                                ));
                            }
                        }
                        // For a row that needs wire authentication, require an
                        // exact current or retained account-signed device proof
                        // and its durable IK->Ed continuity pin. A first-seen
                        // retained proof remains unverified service-mediated
                        // TOFU. The only bypass is our already-persisted local
                        // outgoing plaintext, which is never re-decrypted or
                        // replaced by the server ciphertext here.
                        sender_is_usable = true;
                    }
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

            let locator = ProfileLocator {
                canonical_server_origin: canonical_server_origin.to_string(),
                user_id: message.sender_id.clone(),
                identity_key: response_identity,
            };
            let author_snapshot = match client
                .db()
                .ok_or("database not initialized")?
                .resolve_account_snapshot(&locator)?
            {
                Some(snapshot) => {
                    if snapshot.signing_key != response_signing {
                        return Err(format!(
                            "message {} author signing key conflicts with the origin-scoped directory",
                            message.id
                        ));
                    }
                    snapshot
                }
                None => AccountSnapshot {
                    locator,
                    signing_key: response_signing,
                    username: directory
                        .get(&message.sender_id)
                        .map(|member| member.username.clone()),
                    display_name: None,
                    profile_version: None,
                    profile_origin: canonical_server_origin.to_string(),
                    source: if directory.contains_key(&message.sender_id) {
                        AccountSnapshotSource::AuthenticatedConversationDirectory
                    } else {
                        AccountSnapshotSource::AuthenticatedHistory
                    },
                    observed_at: identity_observed_at(),
                },
            };

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
                    client
                        .db()
                        .ok_or("database not initialized")?
                        .attach_message_author(&message.id, &author_snapshot)?;
                    stats.duplicates += 1;
                    continue;
                }
                veil_client::api::RemoteReconcileAction::Unavailable => {
                    stats.unavailable_history += 1;
                    continue;
                }
                veil_client::api::RemoteReconcileAction::NeedsInitialCiphertext
                    if message.sender_id == authenticated_user_id && !sender_key_mode =>
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

            let (header, ciphertext) = encrypted_wire
                .as_ref()
                .ok_or("active reconciliation action has no encrypted wire")?;
            match action {
                veil_client::api::RemoteReconcileAction::NeedsInitialCiphertext => {
                    match client.receive_and_persist_message(
                        &message.id,
                        conversation_id,
                        &response_identity,
                        Some(&author_snapshot),
                        sender_key_mode,
                        message_security_context.as_ref(),
                        None,
                        header,
                        ciphertext,
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
                        Some(&author_snapshot),
                        sender_key_mode,
                        header,
                        ciphertext,
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
    canonical_server_origin: &str,
) -> Result<OfflineSyncStats, String> {
    let mut stats = OfflineSyncStats::default();
    let mut cursor: Option<String> = None;
    let mut seen_conversations = std::collections::HashSet::new();
    let mut directories = Vec::new();
    let mut isolation = ConversationSyncIsolation::default();
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
            // A malformed identifier cannot be isolated because it has no
            // canonical native key. Every later per-conversation failure can.
            decode_canonical_uuid("conversation directory id", &conversation.id)?;
            if !seen_conversations.insert(conversation.id.clone()) {
                return Err(format!(
                    "conversation directory repeated {} across pages",
                    conversation.id
                ));
            }
            stats.conversations += 1;
            let (directory, sender_key_refresh) = match pin_and_persist_sync_conversation(
                state,
                authenticated_user_id,
                canonical_server_origin,
                conversation,
            ) {
                Ok(pinned) => pinned,
                Err(error) => {
                    require_session_still_unlocked(state)?;
                    quarantine_runtime_conversation(
                        state,
                        &conversation.id,
                        matches!(conversation.conv_type, 1 | 2),
                    )?;
                    isolation.block(&conversation.id, "account_directory_rejected", &error);
                    continue;
                }
            };
            if sender_key_refresh.is_some() {
                // The retained SKDM FIFO barrier and every Sender-Key
                // ciphertext are device-owned. Install the complete current
                // signed roster (including rollback/signature pins) before
                // either can consume cryptographic state.
                match fetch_and_install_authenticated_device_directory(
                    state,
                    server_http_url,
                    authenticated_user_id,
                    &conversation.id,
                    &directory,
                    None,
                ) {
                    Ok(None) => {}
                    Ok(Some(reason)) => {
                        quarantine_runtime_conversation(state, &conversation.id, true)?;
                        isolation.block(&conversation.id, "device_roster_not_ready", &reason);
                        continue;
                    }
                    Err(error) => {
                        require_session_still_unlocked(state)?;
                        quarantine_runtime_conversation(state, &conversation.id, true)?;
                        isolation.block(&conversation.id, "device_roster_rejected", &error);
                        continue;
                    }
                }
            }
            directories.push((conversation.id.clone(), directory, sender_key_refresh));
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
    {
        let mut client = state.client.lock().map_err(|e| e.to_string())?;
        let report = client.process_retained_sender_keys_before_sync()?;
        stats.retained_sender_keys = report.processed;
        for diagnostic in report.diagnostics {
            decode_canonical_uuid(
                "retained Sender-Key diagnostic conversation_id",
                &diagnostic.conversation_id,
            )?;
            if client.is_channel_conversation(&diagnostic.conversation_id) {
                client.invalidate_device_roster_v1(&diagnostic.conversation_id);
                client.mark_channel_conversation(&diagnostic.conversation_id);
            }
            isolation.block(
                &diagnostic.conversation_id,
                "retained_sender_key_rejected",
                &diagnostic.reason,
            );
        }
        // process_sender_key_distribution_v1 queues a receipt only after the
        // exact generation and route proof commit to SQLCipher. Flush that
        // durable queue before any REST ciphertext consumes the generation. A
        // receipt attests only that exact SKDM install, not that every later
        // history row exists; delaying it would permit retention/availability
        // DoS through an unrelated missing generation.
        state
            .runtime
            .block_on(client.flush_sender_key_receipts_v1())?;
    }
    directories.retain(|(conversation_id, _, _)| !isolation.is_blocked(conversation_id));

    // All identities are pinned and all FK parents/groups are installed before
    // consuming any ratchet state from the ciphertext backlog.
    for (conversation_id, directory, sender_key_refresh) in &directories {
        if let Err(error) = sync_conversation_messages(
            state,
            server_http_url,
            authenticated_user_id,
            canonical_server_origin,
            conversation_id,
            directory,
            &mut stats,
        ) {
            require_session_still_unlocked(state)?;
            // Rows accepted earlier are independently authenticated and each
            // plaintext/ratchet mutation committed transactionally. There is no
            // remote message-cursor ACK: reconnect replays the page and those
            // exact rows become validated duplicates. Quarantine prevents any
            // outgoing fanout here; the local N+1 remains pending and the
            // client's immutable retry invariant reuses it on reconnect.
            quarantine_runtime_conversation(state, conversation_id, sender_key_refresh.is_some())?;
            isolation.block(conversation_id, "message_history_unavailable", &error);
        }
    }
    directories.retain(|(conversation_id, _, _)| !isolation.is_blocked(conversation_id));

    // The current roster may have changed while this client was offline and
    // membership events are not durable. After all historical ciphertext has
    // been consumed with its old receive keys, rotate every group/channel
    // outgoing generation and distribute only to the freshly authenticated
    // directory. Sending stays blocked until every server ACK is processed by
    // the live dispatcher.
    for (conversation_id, _, sender_key_refresh) in directories {
        let Some(sender_key_refresh) = sender_key_refresh else {
            continue;
        };
        if let Err(error) = distribute_pinned_sender_key(
            state,
            &conversation_id,
            SenderKeyDistributionPreparation::OfflineRefresh(sender_key_refresh),
            None,
        ) {
            require_session_still_unlocked(state)?;
            quarantine_runtime_conversation(state, &conversation_id, true)?;
            isolation.block(&conversation_id, "sender_key_distribution_failed", &error);
        }
    }
    stats.unavailable_conversations = isolation.into_diagnostics();
    Ok(stats)
}

#[tauri::command]
fn confirm_authenticated_session_scope(
    state: State<'_, AppState>,
    user_id: String,
    canonical_server_origin: String,
    binding_generation: String,
) -> Result<(), String> {
    decode_canonical_uuid("authenticated scope user id", &user_id)?;
    let generation = binding_generation
        .parse::<u64>()
        .map_err(|_| "authenticated binding generation is invalid".to_string())?;
    if generation == 0 || generation.to_string() != binding_generation {
        return Err("authenticated binding generation is non-canonical".to_string());
    }
    let _session_transition = state.session_transition.lock().map_err(|e| e.to_string())?;
    validate_authenticated_session_scope(&state, &user_id, &canonical_server_origin, generation)?;
    let binding = authenticated_rest_binding(&state)?;
    *state
        .renderer_confirmed_rest_binding
        .lock()
        .map_err(|error| error.to_string())? = Some(binding);
    Ok(())
}

#[tauri::command]
fn connect_to_server(
    state: State<'_, AppState>,
    app: AppHandle,
    server_url: String,
    server_http_url: String,
) -> Result<AuthenticatedSessionScope, String> {
    require_unlocked(&state)?;
    validate_server_endpoint_pair(&server_url, &server_http_url)?;
    let requested_rest_url =
        reqwest::Url::parse(&server_http_url).map_err(|e| format!("invalid REST URL: {e}"))?;
    let requested_rest_origin = rest_origin(&requested_rest_url)?;
    let canonical_server_origin = requested_rest_origin.canonical_server_origin();
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
    let requested_event_app =
        AuthenticatedEventAppHandle::new(app.clone(), requested_rest_binding.clone());
    // Linearize the new binding against the live poller. An old event either
    // completes under the same session mutex or observes readiness=false; it
    // can never be processed inside the new generation window.
    {
        let _session_transition = state.session_transition.lock().map_err(|e| e.to_string())?;
        require_session_still_unlocked(&state)?;
        state.offline_sync_ready.store(false, Ordering::SeqCst);
        *state
            .renderer_confirmed_rest_binding
            .lock()
            .map_err(|e| e.to_string())? = None;
        state
            .unavailable_conversations
            .lock()
            .map_err(|error| error.to_string())?
            .clear();
        *state
            .authenticated_rest_origin
            .lock()
            .map_err(|e| e.to_string())? = None;
        // The index stores plaintext in process memory and has no origin
        // field. Erase it before authenticating another binding.
        state.indexer.clear().map_err(|e| e.to_string())?;
    }
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    client.clear_known_user_identities();
    client.clear_server_scoped_conversation_routing();
    client.clear_all_authorized_conversation_senders();
    client.clear_device_rosters_v1();
    let result = state.runtime.block_on(client.connect(&server_url))?;
    decode_canonical_uuid("authenticated user id", &result)?;
    let local_identity_key = client.identity_key()?;
    let local_signing_key = client.signing_key()?;
    drop(client);

    // Durable account trust and REST publication share the same ordered
    // session transition. A lock that started while WebSocket auth held the
    // client mutex completes first and prevents the AuthResult from becoming
    // a persisted trust binding or a published REST origin.
    {
        let _session_transition = state.session_transition.lock().map_err(|e| e.to_string())?;
        require_unlocked_locked(&state)?;
        let client = state.client.lock().map_err(|e| e.to_string())?;
        let current_user_id = client.authenticated_user_id()?;
        let current_identity_key = client.identity_key()?;
        let current_signing_key = client.signing_key()?;
        validate_authenticated_binding_commit(
            state.unlocked.load(Ordering::Acquire),
            &result,
            &current_user_id,
            &local_identity_key,
            &current_identity_key,
            &local_signing_key,
            &current_signing_key,
        )?;
        client
            .db()
            .ok_or("database not initialized")?
            .bind_authenticated_self(
                &canonical_server_origin,
                &result,
                &local_identity_key,
                &local_signing_key,
            )?;
        *state
            .authenticated_rest_origin
            .lock()
            .map_err(|e| e.to_string())? = Some(requested_rest_binding.clone());
    }

    let sync_stats =
        match sync_offline_state(&state, &server_http_url, &result, &canonical_server_origin) {
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
    if let Err(error) = rebuild_search_index_for_current_origin(&state) {
        let _ = state.indexer.clear();
        let _ = requested_event_app.emit(
            "veil://error",
            serde_json::json!({
                "code": 5001,
                "message": format!("origin-scoped search backfill failed: {error}"),
            }),
        );
    }
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
        *state
            .unavailable_conversations
            .lock()
            .map_err(|error| error.to_string())? = sync_stats
            .unavailable_conversations
            .iter()
            .cloned()
            .map(|diagnostic| (diagnostic.conversation_id.clone(), diagnostic))
            .collect();
        state.offline_sync_ready.store(true, Ordering::SeqCst);
        let _ = requested_event_app.emit(
            "veil://sync-complete",
            serde_json::json!({
                "conversations": sync_stats.conversations,
                "messages": sync_stats.messages,
                "duplicates": sync_stats.duplicates,
                "unavailableHistory": sync_stats.unavailable_history,
                "retainedSenderKeys": sync_stats.retained_sender_keys,
                "edits": sync_stats.edits,
                "tombstones": sync_stats.tombstones,
                "unavailableConversations": &sync_stats.unavailable_conversations,
            }),
        );
        for diagnostic in &sync_stats.unavailable_conversations {
            emit_authenticated_conversation_crypto_unavailable(&requested_event_app, diagnostic);
        }
    }

    // Start exactly one background event polling loop for the app lifetime.
    if state
        .event_poller_started
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        let raw_app_handle = app.clone();
        std::thread::spawn(move || {
            let state_inner = raw_app_handle.state::<AppState>();
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
                let event_binding = match authenticated_rest_binding(&state_inner) {
                    Ok(binding) => binding,
                    Err(_) => continue,
                };
                let app_handle =
                    AuthenticatedEventAppHandle::new(raw_app_handle.clone(), event_binding.clone());
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

                if !state_inner.offline_sync_ready.load(Ordering::Acquire)
                    || authenticated_rest_binding(&state_inner).ok().as_ref()
                        != Some(&event_binding)
                {
                    drop(client);
                    continue;
                }

                if let Some(evt) = event {
                    match evt {
                        ConnectionEvent::MessageReceived {
                            message_id,
                            conversation_id,
                            sender_identity_key,
                            sender_username: _,
                            ciphertext,
                            header,
                            server_timestamp,
                            reply_to_id,
                            security_context,
                        } => {
                            if !live_conversation_origin_is_current(
                                &state_inner,
                                &app_handle,
                                &mut client,
                                &conversation_id,
                            ) {
                                drop(client);
                                continue;
                            }
                            if conversation_is_quarantined_fail_closed(
                                &state_inner,
                                &conversation_id,
                            ) {
                                drop(client);
                                continue;
                            }
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
                            let sender_key_mode = client.is_channel_conversation(&conversation_id);

                            if let Err(error) = client
                                .require_currently_authorized_sender(&conversation_id, &sender_key)
                            {
                                let detail =
                                    format!("live message authorization rejected: {error}");
                                let _ = quarantine_live_conversation(
                                    &state_inner,
                                    &app_handle,
                                    &mut client,
                                    &conversation_id,
                                    sender_key_mode,
                                    "live_sender_authorization_rejected",
                                    &detail,
                                );
                                drop(client);
                                let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 4003,
                                        "message": detail,
                                    }),
                                );
                                let _ = app_handle.emit(
                                    "veil://membership-refresh-required",
                                    serde_json::json!({ "conversationId": conversation_id }),
                                );
                                continue;
                            }

                            if let Err(error) = validate_live_message_security_context(
                                sender_key_mode,
                                security_context.as_ref(),
                            ) {
                                let detail =
                                    format!("live message security context rejected: {error}");
                                let _ = quarantine_live_conversation(
                                    &state_inner,
                                    &app_handle,
                                    &mut client,
                                    &conversation_id,
                                    sender_key_mode,
                                    "live_message_context_rejected",
                                    &detail,
                                );
                                drop(client);
                                let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 4004,
                                        "message": detail,
                                    }),
                                );
                                let _ = app_handle.emit(
                                    "veil://membership-refresh-required",
                                    serde_json::json!({ "conversationId": conversation_id }),
                                );
                                continue;
                            }
                            let author_snapshot = match client
                                .db()
                                .ok_or_else(|| "database not initialized".to_string())
                                .and_then(|db| {
                                    db.resolve_account_by_conversation_sender(
                                        &conversation_id,
                                        &sender_key,
                                    )
                                }) {
                                Ok(Some(snapshot)) => snapshot,
                                Ok(None) => {
                                    let detail = "live message author is absent from the authenticated origin-scoped directory";
                                    let _ = quarantine_live_conversation(
                                        &state_inner,
                                        &app_handle,
                                        &mut client,
                                        &conversation_id,
                                        sender_key_mode,
                                        "live_author_directory_missing",
                                        detail,
                                    );
                                    drop(client);
                                    let _ = app_handle.emit(
                                        "veil://error",
                                        serde_json::json!({
                                            "code": 4005,
                                            "message": detail,
                                        }),
                                    );
                                    continue;
                                }
                                Err(error) => {
                                    let detail = format!(
                                        "live message author directory lookup failed: {error}"
                                    );
                                    let _ = quarantine_live_conversation(
                                        &state_inner,
                                        &app_handle,
                                        &mut client,
                                        &conversation_id,
                                        sender_key_mode,
                                        "live_author_directory_rejected",
                                        &detail,
                                    );
                                    drop(client);
                                    let _ = app_handle.emit(
                                        "veil://error",
                                        serde_json::json!({
                                            "code": 4005,
                                            "message": detail,
                                        }),
                                    );
                                    continue;
                                }
                            };
                            let authoritative_sender_name = author_snapshot
                                .display_name
                                .as_deref()
                                .or(author_snapshot.username.as_deref())
                                .unwrap_or("Unknown author")
                                .to_string();
                            let ts_ms = (server_timestamp / 1_000_000) as i64;
                            let text = match client.receive_and_persist_live_message(
                                &message_id,
                                &conversation_id,
                                &sender_key,
                                Some(&author_snapshot),
                                sender_key_mode,
                                security_context.as_ref(),
                                Some(&authoritative_sender_name),
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
                                    let detail = format!("message transaction rejected: {error}");
                                    let _ = quarantine_live_conversation(
                                        &state_inner,
                                        &app_handle,
                                        &mut client,
                                        &conversation_id,
                                        sender_key_mode,
                                        "live_message_transaction_rejected",
                                        &detail,
                                    );
                                    drop(client);
                                    let _ = app_handle.emit(
                                        "veil://error",
                                        serde_json::json!({
                                            "code": 4001,
                                            "message": detail,
                                        }),
                                    );
                                    let _ = app_handle.emit(
                                        "veil://membership-refresh-required",
                                        serde_json::json!({
                                            "conversationId": conversation_id,
                                        }),
                                    );
                                    continue;
                                }
                            };
                            let conversation_context = client.db().and_then(|db| {
                                db.get_conversations().ok().and_then(|conversations| {
                                    conversations
                                        .into_iter()
                                        .find(|conversation| conversation.id == conversation_id)
                                })
                            });
                            let conversation_type = conversation_context.as_ref().map(
                                |conversation| match conversation.conv_type {
                                    veil_store::models::ConversationType::DM => "dm",
                                    veil_store::models::ConversationType::Group => "group",
                                    veil_store::models::ConversationType::Channel => "channel",
                                },
                            );
                            let conversation_name = conversation_context
                                .as_ref()
                                .and_then(|conversation| conversation.name.as_deref());
                            let conversation_peer_user_id = conversation_context
                                .as_ref()
                                .and_then(|conversation| conversation.peer_user_id.as_deref());
                            drop(client); // Release lock before emitting

                            let _ = app_handle.emit(
                                "veil://message",
                                serde_json::json!({
                                    "messageId": message_id,
                                    "conversationId": conversation_id,
                                    "conversationType": conversation_type,
                                    "conversationName": conversation_name,
                                    "conversationPeerUserId": conversation_peer_user_id,
                                    "senderKey": hex::encode(&sender_identity_key),
                                    "senderName": authoritative_sender_name,
                                    "senderUserId": author_snapshot.locator.user_id,
                                    "senderSigningKey": hex::encode(author_snapshot.signing_key),
                                    "senderProfileVersion": author_snapshot.profile_version,
                                    "senderProfileOrigin": author_snapshot.profile_origin,
                                    "senderOrigin": author_snapshot.locator.canonical_server_origin,
                                    "text": text,
                                    "timestamp": server_timestamp / 1_000_000,
                                    "replyToId": reply_to_id,
                                }),
                            );

                            // Desktop notification
                            let _ = app_handle
                                .raw_app()
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
                            ..
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
                            if !live_conversation_origin_is_current(
                                &state_inner,
                                &app_handle,
                                &mut client,
                                &conversation_id,
                            ) {
                                drop(client);
                                continue;
                            }
                            if conversation_is_quarantined_fail_closed(
                                &state_inner,
                                &conversation_id,
                            ) {
                                drop(client);
                                continue;
                            }
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
                            let sender_key_mode = client.is_channel_conversation(&conversation_id);
                            if sender_key_mode {
                                let detail = "encrypted group/channel edits are unavailable without an exact-device edit context";
                                let _ = quarantine_live_conversation(
                                    &state_inner,
                                    &app_handle,
                                    &mut client,
                                    &conversation_id,
                                    true,
                                    "unsupported_encrypted_edit",
                                    detail,
                                );
                                drop(client);
                                let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({ "code": 4004, "message": detail }),
                                );
                                continue;
                            }

                            if let Err(error) = client
                                .require_currently_authorized_sender(&conversation_id, &sender_key)
                            {
                                let detail = format!("live edit authorization rejected: {error}");
                                let _ = quarantine_live_conversation(
                                    &state_inner,
                                    &app_handle,
                                    &mut client,
                                    &conversation_id,
                                    false,
                                    "live_edit_authorization_rejected",
                                    &detail,
                                );
                                drop(client);
                                let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 4003,
                                        "message": detail,
                                    }),
                                );
                                let _ = app_handle.emit(
                                    "veil://membership-refresh-required",
                                    serde_json::json!({ "conversationId": conversation_id }),
                                );
                                continue;
                            }

                            let author_snapshot = match client
                                .db()
                                .ok_or_else(|| "database not initialized".to_string())
                                .and_then(|db| {
                                    db.resolve_account_by_conversation_sender(
                                        &conversation_id,
                                        &sender_key,
                                    )
                                }) {
                                Ok(Some(snapshot)) => snapshot,
                                Ok(None) => {
                                    let detail = "live edit author is absent from the authenticated origin-scoped directory";
                                    let _ = quarantine_live_conversation(
                                        &state_inner,
                                        &app_handle,
                                        &mut client,
                                        &conversation_id,
                                        false,
                                        "live_edit_author_directory_missing",
                                        detail,
                                    );
                                    drop(client);
                                    continue;
                                }
                                Err(error) => {
                                    let detail = format!(
                                        "live edit author directory lookup failed: {error}"
                                    );
                                    let _ = quarantine_live_conversation(
                                        &state_inner,
                                        &app_handle,
                                        &mut client,
                                        &conversation_id,
                                        false,
                                        "live_edit_author_directory_rejected",
                                        &detail,
                                    );
                                    drop(client);
                                    continue;
                                }
                            };

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
                                    if let Err(error) = client
                                        .db()
                                        .ok_or_else(|| "database not initialized".to_string())
                                        .and_then(|db| {
                                            db.attach_message_author(&message_id, &author_snapshot)
                                        })
                                    {
                                        let detail = format!(
                                            "message edit author persistence rejected: {error}"
                                        );
                                        let _ = quarantine_live_conversation(
                                            &state_inner,
                                            &app_handle,
                                            &mut client,
                                            &conversation_id,
                                            false,
                                            "live_edit_author_persistence_rejected",
                                            &detail,
                                        );
                                    }
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
                                    let detail =
                                        format!("message edit reconciliation rejected: {error}");
                                    let _ = quarantine_live_conversation(
                                        &state_inner,
                                        &app_handle,
                                        &mut client,
                                        &conversation_id,
                                        false,
                                        "live_edit_reconciliation_rejected",
                                        &detail,
                                    );
                                    drop(client);
                                    let _ = app_handle.emit(
                                        "veil://error",
                                        serde_json::json!({
                                            "code": 4001,
                                            "message": detail,
                                        }),
                                    );
                                    continue;
                                }
                            }
                            let new_text = match client.receive_and_persist_live_edit(
                                &message_id,
                                &conversation_id,
                                &sender_key,
                                Some(&author_snapshot),
                                sender_key_mode,
                                &header,
                                &ciphertext,
                                Some(&metadata),
                            ) {
                                Ok(plaintext) => plaintext,
                                Err(error) => {
                                    let detail = format!("message edit rejected: {error}");
                                    let _ = quarantine_live_conversation(
                                        &state_inner,
                                        &app_handle,
                                        &mut client,
                                        &conversation_id,
                                        false,
                                        "live_edit_decryption_rejected",
                                        &detail,
                                    );
                                    drop(client);
                                    let _ = app_handle.emit(
                                        "veil://error",
                                        serde_json::json!({
                                            "code": 4001,
                                            "message": detail,
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
                            if !live_conversation_origin_is_current(
                                &state_inner,
                                &app_handle,
                                &mut client,
                                &conversation_id,
                            ) {
                                drop(client);
                                continue;
                            }
                            if conversation_is_quarantined_fail_closed(
                                &state_inner,
                                &conversation_id,
                            ) {
                                drop(client);
                                continue;
                            }
                            let sender_key: [u8; 32] = match sender_identity_key.try_into() {
                                Ok(sender) => sender,
                                Err(_) => {
                                    drop(client);
                                    continue;
                                }
                            };
                            let sender_key_mode = client.is_channel_conversation(&conversation_id);

                            // A durable identity pin proves who signed the event,
                            // but it does not prove that the sender is still a
                            // member of this conversation. Apply the same live
                            // directory guard as NEW/EDIT before a tombstone can
                            // mutate local history.
                            if let Err(error) = client
                                .require_currently_authorized_sender(&conversation_id, &sender_key)
                            {
                                let detail = format!("live delete authorization rejected: {error}");
                                let _ = quarantine_live_conversation(
                                    &state_inner,
                                    &app_handle,
                                    &mut client,
                                    &conversation_id,
                                    sender_key_mode,
                                    "live_delete_authorization_rejected",
                                    &detail,
                                );
                                drop(client);
                                let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 4003,
                                        "message": detail,
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
                                let detail = format!("message delete persistence failed: {error}");
                                let _ = quarantine_live_conversation(
                                    &state_inner,
                                    &app_handle,
                                    &mut client,
                                    &conversation_id,
                                    sender_key_mode,
                                    "live_delete_persistence_failed",
                                    &detail,
                                );
                                drop(client);
                                let _ = app_handle.emit(
                                    "veil://error",
                                    serde_json::json!({
                                        "code": 5001,
                                        "message": detail,
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
                            let invalidation =
                                state_inner
                                    .authenticated_rest_origin
                                    .lock()
                                    .map(|mut binding| {
                                        invalidate_disconnected_binding(
                                            &mut binding,
                                            &event_binding,
                                        )
                                    });
                            let confirmed_invalidation = state_inner
                                .renderer_confirmed_rest_binding
                                .lock()
                                .map(|mut binding| {
                                    invalidate_disconnected_binding(&mut binding, &event_binding)
                                });
                            if !matches!(invalidation, Ok(false)) || confirmed_invalidation.is_err()
                            {
                                // A current disconnect, or an unusable poisoned
                                // binding mutex, must stop authenticated work.
                                // A delayed old-generation disconnect leaves a
                                // replacement binding and its readiness intact.
                                state_inner
                                    .offline_sync_ready
                                    .store(false, Ordering::SeqCst);
                            }
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
                            conversation_id,
                            stale_roster_context,
                            ..
                        } => {
                            if stale_roster_context {
                                // VeilClient has already invalidated the exact
                                // proof associated with the rejected sequence.
                                // Quarantine that conversation only. A malformed
                                // error without the pending sequence's scope is
                                // the sole case that still requires a global
                                // barrier because it cannot be isolated safely.
                                if let Some(conversation_id) = conversation_id.as_deref() {
                                    let sender_key_mode =
                                        client.is_channel_conversation(conversation_id);
                                    let _ = quarantine_live_conversation(
                                        &state_inner,
                                        &app_handle,
                                        &mut client,
                                        conversation_id,
                                        sender_key_mode,
                                        "stale_roster_context",
                                        &message,
                                    );
                                } else {
                                    state_inner
                                        .offline_sync_ready
                                        .store(false, Ordering::Release);
                                }
                            }
                            drop(client);
                            let _ = app_handle.emit(
                                "veil://error",
                                serde_json::json!({
                                    "code": code,
                                    "message": message,
                                    "localMessageId": local_message_id,
                                }),
                            );
                            if stale_roster_context {
                                let _ = app_handle.emit(
                                    "veil://membership-refresh-required",
                                    serde_json::json!({
                                        "conversationId": conversation_id,
                                    }),
                                );
                            }
                        }
                        ConnectionEvent::TypingEvent {
                            conversation_id,
                            identity_key,
                            started,
                        } => {
                            if !live_conversation_origin_is_current(
                                &state_inner,
                                &app_handle,
                                &mut client,
                                &conversation_id,
                            ) {
                                drop(client);
                                continue;
                            }
                            if conversation_is_quarantined_fail_closed(
                                &state_inner,
                                &conversation_id,
                            ) {
                                drop(client);
                                continue;
                            }
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
                            if !live_conversation_origin_is_current(
                                &state_inner,
                                &app_handle,
                                &mut client,
                                &conversation_id,
                            ) {
                                drop(client);
                                continue;
                            }
                            if conversation_is_quarantined_fail_closed(
                                &state_inner,
                                &conversation_id,
                            ) {
                                drop(client);
                                continue;
                            }
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
                                .raw_app()
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
                        ConnectionEvent::ProfileUpdated {
                            user_id,
                            profile_version,
                        } => {
                            // Presentation metadata must stay completely
                            // separate from roster invalidation and Sender-Key
                            // rotation. The renderer refetches the signed REST
                            // profile for this exact authenticated origin.
                            drop(client);
                            let _ = app_handle.emit(
                                "veil://profile-updated",
                                serde_json::json!({
                                    "userId": user_id,
                                    "profileVersion": profile_version.to_string(),
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
                            // Server deletion (2) invalidates persisted channel
                            // authorization just as strongly as membership and
                            // role changes (3..=9). Metadata-only create/update
                            // events (0/1) do not require key rotation.
                            let roster_changed = matches!(event_type, 2..=9);
                            let mut diagnostics = Vec::new();
                            if roster_changed {
                                // Membership and role changes invalidate every
                                // affected channel roster without pausing DMs or
                                // unrelated groups.
                                let canonical_server_origin =
                                    event_binding.origin.canonical_server_origin();
                                let conversation_ids = match origin_scoped_channel_conversation_ids(
                                    &client,
                                    &canonical_server_origin,
                                    &server_id,
                                ) {
                                    Ok(conversation_ids) => conversation_ids,
                                    Err(error) => {
                                        drop(client);
                                        fail_closed_channel_scope_lookup(
                                            &state_inner,
                                            &app_handle,
                                            &server_id,
                                            &error,
                                        );
                                        continue;
                                    }
                                };
                                for conversation_id in conversation_ids {
                                    client.invalidate_device_roster_v1(&conversation_id);
                                    client.mark_channel_conversation(&conversation_id);
                                    if let Ok(diagnostic) = quarantine_conversation_state(
                                        &state_inner,
                                        &conversation_id,
                                        "membership_refresh_required",
                                        "server membership or role authorization changed",
                                    ) {
                                        diagnostics.push(diagnostic);
                                    }
                                }
                            }
                            drop(client);
                            for diagnostic in &diagnostics {
                                emit_authenticated_conversation_crypto_unavailable(
                                    &app_handle,
                                    diagnostic,
                                );
                            }
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
                            let canonical_server_origin =
                                event_binding.origin.canonical_server_origin();
                            let conversation_ids = match origin_scoped_channel_conversation_ids(
                                &client,
                                &canonical_server_origin,
                                &server_id,
                            ) {
                                Ok(conversation_ids) => conversation_ids,
                                Err(error) => {
                                    drop(client);
                                    fail_closed_channel_scope_lookup(
                                        &state_inner,
                                        &app_handle,
                                        &server_id,
                                        &error,
                                    );
                                    continue;
                                }
                            };
                            let mut diagnostics = Vec::new();
                            for conversation_id in conversation_ids {
                                client.invalidate_device_roster_v1(&conversation_id);
                                client.mark_channel_conversation(&conversation_id);
                                if let Ok(diagnostic) = quarantine_conversation_state(
                                    &state_inner,
                                    &conversation_id,
                                    "membership_refresh_required",
                                    "server channel authorization changed",
                                ) {
                                    diagnostics.push(diagnostic);
                                }
                            }
                            drop(client);
                            for diagnostic in &diagnostics {
                                emit_authenticated_conversation_crypto_unavailable(
                                    &app_handle,
                                    diagnostic,
                                );
                            }
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
                            sender_key_message,
                            route,
                        } => {
                            let conversation_id = route.conversation_id.clone();
                            if !live_conversation_origin_is_current(
                                &state_inner,
                                &app_handle,
                                &mut client,
                                &conversation_id,
                            ) {
                                drop(client);
                                continue;
                            }
                            if conversation_is_quarantined_fail_closed(
                                &state_inner,
                                &conversation_id,
                            ) {
                                drop(client);
                                continue;
                            }
                            let result = client
                                .process_sender_key_distribution_v1(&sender_key_message, &route)
                                .and_then(|_| {
                                    state_inner
                                        .runtime
                                        .block_on(client.flush_sender_key_receipts_v1())
                                        .map(|_| ())
                                });
                            match result {
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
                                    let detail = format!("sender-key distribution rejected: {e}");
                                    let _ = quarantine_live_conversation(
                                        &state_inner,
                                        &app_handle,
                                        &mut client,
                                        &conversation_id,
                                        true,
                                        "live_sender_key_distribution_rejected",
                                        &detail,
                                    );
                                    drop(client);
                                    let _ = app_handle.emit(
                                        "veil://error",
                                        serde_json::json!({
                                            "code": 4002,
                                            "message": detail,
                                        }),
                                    );
                                    let _ = app_handle.emit(
                                        "veil://membership-refresh-required",
                                        serde_json::json!({ "conversationId": conversation_id }),
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    {
        let _session_transition = state.session_transition.lock().map_err(|e| e.to_string())?;
        validate_authenticated_session_scope(
            &state,
            &result,
            &canonical_server_origin,
            requested_rest_binding.generation,
        )?;
    }

    Ok(AuthenticatedSessionScope {
        user_id: result,
        canonical_server_origin,
        binding_generation: requested_rest_binding.generation.to_string(),
    })
}

// ─── Messaging ────────────────────────────────────────

#[tauri::command]
fn send_message(
    state: State<'_, AppState>,
    conversation_id: String,
    text: String,
    reply_to_id: Option<String>,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<u64, String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    require_conversation_crypto_available(&state, &conversation_id)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    require_authenticated_conversation_origin(&state, &client, &conversation_id)?;
    if let Some(reply_to_id) = reply_to_id.as_deref() {
        require_persisted_message_conversation(&client, reply_to_id, &conversation_id)?;
    }
    state
        .runtime
        .block_on(client.send_message(&conversation_id, &text, reply_to_id.as_deref()))
}

#[tauri::command]
fn discard_failed_outgoing_message(
    state: State<'_, AppState>,
    local_message_id: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    let conversation_id = client
        .db()
        .ok_or("database not initialized")?
        .get_message_binding(&local_message_id)?
        .map(|binding| binding.0)
        .ok_or("failed outgoing message is absent from encrypted local storage")?;
    require_authenticated_conversation_origin(&state, &client, &conversation_id)?;
    client.discard_failed_outgoing_message(&local_message_id)
}

#[tauri::command]
fn edit_message(
    state: State<'_, AppState>,
    message_id: String,
    conversation_id: String,
    new_text: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<u64, String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    require_conversation_crypto_available(&state, &conversation_id)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    require_authenticated_conversation_origin(&state, &client, &conversation_id)?;
    require_persisted_message_conversation(&client, &message_id, &conversation_id)?;
    if client.is_channel_conversation(&conversation_id) {
        return Err(
            "editing encrypted group/channel messages is unavailable until the exact-device edit protocol is implemented"
                .to_string(),
        );
    }
    state
        .runtime
        .block_on(client.edit_message(&message_id, &conversation_id, &new_text))
}

#[tauri::command]
fn delete_message(
    state: State<'_, AppState>,
    message_id: String,
    conversation_id: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<u64, String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    require_conversation_crypto_available(&state, &conversation_id)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    require_authenticated_conversation_origin(&state, &client, &conversation_id)?;
    require_persisted_message_conversation(&client, &message_id, &conversation_id)?;
    state
        .runtime
        .block_on(client.delete_message(&message_id, &conversation_id))
}

#[tauri::command]
fn send_typing(
    state: State<'_, AppState>,
    conversation_id: String,
    started: bool,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    require_conversation_crypto_available(&state, &conversation_id)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    require_authenticated_conversation_origin(&state, &client, &conversation_id)?;
    state
        .runtime
        .block_on(client.send_typing(&conversation_id, started))
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri IPC fields intentionally stay explicit.
fn toggle_reaction(
    state: State<'_, AppState>,
    message_id: String,
    conversation_id: String,
    emoji: String,
    user_id: String,
    add: bool,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    require_conversation_crypto_available(&state, &conversation_id)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    require_authenticated_conversation_origin(&state, &client, &conversation_id)?;
    require_persisted_message_conversation(&client, &message_id, &conversation_id)?;
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
    let conversation_id = client
        .db()
        .ok_or("database not initialized")?
        .get_message_binding(&message_id)?
        .map(|binding| binding.0)
        .ok_or("message is absent from encrypted local storage")?;
    require_authenticated_conversation_origin(&state, &client, &conversation_id)?;
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
    expected_peer_identity_key: Option<String>,
) -> Result<String, String> {
    require_unlocked(&state)?;
    let _connect_transition = state.connect_transition.lock().map_err(|e| e.to_string())?;
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    decode_canonical_uuid("DM peer user id", &peer_user_id)?;
    // Reject malformed renderer input before the POST can create a server-side
    // conversation. The decoded value remains process-local and is compared
    // with the authenticated response before any local durable/runtime state
    // is published.
    let expected_peer_identity_key =
        parse_expected_dm_peer_identity_key(expected_peer_identity_key.as_deref())?;
    let authenticated_user_id = {
        let client = state.client.lock().map_err(|e| e.to_string())?;
        require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
        let authenticated_user_id = client.authenticated_user_id()?;
        if !our_user_id.is_empty() && our_user_id != authenticated_user_id {
            return Err("UI user id does not match the authenticated session".to_string());
        }
        authenticated_user_id
    };
    if peer_user_id == authenticated_user_id {
        return Err("DM peer must differ from the authenticated account".to_string());
    }

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
    validate_expected_dm_peer_identity_key(
        expected_peer_identity_key.as_ref(),
        &peer_identity_key,
    )?;
    let peer_signing_key = decode_b64_array::<32>(
        "peer_signing_key",
        body["peer_signing_key"]
            .as_str()
            .ok_or_else(|| "DM response missing peer_signing_key".to_string())?,
    )?;
    let requested_url = reqwest::Url::parse(&server_http_url)
        .map_err(|e| format!("invalid authenticated DM origin: {e}"))?;
    let canonical_server_origin = require_authenticated_rest_origin(&state, &requested_url)?
        .origin
        .canonical_server_origin();
    let created_at = identity_observed_at();

    // Fetch and validate the authenticated member directory without publishing
    // it yet. A newly created server conversation has no local origin row, so
    // the normal existing-conversation directory path cannot be used for this
    // preflight. Every substitution/continuity check below completes before
    // the first local durable/runtime binding is written.
    let members = fetch_conversation_directory_members(
        &state,
        &server_http_url,
        &authenticated_user_id,
        &conversation_id,
        Some(&live_action_binding),
    )?;
    let directory = pinned_account_directory_from_json(&members)?;
    {
        let mut client = state.client.lock().map_err(|e| e.to_string())?;
        require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
        if client.authenticated_user_id()? != authenticated_user_id {
            return Err("created DM directory user differs from authenticated session".to_string());
        }
        let peer = validate_created_dm_account_directory(
            &directory,
            &authenticated_user_id,
            &client.identity_key()?,
            &client.signing_key()?,
            &peer_user_id,
            &peer_identity_key,
            &peer_signing_key,
        )?;
        for (member_user_id, member) in &directory {
            client.ensure_user_identity_binding_compatible(member_user_id, member.identity_key)?;
            client.ensure_peer_signing_key_compatible(member.identity_key, member.signing_key)?;
        }
        let snapshots: Vec<AccountSnapshot> = directory
            .iter()
            .map(|(member_user_id, member)| AccountSnapshot {
                locator: ProfileLocator {
                    canonical_server_origin: canonical_server_origin.clone(),
                    user_id: member_user_id.clone(),
                    identity_key: member.identity_key,
                },
                signing_key: member.signing_key,
                username: Some(member.username.clone()),
                display_name: None,
                profile_version: None,
                profile_origin: canonical_server_origin.clone(),
                source: AccountSnapshotSource::AuthenticatedConversationDirectory,
                observed_at: created_at.clone(),
            })
            .collect();
        {
            let db = client.db().ok_or("database not initialized")?;
            // Persist the validated identity snapshots first. A durable
            // continuity conflict therefore fails before the conversation can
            // become addressable by its bare UUID.
            db.upsert_identity_directory(&snapshots)?;
            db.upsert_directory_conversation(
                &conversation_id,
                0,
                &canonical_server_origin,
                Some(&peer.username),
                Some(&peer_user_id),
                Some(peer_identity_key.as_slice()),
                None,
                &created_at,
            )?;
        }
        require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
        for (member_user_id, member) in &directory {
            client.remember_user_identity(member_user_id, member.identity_key)?;
            client.pin_peer_signing_key(member.identity_key, member.signing_key)?;
        }
        client.replace_authorized_conversation_senders(
            &conversation_id,
            directory.values().map(|member| member.identity_key),
        )?;
    }

    // Reopening an existing deterministic DM must never replace a healthy
    // Double Ratchet with a fresh one. Only fetch/consume a new prekey bundle
    // when no session exists locally.
    let session_exists = {
        let mut client = state.client.lock().map_err(|e| e.to_string())?;
        require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
        let exists = client.has_session(&peer_identity_key);
        if exists {
            client.bind_dm_conversation(&conversation_id, peer_identity_key)?;
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
            &live_action_binding,
        )?;
        let mut client = state.client.lock().map_err(|e| e.to_string())?;
        require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
        client.bind_dm_conversation(&conversation_id, peer_identity_key)?;
    } else if !session_exists {
        // The concurrent creator is responsible for the initial X3DH packet.
        // Cross-initiating here would install two incompatible sessions. Bind
        // the authenticated conversation and wait fail-closed for peer INITIAL;
        // send_message reports the missing session until that arrives.
        let mut client = state.client.lock().map_err(|e| e.to_string())?;
        require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
        client.bind_dm_conversation(&conversation_id, peer_identity_key)?;
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

/// Preserve a server-created ID even when its post-create crypto setup must be
/// quarantined. Returning an IPC error would invite duplicate groups when a
/// user retries a POST that already committed on the server.
fn preserve_created_group_outcome(
    conversation_id: String,
    crypto_setup: Result<(), String>,
) -> (String, Option<ConversationCryptoDiagnostic>) {
    let diagnostic = crypto_setup
        .err()
        .map(|error| ConversationCryptoDiagnostic {
            conversation_id: conversation_id.clone(),
            code: "group_crypto_setup_pending".to_string(),
            detail: bounded_diagnostic_detail(&error),
        });
    (conversation_id, diagnostic)
}

/// Create a new group on the server. Returns the conversation_id once the
/// canonical POST succeeded; subsequent crypto setup failures are quarantined.
#[tauri::command]
fn create_group(
    state: State<'_, AppState>,
    app: AppHandle,
    server_http_url: String,
    user_id: String,
    name: String,
) -> Result<String, String> {
    require_live_transport_ready(&state)?;
    let _connect_transition = state.connect_transition.lock().map_err(|e| e.to_string())?;
    require_live_transport_ready(&state)?;
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    let event_app = AuthenticatedEventAppHandle::for_current(&app)?;
    validate_directory_text("group name", &name, 256, false)?;
    let authenticated_user_id = {
        let client = state.client.lock().map_err(|error| error.to_string())?;
        require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
        client.authenticated_user_id()?
    };
    if user_id != authenticated_user_id {
        return Err("group creator does not match the authenticated session".to_string());
    }
    let resp = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        rest_api_url(&server_http_url, &["v1", "groups"])?,
        &authenticated_user_id,
        Some(serde_json::json!({ "name": name })),
    ))?;

    let conv_id = resp["conversation_id"]
        .as_str()
        .ok_or("no conversation_id")?
        .to_string();
    decode_canonical_uuid("created group conversation_id", &conv_id)?;
    let canonical_server_origin = authenticated_rest_binding(&state)?
        .origin
        .canonical_server_origin();
    let created_at = identity_observed_at();

    let crypto_setup = (|| -> Result<(), String> {
        {
            let mut client = state.client.lock().map_err(|e| e.to_string())?;
            require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
            client
                .db()
                .ok_or("database not initialized")?
                .upsert_directory_conversation(
                    &conv_id,
                    1,
                    &canonical_server_origin,
                    Some(&name),
                    None,
                    None,
                    None,
                    &created_at,
                )?;
            client.mark_channel_conversation(&conv_id);
        }

        // A newly-created group is unusable until the signed exact-device roster
        // is pinned and its device-owned Sender-Key generation has reached every
        // other eligible device (including our own other installations).
        let members = fetch_authorized_conversation_directory(
            &state,
            &server_http_url,
            &authenticated_user_id,
            &conv_id,
            Some(&live_action_binding),
        )?;
        let account_directory = pinned_account_directory_from_json(&members)?;
        if let Some(reason) = fetch_and_install_authenticated_device_directory(
            &state,
            &server_http_url,
            &authenticated_user_id,
            &conv_id,
            &account_directory,
            Some(&live_action_binding),
        )? {
            return Err(format!(
                "created group is waiting for a ready exact-device roster: {reason}"
            ));
        }
        distribute_pinned_sender_key(
            &state,
            &conv_id,
            SenderKeyDistributionPreparation::ReusePendingGeneration,
            Some(&live_action_binding),
        )?;
        Ok(())
    })();

    let (conv_id, diagnostic) = preserve_created_group_outcome(conv_id, crypto_setup);
    if let Some(diagnostic) = diagnostic {
        if let Ok(mut client) = state.client.lock() {
            if require_confirmed_live_action_binding_current(&state, &live_action_binding).is_ok() {
                client.invalidate_device_roster_v1(&conv_id);
                client.mark_channel_conversation(&conv_id);
            }
        }
        // The server has already committed the group at this point. A poisoned
        // local diagnostic mutex must not turn that successful POST into an IPC
        // error, because a UI retry could create a duplicate group.
        if let Ok(published) =
            quarantine_conversation_state(&state, &conv_id, &diagnostic.code, &diagnostic.detail)
        {
            emit_authenticated_conversation_crypto_unavailable(&event_app, &published);
        }
    }

    Ok(conv_id)
}

/// Get group members from the server.
fn pin_directory_member_keys(
    client: &mut VeilClient,
    members: &[serde_json::Value],
) -> Result<(), String> {
    let mut validated = Vec::with_capacity(members.len());
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
        client.ensure_peer_signing_key_compatible(identity, signing)?;
        validated.push((identity, signing));
    }
    for (identity, signing) in validated {
        client.pin_peer_signing_key(identity, signing)?;
    }
    Ok(())
}

fn fetch_conversation_directory_members(
    state: &AppState,
    server_http_url: &str,
    user_id: &str,
    conversation_id: &str,
    live_action_binding: Option<&RestBinding>,
) -> Result<Vec<serde_json::Value>, String> {
    decode_canonical_uuid("conversation directory request id", conversation_id)?;
    let request_url = rest_api_url(
        server_http_url,
        &["v1", "conversations", conversation_id, "members"],
    )?;
    let response = match live_action_binding {
        Some(binding) => state.runtime.block_on(rest_send_json_for_binding(
            state,
            reqwest::Method::GET,
            request_url,
            user_id,
            None,
            binding,
        )),
        None => state.runtime.block_on(rest_send_json(
            state,
            reqwest::Method::GET,
            request_url,
            user_id,
            None,
        )),
    }?;
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
    Ok(members)
}

fn fetch_authorized_conversation_directory(
    state: &AppState,
    server_http_url: &str,
    user_id: &str,
    conversation_id: &str,
    live_action_binding: Option<&RestBinding>,
) -> Result<Vec<serde_json::Value>, String> {
    let members = fetch_conversation_directory_members(
        state,
        server_http_url,
        user_id,
        conversation_id,
        live_action_binding,
    )?;

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
        decode_canonical_uuid("conversation directory member user_id", member_user_id)?;
        validate_directory_text(
            "conversation directory member username",
            username,
            MAX_DIRECTORY_USERNAME_BYTES,
            false,
        )?;
        if !user_ids.insert(member_user_id.to_string()) {
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
        validated.push((
            member_user_id.to_string(),
            identity,
            signing,
            username.to_string(),
        ));
    }

    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    if let Some(binding) = live_action_binding {
        require_confirmed_live_action_binding_current(state, binding)?;
    }
    require_authenticated_conversation_origin(state, &client, conversation_id)?;
    let authenticated_user_id = client.authenticated_user_id()?;
    if user_id != authenticated_user_id {
        return Err("conversation directory user differs from authenticated session".into());
    }
    let our_identity = client.identity_key()?;
    let our_signing = client.signing_key()?;
    if !validated
        .iter()
        .any(|(member_user_id, identity, signing, _)| {
            member_user_id == user_id && *identity == our_identity && *signing == our_signing
        })
    {
        return Err("authenticated identity is absent from conversation directory".to_string());
    }
    let requested_url = reqwest::Url::parse(server_http_url)
        .map_err(|e| format!("invalid authenticated directory origin: {e}"))?;
    let rest_binding = require_authenticated_rest_origin(state, &requested_url)?;
    let canonical_server_origin = rest_binding.origin.canonical_server_origin();
    let observed_at = identity_observed_at();
    let snapshots: Vec<AccountSnapshot> = validated
        .iter()
        .map(
            |(member_user_id, identity, signing, username)| AccountSnapshot {
                locator: ProfileLocator {
                    canonical_server_origin: canonical_server_origin.clone(),
                    user_id: member_user_id.clone(),
                    identity_key: *identity,
                },
                signing_key: *signing,
                username: Some(username.clone()),
                display_name: None,
                profile_version: None,
                profile_origin: canonical_server_origin.clone(),
                source: AccountSnapshotSource::AuthenticatedConversationDirectory,
                observed_at: observed_at.clone(),
            },
        )
        .collect();
    client
        .db()
        .ok_or("database not initialized")?
        .upsert_identity_directory(&snapshots)?;
    require_same_rest_binding(state, &requested_url, &rest_binding)?;
    for (member_user_id, identity, signing, _) in &validated {
        client.ensure_user_identity_binding_compatible(member_user_id, *identity)?;
        client.ensure_peer_signing_key_compatible(*identity, *signing)?;
    }
    for (member_user_id, identity, signing, _) in &validated {
        client.remember_user_identity(member_user_id, *identity)?;
        client.pin_peer_signing_key(*identity, *signing)?;
    }
    client.replace_authorized_conversation_senders(
        conversation_id,
        validated.iter().map(|(_, identity, _, _)| *identity),
    )?;
    require_session_still_unlocked(state)?;
    Ok(members)
}

fn pinned_account_directory_from_json(
    members: &[serde_json::Value],
) -> Result<std::collections::HashMap<String, PinnedDirectoryMember>, String> {
    let mut directory = std::collections::HashMap::with_capacity(members.len());
    let mut identities = std::collections::HashSet::with_capacity(members.len());
    for member in members {
        let user_id = member
            .get("user_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("conversation directory member is missing user_id")?;
        decode_canonical_uuid("conversation directory member user_id", user_id)?;
        let username = member
            .get("username")
            .and_then(serde_json::Value::as_str)
            .ok_or("conversation directory member is missing username")?;
        validate_directory_text(
            "conversation directory member username",
            username,
            MAX_DIRECTORY_USERNAME_BYTES,
            false,
        )?;
        let identity_key = decode_lower_hex_32(
            "conversation directory member identity_key",
            member
                .get("identity_key")
                .and_then(serde_json::Value::as_str)
                .ok_or("conversation directory member is missing identity_key")?,
        )?;
        let signing_key = decode_lower_hex_32(
            "conversation directory member signing_key",
            member
                .get("signing_key")
                .and_then(serde_json::Value::as_str)
                .ok_or("conversation directory member is missing signing_key")?,
        )?;
        if !identities.insert(identity_key) {
            return Err("conversation directory maps one identity to multiple users".to_string());
        }
        if directory
            .insert(
                user_id.to_string(),
                PinnedDirectoryMember {
                    username: username.to_string(),
                    identity_key,
                    signing_key,
                },
            )
            .is_some()
        {
            return Err("conversation directory repeats a member".to_string());
        }
    }
    Ok(directory)
}

fn validate_pinned_directory_self(
    directory: &std::collections::HashMap<String, PinnedDirectoryMember>,
    authenticated_user_id: &str,
    identity_key: &[u8; 32],
    signing_key: &[u8; 32],
) -> Result<(), String> {
    let own_member = directory
        .get(authenticated_user_id)
        .ok_or("authenticated user is absent from the account directory")?;
    if own_member.identity_key != *identity_key || own_member.signing_key != *signing_key {
        return Err("account directory returned substituted local identity keys".to_string());
    }
    Ok(())
}

fn fetch_authenticated_device_directory(
    state: &AppState,
    server_http_url: &str,
    user_id: &str,
    conversation_id: &str,
    live_action_binding: Option<&RestBinding>,
) -> Result<ParsedDeviceRoster, String> {
    require_unlocked(state)?;
    let response = state.runtime.block_on(rest_send_json(
        state,
        reqwest::Method::GET,
        rest_api_url(
            server_http_url,
            &["v1", "conversations", conversation_id, "device-directory"],
        )?,
        user_id,
        None,
    ))?;
    let parsed = parse_device_directory(response, conversation_id)?;
    let client = state.client.lock().map_err(|error| error.to_string())?;
    if let Some(binding) = live_action_binding {
        require_confirmed_live_action_binding_current(state, binding)?;
    }
    if client.authenticated_user_id()? != user_id {
        return Err("device directory user differs from authenticated session".to_string());
    }
    let our_identity = client.identity_key()?;
    let our_signing = client.signing_key()?;
    let our_user_id = decode_canonical_uuid("authenticated user id", user_id)?;
    let self_entry = parsed
        .devices
        .iter()
        .find(|device| device.user_id == our_user_id)
        .ok_or("authenticated account has no device in the device directory")?;
    if self_entry.account_identity_key != our_identity
        || self_entry.account_signing_key != our_signing
    {
        return Err("device directory substituted authenticated account keys".to_string());
    }
    require_session_still_unlocked(state)?;
    Ok(parsed)
}

fn invalidate_device_roster_for_binding(
    state: &AppState,
    conversation_id: &str,
    live_action_binding: Option<&RestBinding>,
) -> Result<(), String> {
    let mut client = state.client.lock().map_err(|error| error.to_string())?;
    if let Some(binding) = live_action_binding {
        require_confirmed_live_action_binding_current(state, binding)?;
    }
    client.invalidate_device_roster_v1(conversation_id);
    Ok(())
}

fn fetch_and_install_authenticated_device_directory(
    state: &AppState,
    server_http_url: &str,
    user_id: &str,
    conversation_id: &str,
    account_directory: &std::collections::HashMap<String, PinnedDirectoryMember>,
    live_action_binding: Option<&RestBinding>,
) -> Result<Option<String>, String> {
    let parsed = match fetch_authenticated_device_directory(
        state,
        server_http_url,
        user_id,
        conversation_id,
        live_action_binding,
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            invalidate_device_roster_for_binding(state, conversation_id, live_action_binding)?;
            return Err(error);
        }
    };
    if !parsed.ready {
        let reason = parsed
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "device_roster_not_ready".to_string());
        invalidate_device_roster_for_binding(state, conversation_id, live_action_binding)?;
        return Ok(Some(reason));
    }
    if let Err(error) = verify_device_directory_account_keys(&parsed, account_directory) {
        invalidate_device_roster_for_binding(state, conversation_id, live_action_binding)?;
        return Err(error);
    }
    let mut client = state.client.lock().map_err(|error| error.to_string())?;
    if let Some(binding) = live_action_binding {
        require_confirmed_live_action_binding_current(state, binding)?;
    }
    if client.authenticated_user_id()? != user_id {
        client.invalidate_device_roster_v1(conversation_id);
        return Err("device directory belongs to a stale authenticated session".to_string());
    }
    client.install_device_roster_v1(parsed.into())?;
    require_session_still_unlocked(state)?;
    Ok(None)
}

#[tauri::command]
fn get_group_members(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    group_id: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<Vec<serde_json::Value>, String> {
    let live_action_binding = capture_expected_live_action_binding(
        &state,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    fetch_authorized_conversation_directory(
        &state,
        &server_http_url,
        &user_id,
        &group_id,
        Some(&live_action_binding),
    )
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
    rest_send_json_with_expected_binding(state, method, url, user_id, body, None).await
}

async fn rest_send_json_for_binding(
    state: &AppState,
    method: reqwest::Method,
    url: String,
    user_id: &str,
    body: Option<serde_json::Value>,
    expected_binding: &RestBinding,
) -> Result<serde_json::Value, String> {
    rest_send_json_with_expected_binding(state, method, url, user_id, body, Some(expected_binding))
        .await
}

async fn rest_send_json_with_expected_binding(
    state: &AppState,
    method: reqwest::Method,
    url: String,
    user_id: &str,
    body: Option<serde_json::Value>,
    expected_binding: Option<&RestBinding>,
) -> Result<serde_json::Value, String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    require_unlocked(state)?;
    let parsed_url = reqwest::Url::parse(&url).map_err(|e| format!("invalid REST URL: {e}"))?;
    let rest_binding = require_authenticated_rest_origin(state, &parsed_url)?;
    validate_expected_rest_binding(&rest_binding, expected_binding)?;
    let authenticated_user_id = {
        let client = state.client.lock().map_err(|e| e.to_string())?;
        require_session_still_unlocked(state)?;
        require_same_rest_binding(state, &parsed_url, &rest_binding)?;
        if let Some(expected) = expected_binding {
            require_confirmed_live_action_binding_current(state, expected)?;
        }
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
        require_session_still_unlocked(state)?;
        require_same_rest_binding(state, &parsed_url, &rest_binding)?;
        if let Some(expected) = expected_binding {
            require_confirmed_live_action_binding_current(state, expected)?;
        }
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

fn pause_server_sender_keys(
    state: &AppState,
    app: &AuthenticatedEventAppHandle,
    expected_binding: &RestBinding,
    server_id: &str,
) -> Result<(), String> {
    let canonical_server_origin = expected_binding.origin.canonical_server_origin();
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(state, expected_binding)?;
    let conversation_ids =
        origin_scoped_channel_conversation_ids(&client, &canonical_server_origin, server_id)?;
    let mut diagnostics = Vec::with_capacity(conversation_ids.len());
    for conversation_id in conversation_ids {
        client.invalidate_device_roster_v1(&conversation_id);
        client.mark_channel_conversation(&conversation_id);
        diagnostics.push(quarantine_conversation_state(
            state,
            &conversation_id,
            "membership_refresh_required",
            "server roles or channel authorization changed; refresh the exact-device roster",
        )?);
        // Rotation is deliberately deferred until a fresh signed exact-device
        // directory is installed. Generating against the now-stale roster
        // would create another undistributable key and invites accidental
        // account-level fallback.
    }
    drop(client);
    for diagnostic in &diagnostics {
        emit_authenticated_conversation_crypto_unavailable(app, diagnostic);
    }
    Ok(())
}

fn prepare_server_authorization_change(
    state: &AppState,
    app: &AppHandle,
    request_url: &str,
    server_id: &str,
    expected_server_origin: &str,
    expected_binding_generation: &str,
) -> Result<AuthenticatedEventAppHandle, String> {
    let live_action_binding = capture_confirmed_live_action_binding(state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        expected_server_origin,
        expected_binding_generation,
    )?;
    // Validate the renderer's requested REST authority before touching local
    // channel rosters. The second exact-generation check happens under the
    // client mutex in `pause_server_sender_keys`, closing the queued-action
    // race with a replacement self-hosted origin.
    validate_live_action_rest_origin(&live_action_binding, request_url)?;
    let event_app = AuthenticatedEventAppHandle::new(app.clone(), live_action_binding.clone());
    if let Err(error) = pause_server_sender_keys(state, &event_app, &live_action_binding, server_id)
    {
        emit_server_membership_refresh_required(&event_app, server_id);
        return Err(error);
    }
    Ok(event_app)
}

fn origin_scoped_channel_conversation_ids(
    client: &VeilClient,
    canonical_server_origin: &str,
    server_id: &str,
) -> Result<Vec<String>, String> {
    client
        .db()
        .ok_or("database not initialized")?
        .list_origin_scoped_channel_conversation_ids(canonical_server_origin, server_id)
}

fn fail_closed_channel_scope_lookup(
    state: &AppState,
    app: &AuthenticatedEventAppHandle,
    server_id: &str,
    error: &str,
) {
    state.offline_sync_ready.store(false, Ordering::SeqCst);
    let _ = app.emit(
        "veil://error",
        serde_json::json!({
            "code": 5001,
            "message": format!("origin-scoped channel authorization lookup failed: {error}"),
        }),
    );
    let _ = app.emit(
        "veil://membership-refresh-required",
        serde_json::json!({ "serverId": server_id }),
    );
}

fn emit_server_membership_refresh_required(app: &AuthenticatedEventAppHandle, server_id: &str) {
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
#[allow(clippy::too_many_arguments)] // Security scope fields stay explicit at the IPC boundary.
fn get_network_profile(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    target_user_id: String,
    expected_identity_key: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<NetworkProfileView, String> {
    decode_canonical_uuid("profile requester user id", &user_id)?;
    decode_canonical_uuid("profile target user id", &target_user_id)?;
    let identity_key =
        decode_lower_hex_fixed::<32>("profile expected identity key", &expected_identity_key)?;
    let live_action_binding = capture_expected_live_action_binding(
        &state,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let request_url = rest_api_url(
        &server_http_url,
        &["v1", "users", &target_user_id, "profile"],
    )?;
    validate_live_action_rest_origin(&live_action_binding, &request_url)?;
    let canonical_server_origin = live_action_binding.origin.canonical_server_origin();
    let locator = ProfileLocator {
        canonical_server_origin: canonical_server_origin.clone(),
        user_id: target_user_id.clone(),
        identity_key,
    };

    {
        let client = state.client.lock().map_err(|error| error.to_string())?;
        require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
        if client.authenticated_user_id()? != user_id {
            return Err("profile requester differs from authenticated session".to_string());
        }
        let is_self = target_user_id == user_id;
        if is_self {
            if client.identity_key()? != identity_key {
                return Err("profile identity differs from the authenticated self".to_string());
            }
        } else if client
            .db()
            .ok_or("database not initialized")?
            .resolve_account_snapshot(&locator)?
            .is_none()
        {
            return Err("profile target has no exact pinned account entry".to_string());
        }
    }

    let response = state.runtime.block_on(rest_send_json_for_binding(
        &state,
        reqwest::Method::GET,
        request_url,
        &user_id,
        None,
        &live_action_binding,
    ))?;
    let response = parse_network_profile_response(response, &target_user_id)?;
    let profile = NetworkProfile {
        locator,
        username: response.username,
        display_name: response.display_name,
        about: response.about,
        profile_version: response.profile_version,
        profile_updated_at: response.profile_updated_at,
        observed_at: identity_observed_at(),
    };

    let _session_transition = state
        .session_transition
        .lock()
        .map_err(|error| error.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    let client = state.client.lock().map_err(|error| error.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    if client.authenticated_user_id()? != user_id {
        return Err("authenticated user changed before profile storage".to_string());
    }
    let is_self = target_user_id == user_id;
    let db = client.db().ok_or("database not initialized")?;
    if is_self {
        if client.identity_key()? != identity_key {
            return Err("authenticated identity changed before profile storage".to_string());
        }
        db.upsert_authenticated_network_profile(&profile, client.signing_key()?)?;
    } else {
        if db.resolve_account_snapshot(&profile.locator)?.is_none() {
            return Err("profile target binding disappeared before storage".to_string());
        }
        db.upsert_network_profile(&profile)?;
    }
    let proof = db.local_identity_verification(&profile.locator)?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    Ok(network_profile_view(&profile, proof, is_self))
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // Security scope fields stay explicit at the IPC boundary.
fn update_network_profile(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    expected_version: String,
    display_name: Option<String>,
    about: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<NetworkProfileView, String> {
    decode_canonical_uuid("profile user id", &user_id)?;
    let expected_version = canonical_profile_version(&expected_version)?;
    if expected_version > i64::MAX as u64 {
        return Err("profile version exceeds the server contract".to_string());
    }
    if let Some(display_name) = display_name.as_deref() {
        validate_profile_text("profile display name", display_name, 512, false)?;
    }
    validate_profile_text("profile about", &about, 2048, true)?;
    let live_action_binding = capture_expected_live_action_binding(
        &state,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let request_url = rest_api_url(&server_http_url, &["v1", "users", "me", "profile"])?;
    validate_live_action_rest_origin(&live_action_binding, &request_url)?;
    {
        let client = state.client.lock().map_err(|error| error.to_string())?;
        require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
        if client.authenticated_user_id()? != user_id {
            return Err("profile update user differs from authenticated session".to_string());
        }
    }
    let response = state.runtime.block_on(rest_send_json_for_binding(
        &state,
        reqwest::Method::PUT,
        request_url,
        &user_id,
        Some(serde_json::json!({
            "expected_version": expected_version,
            "display_name": display_name,
            "about": about,
        })),
        &live_action_binding,
    ))?;
    let response = parse_network_profile_response(response, &user_id)?;

    let _session_transition = state
        .session_transition
        .lock()
        .map_err(|error| error.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    let client = state.client.lock().map_err(|error| error.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    if client.authenticated_user_id()? != user_id {
        return Err("authenticated user changed before profile storage".to_string());
    }
    let profile = NetworkProfile {
        locator: ProfileLocator {
            canonical_server_origin: live_action_binding.origin.canonical_server_origin(),
            user_id,
            identity_key: client.identity_key()?,
        },
        username: response.username,
        display_name: response.display_name,
        about: response.about,
        profile_version: response.profile_version,
        profile_updated_at: response.profile_updated_at,
        observed_at: identity_observed_at(),
    };
    let db = client.db().ok_or("database not initialized")?;
    db.upsert_authenticated_network_profile(&profile, client.signing_key()?)?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    Ok(network_profile_view(
        &profile,
        LocalIdentityVerification::NotCompared,
        true,
    ))
}

fn exact_identity_verification_view(
    client: &VeilClient,
    canonical_server_origin: &str,
    target_user_id: &str,
    identity_key: [u8; 32],
) -> Result<IdentityVerificationView, String> {
    if client.authenticated_user_id()? == target_user_id {
        return Err("the current account cannot verify itself".to_string());
    }
    let locator = ProfileLocator {
        canonical_server_origin: canonical_server_origin.to_string(),
        user_id: target_user_id.to_string(),
        identity_key,
    };
    let db = client.db().ok_or("database not initialized")?;
    if db.resolve_account_snapshot(&locator)?.is_none() {
        return Err("identity verification target has no exact pinned account entry".to_string());
    }
    let (fingerprint_emoji, fingerprint_hex) = client.fingerprint(&identity_key)?;
    let proof = db.local_identity_verification(&locator)?;
    Ok(IdentityVerificationView {
        canonical_server_origin: canonical_server_origin.to_string(),
        user_id: target_user_id.to_string(),
        identity_key: hex::encode(identity_key),
        fingerprint_hex,
        fingerprint_emoji,
        proof_state: local_identity_verification_token(proof).to_string(),
    })
}

fn require_matching_identity_fingerprint(
    expected: &[u8; 32],
    actual_hex: &str,
) -> Result<(), String> {
    let actual = decode_lower_hex_fixed::<32>("computed identity fingerprint", actual_hex)?;
    if expected.ct_eq(&actual).unwrap_u8() != 1 {
        return Err("displayed identity fingerprint is stale or mismatched".to_string());
    }
    Ok(())
}

#[tauri::command]
fn get_identity_verification(
    state: State<'_, AppState>,
    user_id: String,
    target_user_id: String,
    expected_identity_key: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<IdentityVerificationView, String> {
    decode_canonical_uuid("verification requester user id", &user_id)?;
    decode_canonical_uuid("verification target user id", &target_user_id)?;
    let identity_key =
        decode_lower_hex_fixed::<32>("verification expected identity key", &expected_identity_key)?;
    let binding = capture_expected_live_action_binding(
        &state,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let canonical_server_origin = binding.origin.canonical_server_origin();
    let _session_transition = state
        .session_transition
        .lock()
        .map_err(|error| error.to_string())?;
    require_confirmed_live_action_binding_current(&state, &binding)?;
    let client = state.client.lock().map_err(|error| error.to_string())?;
    require_confirmed_live_action_binding_current(&state, &binding)?;
    if client.authenticated_user_id()? != user_id {
        return Err("verification requester differs from authenticated session".to_string());
    }
    let view = exact_identity_verification_view(
        &client,
        &canonical_server_origin,
        &target_user_id,
        identity_key,
    )?;
    require_confirmed_live_action_binding_current(&state, &binding)?;
    Ok(view)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // Exact comparison inputs stay explicit at the IPC boundary.
fn confirm_identity_verification(
    state: State<'_, AppState>,
    user_id: String,
    target_user_id: String,
    expected_identity_key: String,
    expected_fingerprint_hex: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<IdentityVerificationView, String> {
    decode_canonical_uuid("verification requester user id", &user_id)?;
    decode_canonical_uuid("verification target user id", &target_user_id)?;
    let identity_key =
        decode_lower_hex_fixed::<32>("verification expected identity key", &expected_identity_key)?;
    let expected_fingerprint = decode_lower_hex_fixed::<32>(
        "verification expected fingerprint",
        &expected_fingerprint_hex,
    )?;
    let binding = capture_expected_live_action_binding(
        &state,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let canonical_server_origin = binding.origin.canonical_server_origin();
    let _session_transition = state
        .session_transition
        .lock()
        .map_err(|error| error.to_string())?;
    require_confirmed_live_action_binding_current(&state, &binding)?;
    let client = state.client.lock().map_err(|error| error.to_string())?;
    require_confirmed_live_action_binding_current(&state, &binding)?;
    if client.authenticated_user_id()? != user_id {
        return Err("verification requester differs from authenticated session".to_string());
    }
    let mut view = exact_identity_verification_view(
        &client,
        &canonical_server_origin,
        &target_user_id,
        identity_key,
    )?;
    require_matching_identity_fingerprint(&expected_fingerprint, &view.fingerprint_hex)?;
    let locator = ProfileLocator {
        canonical_server_origin,
        user_id: target_user_id,
        identity_key,
    };
    client
        .db()
        .ok_or("database not initialized")?
        .mark_identity_verified(&locator, &identity_observed_at())?;
    view.proof_state = local_identity_verification_token(
        client
            .db()
            .ok_or("database not initialized")?
            .local_identity_verification(&locator)?,
    )
    .to_string();
    require_confirmed_live_action_binding_current(&state, &binding)?;
    Ok(view)
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
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<Vec<serde_json::Value>, String> {
    let live_action_binding = capture_expected_live_action_binding(
        &state,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let request_url = rest_api_url(&server_http_url, &["v1", "servers", &server_id, "members"])?;
    validate_live_action_rest_origin(&live_action_binding, &request_url)?;
    let resp = state.runtime.block_on(rest_send_json_for_binding(
        &state,
        reqwest::Method::GET,
        request_url,
        &user_id,
        None,
        &live_action_binding,
    ))?;
    let members = resp["members"].as_array().cloned().unwrap_or_default();
    if members.is_empty() || members.len() > 100_000 {
        return Err("server member directory count is outside client limits".to_string());
    }
    let directory = pinned_account_directory_from_json(&members)?;
    let canonical_server_origin = live_action_binding.origin.canonical_server_origin();
    let _session_transition = state.session_transition.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    if client.authenticated_user_id()? != user_id {
        return Err("server member directory user differs from authenticated session".to_string());
    }
    validate_pinned_directory_self(
        &directory,
        &user_id,
        &client.identity_key()?,
        &client.signing_key()?,
    )?;
    for (member_user_id, member) in &directory {
        client.ensure_user_identity_binding_compatible(member_user_id, member.identity_key)?;
        client.ensure_peer_signing_key_compatible(member.identity_key, member.signing_key)?;
    }
    let observed_at = identity_observed_at();
    let snapshots: Vec<AccountSnapshot> = directory
        .iter()
        .map(|(member_user_id, member)| AccountSnapshot {
            locator: ProfileLocator {
                canonical_server_origin: canonical_server_origin.clone(),
                user_id: member_user_id.clone(),
                identity_key: member.identity_key,
            },
            signing_key: member.signing_key,
            username: Some(member.username.clone()),
            display_name: None,
            profile_version: None,
            profile_origin: canonical_server_origin.clone(),
            source: AccountSnapshotSource::AuthenticatedConversationDirectory,
            observed_at: observed_at.clone(),
        })
        .collect();
    client
        .db()
        .ok_or("database not initialized")?
        .upsert_identity_directory(&snapshots)?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    pin_directory_member_keys(&mut client, &members)?;
    for (member_user_id, member) in &directory {
        client.remember_user_identity(member_user_id, member.identity_key)?;
    }
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    Ok(members)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri IPC fields intentionally stay explicit.
fn kick_server_member(
    state: State<'_, AppState>,
    app: AppHandle,
    server_http_url: String,
    user_id: String,
    server_id: String,
    target_user_id: String,
    reason: Option<String>,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let body = reason.map(|r| serde_json::json!({ "reason": r }));
    let request_url = rest_api_url(
        &server_http_url,
        &["v1", "servers", &server_id, "members", &target_user_id],
    )?;
    let event_app = prepare_server_authorization_change(
        &state,
        &app,
        &request_url,
        &server_id,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let result = state.runtime.block_on(rest_send_json_for_binding(
        &state,
        reqwest::Method::DELETE,
        request_url,
        &user_id,
        body,
        &event_app.binding,
    ));
    emit_server_membership_refresh_required(&event_app, &server_id);
    result.map(|_| ())
}

#[tauri::command]
fn list_channels(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<Vec<serde_json::Value>, String> {
    decode_canonical_uuid("channel directory server id", &server_id)?;
    let live_action_binding = capture_expected_live_action_binding(
        &state,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let request_url = rest_api_url(&server_http_url, &["v1", "servers", &server_id, "channels"])?;
    validate_live_action_rest_origin(&live_action_binding, &request_url)?;
    let resp = state.runtime.block_on(rest_send_json_for_binding(
        &state,
        reqwest::Method::GET,
        request_url,
        &user_id,
        None,
        &live_action_binding,
    ))?;
    let channels = resp
        .get("channels")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .ok_or("channel directory response is missing channels")?;
    if channels.len() > 10_000 {
        return Err("channel directory count exceeds client limits".to_string());
    }

    // Validate the complete signed page before making any local row visible.
    // The renderer is never trusted to supply a conversation origin or bind
    // an arbitrary conversation UUID to the selected server.
    let mut channel_ids = std::collections::HashSet::with_capacity(channels.len());
    let mut conversation_ids = std::collections::HashSet::new();
    let mut text_channels = Vec::new();
    for channel in &channels {
        let channel_id = channel
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or("channel directory entry is missing id")?;
        decode_canonical_uuid("channel directory id", channel_id)?;
        if !channel_ids.insert(channel_id.to_string()) {
            return Err("channel directory repeats a channel id".to_string());
        }
        if channel.get("server_id").and_then(serde_json::Value::as_str) != Some(server_id.as_str())
        {
            return Err("channel directory entry changed its server id".to_string());
        }
        let channel_type = channel
            .get("channel_type")
            .and_then(serde_json::Value::as_i64)
            .ok_or("channel directory entry is missing channel_type")?;
        if !(0..=2).contains(&channel_type) {
            return Err("channel directory entry has an invalid type".to_string());
        }
        let name = channel
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or("channel directory entry is missing name")?;
        validate_directory_text("channel directory name", name, 256, false)?;
        let created_at = channel
            .get("created_at")
            .and_then(serde_json::Value::as_str)
            .ok_or("channel directory entry is missing created_at")?;
        validate_utc_rfc3339_nano("channel directory created_at", created_at)?;
        let conversation_id = channel
            .get("conversation_id")
            .and_then(serde_json::Value::as_str);
        if channel_type == 0 {
            let conversation_id =
                conversation_id.ok_or("text channel directory entry is missing conversation_id")?;
            decode_canonical_uuid("channel directory conversation_id", conversation_id)?;
            if !conversation_ids.insert(conversation_id.to_string()) {
                return Err("channel directory repeats a conversation id".to_string());
            }
            text_channels.push((
                conversation_id.to_string(),
                name.to_string(),
                created_at.to_string(),
            ));
        } else if conversation_id.is_some() {
            return Err("non-text channel unexpectedly has a conversation id".to_string());
        }
    }

    let canonical_server_origin = live_action_binding.origin.canonical_server_origin();
    let _session_transition = state.session_transition.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    if client.authenticated_user_id()? != user_id {
        return Err("channel directory user differs from authenticated session".to_string());
    }
    let db = client.db().ok_or("database not initialized")?;
    db.upsert_directory_channels(&canonical_server_origin, &server_id, &text_channels)?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    Ok(channels)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri IPC fields intentionally stay explicit.
fn create_channel(
    state: State<'_, AppState>,
    app: AppHandle,
    server_http_url: String,
    user_id: String,
    server_id: String,
    name: String,
    channel_type: i16,
    category_id: Option<String>,
    topic: Option<String>,
) -> Result<serde_json::Value, String> {
    require_unlocked(&state)?;
    let _connect_transition = state.connect_transition.lock().map_err(|e| e.to_string())?;
    require_unlocked(&state)?;
    let event_app = AuthenticatedEventAppHandle::for_current(&app)?;
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
    let response = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        rest_api_url(&server_http_url, &["v1", "servers", &server_id, "channels"])?,
        &user_id,
        Some(body),
    ))?;
    // Only text channels have a backing conversation. The POST has already
    // committed on the server, so a local persistence failure must quarantine
    // that conversation without turning the result into a retryable create
    // error (which could duplicate the channel).
    if channel_type == 0 {
        let conversation_id = response
            .get("conversation_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        if let Some(conversation_id) = conversation_id {
            let scope_result = (|| -> Result<(), String> {
                decode_canonical_uuid("created channel conversation_id", &conversation_id)?;
                if response
                    .get("server_id")
                    .and_then(serde_json::Value::as_str)
                    != Some(server_id.as_str())
                {
                    return Err("created channel response changed its server id".to_string());
                }
                if response
                    .get("channel_type")
                    .and_then(serde_json::Value::as_i64)
                    != Some(i64::from(channel_type))
                {
                    return Err("created channel response changed its channel type".to_string());
                }
                let canonical_server_origin = authenticated_rest_binding(&state)?
                    .origin
                    .canonical_server_origin();
                let created_at = response
                    .get("created_at")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("created channel response is missing created_at")?;
                validate_utc_rfc3339_nano("created channel created_at", created_at)?;
                let response_name = response
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("created channel response is missing name")?;
                validate_directory_text("created channel name", response_name, 256, false)?;
                let mut client = state.client.lock().map_err(|error| error.to_string())?;
                client
                    .db()
                    .ok_or("database not initialized")?
                    .upsert_directory_conversation(
                        &conversation_id,
                        2,
                        &canonical_server_origin,
                        Some(response_name),
                        None,
                        None,
                        Some(&server_id),
                        created_at,
                    )?;
                client.mark_channel_conversation(&conversation_id);
                Ok(())
            })();

            if let Err(error) = scope_result {
                if let Ok(mut client) = state.client.lock() {
                    client.invalidate_device_roster_v1(&conversation_id);
                    client.mark_channel_conversation(&conversation_id);
                }
                if let Ok(diagnostic) = quarantine_conversation_state(
                    &state,
                    &conversation_id,
                    "channel_identity_scope_pending",
                    &error,
                ) {
                    emit_authenticated_conversation_crypto_unavailable(&event_app, &diagnostic);
                }
            }
        }
    }
    Ok(response)
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
    expected_server_origin: String,
    expected_binding_generation: String,
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
    let request_url = rest_api_url(
        &server_http_url,
        &["v1", "servers", &server_id, "roles", &role_id],
    )?;
    let event_app = prepare_server_authorization_change(
        &state,
        &app,
        &request_url,
        &server_id,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let result = state.runtime.block_on(rest_send_json_for_binding(
        &state,
        reqwest::Method::PATCH,
        request_url,
        &user_id,
        Some(serde_json::Value::Object(body)),
        &event_app.binding,
    ));
    emit_server_membership_refresh_required(&event_app, &server_id);
    result.map(|_| ())
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri IPC fields intentionally stay explicit.
fn delete_role(
    state: State<'_, AppState>,
    app: AppHandle,
    server_http_url: String,
    user_id: String,
    server_id: String,
    role_id: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let request_url = rest_api_url(
        &server_http_url,
        &["v1", "servers", &server_id, "roles", &role_id],
    )?;
    let event_app = prepare_server_authorization_change(
        &state,
        &app,
        &request_url,
        &server_id,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let result = state.runtime.block_on(rest_send_json_for_binding(
        &state,
        reqwest::Method::DELETE,
        request_url,
        &user_id,
        None,
        &event_app.binding,
    ));
    emit_server_membership_refresh_required(&event_app, &server_id);
    result.map(|_| ())
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri IPC fields intentionally stay explicit.
fn assign_role(
    state: State<'_, AppState>,
    app: AppHandle,
    server_http_url: String,
    user_id: String,
    server_id: String,
    target_user_id: String,
    role_id: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let request_url = rest_api_url(
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
    )?;
    let event_app = prepare_server_authorization_change(
        &state,
        &app,
        &request_url,
        &server_id,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let result = state.runtime.block_on(rest_send_json_for_binding(
        &state,
        reqwest::Method::PUT,
        request_url,
        &user_id,
        None,
        &event_app.binding,
    ));
    emit_server_membership_refresh_required(&event_app, &server_id);
    result.map(|_| ())
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri IPC fields intentionally stay explicit.
fn unassign_role(
    state: State<'_, AppState>,
    app: AppHandle,
    server_http_url: String,
    user_id: String,
    server_id: String,
    target_user_id: String,
    role_id: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let request_url = rest_api_url(
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
    )?;
    let event_app = prepare_server_authorization_change(
        &state,
        &app,
        &request_url,
        &server_id,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let result = state.runtime.block_on(rest_send_json_for_binding(
        &state,
        reqwest::Method::DELETE,
        request_url,
        &user_id,
        None,
        &event_app.binding,
    ));
    emit_server_membership_refresh_required(&event_app, &server_id);
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

// The legacy server/channel cache intentionally has no renderer IPC surface:
// its bare UUID rows cannot be used until a later origin-scoped cache schema.

// ─── Sender Keys (Phase E) ────────────────────────────

/// Mark a conversation as a channel — outgoing messages are encrypted with
/// per-group sender keys and incoming messages are decrypted via SenderKeyStore.
#[tauri::command]
fn mark_channel_conversation(
    state: State<'_, AppState>,
    conversation_id: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    require_authenticated_conversation_origin(&state, &client, &conversation_id)?;
    client.mark_channel_conversation(&conversation_id);
    Ok(())
}

/// Hydrate sender keys (outgoing + all incoming) for a channel from the local DB.
#[tauri::command]
fn hydrate_channel_sender_keys(
    state: State<'_, AppState>,
    conversation_id: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    require_authenticated_conversation_origin(&state, &client, &conversation_id)?;
    client
        .hydrate_channel_sender_keys(&conversation_id)
        .map(|_| ())
}

#[tauri::command]
fn sender_key_distribution_status(
    state: State<'_, AppState>,
    conversation_id: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<String, String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    require_authenticated_conversation_origin(&state, &client, &conversation_id)?;
    Ok(client
        .sender_key_distribution_status(&conversation_id)
        .to_string())
}

/// Distribute our outgoing sender key to a list of channel members
/// (sealed envelope per recipient identity key, sent via SenderKeyDist envelope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SenderKeyDistributionPreparation {
    ReusePendingGeneration,
    OfflineRefresh(OfflineSenderKeyRefresh),
}

fn distribute_pinned_sender_key(
    state: &AppState,
    conversation_id: &str,
    preparation: SenderKeyDistributionPreparation,
    live_action_binding: Option<&RestBinding>,
) -> Result<u32, String> {
    if live_action_binding.is_none() {
        // Native offline sync deliberately runs before renderer confirmation.
        require_unlocked(state)?;
    }
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    if let Some(binding) = live_action_binding {
        require_confirmed_live_action_binding_current(state, binding)?;
    }
    require_authenticated_conversation_origin(state, &client, conversation_id)?;
    client.mark_channel_conversation(conversation_id);
    let targets = client.sender_key_device_targets(conversation_id)?;
    if targets.len() > MAX_SYNC_SENDER_KEY_RECIPIENTS {
        client.mark_sender_key_distribution_failed(conversation_id);
        return Err(format!(
            "sender-key fanout exceeds {MAX_SYNC_SENDER_KEY_RECIPIENTS} exact devices"
        ));
    }
    if targets.is_empty() {
        // A one-device conversation needs no transport round trip, but still
        // requires a validated roster and a device-owned outgoing generation.
        client.mark_sender_key_distributed(conversation_id)?;
        return Ok(0);
    }
    let should_distribute = match preparation {
        SenderKeyDistributionPreparation::ReusePendingGeneration => {
            client.begin_sender_key_distribution(conversation_id)?
        }
        SenderKeyDistributionPreparation::OfflineRefresh(refresh) => {
            client.begin_offline_sender_key_distribution(conversation_id, refresh)?
        }
    };
    if !should_distribute {
        return Ok(0);
    }

    let mut seen = std::collections::HashSet::new();
    let mut sent = 0u32;
    let started = Instant::now();
    client.buffer_connection_events_during_sync();
    for target in targets {
        if let Some(binding) = live_action_binding {
            if let Err(error) = require_confirmed_live_action_binding_current(state, binding) {
                client.mark_sender_key_distribution_failed(conversation_id);
                return Err(error);
            }
        }
        if !seen.insert(target.device_id) {
            client.mark_sender_key_distribution_failed(conversation_id);
            return Err("validated device roster repeated an exact fanout target".to_string());
        }
        if !client.is_currently_authorized_sender(conversation_id, &target.account_identity_key) {
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
            .block_on(client.send_sender_key_to_device(&target))
        {
            client.mark_sender_key_distribution_failed(conversation_id);
            return Err(format!(
                "sender-key delivery to device {} failed: {error}",
                hex::encode(target.device_id)
            ));
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
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<u32, String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    // The renderer never chooses recipients. Fetch the signed, permission-
    // filtered directory for this exact conversation and pin it first.
    let members = fetch_authorized_conversation_directory(
        &state,
        &server_http_url,
        &user_id,
        &conversation_id,
        Some(&live_action_binding),
    );
    let members = match members {
        Ok(members) => members,
        Err(error) => {
            invalidate_device_roster_for_binding(
                &state,
                &conversation_id,
                Some(&live_action_binding),
            )?;
            return Err(error);
        }
    };
    let account_directory = pinned_account_directory_from_json(&members)?;
    if let Some(reason) = fetch_and_install_authenticated_device_directory(
        &state,
        &server_http_url,
        &user_id,
        &conversation_id,
        &account_directory,
        Some(&live_action_binding),
    )? {
        return Err(format!(
            "conversation exact-device roster is not ready: {reason}"
        ));
    }
    distribute_pinned_sender_key(
        &state,
        &conversation_id,
        SenderKeyDistributionPreparation::ReusePendingGeneration,
        Some(&live_action_binding),
    )
}

// ─── Phase 6: per-conversation crypto mode ───────────

// ─── Friends & Presence ───────────────────────────────

#[tauri::command]
fn send_friend_request(
    state: State<'_, AppState>,
    target_user_id: String,
    message: Option<String>,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    state
        .runtime
        .block_on(client.send_friend_request(&target_user_id, message.as_deref()))
}

#[tauri::command]
fn respond_friend_request(
    state: State<'_, AppState>,
    request_id: String,
    accept: bool,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    state
        .runtime
        .block_on(client.respond_friend_request(&request_id, accept))
}

#[tauri::command]
fn remove_friend(
    state: State<'_, AppState>,
    user_id: String,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    state.runtime.block_on(client.remove_friend(&user_id))
}

#[tauri::command]
fn request_friend_list(
    state: State<'_, AppState>,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
    state.runtime.block_on(client.request_friend_list())
}

#[tauri::command]
fn send_presence(
    state: State<'_, AppState>,
    status: i32,
    status_text: Option<String>,
    expected_server_origin: String,
    expected_binding_generation: String,
) -> Result<(), String> {
    let live_action_binding = capture_confirmed_live_action_binding(&state)?;
    validate_expected_live_action_binding(
        &live_action_binding,
        &expected_server_origin,
        &expected_binding_generation,
    )?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    require_confirmed_live_action_binding_current(&state, &live_action_binding)?;
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
    require_live_transport_ready(&state)?;
    let user_id = state
        .client
        .lock()
        .map_err(|e| e.to_string())?
        .authenticated_user_id()?;
    let mut url = reqwest::Url::parse(&rest_api_url(&server_http_url, &["v1", "users", "search"])?)
        .map_err(|e| format!("invalid server URL: {e}"))?;
    url.query_pairs_mut().append_pair("username", &username);
    let rest_binding = require_authenticated_rest_origin(&state, &url)?;

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
    decode_canonical_uuid("user search result user_id", peer_user_id)?;
    let peer_identity_key = decode_lower_hex_32(
        "user search result identity_key",
        result["identity_key"]
            .as_str()
            .ok_or_else(|| "directory response missing identity_key".to_string())?,
    )?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    require_live_transport_still_ready(&state)?;
    require_same_rest_binding(&state, &url, &rest_binding)?;
    if client.authenticated_user_id()? != user_id {
        return Err("authenticated user changed while resolving user search".to_string());
    }
    client.ensure_user_identity_binding_compatible(peer_user_id, peer_identity_key)?;
    client.remember_user_identity(peer_user_id, peer_identity_key)?;
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
    let client = state.client.lock().map_err(|e| e.to_string())?;
    if let Some(conversation_id) = conversation_id.as_deref() {
        require_authenticated_conversation_origin(&state, &client, conversation_id)?;
    }
    let canonical_server_origin = authenticated_rest_binding(&state)?
        .origin
        .canonical_server_origin();
    let allowed_conversations: std::collections::HashSet<String> = client
        .db()
        .ok_or("database not initialized")?
        .get_conversations()?
        .into_iter()
        .filter(|conversation| {
            conversation.server_origin.as_deref() == Some(canonical_server_origin.as_str())
        })
        .map(|conversation| conversation.id)
        .collect();
    drop(client);
    let hits = state
        .indexer
        .search(trimmed, conversation_id.as_deref(), limit)
        .map_err(|e| e.to_string())?;
    let result = hits
        .into_iter()
        .filter(|hit| allowed_conversations.contains(&hit.conversation_id))
        .map(SearchHitDto::from)
        .collect();
    require_session_still_unlocked(&state)?;
    Ok(result)
}

#[tauri::command]
fn clear_search_index(state: State<'_, AppState>) -> Result<(), String> {
    require_unlocked(&state)?;
    state.indexer.clear().map_err(|e| e.to_string())
}

fn rebuild_search_index_for_current_origin(state: &AppState) -> Result<usize, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    require_unlocked(state)?;
    let canonical_server_origin = authenticated_rest_binding(state)?
        .origin
        .canonical_server_origin();
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("database not initialized")?;
    state.indexer.clear().map_err(|e| e.to_string())?;
    let convs: Vec<_> = db
        .get_conversations()?
        .into_iter()
        .filter(|conversation| {
            conversation.server_origin.as_deref() == Some(canonical_server_origin.as_str())
        })
        .collect();
    let mut indexed = 0usize;
    for conv in convs {
        if let Err(error) = require_session_still_unlocked(state) {
            let _ = state.indexer.clear();
            return Err(error);
        }
        let msgs = db.get_messages(&conv.id, 100_000)?;
        for m in msgs {
            if indexed.is_multiple_of(64) {
                if let Err(error) = require_session_still_unlocked(state) {
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
    require_session_still_unlocked(state)?;
    Ok(indexed)
}

#[tauri::command]
fn rebuild_search_index(state: State<'_, AppState>) -> Result<usize, String> {
    rebuild_search_index_for_current_origin(&state)
}

/// Rebuild the process-memory-only search index after each unlock.
#[tauri::command]
fn ensure_search_backfill(state: State<'_, AppState>) -> Result<usize, String> {
    require_unlocked(&state)?;
    rebuild_search_index_for_current_origin(&state)
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
            let auto_lock_seconds = load_auto_lock_seconds().map_err(std::io::Error::other)?;

            app.manage(AppState {
                client: Mutex::new(VeilClient::new()),
                session_transition: Mutex::new(()),
                session_epoch: AtomicU64::new(0),
                connect_transition: Mutex::new(()),
                authenticated_rest_origin: Mutex::new(None),
                renderer_confirmed_rest_binding: Mutex::new(None),
                rest_binding_generation: AtomicU64::new(0),
                unlocked: AtomicBool::new(!pin_configured),
                pin_configured: AtomicBool::new(pin_configured),
                event_poller_started: AtomicBool::new(false),
                offline_sync_ready: AtomicBool::new(false),
                unavailable_conversations: Mutex::new(std::collections::HashMap::new()),
                lock_event_pending: AtomicBool::new(false),
                pin_throttle: Mutex::new(PinThrottle::default()),
                runtime: tokio::runtime::Runtime::new().expect("failed to create tokio runtime"),
                auto_lock_seconds: AtomicU64::new(auto_lock_seconds),
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
                let mut emit_locked = false;
                if let Ok(_transition) = state.session_transition.lock() {
                    emit_locked =
                        consume_pending_lock_event(&state.lock_event_pending, &state.unlocked);
                    if state.unlocked.load(Ordering::Acquire)
                        && inactivity_expired(&state).unwrap_or(true)
                        && reset_sensitive_state_locked(&state).is_ok()
                    {
                        state.lock_event_pending.store(false, Ordering::Release);
                        emit_locked = true;
                    }
                }
                if emit_locked {
                    let _ = watchdog_app.emit("veil://locked", serde_json::json!({}));
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
                                if configured_pin(&state) {
                                    // Clear native plaintext/key state and
                                    // renderer plaintext in one ordered
                                    // transition before hiding to tray.
                                    let reset = reset_sensitive_state_locked(&state);
                                    state.lock_event_pending.store(false, Ordering::Release);
                                    let _ = app_handle.emit("veil://locked", serde_json::json!({}));
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
                                } else {
                                    let _ = w.hide();
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
            open_project_repository,
            set_pin,
            verify_pin,
            has_pin,
            clear_pin,
            reveal_recovery_phrase,
            lock_app,
            sign_out,
            touch_activity,
            idle_seconds,
            get_auto_lock_seconds,
            set_auto_lock_seconds,
            init_from_seed,
            get_conversations,
            get_conversation_crypto_diagnostics,
            get_messages,
            upload_prekeys,
            connect_to_server,
            confirm_authenticated_session_scope,
            send_message,
            discard_failed_outgoing_message,
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
            appearance::get_appearance_settings,
            appearance::save_appearance_settings,
            appearance::choose_appearance_wallpaper,
            appearance::load_appearance_wallpaper,
            appearance::remove_appearance_wallpaper,
            create_group,
            get_group_members,
            send_friend_request,
            respond_friend_request,
            remove_friend,
            request_friend_list,
            send_presence,
            search_user,
            create_server,
            list_servers,
            get_server,
            get_network_profile,
            update_network_profile,
            get_identity_verification,
            confirm_identity_verification,
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
            mark_channel_conversation,
            hydrate_channel_sender_keys,
            sender_key_distribution_status,
            distribute_sender_key,
        ])
        .run(tauri::generate_context!())
        .expect("error while running veil");
}

#[cfg(test)]
mod e2ee_rest_tests {
    use super::{
        authenticated_event_payload, canonical_profile_version, consume_pending_lock_event,
        exact_confirmed_live_action_binding, invalidate_disconnected_binding, offline_sync_url,
        parse_device_directory, parse_expected_dm_peer_identity_key, parse_message_crypto_context,
        parse_network_profile_response, parse_prekey_bundle, preserve_created_group_outcome,
        publish_unlocked_session, require_matching_identity_fingerprint, resolve_auto_lock_seconds,
        rest_api_url, rest_authority, rest_canonical, rest_origin, rest_request_target,
        valid_auto_lock_seconds, valid_unlock_pin, validate_authenticated_binding_commit,
        validate_created_dm_account_directory, validate_expected_dm_peer_identity_key,
        validate_expected_live_action_binding, validate_expected_rest_binding,
        validate_live_action_rest_origin, validate_live_message_security_context,
        validate_next_cursor, validate_persisted_message_conversation,
        validate_pinned_directory_self, validate_rest_url, validate_server_endpoint_pair,
        validate_utc_rfc3339_nano, verify_device_directory_account_keys, AuthenticatedSessionScope,
        ConversationSyncIsolation, ParsedMessageCryptoContext, PinnedDirectoryMember, RestBinding,
        RestOrigin, DEFAULT_AUTO_LOCK_SECONDS,
    };
    use base64::Engine;

    fn authenticated_test_binding(host: &str, generation: u64) -> RestBinding {
        RestBinding {
            origin: RestOrigin {
                scheme: "https".to_string(),
                host: host.to_string(),
                port: 443,
            },
            generation,
        }
    }

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
    fn expected_dm_peer_identity_key_accepts_an_exact_authenticated_match() {
        let authenticated = [0x2au8; 32];
        let encoded = hex::encode(authenticated);
        let expected = parse_expected_dm_peer_identity_key(Some(&encoded))
            .unwrap()
            .expect("expected key must be decoded");

        assert_eq!(expected, authenticated);
        assert!(validate_expected_dm_peer_identity_key(Some(&expected), &authenticated).is_ok());
    }

    #[test]
    fn expected_dm_peer_identity_key_rejects_an_authenticated_mismatch() {
        let expected = [0x2au8; 32];
        let authenticated = [0x2bu8; 32];

        let error = validate_expected_dm_peer_identity_key(Some(&expected), &authenticated)
            .expect_err("identity substitution must fail closed");
        assert!(error.contains("does not match"));
    }

    #[test]
    fn expected_dm_peer_identity_key_rejects_noncanonical_hex() {
        assert!(parse_expected_dm_peer_identity_key(Some(&"2a".repeat(31))).is_err());
        assert!(parse_expected_dm_peer_identity_key(Some(&"2A".repeat(32))).is_err());
        assert!(parse_expected_dm_peer_identity_key(Some(&"zz".repeat(32))).is_err());
    }

    #[test]
    fn absent_expected_dm_peer_identity_key_preserves_directory_driven_creation() {
        let authenticated = [0x2au8; 32];
        let expected = parse_expected_dm_peer_identity_key(None).unwrap();

        assert!(expected.is_none());
        assert!(validate_expected_dm_peer_identity_key(expected.as_ref(), &authenticated).is_ok());
    }

    #[test]
    fn created_dm_directory_requires_an_exact_two_account_binding() {
        let local_user_id = "00000000-0000-0000-0000-000000000001";
        let peer_user_id = "00000000-0000-0000-0000-000000000002";
        let local_identity = [0x11; 32];
        let local_signing = [0x12; 32];
        let peer_identity = [0x21; 32];
        let peer_signing = [0x22; 32];
        let mut directory = std::collections::HashMap::from([
            (
                local_user_id.to_string(),
                PinnedDirectoryMember {
                    username: "alice".to_string(),
                    identity_key: local_identity,
                    signing_key: local_signing,
                },
            ),
            (
                peer_user_id.to_string(),
                PinnedDirectoryMember {
                    username: "bob".to_string(),
                    identity_key: peer_identity,
                    signing_key: peer_signing,
                },
            ),
        ]);

        let peer = validate_created_dm_account_directory(
            &directory,
            local_user_id,
            &local_identity,
            &local_signing,
            peer_user_id,
            &peer_identity,
            &peer_signing,
        )
        .unwrap();
        assert_eq!(peer.username, "bob");

        assert!(validate_created_dm_account_directory(
            &directory,
            local_user_id,
            &local_identity,
            &local_signing,
            local_user_id,
            &local_identity,
            &local_signing,
        )
        .is_err());
        assert!(validate_created_dm_account_directory(
            &directory,
            local_user_id,
            &local_identity,
            &local_signing,
            peer_user_id,
            &[0x23; 32],
            &peer_signing,
        )
        .is_err());

        directory.insert(
            "00000000-0000-0000-0000-000000000003".to_string(),
            PinnedDirectoryMember {
                username: "mallory".to_string(),
                identity_key: [0x31; 32],
                signing_key: [0x32; 32],
            },
        );
        assert!(validate_created_dm_account_directory(
            &directory,
            local_user_id,
            &local_identity,
            &local_signing,
            peer_user_id,
            &peer_identity,
            &peer_signing,
        )
        .is_err());
    }

    #[test]
    fn native_unlock_pin_boundary_matches_legacy_and_current_ui() {
        assert!(valid_unlock_pin("1234"));
        assert!(valid_unlock_pin("12345"));
        assert!(valid_unlock_pin("123456"));
        assert!(valid_unlock_pin("123456789012"));
        assert!(!valid_unlock_pin("123"));
        assert!(!valid_unlock_pin("1234567890123"));
        assert!(!valid_unlock_pin("１２３４５６"));
        assert!(!valid_unlock_pin("12a456"));
    }

    #[test]
    fn auto_lock_whitelist_matches_the_renderer_contract() {
        for seconds in [60, 300, 900, 1800, 3600] {
            assert!(valid_auto_lock_seconds(seconds));
        }
        for seconds in [0, 1, 59, 61, 299, 301, 3599, 3601, u64::MAX] {
            assert!(!valid_auto_lock_seconds(seconds));
        }
    }

    #[test]
    fn auto_lock_loader_defaults_only_for_a_missing_credential() {
        assert_eq!(
            resolve_auto_lock_seconds(Ok(None)).unwrap(),
            DEFAULT_AUTO_LOCK_SECONDS
        );
        assert_eq!(
            resolve_auto_lock_seconds(Ok(Some("900".to_string()))).unwrap(),
            900
        );
        assert!(resolve_auto_lock_seconds(Ok(Some("invalid".to_string()))).is_err());
        assert!(resolve_auto_lock_seconds(Ok(Some("120".to_string()))).is_err());

        let backend_error = "credential store unavailable".to_string();
        assert_eq!(
            resolve_auto_lock_seconds(Err(backend_error.clone())).unwrap_err(),
            backend_error
        );
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
        assert_eq!(
            bound.canonical_server_origin(),
            "https://chat.example.test:443"
        );
        assert_eq!(
            rest_origin(&reqwest::Url::parse("http://[::1]:9080").unwrap())
                .unwrap()
                .canonical_server_origin(),
            "http://[::1]:9080"
        );
    }

    #[test]
    fn authenticated_scope_keeps_native_origin_and_u64_generation_exact() {
        let scope = AuthenticatedSessionScope {
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            canonical_server_origin: "https://chat.example.test:443".to_string(),
            binding_generation: u64::MAX.to_string(),
        };
        assert_eq!(
            serde_json::to_value(scope).unwrap(),
            serde_json::json!({
                "userId": "550e8400-e29b-41d4-a716-446655440000",
                "canonicalServerOrigin": "https://chat.example.test:443",
                "bindingGeneration": "18446744073709551615",
            })
        );
    }

    #[test]
    fn durable_account_binding_commit_rejects_lock_and_client_replacement() {
        let user_id = "550e8400-e29b-41d4-a716-446655440000";
        let identity_key = [0x11; 32];
        let signing_key = [0x12; 32];

        assert!(validate_authenticated_binding_commit(
            true,
            user_id,
            user_id,
            &identity_key,
            &identity_key,
            &signing_key,
            &signing_key,
        )
        .is_ok());
        assert!(validate_authenticated_binding_commit(
            false,
            user_id,
            user_id,
            &identity_key,
            &identity_key,
            &signing_key,
            &signing_key,
        )
        .is_err());
        assert!(validate_authenticated_binding_commit(
            true,
            user_id,
            "550e8400-e29b-41d4-a716-446655440009",
            &identity_key,
            &identity_key,
            &signing_key,
            &signing_key,
        )
        .is_err());
        assert!(validate_authenticated_binding_commit(
            true,
            user_id,
            user_id,
            &identity_key,
            &[0x21; 32],
            &signing_key,
            &signing_key,
        )
        .is_err());
    }

    #[test]
    fn authenticated_member_directory_requires_the_exact_local_account() {
        let user_id = "550e8400-e29b-41d4-a716-446655440000";
        let identity_key = [0x31; 32];
        let signing_key = [0x32; 32];
        let mut directory = std::collections::HashMap::new();
        directory.insert(
            user_id.to_string(),
            PinnedDirectoryMember {
                username: "self".to_string(),
                identity_key,
                signing_key,
            },
        );

        assert!(
            validate_pinned_directory_self(&directory, user_id, &identity_key, &signing_key,)
                .is_ok()
        );
        assert!(validate_pinned_directory_self(
            &directory,
            "550e8400-e29b-41d4-a716-446655440009",
            &identity_key,
            &signing_key,
        )
        .is_err());
        assert!(
            validate_pinned_directory_self(&directory, user_id, &[0x41; 32], &signing_key,)
                .is_err()
        );
        assert!(
            validate_pinned_directory_self(&directory, user_id, &identity_key, &[0x42; 32],)
                .is_err()
        );
    }

    #[test]
    fn authenticated_event_payload_uses_the_exact_captured_binding() {
        let binding = authenticated_test_binding("chat.example.test", u64::MAX);
        let payload = authenticated_event_payload(
            &binding,
            "veil://message",
            serde_json::json!({
                "message": "hello",
                "serverScopeOrigin": "https://spoofed.example:443",
                "serverBindingGeneration": "1",
            }),
        )
        .unwrap();

        assert_eq!(payload["message"], "hello");
        assert_eq!(
            payload["serverScopeOrigin"],
            "https://chat.example.test:443"
        );
        assert_eq!(payload["serverBindingGeneration"], u64::MAX.to_string());
        assert!(authenticated_event_payload(&binding, "veil://message", "not-an-object").is_err());
    }

    #[test]
    fn renderer_live_action_is_rejected_before_exact_confirmation() {
        let binding = authenticated_test_binding("chat.example.test", 7);
        assert!(exact_confirmed_live_action_binding(Some(&binding), None, true, None).is_err());
        assert!(
            exact_confirmed_live_action_binding(Some(&binding), Some(&binding), false, None,)
                .is_err()
        );
    }

    #[test]
    fn renderer_live_action_accepts_only_the_exact_confirmed_scope() {
        let binding = authenticated_test_binding("chat.example.test", 7);
        assert_eq!(
            exact_confirmed_live_action_binding(
                Some(&binding),
                Some(&binding),
                true,
                Some(&binding),
            )
            .unwrap(),
            binding
        );
        assert!(validate_expected_live_action_binding(
            &binding,
            "https://chat.example.test:443",
            "7",
        )
        .is_ok());
        assert!(validate_expected_live_action_binding(
            &binding,
            "https://chat.example.test:443",
            "07",
        )
        .is_err());
    }

    #[test]
    fn renderer_live_action_rejects_another_rest_origin_before_local_mutation() {
        let binding = authenticated_test_binding("alpha.example.test", 7);
        let same_origin = reqwest::Url::parse(
            "https://ALPHA.example.test/v1/servers/550e8400-e29b-41d4-a716-446655440000/roles",
        )
        .unwrap();
        let other_origin = reqwest::Url::parse(
            "https://beta.example.test/v1/servers/550e8400-e29b-41d4-a716-446655440000/roles",
        )
        .unwrap();

        assert!(validate_live_action_rest_origin(&binding, same_origin.as_str()).is_ok());
        assert!(validate_live_action_rest_origin(&binding, other_origin.as_str()).is_err());
    }

    #[test]
    fn bound_rest_live_action_rejects_a_replacement_generation() {
        let old_binding = authenticated_test_binding("chat.example.test", 7);
        let replacement_binding = authenticated_test_binding("chat.example.test", 8);

        assert!(validate_expected_rest_binding(&old_binding, Some(&old_binding)).is_ok());
        assert!(validate_expected_rest_binding(&replacement_binding, Some(&old_binding)).is_err());
    }

    #[test]
    fn queued_old_live_action_is_rejected_after_reconfirmation() {
        let old_binding = authenticated_test_binding("chat.example.test", 7);
        let replacement_binding = authenticated_test_binding("chat.example.test", 8);
        assert!(exact_confirmed_live_action_binding(
            Some(&replacement_binding),
            Some(&replacement_binding),
            true,
            Some(&old_binding),
        )
        .is_err());
    }

    #[test]
    fn old_disconnect_cannot_clear_a_new_renderer_confirmation() {
        let old_binding = authenticated_test_binding("chat.example.test", 7);
        let replacement_binding = authenticated_test_binding("chat.example.test", 8);
        let mut renderer_confirmation = Some(replacement_binding.clone());
        assert!(!invalidate_disconnected_binding(
            &mut renderer_confirmation,
            &old_binding,
        ));
        assert_eq!(renderer_confirmation, Some(replacement_binding));
    }

    #[test]
    fn persisted_message_binding_rejects_cross_conversation_mutations() {
        assert!(
            validate_persisted_message_conversation(Some("conversation-a"), "conversation-a")
                .is_ok()
        );
        assert!(
            validate_persisted_message_conversation(Some("conversation-a"), "conversation-b")
                .is_err()
        );
        assert!(validate_persisted_message_conversation(None, "conversation-a").is_err());
    }

    #[test]
    fn old_disconnect_cannot_invalidate_a_replacement_binding() {
        let old_binding = authenticated_test_binding("chat.example.test", 7);
        let replacement_binding = authenticated_test_binding("chat.example.test", 8);
        let foreign_binding = authenticated_test_binding("other.example.test", 8);
        let mut current = Some(replacement_binding.clone());

        assert!(!invalidate_disconnected_binding(&mut current, &old_binding));
        assert_eq!(current, Some(replacement_binding.clone()));
        assert!(!invalidate_disconnected_binding(
            &mut current,
            &foreign_binding
        ));
        assert_eq!(current, Some(replacement_binding.clone()));
        assert!(invalidate_disconnected_binding(
            &mut current,
            &replacement_binding
        ));
        assert_eq!(current, None);
    }

    #[test]
    fn successful_unlock_suppresses_a_stale_pending_lock_event() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

        let pending = AtomicBool::new(true);
        let unlocked = AtomicBool::new(false);
        let epoch = AtomicU64::new(7);
        // All identity-init/unlock paths call this while holding the same
        // transition mutex as the watchdog's consume/check/emit operation.
        publish_unlocked_session(&pending, &unlocked, &epoch);
        assert_eq!(epoch.load(Ordering::Acquire), 8);
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

    #[test]
    fn conversation_failure_isolated_without_blocking_unrelated_dm_or_group() {
        let blocked = "00000000-0000-0000-0000-000000000101";
        let ready_group = "00000000-0000-0000-0000-000000000102";
        let ready_dm = "00000000-0000-0000-0000-000000000103";
        let mut isolation = ConversationSyncIsolation::default();
        isolation.block(
            blocked,
            "retained_sender_key_rejected",
            "generation 7 is unavailable\nretry safely",
        );
        // A later stage never hides the first actionable root cause.
        isolation.block(blocked, "message_history_unavailable", "secondary failure");

        let syncable: Vec<_> = [blocked, ready_group, ready_dm]
            .into_iter()
            .filter(|conversation_id| !isolation.is_blocked(conversation_id))
            .collect();
        assert_eq!(syncable, vec![ready_group, ready_dm]);

        let diagnostics = isolation.into_diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].conversation_id, blocked);
        assert_eq!(diagnostics[0].code, "retained_sender_key_rejected");
        assert_eq!(
            diagnostics[0].detail,
            "generation 7 is unavailable retry safely"
        );
    }

    #[test]
    fn post_create_crypto_failure_preserves_group_id_and_becomes_diagnostic() {
        let conversation_id = "00000000-0000-0000-0000-000000000104".to_string();
        let (returned_id, diagnostic) = preserve_created_group_outcome(
            conversation_id.clone(),
            Err("exact-device roster is not ready".to_string()),
        );
        assert_eq!(returned_id, conversation_id);
        let diagnostic = diagnostic.expect("post-create failure must be visible");
        assert_eq!(diagnostic.conversation_id, returned_id);
        assert_eq!(diagnostic.code, "group_crypto_setup_pending");

        let (returned_id, diagnostic) = preserve_created_group_outcome(returned_id.clone(), Ok(()));
        assert_eq!(returned_id, conversation_id);
        assert!(diagnostic.is_none());
    }

    fn ready_device_directory_fixture() -> serde_json::Value {
        let b64 = base64::engine::general_purpose::STANDARD;
        serde_json::json!({
            "conversation_id": "00000000-0000-0000-0000-000000000010",
            "roster_version": "7",
            "roster_commitment": "abababababababababababababababababababababababababababababababab",
            "ready": true,
            "required_capabilities": "3",
            "member_user_ids": [
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002"
            ],
            "devices": [
                {
                    "user_id": "00000000-0000-0000-0000-000000000001",
                    "username": "alice",
                    "account_identity_key": b64.encode([0x11; 32]),
                    "account_signing_key": b64.encode([0x12; 32]),
                    "device_id": "10101010101010101010101010101010",
                    "device_name": "alice desktop",
                    "binding": {
                        "device_id": "10101010101010101010101010101010",
                        "device_identity_key": b64.encode([0x13; 32]),
                        "device_signing_key": b64.encode([0x14; 32]),
                        "version": "1",
                        "capabilities": "3",
                        "status": 1,
                        "account_signature": b64.encode([0x15; 64]),
                        "created_at": "2026-07-11T18:00:00.123456789Z"
                    },
                    "status": 1,
                    "eligible": true
                },
                {
                    "user_id": "00000000-0000-0000-0000-000000000002",
                    "username": "bob",
                    "account_identity_key": b64.encode([0x21; 32]),
                    "account_signing_key": b64.encode([0x22; 32]),
                    "device_id": "20202020202020202020202020202020",
                    "device_name": "bob phone",
                    "binding": {
                        "device_id": "20202020202020202020202020202020",
                        "device_identity_key": b64.encode([0x23; 32]),
                        "device_signing_key": b64.encode([0x24; 32]),
                        "version": "9223372036854775807",
                        "capabilities": "3",
                        "status": 1,
                        "account_signature": b64.encode([0x25; 64]),
                        "created_at": "2026-07-11T18:00:00Z"
                    },
                    "status": 1,
                    "eligible": true
                }
            ]
        })
    }

    #[test]
    fn device_directory_parser_produces_bounded_canonical_crypto_input() {
        let parsed = parse_device_directory(
            ready_device_directory_fixture(),
            "00000000-0000-0000-0000-000000000010",
        )
        .unwrap();
        assert!(parsed.ready);
        assert_eq!(parsed.roster_version, 7);
        assert_eq!(parsed.required_capabilities, 3);
        assert_eq!(parsed.roster_commitment, [0xab; 32]);
        assert_eq!(parsed.member_user_ids.len(), 2);
        assert_eq!(parsed.devices.len(), 2);
        assert_eq!(parsed.devices[0].device_id, [0x10; 16]);
        assert_eq!(
            parsed.devices[1].binding.as_ref().unwrap().version,
            i64::MAX as u64
        );
        let candidate: veil_client::api::DeviceRosterCandidateV1 = parsed.into();
        assert_eq!(candidate.devices[0].binding.as_ref().unwrap().status, 1);
        assert_eq!(candidate.devices[1].user_id[15], 2);
    }

    #[test]
    fn device_directory_cannot_substitute_the_pinned_account_directory() {
        let roster = parse_device_directory(
            ready_device_directory_fixture(),
            "00000000-0000-0000-0000-000000000010",
        )
        .unwrap();
        let mut accounts = std::collections::HashMap::new();
        accounts.insert(
            "00000000-0000-0000-0000-000000000001".to_string(),
            PinnedDirectoryMember {
                username: "alice".to_string(),
                identity_key: [0x11; 32],
                signing_key: [0x12; 32],
            },
        );
        accounts.insert(
            "00000000-0000-0000-0000-000000000002".to_string(),
            PinnedDirectoryMember {
                username: "bob".to_string(),
                identity_key: [0x21; 32],
                signing_key: [0x22; 32],
            },
        );
        verify_device_directory_account_keys(&roster, &accounts).unwrap();
        accounts
            .get_mut("00000000-0000-0000-0000-000000000002")
            .unwrap()
            .signing_key = [0x42; 32];
        assert!(verify_device_directory_account_keys(&roster, &accounts).is_err());
    }

    #[test]
    fn device_directory_parser_rejects_noncanonical_numbers_and_encodings() {
        let conversation_id = "00000000-0000-0000-0000-000000000010";
        for invalid_version in ["0", "01", "9223372036854775808", "+7"] {
            let mut fixture = ready_device_directory_fixture();
            fixture["roster_version"] = serde_json::json!(invalid_version);
            assert!(parse_device_directory(fixture, conversation_id).is_err());
        }

        let mut numeric_version = ready_device_directory_fixture();
        numeric_version["roster_version"] = serde_json::json!(7);
        assert!(parse_device_directory(numeric_version, conversation_id).is_err());

        let mut uppercase_hex = ready_device_directory_fixture();
        uppercase_hex["roster_commitment"] =
            serde_json::json!("ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB");
        assert!(parse_device_directory(uppercase_hex, conversation_id).is_err());

        let mut unpadded_base64 = ready_device_directory_fixture();
        let encoded = unpadded_base64["devices"][0]["account_identity_key"]
            .as_str()
            .unwrap()
            .trim_end_matches('=')
            .to_string();
        unpadded_base64["devices"][0]["account_identity_key"] = serde_json::json!(encoded);
        assert!(parse_device_directory(unpadded_base64, conversation_id).is_err());
    }

    #[test]
    fn device_directory_parser_rejects_ambiguous_or_inconsistent_rosters() {
        let conversation_id = "00000000-0000-0000-0000-000000000010";

        let mut unknown_field = ready_device_directory_fixture();
        unknown_field["downgrade_allowed"] = serde_json::json!(true);
        assert!(parse_device_directory(unknown_field, conversation_id).is_err());

        let mut wrong_conversation = ready_device_directory_fixture();
        wrong_conversation["conversation_id"] =
            serde_json::json!("00000000-0000-0000-0000-000000000011");
        assert!(parse_device_directory(wrong_conversation, conversation_id).is_err());

        let mut inconsistent_ready = ready_device_directory_fixture();
        inconsistent_ready["ready"] = serde_json::json!(false);
        inconsistent_ready["reason"] = serde_json::json!("legacy_unbound_device");
        assert!(parse_device_directory(inconsistent_ready, conversation_id).is_err());

        let mut false_eligibility = ready_device_directory_fixture();
        false_eligibility["devices"][0]["eligible"] = serde_json::json!(false);
        false_eligibility["devices"][0]["exclusion_reason"] =
            serde_json::json!("missing_required_capabilities");
        assert!(parse_device_directory(false_eligibility, conversation_id).is_err());

        let mut binding_substitution = ready_device_directory_fixture();
        binding_substitution["devices"][0]["binding"]["device_id"] =
            serde_json::json!("30303030303030303030303030303030");
        assert!(parse_device_directory(binding_substitution, conversation_id).is_err());

        let mut repeated_device = ready_device_directory_fixture();
        repeated_device["devices"][1]["device_id"] =
            serde_json::json!("10101010101010101010101010101010");
        repeated_device["devices"][1]["binding"]["device_id"] =
            serde_json::json!("10101010101010101010101010101010");
        assert!(parse_device_directory(repeated_device, conversation_id).is_err());
    }

    #[test]
    fn persisted_message_crypto_context_is_strictly_all_or_none() {
        assert_eq!(
            parse_message_crypto_context("legacy_unknown", None, None, None, None, None).unwrap(),
            ParsedMessageCryptoContext::LegacyUnknown
        );
        assert!(
            parse_message_crypto_context("legacy_unknown", Some("1"), None, None, None, None,)
                .is_err()
        );
        assert!(
            parse_message_crypto_context("sender_key_v5", None, None, None, None, None).is_err()
        );
        assert!(parse_message_crypto_context("unknown", None, None, None, None, None).is_err());

        let parsed = parse_message_crypto_context(
            "sender_key_v5",
            Some("1"),
            Some("7"),
            Some("abababababababababababababababababababababababababababababababab"),
            Some("10101010101010101010101010101010"),
            Some("9"),
        )
        .unwrap();
        assert_eq!(
            parsed,
            ParsedMessageCryptoContext::SenderKeyV5 {
                roster_version: 7,
                roster_commitment: [0xab; 32],
                sender_device_id: [0x10; 16],
                sender_binding_version: 9,
            }
        );
    }

    #[test]
    fn live_message_mode_never_accepts_a_missing_or_cross_protocol_context() {
        use veil_client::api::{MessageSecurityContextV1, SenderKeyMessageSecurityContextV1};

        let sender_key = MessageSecurityContextV1::SenderKeyV5(SenderKeyMessageSecurityContextV1 {
            roster_version: 7,
            roster_commitment: [0xab; 32],
            sender_device_id: [0x10; 16],
            target_device_id: [0x20; 16],
            sender_binding_version: 9,
        });
        validate_live_message_security_context(false, None).unwrap();
        validate_live_message_security_context(true, Some(&sender_key)).unwrap();
        assert!(validate_live_message_security_context(true, None).is_err());
        assert!(validate_live_message_security_context(false, Some(&sender_key)).is_err());
    }

    #[test]
    fn signed_directory_timestamp_accepts_only_canonical_go_rfc3339_nano() {
        for valid in [
            "2026-07-11T18:00:00Z",
            "2024-02-29T23:59:59.1Z",
            "2026-07-11T18:00:00.123456789Z",
        ] {
            validate_utc_rfc3339_nano("created_at", valid).unwrap();
        }
        for invalid in [
            "2026-02-29T18:00:00Z",
            "2026-04-31T18:00:00Z",
            "2026-07-11T18:00:00.10Z",
            "2026-07-11T18:00:00+00:00",
            "2026-07-11t18:00:00Z",
        ] {
            assert!(validate_utc_rfc3339_nano("created_at", invalid).is_err());
        }
    }

    #[test]
    fn network_profile_response_is_strict_and_bound_to_the_requested_user() {
        let user_id = "00000000-0000-0000-0000-0000000000a1";
        let valid = serde_json::json!({
            "user_id": user_id,
            "username": "alice",
            "display_name": "Alice",
            "about": "first line\nsecond line",
            "profile_version": 7,
            "profile_updated_at": "2026-07-13T08:00:00Z"
        });
        assert_eq!(
            parse_network_profile_response(valid.clone(), user_id)
                .unwrap()
                .profile_version,
            7
        );

        let mut other_user = valid.clone();
        other_user["user_id"] = serde_json::json!("00000000-0000-0000-0000-0000000000a2");
        assert!(parse_network_profile_response(other_user, user_id).is_err());

        let mut unknown_field = valid.clone();
        unknown_field["avatar_url"] = serde_json::json!("https://example.test/avatar.png");
        assert!(parse_network_profile_response(unknown_field, user_id).is_err());

        let mut bidi = valid;
        bidi["about"] = serde_json::json!("safe\u{202e}evil");
        assert!(parse_network_profile_response(bidi, user_id).is_err());
    }

    #[test]
    fn profile_version_from_renderer_is_canonical() {
        assert_eq!(canonical_profile_version("0").unwrap(), 0);
        assert_eq!(canonical_profile_version("42").unwrap(), 42);
        for invalid in ["", "00", "01", "+1", "-1", " 1"] {
            assert!(canonical_profile_version(invalid).is_err());
        }
    }

    #[test]
    fn identity_verification_confirms_the_exact_displayed_fingerprint() {
        let expected = [0x41; 32];
        require_matching_identity_fingerprint(&expected, &hex::encode(expected)).unwrap();
        assert!(
            require_matching_identity_fingerprint(&expected, &hex::encode([0x42; 32])).is_err()
        );
        assert!(require_matching_identity_fingerprint(&expected, &"41".repeat(31)).is_err());
        assert!(require_matching_identity_fingerprint(&expected, &"AA".repeat(32)).is_err());
    }
}
