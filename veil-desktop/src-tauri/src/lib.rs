use std::sync::Mutex;
use std::time::Instant;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use veil_client::api::VeilClient;
use veil_client::connection::ConnectionEvent;
use veil_store::keychain;

struct AppState {
    client: Mutex<VeilClient>,
    runtime: tokio::runtime::Runtime,
    last_activity: Mutex<Instant>,
}

const KEYCHAIN_ACCOUNT: &str = "veil-default";
const PIN_HASH_ACCOUNT: &str = "veil-pin-hash";
const PIN_SALT_ACCOUNT: &str = "veil-pin-salt";

// ─── Identity ─────────────────────────────────────────

#[tauri::command]
fn generate_mnemonic() -> String {
    veil_crypto::keys::generate_mnemonic().to_string()
}

#[tauri::command]
fn validate_mnemonic_cmd(mnemonic: &str) -> bool {
    veil_crypto::keys::validate_mnemonic(mnemonic)
}

#[tauri::command]
fn init_identity(state: State<'_, AppState>, mnemonic: &str) -> Result<String, String> {
    let kp = veil_crypto::IdentityKeyPair::from_mnemonic(mnemonic)?;
    let hex_key = hex::encode(kp.x25519_public_bytes());
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    *client = VeilClient::from_identity(kp);
    Ok(hex_key)
}

#[tauri::command]
fn get_identity_key(state: State<'_, AppState>) -> Result<String, String> {
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let key = client.identity_key()?;
    Ok(hex::encode(key))
}

#[tauri::command]
fn store_seed(mnemonic: &str) -> Result<(), String> {
    keychain::store_seed(KEYCHAIN_ACCOUNT, mnemonic)
}

#[tauri::command]
fn get_stored_seed() -> Result<Option<String>, String> {
    if keychain::has_seed(KEYCHAIN_ACCOUNT) {
        keychain::get_seed(KEYCHAIN_ACCOUNT).map(Some)
    } else {
        Ok(None)
    }
}

// ─── PIN Lock ─────────────────────────────────────────

#[tauri::command]
fn set_pin(pin: String) -> Result<(), String> {
    // Generate random salt
    let mut salt = [0u8; 32];
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .map_err(|e| e.to_string())?
        .read_exact(&mut salt)
        .map_err(|e| e.to_string())?;

    let hash = veil_crypto::kdf::derive_key_from_pin(&pin, &salt)?;
    keychain::store_seed(PIN_HASH_ACCOUNT, &hex::encode(hash))?;
    keychain::store_seed(PIN_SALT_ACCOUNT, &hex::encode(salt))?;
    Ok(())
}

#[tauri::command]
fn verify_pin(state: State<'_, AppState>, pin: String) -> Result<bool, String> {
    let stored_hash = keychain::get_seed(PIN_HASH_ACCOUNT)?;
    let stored_salt = keychain::get_seed(PIN_SALT_ACCOUNT)?;

    let salt_bytes = hex::decode(&stored_salt).map_err(|e| e.to_string())?;
    let salt: [u8; 32] = salt_bytes
        .try_into()
        .map_err(|_| "invalid salt length".to_string())?;

    let hash = veil_crypto::kdf::derive_key_from_pin(&pin, &salt)?;
    let matches = hex::encode(hash) == stored_hash;

    if matches {
        // Reset activity timer on successful unlock
        *state.last_activity.lock().map_err(|e| e.to_string())? = Instant::now();
    }

    Ok(matches)
}

#[tauri::command]
fn has_pin() -> bool {
    keychain::has_seed(PIN_HASH_ACCOUNT)
}

#[tauri::command]
fn clear_pin() -> Result<(), String> {
    let _ = keychain::delete_seed(PIN_HASH_ACCOUNT);
    let _ = keychain::delete_seed(PIN_SALT_ACCOUNT);
    Ok(())
}

#[tauri::command]
fn touch_activity(state: State<'_, AppState>) {
    if let Ok(mut t) = state.last_activity.lock() {
        *t = Instant::now();
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

// ─── Connection ───────────────────────────────────────

#[tauri::command]
fn connect_to_server(
    state: State<'_, AppState>,
    app: AppHandle,
    server_url: String,
) -> Result<String, String> {
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    let result = state.runtime.block_on(client.connect(&server_url))?;

    // Start background event polling loop
    // We'll poll every 50ms and emit events to the UI
    let app_handle = app.clone();
    std::thread::spawn(move || {
        let state_inner = app_handle.state::<AppState>();
        loop {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let mut client: std::sync::MutexGuard<'_, VeilClient> = match state_inner.client.lock() {
                Ok(c) => c,
                Err(_) => break,
            };
            let event = state_inner.runtime.block_on(client.poll_event());
            drop(client); // Release lock before emitting

            if let Some(evt) = event {
                match evt {
                    ConnectionEvent::MessageReceived {
                        message_id,
                        conversation_id,
                        sender_identity_key,
                        sender_username,
                        ciphertext,
                        server_timestamp,
                        ..
                    } => {
                        // For now, treat ciphertext as plaintext (pre-E2E)
                        let text = String::from_utf8_lossy(&ciphertext).to_string();
                        let _ = app_handle.emit(
                            "veil://message",
                            serde_json::json!({
                                "messageId": message_id,
                                "conversationId": conversation_id,
                                "senderKey": hex::encode(&sender_identity_key),
                                "senderName": sender_username,
                                "text": text,
                                "timestamp": server_timestamp / 1_000_000, // ns → ms
                            }),
                        );
                    }
                    ConnectionEvent::MessageAcked {
                        message_id,
                        ref_seq,
                        ..
                    } => {
                        let _ = app_handle.emit(
                            "veil://message-ack",
                            serde_json::json!({
                                "messageId": message_id,
                                "refSeq": ref_seq,
                            }),
                        );
                    }
                    ConnectionEvent::Disconnected { reason } => {
                        let _ = app_handle.emit(
                            "veil://disconnected",
                            serde_json::json!({ "reason": reason }),
                        );
                        break;
                    }
                    ConnectionEvent::Error { code, message } => {
                        let _ = app_handle.emit(
                            "veil://error",
                            serde_json::json!({ "code": code, "message": message }),
                        );
                    }
                    _ => {}
                }
            }
        }
    });

    Ok(result)
}

// ─── Messaging ────────────────────────────────────────

#[tauri::command]
fn send_message(
    state: State<'_, AppState>,
    conversation_id: String,
    text: String,
) -> Result<u64, String> {
    let client = state.client.lock().map_err(|e| e.to_string())?;
    state
        .runtime
        .block_on(client.send_message(&conversation_id, &text))
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
    // POST /v1/conversations/dm to the Go server
    let resp = state.runtime.block_on(async {
        let http = reqwest::Client::new();
        http.post(format!("{}/v1/conversations/dm", server_http_url))
            .json(&serde_json::json!({
                "user_id_1": our_user_id,
                "user_id_2": peer_user_id,
            }))
            .send()
            .await
            .map_err(|e| format!("http request failed: {e}"))
    })?;

    let body: serde_json::Value = state
        .runtime
        .block_on(resp.json())
        .map_err(|e| format!("invalid json: {e}"))?;

    body["conversation_id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "no conversation_id in response".to_string())
}

#[tauri::command]
fn is_connected(state: State<'_, AppState>) -> bool {
    let client = state.client.lock().unwrap_or_else(|e| e.into_inner());
    client.is_connected()
}

// ─── App ──────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    tauri::Builder::default()
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_deep_link::init())
        .manage(AppState {
            client: Mutex::new(VeilClient::new()),
            runtime,
            last_activity: Mutex::new(Instant::now()),
        })
        .setup(|app| {
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
                        let _ = w.hide();
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
            store_seed,
            get_stored_seed,
            set_pin,
            verify_pin,
            has_pin,
            clear_pin,
            touch_activity,
            idle_seconds,
            connect_to_server,
            send_message,
            create_dm,
            is_connected,
        ])
        .run(tauri::generate_context!())
        .expect("error while running veil");
}
