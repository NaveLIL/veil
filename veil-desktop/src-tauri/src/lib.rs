use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_notification::NotificationExt;
use veil_client::api::VeilClient;
use veil_client::connection::ConnectionEvent;
use veil_store::keychain;

struct AppState {
    client: Mutex<VeilClient>,
    runtime: tokio::runtime::Runtime,
    last_activity: Mutex<Instant>,
    db_dir: PathBuf,
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
    let db_path = state.db_dir.join("veil.db");
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    client.init_with_mnemonic(mnemonic, &db_path)?;
    let hex_key = hex::encode(client.identity_key()?);
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
    // Generate random salt (cross-platform)
    let mut salt = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|e| format!("RNG failed: {e}"))?;

    let hash = veil_crypto::kdf::derive_key_from_pin(&pin, &salt)?;
    keychain::store_seed(PIN_HASH_ACCOUNT, &hex::encode(hash))?;
    keychain::store_seed(PIN_SALT_ACCOUNT, &hex::encode(salt))?;
    Ok(())
}

#[tauri::command]
async fn verify_pin(state: State<'_, AppState>, pin: String) -> Result<bool, String> {
    let stored_hash = keychain::get_seed(PIN_HASH_ACCOUNT)?;
    let stored_salt = keychain::get_seed(PIN_SALT_ACCOUNT)?;

    // Run Argon2id off main thread so WebView animations keep rendering
    let matches = tokio::task::spawn_blocking(move || -> Result<bool, String> {
        let salt_bytes = hex::decode(&stored_salt).map_err(|e| e.to_string())?;
        let salt: [u8; 32] = salt_bytes
            .try_into()
            .map_err(|_| "invalid salt length".to_string())?;
        let hash = veil_crypto::kdf::derive_key_from_pin(&pin, &salt)?;
        Ok(hex::encode(hash) == stored_hash)
    })
    .await
    .map_err(|e| e.to_string())??;

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

// ─── DB Persistence ───────────────────────────────────

/// Re-initialize client from stored seed (called after PIN unlock on restart).
/// Async so the heavy Argon2id work runs off the main thread.
#[tauri::command]
async fn init_from_seed(state: State<'_, AppState>) -> Result<String, String> {
    let mnemonic = keychain::get_seed(KEYCHAIN_ACCOUNT)?;
    let db_path = state.db_dir.join("veil.db");
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    client.init_with_mnemonic(&mnemonic, &db_path)?;
    let hex_key = hex::encode(client.identity_key()?);
    Ok(hex_key)
}

/// Get persisted conversations from the encrypted DB.
#[tauri::command]
fn get_conversations(state: State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("database not initialized")?;
    let convs = db.get_conversations()?;
    Ok(convs
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
        .collect())
}

/// Get persisted messages for a conversation.
#[tauri::command]
fn get_messages(
    state: State<'_, AppState>,
    conversation_id: String,
    limit: Option<u32>,
) -> Result<Vec<serde_json::Value>, String> {
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("database not initialized")?;
    let msgs = db.get_messages(&conversation_id, limit.unwrap_or(200))?;
    Ok(msgs
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "id": m.id,
                "conversationId": m.conversation_id,
                "senderKey": hex::encode(&m.sender_key),
                "text": m.plaintext,
                "isOwn": m.is_outgoing,
                "timestamp": m.server_timestamp.unwrap_or(0),
                "createdAt": m.created_at,
                "replyToId": m.reply_to_id,
            })
        })
        .collect())
}

/// Generate and upload prekeys for X3DH key exchange.
#[tauri::command]
fn upload_prekeys(state: State<'_, AppState>, server_http_url: String) -> Result<(), String> {
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    let prekey_set = client.generate_prekeys()?;
    let identity_key = hex::encode(client.identity_key()?);

    // Upload via REST API
    let otks: Vec<serde_json::Value> = prekey_set
        .otk_publics
        .iter()
        .map(|(key, id)| {
            serde_json::json!({
                "key": hex::encode(key),
                "id": id,
            })
        })
        .collect();

    state.runtime.block_on(async {
        let http = reqwest::Client::new();
        http.post(format!("{}/v1/prekeys", server_http_url))
            .json(&serde_json::json!({
                "identity_key": identity_key,
                "signing_key": hex::encode(prekey_set.signing_key),
                "signed_prekey": hex::encode(prekey_set.spk_public),
                "signed_prekey_id": prekey_set.spk_id,
                "signed_prekey_signature": hex::encode(prekey_set.spk_signature),
                "one_time_prekeys": otks,
            }))
            .send()
            .await
            .map_err(|e| format!("upload prekeys: {e}"))
    })?;

    Ok(())
}

/// Fetch a peer's prekey bundle and establish an encrypted session.
#[tauri::command]
fn establish_session(
    state: State<'_, AppState>,
    server_http_url: String,
    peer_identity_key: String,
) -> Result<(), String> {
    let bundle_json: serde_json::Value = state.runtime.block_on(async {
        let http = reqwest::Client::new();
        let resp = http
            .get(format!(
                "{}/v1/prekeys/{}",
                server_http_url, peer_identity_key
            ))
            .send()
            .await
            .map_err(|e| format!("fetch prekeys: {e}"))?;
        resp.json().await.map_err(|e| format!("parse prekeys: {e}"))
    })?;

    // Parse bundle from JSON
    let ik = hex::decode(bundle_json["identity_key"].as_str().unwrap_or(""))
        .map_err(|e| format!("decode ik: {e}"))?;
    let spk = hex::decode(bundle_json["signed_prekey"].as_str().unwrap_or(""))
        .map_err(|e| format!("decode spk: {e}"))?;
    let spk_sig = hex::decode(
        bundle_json["signed_prekey_signature"]
            .as_str()
            .unwrap_or(""),
    )
    .map_err(|e| format!("decode sig: {e}"))?;
    let signing = hex::decode(bundle_json["signing_key"].as_str().unwrap_or(""))
        .map_err(|e| format!("decode signing: {e}"))?;
    let spk_id = bundle_json["signed_prekey_id"].as_u64().unwrap_or(1) as u32;

    let opk = bundle_json["one_time_prekey"]
        .as_str()
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| if b.len() == 32 { Some(b) } else { None });
    let opk_id = bundle_json["one_time_prekey_id"].as_u64().map(|v| v as u32);

    if ik.len() != 32 || spk.len() != 32 || spk_sig.len() != 64 || signing.len() != 32 {
        return Err("invalid prekey bundle field lengths".to_string());
    }

    let mut ik_arr = [0u8; 32];
    let mut spk_arr = [0u8; 32];
    let mut sig_arr = [0u8; 64];
    let mut sign_arr = [0u8; 32];
    ik_arr.copy_from_slice(&ik);
    spk_arr.copy_from_slice(&spk);
    sig_arr.copy_from_slice(&spk_sig);
    sign_arr.copy_from_slice(&signing);

    let bundle = veil_crypto::x3dh::PreKeyBundle {
        identity_key: ik_arr,
        signing_key: sign_arr,
        signed_prekey: spk_arr,
        signed_prekey_signature: sig_arr,
        signed_prekey_id: spk_id,
        one_time_prekey: opk.map(|b| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }),
        one_time_prekey_id: opk_id,
    };

    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    client.establish_session(&ik_arr, &bundle)
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
    let app_handle = app.clone();
    std::thread::spawn(move || {
        let state_inner = app_handle.state::<AppState>();
        loop {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let mut client = match state_inner.client.lock() {
                Ok(c) => c,
                Err(_) => break,
            };
            let event = state_inner.runtime.block_on(client.poll_event());

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
                        // Decrypt: try E2E, fallback to plaintext
                        let sender_key: [u8; 32] = sender_identity_key
                            .as_slice()
                            .try_into()
                            .unwrap_or([0u8; 32]);

                        let text = match client.decrypt_from(&sender_key, &header, &ciphertext) {
                            Ok(pt) => String::from_utf8_lossy(&pt).to_string(),
                            Err(_) => String::from_utf8_lossy(&ciphertext).to_string(),
                        };

                        // Persist to DB
                        let ts_ms = (server_timestamp / 1_000_000) as i64;
                        client.persist_incoming_message(
                            &message_id,
                            &conversation_id,
                            &sender_identity_key,
                            &text,
                            Some(ts_ms),
                            reply_to_id.as_deref(),
                        );
                        client.persist_conversation(
                            &conversation_id,
                            0, // DM
                            Some(&sender_username),
                            Some(&sender_identity_key),
                        );

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
                            .title(&sender_username)
                            .body(&text)
                            .show();
                    }
                    ConnectionEvent::MessageAcked {
                        message_id,
                        ref_seq,
                        ..
                    } => {
                        drop(client);
                        let _ = app_handle.emit(
                            "veil://message-ack",
                            serde_json::json!({
                                "messageId": message_id,
                                "refSeq": ref_seq,
                            }),
                        );
                    }
                    ConnectionEvent::MessageEdited {
                        message_id,
                        conversation_id,
                        sender_identity_key,
                        ciphertext,
                        header,
                        edit_timestamp,
                    } => {
                        let sender_key: [u8; 32] = sender_identity_key
                            .as_slice()
                            .try_into()
                            .unwrap_or([0u8; 32]);

                        let new_text = match client.decrypt_from(&sender_key, &header, &ciphertext) {
                            Ok(pt) => String::from_utf8_lossy(&pt).to_string(),
                            Err(_) => String::from_utf8_lossy(&ciphertext).to_string(),
                        };

                        client.update_local_message(&message_id, &new_text);
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
                    } => {
                        client.delete_local_message(&message_id);
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
                        break;
                    }
                    ConnectionEvent::Error { code, message } => {
                        drop(client);
                        let _ = app_handle.emit(
                            "veil://error",
                            serde_json::json!({ "code": code, "message": message }),
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
                        if add {
                            client.add_local_reaction(&message_id, &user_id, &emoji, &username);
                        } else {
                            client.remove_local_reaction(&message_id, &user_id, &emoji);
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
                            .title("Friend Request")
                            .body(&format!("{} wants to be your friend", from_username))
                            .show();
                    }
                    ConnectionEvent::FriendAccepted {
                        user_id,
                        username,
                    } => {
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
    reply_to_id: Option<String>,
) -> Result<u64, String> {
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
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    if add {
        client.add_local_reaction(&message_id, &user_id, &emoji, "You");
    } else {
        client.remove_local_reaction(&message_id, &user_id, &emoji);
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
    let client = state.client.lock().map_err(|e| e.to_string())?;
    Ok(client.get_local_reactions(&message_id))
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

// ─── Groups ───────────────────────────────────────────

/// Create a new group on the server. Returns the conversation_id.
#[tauri::command]
fn create_group(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    name: String,
) -> Result<String, String> {
    let resp: serde_json::Value = state.runtime.block_on(async {
        let http = reqwest::Client::new();
        let r = http
            .post(format!("{}/v1/groups", server_http_url))
            .header("X-User-ID", &user_id)
            .json(&serde_json::json!({ "name": name }))
            .send()
            .await
            .map_err(|e| format!("create group: {e}"))?;
        r.json().await.map_err(|e| format!("parse: {e}"))
    })?;

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
    state.runtime.block_on(async {
        let http = reqwest::Client::new();
        let r = http
            .post(format!(
                "{}/v1/groups/{}/members",
                server_http_url, group_id
            ))
            .header("X-User-ID", &user_id)
            .json(&serde_json::json!({ "user_id": target_user_id }))
            .send()
            .await
            .map_err(|e| format!("add member: {e}"))?;

        if !r.status().is_success() {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            return Err(body["error"].as_str().unwrap_or("failed").to_string());
        }
        Ok(())
    })
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
    state.runtime.block_on(async {
        let http = reqwest::Client::new();
        let r = http
            .delete(format!(
                "{}/v1/groups/{}/members/{}",
                server_http_url, group_id, target_user_id
            ))
            .header("X-User-ID", &user_id)
            .send()
            .await
            .map_err(|e| format!("remove member: {e}"))?;

        if !r.status().is_success() {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            return Err(body["error"].as_str().unwrap_or("failed").to_string());
        }
        Ok(())
    })
}

/// Get group members from the server.
#[tauri::command]
fn get_group_members(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    group_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let resp: serde_json::Value = state.runtime.block_on(async {
        let http = reqwest::Client::new();
        let r = http
            .get(format!(
                "{}/v1/groups/{}/members",
                server_http_url, group_id
            ))
            .header("X-User-ID", &user_id)
            .send()
            .await
            .map_err(|e| format!("get members: {e}"))?;
        r.json().await.map_err(|e| format!("parse: {e}"))
    })?;

    let members = resp["members"].as_array().cloned().unwrap_or_default();

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

    Ok(members)
}

// ─── Friends & Presence ───────────────────────────────

#[tauri::command]
fn send_friend_request(
    state: State<'_, AppState>,
    target_user_id: String,
    message: Option<String>,
) -> Result<(), String> {
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
    let client = state.client.lock().map_err(|e| e.to_string())?;
    state
        .runtime
        .block_on(client.respond_friend_request(&request_id, accept))
}

#[tauri::command]
fn remove_friend(state: State<'_, AppState>, user_id: String) -> Result<(), String> {
    let client = state.client.lock().map_err(|e| e.to_string())?;
    state.runtime.block_on(client.remove_friend(&user_id))
}

#[tauri::command]
fn request_friend_list(state: State<'_, AppState>) -> Result<(), String> {
    let client = state.client.lock().map_err(|e| e.to_string())?;
    state.runtime.block_on(client.request_friend_list())
}

#[tauri::command]
fn send_presence(
    state: State<'_, AppState>,
    status: i32,
    status_text: Option<String>,
) -> Result<(), String> {
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
    state.runtime.block_on(async {
        let http = reqwest::Client::new();
        let r = http
            .get(format!("{}/v1/users/search", server_http_url))
            .query(&[("username", &username)])
            .send()
            .await
            .map_err(|e| format!("search user: {e}"))?;
        if !r.status().is_success() {
            return Err("user not found".to_string());
        }
        r.json().await.map_err(|e| format!("parse: {e}"))
    })
}

// ─── App ──────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| PathBuf::from("."));
            std::fs::create_dir_all(&data_dir).ok();

            app.manage(AppState {
                client: Mutex::new(VeilClient::new()),
                runtime: tokio::runtime::Runtime::new().expect("failed to create tokio runtime"),
                last_activity: Mutex::new(Instant::now()),
                db_dir: data_dir,
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
            create_group,
            add_group_member,
            remove_group_member,
            get_group_members,
            send_friend_request,
            respond_friend_request,
            remove_friend,
            request_friend_list,
            send_presence,
            search_user,
        ])
        .run(tauri::generate_context!())
        .expect("error while running veil");
}
