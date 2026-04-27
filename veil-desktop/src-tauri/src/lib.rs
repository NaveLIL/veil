use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_notification::NotificationExt;
use veil_client::api::VeilClient;
use veil_client::connection::ConnectionEvent;
use veil_search::{Indexer, SearchHit};
use veil_store::keychain;

mod mls_cmd;
use mls_cmd::MlsState;

struct AppState {
    client: Mutex<VeilClient>,
    runtime: tokio::runtime::Runtime,
    last_activity: Mutex<Instant>,
    db_dir: PathBuf,
    /// Shared HTTP client — reuses TCP/TLS connections + HTTP/2 streams across
    /// all REST calls. Eliminates per-request handshake overhead, the main
    /// cause of the perceived "server tab is slow / hangs" UX.
    http: reqwest::Client,
    /// Local-only full-text index. Initialised lazily in `setup`.
    indexer: Arc<Indexer>,
    /// Phase 6 — OpenMLS session state. Lazily initialised by `mls_init`.
    mls: MlsState,
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
    client.set_indexer(state.indexer.clone());
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
    client.set_indexer(state.indexer.clone());
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

                        let text = match client.decrypt_from(
                            &sender_key,
                            &conversation_id,
                            &header,
                            &ciphertext,
                        ) {
                            Ok(veil_client::api::DecryptedPayload::Text(pt)) => {
                                String::from_utf8_lossy(&pt).to_string()
                            }
                            Ok(veil_client::api::DecryptedPayload::Control) => {
                                // SKDM or other control frame — swallow.
                                drop(client);
                                continue;
                            }
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

                        let new_text = match client.decrypt_from(
                            &sender_key,
                            &conversation_id,
                            &header,
                            &ciphertext,
                        ) {
                            Ok(veil_client::api::DecryptedPayload::Text(pt)) => {
                                String::from_utf8_lossy(&pt).to_string()
                            }
                            Ok(veil_client::api::DecryptedPayload::Control) => {
                                drop(client);
                                continue;
                            }
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
                    ConnectionEvent::ServerEvent {
                        event_type,
                        server_id,
                        server_info,
                        member_info,
                        role_info,
                    } => {
                        drop(client);
                        let _ = app_handle.emit(
                            "veil://server-event",
                            serde_json::json!({
                                "eventType": event_type,
                                "serverId": server_id,
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
                    }
                    ConnectionEvent::ChannelEvent {
                        event_type,
                        server_id,
                        channel,
                    } => {
                        drop(client);
                        let _ = app_handle.emit(
                            "veil://channel-event",
                            serde_json::json!({
                                "eventType": event_type,
                                "serverId": server_id,
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
                    }
                    ConnectionEvent::SenderKeyDist {
                        conversation_id,
                        sender_key_message,
                        ..
                    } => {
                        match client.process_sealed_skdm(&sender_key_message) {
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
                                drop(client);
                                eprintln!("[skdm] open failed: {e}");
                            }
                        }
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
    let resp = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        format!("{}/v1/groups", server_http_url),
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
            format!("{}/v1/groups/{}/members", server_http_url, group_id),
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
            format!(
                "{}/v1/groups/{}/members/{}",
                server_http_url, group_id, target_user_id
            ),
            &user_id,
            None,
        ))
        .map(|_| ())
}

/// Get group members from the server.
#[tauri::command]
fn get_group_members(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    group_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let resp = state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::GET,
        format!("{}/v1/groups/{}/members", server_http_url, group_id),
        &user_id,
        None,
    ))?;

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

// ─── Servers / Channels / Roles / Invites ─────────────

/// Helper: parse a JSON error body and produce a String.
fn rest_err(body: &serde_json::Value, fallback: &str) -> String {
    body.get("error")
        .and_then(|v| v.as_str())
        .unwrap_or(fallback)
        .to_string()
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

    // 1. Compute body bytes + hash up-front (so signing covers the wire body).
    let body_bytes: Vec<u8> = match body.as_ref() {
        Some(b) => serde_json::to_vec(b).map_err(|e| format!("serialize body: {e}"))?,
        None => Vec::new(),
    };
    let body_hash = Sha256::digest(&body_bytes);

    // 2. Extract path from URL for canonical signing message.
    let path = reqwest::Url::parse(&url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| url.clone());

    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let canonical = format!(
        "{}\n{}\n{}\n{}",
        method.as_str(),
        path,
        ts_ms,
        hex::encode(body_hash)
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
        .request(method, url)
        .header("X-Veil-User", user_id)
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
    let status = resp.status();
    // Read body once as bytes so we can include raw text in error paths even
    // when the server returns non-JSON (proxy errors, html, etc.).
    let body_bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("read response body: {e}"))?;
    let json: serde_json::Value = if body_bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null)
    };
    if !status.is_success() {
        let fallback = if json.is_null() {
            let snippet = String::from_utf8_lossy(&body_bytes);
            let truncated: String = snippet.chars().take(200).collect();
            format!("HTTP {}: {}", status.as_u16(), truncated)
        } else {
            format!("HTTP {}", status.as_u16())
        };
        return Err(rest_err(&json, &fallback));
    }
    Ok(json)
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
        format!("{}/v1/servers", server_http_url),
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
        format!("{}/v1/servers", server_http_url),
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
        format!("{}/v1/servers/{}", server_http_url, server_id),
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
        format!("{}/v1/servers/{}", server_http_url, server_id),
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
        format!("{}/v1/servers/{}", server_http_url, server_id),
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
        format!("{}/v1/servers/{}/leave", server_http_url, server_id),
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
        format!("{}/v1/servers/{}/members", server_http_url, server_id),
        &user_id,
        None,
    ))?;
    Ok(resp["members"].as_array().cloned().unwrap_or_default())
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
        format!(
            "{}/v1/servers/{}/members/{}",
            server_http_url, server_id, target_user_id
        ),
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
        format!("{}/v1/servers/{}/channels", server_http_url, server_id),
        &user_id,
        None,
    ))?;
    Ok(resp["channels"].as_array().cloned().unwrap_or_default())
}

#[tauri::command]
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
        format!("{}/v1/servers/{}/channels", server_http_url, server_id),
        &user_id,
        Some(body),
    ))
}

#[tauri::command]
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
        format!("{}/v1/channels/{}", server_http_url, channel_id),
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
        format!("{}/v1/channels/{}", server_http_url, channel_id),
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
        format!(
            "{}/v1/servers/{}/channels/reorder",
            server_http_url, server_id
        ),
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
        format!("{}/v1/servers/{}/roles", server_http_url, server_id),
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
        format!("{}/v1/servers/{}/roles", server_http_url, server_id),
        &user_id,
        Some(body),
    ))
}

#[tauri::command]
fn update_role(
    state: State<'_, AppState>,
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
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::PATCH,
        format!(
            "{}/v1/servers/{}/roles/{}",
            server_http_url, server_id, role_id
        ),
        &user_id,
        Some(serde_json::Value::Object(body)),
    ))?;
    Ok(())
}

#[tauri::command]
fn delete_role(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
    role_id: String,
) -> Result<(), String> {
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::DELETE,
        format!(
            "{}/v1/servers/{}/roles/{}",
            server_http_url, server_id, role_id
        ),
        &user_id,
        None,
    ))?;
    Ok(())
}

#[tauri::command]
fn assign_role(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
    target_user_id: String,
    role_id: String,
) -> Result<(), String> {
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::PUT,
        format!(
            "{}/v1/servers/{}/members/{}/roles/{}",
            server_http_url, server_id, target_user_id, role_id
        ),
        &user_id,
        None,
    ))?;
    Ok(())
}

#[tauri::command]
fn unassign_role(
    state: State<'_, AppState>,
    server_http_url: String,
    user_id: String,
    server_id: String,
    target_user_id: String,
    role_id: String,
) -> Result<(), String> {
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::DELETE,
        format!(
            "{}/v1/servers/{}/members/{}/roles/{}",
            server_http_url, server_id, target_user_id, role_id
        ),
        &user_id,
        None,
    ))?;
    Ok(())
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
        format!("{}/v1/servers/{}/invites", server_http_url, server_id),
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
        format!("{}/v1/servers/{}/invites", server_http_url, server_id),
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
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::DELETE,
        format!("{}/v1/invites/{}", server_http_url, code),
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
    // Public endpoint — no auth required.
    let url = format!("{}/v1/invites/{}", server_http_url, code);
    state.runtime.block_on(async move {
        let http = reqwest::Client::new();
        let resp = http
            .get(url)
            .send()
            .await
            .map_err(|e| format!("preview: {e}"))?;
        let status = resp.status();
        let json: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
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
    state.runtime.block_on(rest_send_json(
        &state,
        reqwest::Method::POST,
        format!("{}/v1/invites/{}/use", server_http_url, code),
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

fn cached_server_from_json(v: &serde_json::Value, position: i32) -> Option<veil_store::models::CachedServer> {
    Some(veil_store::models::CachedServer {
        id: v.get("id")?.as_str()?.to_string(),
        name: v.get("name")?.as_str()?.to_string(),
        description: v.get("description").and_then(|x| x.as_str()).map(String::from),
        icon_url: v.get("icon_url").and_then(|x| x.as_str()).map(String::from),
        owner_id: v.get("owner_id")?.as_str()?.to_string(),
        position,
        created_at: v.get("created_at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    })
}

fn cached_channel_from_json(server_id: &str, v: &serde_json::Value) -> Option<veil_store::models::CachedChannel> {
    Some(veil_store::models::CachedChannel {
        id: v.get("id")?.as_str()?.to_string(),
        server_id: server_id.to_string(),
        conversation_id: v.get("conversation_id").and_then(|x| x.as_str()).map(String::from),
        name: v.get("name")?.as_str()?.to_string(),
        channel_type: v.get("channel_type").and_then(|x| x.as_i64()).unwrap_or(0) as i16,
        category_id: v.get("category_id").and_then(|x| x.as_str()).map(String::from),
        position: v.get("position").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
        topic: v.get("topic").and_then(|x| x.as_str()).map(String::from),
        nsfw: v.get("nsfw").and_then(|x| x.as_bool()).unwrap_or(false),
        slowmode_secs: v.get("slowmode_secs").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
    })
}

fn cached_role_from_json(server_id: &str, v: &serde_json::Value) -> Option<veil_store::models::CachedRole> {
    Some(veil_store::models::CachedRole {
        id: v.get("id")?.as_str()?.to_string(),
        server_id: server_id.to_string(),
        name: v.get("name")?.as_str()?.to_string(),
        permissions: v.get("permissions").and_then(|x| x.as_u64()).unwrap_or(0),
        position: v.get("position").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
        color: v.get("color").and_then(|x| x.as_i64()).map(|c| c as i32),
        is_default: v.get("is_default").and_then(|x| x.as_bool()).unwrap_or(false),
        hoist: v.get("hoist").and_then(|x| x.as_bool()).unwrap_or(false),
        mentionable: v.get("mentionable").and_then(|x| x.as_bool()).unwrap_or(false),
    })
}

fn cached_member_from_json(server_id: &str, v: &serde_json::Value) -> Option<veil_store::models::CachedServerMember> {
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
        username: v.get("username").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        nickname: v.get("nickname").and_then(|x| x.as_str()).map(String::from),
        role_ids,
        joined_at: v.get("joined_at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    })
}

#[tauri::command]
fn cache_load_servers(state: State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("db not initialized")?;
    let servers = db.list_servers()?;
    Ok(servers
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
        .collect())
}

#[tauri::command]
fn cache_save_servers(
    state: State<'_, AppState>,
    servers: Vec<serde_json::Value>,
) -> Result<(), String> {
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
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("db not initialized")?;
    db.delete_server(&server_id)
}

#[tauri::command]
fn cache_load_channels(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("db not initialized")?;
    let chans = db.list_channels(&server_id)?;
    Ok(chans
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
        .collect())
}

#[tauri::command]
fn cache_save_channels(
    state: State<'_, AppState>,
    server_id: String,
    channels: Vec<serde_json::Value>,
) -> Result<(), String> {
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
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("db not initialized")?;
    db.delete_channel(&channel_id)
}

#[tauri::command]
fn cache_load_roles(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("db not initialized")?;
    let roles = db.list_roles(&server_id)?;
    Ok(roles
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
        .collect())
}

#[tauri::command]
fn cache_save_roles(
    state: State<'_, AppState>,
    server_id: String,
    roles: Vec<serde_json::Value>,
) -> Result<(), String> {
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
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("db not initialized")?;
    let members = db.list_server_members(&server_id)?;
    Ok(members
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
        .collect())
}

#[tauri::command]
fn cache_save_server_members(
    state: State<'_, AppState>,
    server_id: String,
    members: Vec<serde_json::Value>,
) -> Result<(), String> {
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
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    client.hydrate_channel_sender_keys(&conversation_id)
}

/// Distribute our outgoing sender key to a list of channel members
/// (sealed envelope per recipient identity key, sent via SenderKeyDist envelope).
#[tauri::command]
fn distribute_sender_key(
    state: State<'_, AppState>,
    conversation_id: String,
    peer_identity_keys: Vec<String>,
) -> Result<u32, String> {
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    client.mark_channel_conversation(&conversation_id);

    let our_ik = client.identity_key()?;
    let mut sent = 0u32;
    for hex_key in &peer_identity_keys {
        let bytes = match hex::decode(hex_key) {
            Ok(b) if b.len() == 32 => b,
            _ => continue,
        };
        let mut peer_ik = [0u8; 32];
        peer_ik.copy_from_slice(&bytes);
        if peer_ik == our_ik {
            continue; // skip self
        }
        match state
            .runtime
            .block_on(client.send_sender_key_to(&conversation_id, &peer_ik))
        {
            Ok(_) => sent += 1,
            Err(e) => eprintln!("[skdm] send to {hex_key}: {e}"),
        }
    }
    Ok(sent)
}

/// Force-rotate our outgoing sender key for a channel (e.g. on member kick).
#[tauri::command]
fn rotate_sender_key(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<(), String> {
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    client.rotate_sender_key(&conversation_id)
}

// ─── Phase 6: per-conversation crypto mode ───────────

/// Read the cached `crypto_mode` for a conversation. Returns
/// `"sender_key"` if missing or unset (default for legacy conversations).
#[tauri::command]
fn get_conversation_crypto_mode(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<String, String> {
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let mode = client
        .db()
        .ok_or_else(|| "db not initialised".to_string())?
        .get_conversation_crypto_mode(&conversation_id)?
        .unwrap_or_else(|| "sender_key".to_string());
    Ok(mode)
}

/// Update the `crypto_mode` for a conversation. Accepts only
/// `"sender_key"` or `"mls"`; the UI uses this as a marker so the chat
/// header can render the "MLS active" badge after a successful upgrade.
#[tauri::command]
fn set_conversation_crypto_mode(
    state: State<'_, AppState>,
    conversation_id: String,
    mode: String,
) -> Result<(), String> {
    if mode != "sender_key" && mode != "mls" {
        return Err(format!("unknown crypto mode: {mode}"));
    }
    let client = state.client.lock().map_err(|e| e.to_string())?;
    client
        .db()
        .ok_or_else(|| "db not initialised".to_string())?
        .set_conversation_crypto_mode(&conversation_id, &mode)
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
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let limit = limit.unwrap_or(50).clamp(1, 500);
    let hits = state
        .indexer
        .search(trimmed, conversation_id.as_deref(), limit)
        .map_err(|e| e.to_string())?;
    Ok(hits.into_iter().map(SearchHitDto::from).collect())
}

#[tauri::command]
fn clear_search_index(state: State<'_, AppState>) -> Result<(), String> {
    state.indexer.clear().map_err(|e| e.to_string())
}

#[tauri::command]
fn rebuild_search_index(state: State<'_, AppState>) -> Result<usize, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let db = client.db().ok_or("database not initialized")?;
    state.indexer.clear().map_err(|e| e.to_string())?;
    let convs = db.get_conversations()?;
    let mut indexed = 0usize;
    for conv in convs {
        let msgs = db.get_messages(&conv.id, 100_000)?;
        for m in msgs {
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
    Ok(indexed)
}

/// Run [`rebuild_search_index`] once per install. A marker file under the
/// index directory records that backfill has happened so subsequent launches
/// skip the work. Returns the number of messages indexed (0 if skipped).
#[tauri::command]
fn ensure_search_backfill(state: State<'_, AppState>) -> Result<usize, String> {
    let marker = state.db_dir.join("search").join("v1").join(".backfilled");
    if marker.exists() {
        return Ok(0);
    }
    let n = rebuild_search_index(state)?;
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let _ = std::fs::write(&marker, b"1");
    Ok(n)
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

            let index_dir = data_dir.join("search").join("v1");
            let indexer = Arc::new(
                Indexer::open(&index_dir)
                    .expect("failed to open local search index"),
            );

            app.manage(AppState {
                client: Mutex::new(VeilClient::new()),
                runtime: tokio::runtime::Runtime::new().expect("failed to create tokio runtime"),
                last_activity: Mutex::new(Instant::now()),
                db_dir: data_dir,
                http: reqwest::Client::builder()
                    .pool_idle_timeout(std::time::Duration::from_secs(30))
                    .pool_max_idle_per_host(8)
                    .timeout(std::time::Duration::from_secs(20))
                    .build()
                    .expect("reqwest client"),
                indexer,
                mls: MlsState::new(),
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
            search_messages,
            clear_search_index,
            rebuild_search_index,
            ensure_search_backfill,
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
            get_conversation_crypto_mode,
            set_conversation_crypto_mode,
            mls_cmd::mls_init,
            mls_cmd::mls_ready,
            mls_cmd::mls_generate_key_packages,
            mls_cmd::mls_create_group,
            mls_cmd::mls_add_member,
            mls_cmd::mls_process_welcome,
            mls_cmd::mls_process_commit,
            mls_cmd::mls_encrypt,
            mls_cmd::mls_decrypt,
            mls_cmd::mls_epoch,
            mls_cmd::mls_export_secret,
        ])
        .run(tauri::generate_context!())
        .expect("error while running veil");
}
