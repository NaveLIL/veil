use std::sync::Mutex;
use tauri::State;
use veil_crypto::IdentityKeyPair;
use veil_store::keychain;

struct AppState {
    identity: Mutex<Option<IdentityKeyPair>>,
}

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
    let kp = IdentityKeyPair::from_mnemonic(mnemonic)?;
    let hex_key = hex::encode(kp.x25519_public_bytes());
    *state.identity.lock().map_err(|e| e.to_string())? = Some(kp);
    Ok(hex_key)
}

#[tauri::command]
fn get_identity_key(state: State<'_, AppState>) -> Result<String, String> {
    let guard = state.identity.lock().map_err(|e| e.to_string())?;
    match guard.as_ref() {
        Some(kp) => Ok(hex::encode(kp.x25519_public_bytes())),
        None => Err("no identity loaded".into()),
    }
}

const KEYCHAIN_ACCOUNT: &str = "veil-default";

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_os::init())
        .manage(AppState {
            identity: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            generate_mnemonic,
            validate_mnemonic_cmd,
            init_identity,
            get_identity_key,
            store_seed,
            get_stored_seed,
        ])
        .run(tauri::generate_context!())
        .expect("error while running veil");
}
