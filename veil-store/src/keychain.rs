use keyring::Entry;
use zeroize::Zeroize;

const SERVICE_NAME: &str = "veil-messenger";

/// Store the user's seed phrase securely in the OS keychain.
pub fn store_seed(account: &str, seed: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, account).map_err(|e| format!("keychain entry: {e}"))?;
    entry
        .set_password(seed)
        .map_err(|e| format!("keychain store: {e}"))
}

/// Retrieve the user's seed phrase from the OS keychain.
pub fn get_seed(account: &str) -> Result<String, String> {
    let entry = Entry::new(SERVICE_NAME, account).map_err(|e| format!("keychain entry: {e}"))?;
    entry
        .get_password()
        .map_err(|e| format!("keychain get: {e}"))
}

/// Retrieve an optional credential from the OS keychain.
///
/// Only a genuinely missing entry maps to `None`. Backend, permission and
/// availability failures remain explicit so callers cannot silently replace a
/// persisted security policy with a fallback value.
pub fn get_optional_seed(account: &str) -> Result<Option<String>, String> {
    let entry = Entry::new(SERVICE_NAME, account).map_err(|e| format!("keychain entry: {e}"))?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!("keychain get: {error}")),
    }
}

/// Delete the user's seed from the OS keychain.
pub fn delete_seed(account: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, account).map_err(|e| format!("keychain entry: {e}"))?;
    entry
        .delete_credential()
        .map_err(|e| format!("keychain delete: {e}"))
}

/// Check if a credential exists without treating secure-storage failures as
/// absence. Callers use this for lock decisions, so only `NoEntry` may map to
/// `false`; a locked or unavailable OS credential store must fail closed.
pub fn has_seed(account: &str) -> Result<bool, String> {
    let entry = Entry::new(SERVICE_NAME, account).map_err(|e| format!("keychain entry: {e}"))?;
    match entry.get_password() {
        Ok(mut value) => {
            value.zeroize();
            Ok(true)
        }
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(error) => Err(format!("keychain access: {error}")),
    }
}
