use keyring::Entry;

const SERVICE_NAME: &str = "veil-messenger";

/// Store the user's seed phrase securely in the OS keychain.
pub fn store_seed(account: &str, seed: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, account)
        .map_err(|e| format!("keychain entry: {e}"))?;
    entry.set_password(seed)
        .map_err(|e| format!("keychain store: {e}"))
}

/// Retrieve the user's seed phrase from the OS keychain.
pub fn get_seed(account: &str) -> Result<String, String> {
    let entry = Entry::new(SERVICE_NAME, account)
        .map_err(|e| format!("keychain entry: {e}"))?;
    entry.get_password()
        .map_err(|e| format!("keychain get: {e}"))
}

/// Delete the user's seed from the OS keychain.
pub fn delete_seed(account: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, account)
        .map_err(|e| format!("keychain entry: {e}"))?;
    entry.delete_credential()
        .map_err(|e| format!("keychain delete: {e}"))
}

/// Check if a seed exists in the keychain.
pub fn has_seed(account: &str) -> bool {
    let Ok(entry) = Entry::new(SERVICE_NAME, account) else {
        return false;
    };
    entry.get_password().is_ok()
}
