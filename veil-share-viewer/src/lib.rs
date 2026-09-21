use base64::Engine;
use wasm_bindgen::prelude::*;

fn decode_b64(input: &str) -> Result<Vec<u8>, JsValue> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .map_err(|e| JsValue::from_str(&format!("base64 decode error: {e}")))
}

fn encode_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Derive redemption key for claiming a v1 Secure Share.
#[wasm_bindgen]
pub fn derive_redemption_key(root_secret_b64: &str, selector: &str) -> Result<String, JsValue> {
    let secret_bytes = decode_b64(root_secret_b64)?;
    if secret_bytes.len() != 32 {
        return Err(JsValue::from_str("root secret must be 32 bytes"));
    }
    let mut root_secret = [0u8; 32];
    root_secret.copy_from_slice(&secret_bytes);

    let redemption_key = veil_crypto::share::derive_redemption_key(&root_secret, selector);
    Ok(encode_b64(&redemption_key))
}

/// Decrypt a v1 Secure Share using the root secret from the URL fragment.
#[wasm_bindgen]
pub fn decrypt_share_v1(
    origin: &str,
    selector: &str,
    ciphertext_b64: &str,
    root_secret_b64: &str,
    content_type: &str,
) -> Result<Vec<u8>, JsValue> {
    let ciphertext = decode_b64(ciphertext_b64)?;
    let secret_bytes = decode_b64(root_secret_b64)?;
    if secret_bytes.len() != 32 {
        return Err(JsValue::from_str("root secret must be 32 bytes"));
    }
    let mut root_secret = [0u8; 32];
    root_secret.copy_from_slice(&secret_bytes);

    veil_crypto::share::decrypt_share_v1(
        origin,
        selector,
        &ciphertext,
        &root_secret,
        content_type,
    )
    .map_err(|e| JsValue::from_str(&format!("decryption failed: {e}")))
}

/// Decrypt raw bytes directly from ArrayBuffer / Uint8Array.
#[wasm_bindgen]
pub fn decrypt_share_bytes_v1(
    origin: &str,
    selector: &str,
    ciphertext_bytes: &[u8],
    root_secret_b64: &str,
    content_type: &str,
) -> Result<Vec<u8>, JsValue> {
    let secret_bytes = decode_b64(root_secret_b64)?;
    if secret_bytes.len() != 32 {
        return Err(JsValue::from_str("root secret must be 32 bytes"));
    }
    let mut root_secret = [0u8; 32];
    root_secret.copy_from_slice(&secret_bytes);

    veil_crypto::share::decrypt_share_v1(
        origin,
        selector,
        ciphertext_bytes,
        &root_secret,
        content_type,
    )
    .map_err(|e| JsValue::from_str(&format!("decryption failed: {e}")))
}

/// Library version check.
#[wasm_bindgen]
pub fn version() -> String {
    "1.0.0".to_string()
}
