use base64::Engine;
use wasm_bindgen::prelude::*;

/// Decrypt a secure share given the ciphertext (base64), content key (hex),
/// and optionally a password + wrapped key + salt.
#[wasm_bindgen]
pub fn decrypt_share(
    ciphertext_b64: &str,
    content_key_hex: Option<String>,
    password: Option<String>,
    wrapped_key_b64: Option<String>,
    salt_hex: Option<String>,
) -> Result<Vec<u8>, JsValue> {
    let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(ciphertext_b64)
        .map_err(|e| JsValue::from_str(&format!("base64 decode error: {e}")))?;

    let content_key: Option<[u8; 32]> = match content_key_hex {
        Some(ref h) => {
            let bytes =
                hex::decode(h).map_err(|e| JsValue::from_str(&format!("hex decode error: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| JsValue::from_str("content key must be 32 bytes"))?;
            Some(arr)
        }
        None => None,
    };

    let wrapped_key: Option<Vec<u8>> = match wrapped_key_b64 {
        Some(ref b) => Some(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(b)
                .map_err(|e| JsValue::from_str(&format!("wrapped key decode: {e}")))?,
        ),
        None => None,
    };

    let salt: Option<[u8; 32]> = match salt_hex {
        Some(ref h) => {
            let bytes =
                hex::decode(h).map_err(|e| JsValue::from_str(&format!("salt hex decode: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| JsValue::from_str("salt must be 32 bytes"))?;
            Some(arr)
        }
        None => None,
    };

    veil_crypto::share::decrypt_share(
        &ciphertext,
        content_key.as_ref(),
        password.as_deref(),
        wrapped_key.as_deref(),
        salt.as_ref(),
    )
    .map_err(|e| JsValue::from_str(&e))
}

/// Check library is loaded.
#[wasm_bindgen]
pub fn version() -> String {
    "0.1.0".to_string()
}
