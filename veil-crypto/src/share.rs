use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::aead::{self, NONCE_SIZE};
use crate::kdf::hkdf_sha256;

const SALT_MANIFEST: &[u8] = b"veil/share/manifest/v1";
const SALT_REDEMPTION: &[u8] = b"veil/share/redemption/v1";
const SALT_REPORT: &[u8] = b"veil/share/report/v1";
const SHARE_PROTOCOL_VERSION: u8 = 1;

/// Bundle resulting from encrypting a v1 Secure Share.
pub struct EncryptedShareV1 {
    /// Encrypted payload with prepended 24-byte nonce.
    pub ciphertext: Vec<u8>,
    /// 256-bit root secret (placed in URL fragment #k=...).
    pub root_secret: [u8; 32],
    /// 256-bit redemption key sent by guest upon claiming.
    pub redemption_key: [u8; 32],
    /// SHA-256 hash of the redemption key stored on the server.
    pub redemption_hash: [u8; 32],
    /// SHA-256 hash of the report capability stored on the server.
    pub report_capability_hash: [u8; 32],
}

impl Drop for EncryptedShareV1 {
    fn drop(&mut self) {
        self.root_secret.zeroize();
        self.redemption_key.zeroize();
    }
}

/// Derive domain-separated keys for a Secure Share v1 from a 256-bit root secret.
pub fn derive_share_keys(
    root_secret: &[u8; 32],
    selector: &str,
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let manifest_bytes = hkdf_sha256(SALT_MANIFEST, root_secret, selector.as_bytes(), 32);
    let mut manifest_key = [0u8; 32];
    manifest_key.copy_from_slice(&manifest_bytes);

    let redemption_bytes = hkdf_sha256(SALT_REDEMPTION, root_secret, selector.as_bytes(), 32);
    let mut redemption_key = [0u8; 32];
    redemption_key.copy_from_slice(&redemption_bytes);

    let report_bytes = hkdf_sha256(SALT_REPORT, root_secret, selector.as_bytes(), 32);
    let mut report_capability = [0u8; 32];
    report_capability.copy_from_slice(&report_bytes);

    (manifest_key, redemption_key, report_capability)
}

/// Derive only the redemption key from a root secret.
pub fn derive_redemption_key(root_secret: &[u8; 32], selector: &str) -> [u8; 32] {
    let redemption_bytes = hkdf_sha256(SALT_REDEMPTION, root_secret, selector.as_bytes(), 32);
    let mut redemption_key = [0u8; 32];
    redemption_key.copy_from_slice(&redemption_bytes);
    redemption_key
}

/// Compute SHA-256 hash of a 32-byte key/capability.
pub fn hash_capability(cap: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(cap);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Build the authenticated additional data (AAD) binding the ciphertext to the share context.
pub fn build_share_aad(
    version: u8,
    origin: &str,
    selector: &str,
    content_type: &str,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + origin.len() + selector.len() + content_type.len());
    aad.extend_from_slice(b"veil/share/v1|");
    aad.push(version);
    aad.push(b'|');
    aad.extend_from_slice(origin.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(selector.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(content_type.as_bytes());
    aad
}

/// Encrypt a Secure Share payload with v1 domain separation and AAD binding.
pub fn encrypt_share_v1(
    origin: &str,
    selector: &str,
    payload: &[u8],
    content_type: &str,
) -> Result<EncryptedShareV1, String> {
    let mut root_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut root_secret);

    let (mut manifest_key, redemption_key, report_capability) =
        derive_share_keys(&root_secret, selector);

    let redemption_hash = hash_capability(&redemption_key);
    let report_capability_hash = hash_capability(&report_capability);

    let aad = build_share_aad(SHARE_PROTOCOL_VERSION, origin, selector, content_type);
    let (ciphertext, nonce) = aead::encrypt_with_aad(&manifest_key, payload, &aad)?;
    manifest_key.zeroize();

    let mut full_ciphertext = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    full_ciphertext.extend_from_slice(&nonce);
    full_ciphertext.extend_from_slice(&ciphertext);

    Ok(EncryptedShareV1 {
        ciphertext: full_ciphertext,
        root_secret,
        redemption_key,
        redemption_hash,
        report_capability_hash,
    })
}

/// Decrypt a Secure Share v1 payload using the root secret.
pub fn decrypt_share_v1(
    origin: &str,
    selector: &str,
    ciphertext_with_nonce: &[u8],
    root_secret: &[u8; 32],
    content_type: &str,
) -> Result<Vec<u8>, String> {
    if ciphertext_with_nonce.len() < NONCE_SIZE {
        return Err("ciphertext too short: missing nonce".to_string());
    }

    let (mut manifest_key, _, _) = derive_share_keys(root_secret, selector);
    let nonce: [u8; NONCE_SIZE] = ciphertext_with_nonce[..NONCE_SIZE]
        .try_into()
        .map_err(|_| "invalid nonce slice")?;
    let ciphertext = &ciphertext_with_nonce[NONCE_SIZE..];

    let aad = build_share_aad(SHARE_PROTOCOL_VERSION, origin, selector, content_type);
    let result = aead::decrypt_with_aad(&manifest_key, ciphertext, &nonce, &aad);
    manifest_key.zeroize();

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_v1_encrypt_decrypt_roundtrip() {
        let origin = "https://node.example.com";
        let selector = "dGVzdC1zZWxlY3Rvci0xMjM0NQ";
        let payload = b"Hello, this is a secure guest share message!";
        let content_type = "text";

        let encrypted = encrypt_share_v1(origin, selector, payload, content_type).unwrap();
        assert_ne!(encrypted.ciphertext, payload);

        let decrypted = decrypt_share_v1(
            origin,
            selector,
            &encrypted.ciphertext,
            &encrypted.root_secret,
            content_type,
        )
        .unwrap();

        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_share_v1_key_derivation_deterministic() {
        let root_secret = [0x42u8; 32];
        let selector = "selector-abc";

        let (m1, r1, p1) = derive_share_keys(&root_secret, selector);
        let (m2, r2, p2) = derive_share_keys(&root_secret, selector);

        assert_eq!(m1, m2);
        assert_eq!(r1, r2);
        assert_eq!(p1, p2);
        assert_ne!(m1, r1);
        assert_ne!(r1, p1);
    }

    #[test]
    fn test_share_v1_fails_on_tampered_ciphertext() {
        let origin = "https://node.example.com";
        let selector = "dGVzdC1zZWxlY3Rvci0xMjM0NQ";
        let payload = b"Sensitive document";
        let content_type = "text";

        let mut encrypted = encrypt_share_v1(origin, selector, payload, content_type).unwrap();
        let last_idx = encrypted.ciphertext.len() - 1;
        encrypted.ciphertext[last_idx] ^= 0x01; // Tamper 1 bit

        let res = decrypt_share_v1(
            origin,
            selector,
            &encrypted.ciphertext,
            &encrypted.root_secret,
            content_type,
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_share_v1_fails_on_wrong_origin_or_selector() {
        let origin = "https://node.example.com";
        let selector = "dGVzdC1zZWxlY3Rvci0xMjM0NQ";
        let payload = b"Secret payload";
        let content_type = "text";

        let encrypted = encrypt_share_v1(origin, selector, payload, content_type).unwrap();

        // Wrong origin
        let res = decrypt_share_v1(
            "https://fake.example.com",
            selector,
            &encrypted.ciphertext,
            &encrypted.root_secret,
            content_type,
        );
        assert!(res.is_err());

        // Wrong selector
        let res = decrypt_share_v1(
            origin,
            "wrong-selector",
            &encrypted.ciphertext,
            &encrypted.root_secret,
            content_type,
        );
        assert!(res.is_err());
    }
}
