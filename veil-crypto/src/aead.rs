use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use zeroize::Zeroize;

/// Poly1305 authentication tag size.
const TAG_SIZE: usize = 16;
/// XChaCha20 nonce size.
pub const NONCE_SIZE: usize = 24;
/// Padding block size to hide message length.
const PAD_BLOCK: usize = 256;

/// Encrypt plaintext with XChaCha20-Poly1305.
///
/// The plaintext is padded to a multiple of 256 bytes before encryption
/// to hide the actual message length (traffic analysis resistance).
///
/// Returns `(ciphertext, nonce)`. The nonce is 24 bytes, randomly generated.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), String> {
    if plaintext.len() > u32::MAX as usize {
        return Err("plaintext too large (max 4GB)".to_string());
    }

    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("cipher init: {e}"))?;

    // Generate random nonce (24 bytes — safe for random generation, no collision risk)
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Pad plaintext to hide length
    let mut padded = pad(plaintext);

    let ciphertext = cipher
        .encrypt(nonce, padded.as_ref())
        .map_err(|e| format!("encrypt: {e}"))?;

    // Zeroize padded plaintext
    padded.zeroize();

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt ciphertext with XChaCha20-Poly1305.
///
/// Returns the original plaintext (padding removed).
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; NONCE_SIZE]) -> Result<Vec<u8>, String> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("cipher init: {e}"))?;

    let nonce = XNonce::from_slice(nonce);

    let mut padded = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "decryption failed: invalid key or corrupted data".to_string())?;

    let plaintext = unpad(&padded)?;

    // Zeroize padded buffer
    padded.zeroize();

    Ok(plaintext)
}

/// Pad plaintext to a multiple of PAD_BLOCK (256 bytes).
///
/// Format: `[4 bytes big-endian length][plaintext][zero padding]`
/// Total length is always a multiple of PAD_BLOCK.
fn pad(plaintext: &[u8]) -> Vec<u8> {
    let len = plaintext.len();
    let total = ((len + 4 + PAD_BLOCK - 1) / PAD_BLOCK) * PAD_BLOCK;
    let mut padded = vec![0u8; total];

    // First 4 bytes: plaintext length (big-endian)
    let len_bytes = (len as u32).to_be_bytes();
    padded[..4].copy_from_slice(&len_bytes);
    padded[4..4 + len].copy_from_slice(plaintext);
    // Remaining bytes are already zero

    padded
}

/// Remove padding and extract original plaintext.
fn unpad(padded: &[u8]) -> Result<Vec<u8>, String> {
    if padded.len() < 4 {
        return Err("padded data too short".to_string());
    }

    let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;

    if 4 + len > padded.len() {
        return Err("invalid padding: declared length exceeds data".to_string());
    }

    Ok(padded[4..4 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"Hello, Veil! This is a secret message.";

        let (ciphertext, nonce) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_is_padded() {
        let key = [42u8; 32];
        let plaintext = b"short";

        let (ciphertext, _) = encrypt(&key, plaintext).unwrap();

        // Ciphertext should be at least PAD_BLOCK + TAG_SIZE bytes
        assert!(ciphertext.len() >= PAD_BLOCK + TAG_SIZE);
        // Ciphertext length (minus tag) should be a multiple of PAD_BLOCK
        assert_eq!((ciphertext.len() - TAG_SIZE) % PAD_BLOCK, 0);
    }

    #[test]
    fn test_different_nonces() {
        let key = [42u8; 32];
        let plaintext = b"same message";

        let (ct1, n1) = encrypt(&key, plaintext).unwrap();
        let (ct2, n2) = encrypt(&key, plaintext).unwrap();

        assert_ne!(n1, n2, "Nonces must be unique");
        assert_ne!(ct1, ct2, "Same plaintext must produce different ciphertext");
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let plaintext = b"secret";

        let (ciphertext, nonce) = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &ciphertext, &nonce);

        assert!(result.is_err(), "Wrong key must fail");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let plaintext = b"integrity check";

        let (mut ciphertext, nonce) = encrypt(&key, plaintext).unwrap();
        ciphertext[0] ^= 0xff; // Flip a byte

        let result = decrypt(&key, &ciphertext, &nonce);
        assert!(result.is_err(), "Tampered ciphertext must fail");
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [42u8; 32];
        let plaintext = b"";

        let (ciphertext, nonce) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let key = [42u8; 32];
        let plaintext = vec![0xAB; 10_000]; // 10 KB

        let (ciphertext, nonce) = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_padding_alignment() {
        // Test that padding works for various sizes
        for size in [0, 1, 100, 251, 252, 253, 500, 1000] {
            let data = vec![0x42; size];
            let padded = pad(&data);
            assert_eq!(padded.len() % PAD_BLOCK, 0, "Failed for size {size}");

            let unpadded = unpad(&padded).unwrap();
            assert_eq!(unpadded, data, "Roundtrip failed for size {size}");
        }
    }
}
