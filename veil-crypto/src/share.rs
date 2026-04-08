use rand::RngCore;
use zeroize::Zeroize;

use crate::aead;
use crate::kdf;

/// Encrypt data for a secure share.
///
/// If `password` is provided, the content key is wrapped with Argon2id(password).
/// If no password, the content key should be embedded in the URL fragment.
///
/// Returns `(ciphertext, content_key, salt)`.
/// - `ciphertext`: encrypted payload
/// - `content_key`: 32-byte key (embed in URL fragment if no password)
/// - `salt`: 32-byte salt (needed for password-based decryption)
pub fn encrypt_share(
    payload: &[u8],
    password: Option<&str>,
) -> Result<ShareBundle, String> {
    // Generate random content key
    let mut content_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut content_key);

    // Encrypt payload with content key
    let (ciphertext, nonce) = aead::encrypt(&content_key, payload)?;

    // Prepend nonce to ciphertext
    let mut encrypted = Vec::with_capacity(aead::NONCE_SIZE + ciphertext.len());
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&ciphertext);

    let (wrapped_key, salt) = if let Some(pwd) = password {
        // Wrap content key with password-derived key
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let password_key = kdf::derive_key_from_password(pwd, &salt)?;
        let (wrapped, wrap_nonce) = aead::encrypt(&password_key, &content_key)?;

        let mut wrapped_with_nonce = Vec::with_capacity(aead::NONCE_SIZE + wrapped.len());
        wrapped_with_nonce.extend_from_slice(&wrap_nonce);
        wrapped_with_nonce.extend_from_slice(&wrapped);

        (Some(wrapped_with_nonce), Some(salt))
    } else {
        (None, None)
    };

    Ok(ShareBundle {
        ciphertext: encrypted,
        content_key,
        wrapped_key,
        salt,
    })
}

/// Decrypt a secure share.
///
/// If `password` is provided, derives the content key from the wrapped key.
/// Otherwise, `content_key` must be provided (from URL fragment).
pub fn decrypt_share(
    ciphertext: &[u8],
    content_key: Option<&[u8; 32]>,
    password: Option<&str>,
    wrapped_key: Option<&[u8]>,
    salt: Option<&[u8; 32]>,
) -> Result<Vec<u8>, String> {
    let key = if let Some(ck) = content_key {
        *ck
    } else if let (Some(pwd), Some(wk), Some(s)) = (password, wrapped_key, salt) {
        // Derive password key and unwrap content key
        let password_key = kdf::derive_key_from_password(pwd, s)?;

        if wk.len() < aead::NONCE_SIZE {
            return Err("wrapped key too short".to_string());
        }
        let wrap_nonce: [u8; aead::NONCE_SIZE] = wk[..aead::NONCE_SIZE]
            .try_into()
            .map_err(|_| "invalid wrap nonce")?;
        let wrap_ct = &wk[aead::NONCE_SIZE..];

        let unwrapped = aead::decrypt(&password_key, wrap_ct, &wrap_nonce)?;
        if unwrapped.len() != 32 {
            return Err("unwrapped key has wrong length".to_string());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&unwrapped);
        key
    } else {
        return Err("must provide either content_key or (password + wrapped_key + salt)".to_string());
    };

    // Decrypt payload
    if ciphertext.len() < aead::NONCE_SIZE {
        return Err("ciphertext too short".to_string());
    }
    let nonce: [u8; aead::NONCE_SIZE] = ciphertext[..aead::NONCE_SIZE]
        .try_into()
        .map_err(|_| "invalid nonce")?;
    let ct = &ciphertext[aead::NONCE_SIZE..];

    let mut key_copy = key;
    let result = aead::decrypt(&key_copy, ct, &nonce);
    key_copy.zeroize();
    result
}

/// Bundle returned from share encryption.
pub struct ShareBundle {
    /// Encrypted payload (nonce prepended)
    pub ciphertext: Vec<u8>,
    /// Content encryption key (32 bytes) — embed in URL fragment if no password
    pub content_key: [u8; 32],
    /// Wrapped content key (if password-protected)
    pub wrapped_key: Option<Vec<u8>>,
    /// Salt for password derivation (if password-protected)
    pub salt: Option<[u8; 32]>,
}

impl Drop for ShareBundle {
    fn drop(&mut self) {
        self.content_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_no_password() {
        let payload = b"Secret data for sharing";
        let bundle = encrypt_share(payload, None).unwrap();

        assert!(bundle.wrapped_key.is_none());
        assert!(bundle.salt.is_none());

        let decrypted = decrypt_share(
            &bundle.ciphertext,
            Some(&bundle.content_key),
            None,
            None,
            None,
        ).unwrap();

        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_share_with_password() {
        let payload = b"Password-protected secret";
        let password = "str0ng_p@ssw0rd!";

        let bundle = encrypt_share(payload, Some(password)).unwrap();

        assert!(bundle.wrapped_key.is_some());
        assert!(bundle.salt.is_some());

        let decrypted = decrypt_share(
            &bundle.ciphertext,
            None,
            Some(password),
            bundle.wrapped_key.as_deref(),
            bundle.salt.as_ref(),
        ).unwrap();

        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_share_wrong_password() {
        let payload = b"Secret";
        let bundle = encrypt_share(payload, Some("correct")).unwrap();

        let result = decrypt_share(
            &bundle.ciphertext,
            None,
            Some("wrong"),
            bundle.wrapped_key.as_deref(),
            bundle.salt.as_ref(),
        );

        assert!(result.is_err(), "Wrong password must fail");
    }

    #[test]
    fn test_share_large_payload() {
        let payload = vec![0xAB; 1_000_000]; // 1 MB
        let bundle = encrypt_share(&payload, Some("test")).unwrap();

        let decrypted = decrypt_share(
            &bundle.ciphertext,
            None,
            Some("test"),
            bundle.wrapped_key.as_deref(),
            bundle.salt.as_ref(),
        ).unwrap();

        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_share_empty_payload() {
        let bundle = encrypt_share(b"", None).unwrap();
        let decrypted = decrypt_share(
            &bundle.ciphertext,
            Some(&bundle.content_key),
            None,
            None,
            None,
        ).unwrap();
        assert_eq!(decrypted, b"");
    }
}
