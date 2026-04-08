use argon2::{self, Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Argon2id parameters for seed derivation (from BIP39 mnemonic).
/// Tuned for native performance: ~200ms on mobile, ~50ms on desktop.
const ARGON2_M_COST: u32 = 65536; // 64 MB
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 4; // 4 parallel lanes

/// Argon2id parameters for PIN (lighter, ~100ms)
const ARGON2_PIN_M_COST: u32 = 32768; // 32 MB
const ARGON2_PIN_T_COST: u32 = 2;
const ARGON2_PIN_P_COST: u32 = 2;

/// Derive a 64-byte seed from a BIP39 mnemonic using Argon2id.
///
/// Returns `[0..32]` for X25519 key, `[32..64]` for Ed25519 key.
/// The salt is derived from the mnemonic itself (deterministic).
pub fn derive_seed_from_mnemonic(mnemonic: &str) -> Result<[u8; 64], String> {
    let salt = {
        let mut hasher = <Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, b"veil-identity-v1:");
        sha2::Digest::update(&mut hasher, mnemonic.as_bytes());
        sha2::Digest::finalize(hasher)
    };

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(64))
        .map_err(|e| format!("argon2 params: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 64];
    argon2
        .hash_password_into(mnemonic.as_bytes(), &salt, &mut output)
        .map_err(|e| format!("argon2 hash: {e}"))?;

    Ok(output)
}

/// Derive a key from a PIN using Argon2id (lighter parameters).
pub fn derive_key_from_pin(pin: &str, salt: &[u8; 32]) -> Result<[u8; 32], String> {
    let params = Params::new(
        ARGON2_PIN_M_COST,
        ARGON2_PIN_T_COST,
        ARGON2_PIN_P_COST,
        Some(32),
    )
    .map_err(|e| format!("argon2 params: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(pin.as_bytes(), salt, &mut output)
        .map_err(|e| format!("argon2 hash: {e}"))?;

    Ok(output)
}

/// Derive a key from a password using Argon2id (for secure shares).
pub fn derive_key_from_password(password: &str, salt: &[u8; 32]) -> Result<[u8; 32], String> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| format!("argon2 params: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| format!("argon2 hash: {e}"))?;

    Ok(output)
}

/// HKDF-SHA256: extract and expand.
/// Used in Double Ratchet for root key derivation (KDF_RK).
///
/// `output_len` must be <= 8160 (255 * 32).
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    assert!(output_len <= 255 * 32, "HKDF output_len must be <= 8160");
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .expect("HKDF output length already validated");
    okm
}

/// HMAC-SHA256: used in Double Ratchet for chain key derivation (KDF_CK).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length should be valid");
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_seed_deterministic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed1 = derive_seed_from_mnemonic(mnemonic).unwrap();
        let seed2 = derive_seed_from_mnemonic(mnemonic).unwrap();
        assert_eq!(seed1, seed2, "Same mnemonic must produce same seed");
        assert_ne!(seed1, [0u8; 64], "Seed must not be all zeros");
    }

    #[test]
    fn test_derive_seed_different_mnemonics() {
        let seed1 = derive_seed_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let seed2 =
            derive_seed_from_mnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong").unwrap();
        assert_ne!(
            seed1, seed2,
            "Different mnemonics must produce different seeds"
        );
    }

    #[test]
    fn test_derive_pin_key() {
        let salt = [42u8; 32];
        let key1 = derive_key_from_pin("1234", &salt).unwrap();
        let key2 = derive_key_from_pin("1234", &salt).unwrap();
        let key3 = derive_key_from_pin("5678", &salt).unwrap();
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_hkdf_sha256() {
        let output = hkdf_sha256(b"salt", b"input key material", b"info", 32);
        assert_eq!(output.len(), 32);
        assert_ne!(output, vec![0u8; 32]);
    }

    #[test]
    fn test_hmac_sha256() {
        let mac1 = hmac_sha256(b"key", b"data");
        let mac2 = hmac_sha256(b"key", b"data");
        let mac3 = hmac_sha256(b"key", b"other");
        assert_eq!(mac1, mac2);
        assert_ne!(mac1, mac3);
    }
}
