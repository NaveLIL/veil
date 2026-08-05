//! Independent, account-authorized per-install device identity.
//!
//! Device private keys are random and live only in native memory/SQLCipher;
//! they are never derived from the account mnemonic and never cross FFI.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use veil_crypto::{signature, IdentityKeyPair};
use veil_store::db::LocalDeviceIdentityV1;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

pub const DEVICE_BINDING_VERSION_V1: u64 = 1;
pub const DEVICE_CAPABILITY_SENDER_KEY_V5: u64 = 1;
pub const DEVICE_CAPABILITY_SEALED_SKDM_V3: u64 = 2;
pub const DEVICE_CAPABILITY_MEMBERSHIP_EPOCH_V1: u64 = 4;
pub const REQUIRED_DEVICE_CAPABILITIES: u64 =
    DEVICE_CAPABILITY_SENDER_KEY_V5 | DEVICE_CAPABILITY_SEALED_SKDM_V3;
pub const CURRENT_DEVICE_CAPABILITIES: u64 =
    REQUIRED_DEVICE_CAPABILITIES | DEVICE_CAPABILITY_MEMBERSHIP_EPOCH_V1;
pub const DEVICE_BINDING_STATUS_ACTIVE: u8 = 1;
const MAX_DEVICE_V1_INTEGER: u64 = i64::MAX as u64;

const DEVICE_BINDING_DOMAIN: &[u8] = b"veil-device-binding-v1\0";
const DEVICE_AUTH_DOMAIN: &[u8] = b"veil-device-auth-v1\0";

fn canonicalize_x25519_secret(secret: &mut [u8; 32]) {
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceBindingPublicV1 {
    pub device_id: [u8; 16],
    pub device_identity_key: [u8; 32],
    pub device_signing_key: [u8; 32],
    pub version: u64,
    pub capabilities: u64,
    pub status: u8,
    pub account_signature: [u8; 64],
}

/// Live native device keypair. Both secret types zeroize on drop through their
/// respective dalek implementations; this type is intentionally not Clone or
/// serializable.
pub struct DeviceIdentityV1 {
    x25519_secret: X25519StaticSecret,
    ed25519_signing: SigningKey,
    binding: DeviceBindingPublicV1,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn device_binding_signing_bytes(
    account_identity_key: &[u8; 32],
    account_signing_key: &[u8; 32],
    device_id: &[u8; 16],
    version: u64,
    device_identity_key: &[u8; 32],
    device_signing_key: &[u8; 32],
    capabilities: u64,
    status: u8,
) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(DEVICE_BINDING_DOMAIN.len() + 32 + 32 + 16 + 8 + 32 + 32 + 8 + 1);
    bytes.extend_from_slice(DEVICE_BINDING_DOMAIN);
    bytes.extend_from_slice(account_identity_key);
    bytes.extend_from_slice(account_signing_key);
    bytes.extend_from_slice(device_id);
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(device_identity_key);
    bytes.extend_from_slice(device_signing_key);
    bytes.extend_from_slice(&capabilities.to_be_bytes());
    bytes.push(status);
    bytes
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn device_auth_signing_bytes(
    server_ephemeral: &[u8; 32],
    account_identity_key: &[u8; 32],
    account_signing_key: &[u8; 32],
    binding: &DeviceBindingPublicV1,
    device_dh_shared: &[u8; 32],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        DEVICE_AUTH_DOMAIN.len() + 32 + 32 + 32 + 16 + 8 + 32 + 32 + 8 + 1 + 64 + 32,
    );
    bytes.extend_from_slice(DEVICE_AUTH_DOMAIN);
    bytes.extend_from_slice(server_ephemeral);
    bytes.extend_from_slice(account_identity_key);
    bytes.extend_from_slice(account_signing_key);
    bytes.extend_from_slice(&binding.device_id);
    bytes.extend_from_slice(&binding.version.to_be_bytes());
    bytes.extend_from_slice(&binding.device_identity_key);
    bytes.extend_from_slice(&binding.device_signing_key);
    bytes.extend_from_slice(&binding.capabilities.to_be_bytes());
    bytes.push(binding.status);
    bytes.extend_from_slice(&binding.account_signature);
    bytes.extend_from_slice(device_dh_shared);
    bytes
}

impl DeviceIdentityV1 {
    /// Generate fresh random device secrets and the account-authorized record
    /// that must be committed to SQLCipher before this identity can be used.
    pub fn generate_stored(
        account: &IdentityKeyPair,
        device_id: [u8; 16],
    ) -> Result<LocalDeviceIdentityV1, String> {
        if device_id == [0u8; 16] {
            return Err("refusing to bind an all-zero device id".to_string());
        }
        let generated_x25519 = X25519StaticSecret::random_from_rng(OsRng);
        let mut x25519_bytes = generated_x25519.to_bytes();
        drop(generated_x25519);
        canonicalize_x25519_secret(&mut x25519_bytes);
        let x25519_secret = X25519StaticSecret::from(x25519_bytes);
        x25519_bytes.zeroize();
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        let ed25519_signing = SigningKey::generate(&mut OsRng);
        let device_identity_key = *x25519_public.as_bytes();
        let device_signing_key = ed25519_signing.verifying_key().to_bytes();
        let account_identity_key = account.x25519_public_bytes();
        let account_signing_key = account.ed25519_public_bytes();
        let signing_bytes = device_binding_signing_bytes(
            &account_identity_key,
            &account_signing_key,
            &device_id,
            DEVICE_BINDING_VERSION_V1,
            &device_identity_key,
            &device_signing_key,
            CURRENT_DEVICE_CAPABILITIES,
            DEVICE_BINDING_STATUS_ACTIVE,
        );
        let account_signature = signature::sign(account, &signing_bytes);

        Ok(LocalDeviceIdentityV1 {
            device_id,
            version: DEVICE_BINDING_VERSION_V1,
            x25519_secret: x25519_secret.to_bytes(),
            ed25519_secret: ed25519_signing.to_bytes(),
            device_identity_key,
            device_signing_key,
            capabilities: CURRENT_DEVICE_CAPABILITIES,
            status: DEVICE_BINDING_STATUS_ACTIVE,
            account_identity_key,
            account_signing_key,
            account_signature,
        })
    }

    /// Validate and hydrate a stored identity. Every public/authenticated field
    /// is recomputed before any private key becomes eligible for WS auth.
    pub fn from_stored(
        account: &IdentityKeyPair,
        mut stored: LocalDeviceIdentityV1,
    ) -> Result<Self, String> {
        if stored.device_id == [0u8; 16] {
            return Err("persisted device id is all zero".to_string());
        }
        if stored.version == 0 || stored.version > MAX_DEVICE_V1_INTEGER {
            return Err(format!(
                "invalid persisted device binding version {}",
                stored.version
            ));
        }
        if stored.capabilities & REQUIRED_DEVICE_CAPABILITIES != REQUIRED_DEVICE_CAPABILITIES {
            return Err("persisted device binding lacks required crypto capabilities".to_string());
        }
        if stored.capabilities > MAX_DEVICE_V1_INTEGER {
            return Err("persisted device capabilities reserve the high bit".to_string());
        }
        if stored.status != DEVICE_BINDING_STATUS_ACTIVE {
            return Err("persisted device binding is not active".to_string());
        }

        let account_identity_key = account.x25519_public_bytes();
        let account_signing_key = account.ed25519_public_bytes();
        if !bool::from(account_identity_key.ct_eq(&stored.account_identity_key))
            || !bool::from(account_signing_key.ct_eq(&stored.account_signing_key))
        {
            return Err("persisted device binding belongs to a different account".to_string());
        }

        let mut x25519_bytes = std::mem::take(&mut stored.x25519_secret);
        let mut canonical_x25519 = x25519_bytes;
        canonicalize_x25519_secret(&mut canonical_x25519);
        if !bool::from(canonical_x25519.ct_eq(&x25519_bytes)) {
            canonical_x25519.zeroize();
            x25519_bytes.zeroize();
            return Err("persisted device X25519 secret is non-canonical".to_string());
        }
        canonical_x25519.zeroize();
        let x25519_secret = X25519StaticSecret::from(x25519_bytes);
        x25519_bytes.zeroize();
        let derived_x25519 = X25519PublicKey::from(&x25519_secret);
        if !bool::from(derived_x25519.as_bytes().ct_eq(&stored.device_identity_key)) {
            return Err("persisted device X25519 secret/public key mismatch".to_string());
        }

        let mut ed25519_bytes = std::mem::take(&mut stored.ed25519_secret);
        let ed25519_signing = SigningKey::from_bytes(&ed25519_bytes);
        ed25519_bytes.zeroize();
        let derived_ed25519 = ed25519_signing.verifying_key().to_bytes();
        if !bool::from(derived_ed25519.ct_eq(&stored.device_signing_key)) {
            return Err("persisted device Ed25519 secret/public key mismatch".to_string());
        }

        let signing_bytes = device_binding_signing_bytes(
            &account_identity_key,
            &account_signing_key,
            &stored.device_id,
            stored.version,
            &stored.device_identity_key,
            &stored.device_signing_key,
            stored.capabilities,
            stored.status,
        );
        if !signature::verify(
            &account_signing_key,
            &signing_bytes,
            &stored.account_signature,
        ) {
            return Err("persisted device binding account signature is invalid".to_string());
        }

        let binding = DeviceBindingPublicV1 {
            device_id: stored.device_id,
            device_identity_key: stored.device_identity_key,
            device_signing_key: stored.device_signing_key,
            version: stored.version,
            capabilities: stored.capabilities,
            status: stored.status,
            account_signature: stored.account_signature,
        };
        Ok(Self {
            x25519_secret,
            ed25519_signing,
            binding,
        })
    }

    pub fn clone_for_background(&self) -> Self {
        let mut x_bytes = self.x25519_secret.to_bytes();
        let mut e_bytes = self.ed25519_signing.to_bytes();

        let x25519_secret = X25519StaticSecret::from(x_bytes);
        let ed25519_signing = SigningKey::from_bytes(&e_bytes);

        x_bytes.zeroize();
        e_bytes.zeroize();

        Self {
            x25519_secret,
            ed25519_signing,
            binding: self.binding.clone(),
        }
    }

    pub(crate) fn capability_upgrade_v1(
        &self,
        account: &IdentityKeyPair,
    ) -> Result<Option<Self>, String> {
        if self.binding.capabilities & CURRENT_DEVICE_CAPABILITIES == CURRENT_DEVICE_CAPABILITIES {
            return Ok(None);
        }
        let version = self
            .binding
            .version
            .checked_add(1)
            .filter(|value| *value <= MAX_DEVICE_V1_INTEGER)
            .ok_or("device binding version is exhausted")?;
        let account_identity_key = account.x25519_public_bytes();
        let account_signing_key = account.ed25519_public_bytes();
        let capabilities = self.binding.capabilities | CURRENT_DEVICE_CAPABILITIES;
        let signing_bytes = device_binding_signing_bytes(
            &account_identity_key,
            &account_signing_key,
            &self.binding.device_id,
            version,
            &self.binding.device_identity_key,
            &self.binding.device_signing_key,
            capabilities,
            self.binding.status,
        );
        let binding = DeviceBindingPublicV1 {
            device_id: self.binding.device_id,
            device_identity_key: self.binding.device_identity_key,
            device_signing_key: self.binding.device_signing_key,
            version,
            capabilities,
            status: self.binding.status,
            account_signature: signature::sign(account, &signing_bytes),
        };
        let mut x25519 = self.x25519_secret.to_bytes();
        let mut ed25519 = self.ed25519_signing.to_bytes();
        let upgraded = Self {
            x25519_secret: X25519StaticSecret::from(x25519),
            ed25519_signing: SigningKey::from_bytes(&ed25519),
            binding,
        };
        x25519.zeroize();
        ed25519.zeroize();
        Ok(Some(upgraded))
    }

    pub(crate) fn to_stored_v1(&self, account: &IdentityKeyPair) -> LocalDeviceIdentityV1 {
        LocalDeviceIdentityV1 {
            device_id: self.binding.device_id,
            version: self.binding.version,
            x25519_secret: self.x25519_secret.to_bytes(),
            ed25519_secret: self.ed25519_signing.to_bytes(),
            device_identity_key: self.binding.device_identity_key,
            device_signing_key: self.binding.device_signing_key,
            capabilities: self.binding.capabilities,
            status: self.binding.status,
            account_identity_key: account.x25519_public_bytes(),
            account_signing_key: account.ed25519_public_bytes(),
            account_signature: self.binding.account_signature,
        }
    }

    pub fn binding(&self) -> &DeviceBindingPublicV1 {
        &self.binding
    }

    pub(crate) fn x25519_secret(&self) -> &X25519StaticSecret {
        &self.x25519_secret
    }

    pub(crate) fn ed25519_signing_key(&self) -> &SigningKey {
        &self.ed25519_signing
    }

    /// Sign the device-auth proof over the server ephemeral and device DH.
    pub fn auth_signature(
        &self,
        account: &IdentityKeyPair,
        server_ephemeral: &[u8],
    ) -> Result<[u8; 64], String> {
        let server_ephemeral: [u8; 32] = server_ephemeral
            .try_into()
            .map_err(|_| "invalid device auth challenge length".to_string())?;
        let account_identity_key = account.x25519_public_bytes();
        let account_signing_key = account.ed25519_public_bytes();
        if !signature::verify(
            &account_signing_key,
            &device_binding_signing_bytes(
                &account_identity_key,
                &account_signing_key,
                &self.binding.device_id,
                self.binding.version,
                &self.binding.device_identity_key,
                &self.binding.device_signing_key,
                self.binding.capabilities,
                self.binding.status,
            ),
            &self.binding.account_signature,
        ) {
            return Err("device binding no longer matches the account identity".to_string());
        }

        let server_public = X25519PublicKey::from(server_ephemeral);
        let mut shared = self.x25519_secret.diffie_hellman(&server_public).to_bytes();
        if bool::from(shared.ct_eq(&[0u8; 32])) {
            shared.zeroize();
            return Err("invalid device auth challenge: all-zero DH result".to_string());
        }
        let mut proof = device_auth_signing_bytes(
            &server_ephemeral,
            &account_identity_key,
            &account_signing_key,
            &self.binding,
            &shared,
        );
        let signature = self.ed25519_signing.sign(&proof).to_bytes();
        proof.zeroize();
        shared.zeroize();
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn generated_device_binding_roundtrips_and_detects_corruption() {
        let account = IdentityKeyPair::from_mnemonic(TEST_MNEMONIC).unwrap();
        let stored = DeviceIdentityV1::generate_stored(&account, [0xA5; 16]).unwrap();
        let public = (
            stored.device_identity_key,
            stored.device_signing_key,
            stored.account_signature,
        );
        let loaded = DeviceIdentityV1::from_stored(&account, stored).unwrap();
        assert_eq!(loaded.binding().device_identity_key, public.0);
        assert_eq!(loaded.binding().device_signing_key, public.1);
        assert_eq!(loaded.binding().account_signature, public.2);

        let server = IdentityKeyPair::generate();
        let server_ephemeral = server.x25519_public_bytes();
        let device_signature = loaded.auth_signature(&account, &server_ephemeral).unwrap();
        let shared = server.x25519_dh(&loaded.binding().device_identity_key);
        let proof = device_auth_signing_bytes(
            &server_ephemeral,
            &account.x25519_public_bytes(),
            &account.ed25519_public_bytes(),
            loaded.binding(),
            &shared,
        );
        assert!(signature::verify(
            &loaded.binding().device_signing_key,
            &proof,
            &device_signature
        ));
        assert!(loaded.auth_signature(&account, &[0u8; 31]).is_err());
        assert!(loaded.auth_signature(&account, &[0u8; 32]).is_err());

        let mut corrupt_secret = DeviceIdentityV1::generate_stored(&account, [0xA6; 16]).unwrap();
        // Even a flip in a clamped/otherwise ignored bit is rejected because
        // generated secrets are persisted in one canonical representation.
        corrupt_secret.x25519_secret[0] ^= 1;
        assert!(DeviceIdentityV1::from_stored(&account, corrupt_secret)
            .err()
            .unwrap()
            .contains("secret is non-canonical"));

        let mut corrupt_signature =
            DeviceIdentityV1::generate_stored(&account, [0xA7; 16]).unwrap();
        corrupt_signature.account_signature[0] ^= 1;
        assert!(DeviceIdentityV1::from_stored(&account, corrupt_signature)
            .err()
            .unwrap()
            .contains("account signature is invalid"));
    }

    #[test]
    fn legacy_device_capabilities_upgrade_once_without_replacing_private_identity() {
        let account = IdentityKeyPair::from_mnemonic(TEST_MNEMONIC).unwrap();
        let mut stored = DeviceIdentityV1::generate_stored(&account, [0xB5; 16]).unwrap();
        stored.capabilities = REQUIRED_DEVICE_CAPABILITIES;
        stored.account_signature = signature::sign(
            &account,
            &device_binding_signing_bytes(
                &stored.account_identity_key,
                &stored.account_signing_key,
                &stored.device_id,
                stored.version,
                &stored.device_identity_key,
                &stored.device_signing_key,
                stored.capabilities,
                stored.status,
            ),
        );
        let original_version = stored.version;
        let original_device_id = stored.device_id;
        let original_x25519_secret = stored.x25519_secret;
        let original_ed25519_secret = stored.ed25519_secret;
        let original_device_identity_key = stored.device_identity_key;
        let original_device_signing_key = stored.device_signing_key;
        let original_account_signature = stored.account_signature;
        let legacy = DeviceIdentityV1::from_stored(&account, stored).unwrap();
        let upgraded = legacy
            .capability_upgrade_v1(&account)
            .unwrap()
            .expect("legacy capability set must be upgraded");
        let persisted = upgraded.to_stored_v1(&account);

        assert_eq!(persisted.version, original_version + 1);
        assert_eq!(persisted.capabilities, CURRENT_DEVICE_CAPABILITIES);
        assert_eq!(persisted.device_id, original_device_id);
        assert_eq!(persisted.x25519_secret, original_x25519_secret);
        assert_eq!(persisted.ed25519_secret, original_ed25519_secret);
        assert_eq!(persisted.device_identity_key, original_device_identity_key);
        assert_eq!(persisted.device_signing_key, original_device_signing_key);
        assert_ne!(persisted.account_signature, original_account_signature);

        let restored = DeviceIdentityV1::from_stored(&account, persisted).unwrap();
        assert!(restored.capability_upgrade_v1(&account).unwrap().is_none());
    }

    #[test]
    fn binding_preimage_has_the_locked_wire_layout() {
        let bytes = device_binding_signing_bytes(
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 16],
            1,
            &[0x44; 32],
            &[0x55; 32],
            3,
            1,
        );
        assert_eq!(
            hex::encode(bytes),
            concat!(
                "7665696c2d6465766963652d62696e64696e672d763100",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222222222222222222222222222",
                "33333333333333333333333333333333",
                "0000000000000001",
                "4444444444444444444444444444444444444444444444444444444444444444",
                "5555555555555555555555555555555555555555555555555555555555555555",
                "0000000000000003",
                "01"
            )
        );
    }

    #[test]
    fn device_binding_and_auth_match_the_cross_language_v1_vector() {
        let account_identity_key = [0x11u8; 32];
        let account_signing = SigningKey::from_bytes(&[0x22u8; 32]);
        let account_signing_key = account_signing.verifying_key().to_bytes();
        assert_eq!(
            hex::encode(account_signing_key),
            "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"
        );

        let device_x25519 = X25519StaticSecret::from([0x44u8; 32]);
        let device_identity_key = X25519PublicKey::from(&device_x25519).to_bytes();
        let device_signing = SigningKey::from_bytes(&[0x55u8; 32]);
        let device_signing_key = device_signing.verifying_key().to_bytes();
        assert_eq!(
            hex::encode(device_identity_key),
            "ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b"
        );
        assert_eq!(
            hex::encode(device_signing_key),
            "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242"
        );

        let binding_preimage = device_binding_signing_bytes(
            &account_identity_key,
            &account_signing_key,
            &[0x33u8; 16],
            1,
            &device_identity_key,
            &device_signing_key,
            3,
            1,
        );
        assert_eq!(
            hex::encode(&binding_preimage),
            concat!(
                "7665696c2d6465766963652d62696e64696e672d763100",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0",
                "33333333333333333333333333333333",
                "0000000000000001",
                "ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b",
                "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242",
                "0000000000000003",
                "01"
            )
        );
        let account_signature = account_signing.sign(&binding_preimage).to_bytes();
        assert_eq!(
            hex::encode(account_signature),
            concat!(
                "30c502700162d164a178a1fd624b3876c084f327f5e1a822fca2c9be977f709",
                "2928ff337559313ae0d11f7cc2447ae33f66f1f369dc9b2f32af3ee6fede29a00"
            )
        );

        let server_x25519 = X25519StaticSecret::from([0x66u8; 32]);
        let server_ephemeral = X25519PublicKey::from(&server_x25519).to_bytes();
        assert_eq!(
            hex::encode(server_ephemeral),
            "219e4d800da968d2a5fcb009c784f4746c7138edb9ee4844b739e830b05cf424"
        );
        let shared = device_x25519.diffie_hellman(&X25519PublicKey::from(server_ephemeral));
        assert_eq!(
            hex::encode(shared.as_bytes()),
            "bef8ae582f817bd7eb1b104a83343a15770c1cf2dbc4b4207b70897b7a532209"
        );
        let binding = DeviceBindingPublicV1 {
            device_id: [0x33u8; 16],
            device_identity_key,
            device_signing_key,
            version: 1,
            capabilities: 3,
            status: 1,
            account_signature,
        };
        let auth_preimage = device_auth_signing_bytes(
            &server_ephemeral,
            &account_identity_key,
            &account_signing_key,
            &binding,
            shared.as_bytes(),
        );
        assert_eq!(
            hex::encode(&auth_preimage),
            concat!(
                "7665696c2d6465766963652d617574682d763100",
                "219e4d800da968d2a5fcb009c784f4746c7138edb9ee4844b739e830b05cf424",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0",
                "33333333333333333333333333333333",
                "0000000000000001",
                "ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b",
                "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242",
                "0000000000000003",
                "01",
                "30c502700162d164a178a1fd624b3876c084f327f5e1a822fca2c9be977f709",
                "2928ff337559313ae0d11f7cc2447ae33f66f1f369dc9b2f32af3ee6fede29a00",
                "bef8ae582f817bd7eb1b104a83343a15770c1cf2dbc4b4207b70897b7a532209"
            )
        );
        let device_signature = device_signing.sign(&auth_preimage).to_bytes();
        assert_eq!(
            hex::encode(device_signature),
            concat!(
                "c17d2519f57119fc9415472aef77b212233c586365f10db7b5011dc3f45f7bd",
                "883eedbb6bbfcabe0291fedcc83685ec17790901ce252a3683937b3659f448303"
            )
        );
    }
}
