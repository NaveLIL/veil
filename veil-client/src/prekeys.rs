//! Durable own-device X3DH prekey publication contracts.
//!
//! Network I/O deliberately stays outside this module. Native transports use
//! the exact request body returned by [`crate::api::VeilClient`] and hand raw,
//! bounded server responses back to these fail-closed validators.

use std::collections::HashSet;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use veil_store::db::LocalPreKeyPublicationV1;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const OWN_PREKEY_LOW_WATERMARK: u32 = 10;
pub const OWN_PREKEY_BATCH_SIZE: usize = 20;
pub const OWN_PREKEY_UPLOAD_STORED_COUNT: u32 = OWN_PREKEY_BATCH_SIZE as u32 + 1;
pub const OWN_PREKEY_RESPONSE_LIMIT: usize = 64 * 1024;
pub const OWN_PREKEY_MAX_UNUSED: u32 = 100;
pub const OWN_PREKEY_UPLOAD_TARGET: &str = "/v1/prekeys";

/// Public-only, exact-byte publication state retained in SQLCipher.
///
/// The body and its digest are capabilities for one origin/account/device
/// tuple. Callers must never rebuild or reserialize `request_body` on retry.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct OwnPreKeyPublication {
    pub canonical_server_origin: String,
    pub user_id: String,
    pub device_id: [u8; 16],
    pub signed_prekey_id: u32,
    pub body_sha256: [u8; 32],
    pub request_body: Vec<u8>,
    pub acknowledged: bool,
}

impl OwnPreKeyPublication {
    pub(crate) fn from_local(value: &LocalPreKeyPublicationV1) -> Self {
        Self {
            canonical_server_origin: value.canonical_server_origin.clone(),
            user_id: value.user_id.clone(),
            device_id: value.device_id,
            signed_prekey_id: value.signed_prekey_id,
            body_sha256: value.body_sha256,
            request_body: value.request_body.clone(),
            acknowledged: value.acknowledged,
        }
    }
}

/// Coarse result returned only after the exact current publication was
/// acknowledged durably. Server inventory remains an advisory native detail.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnPreKeyAcknowledgeResult {
    Acknowledged,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnPreKeyCount {
    pub remaining: u32,
    pub signed_prekey_id: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ValidatedOwnPreKeyUploadAck {
    pub(crate) opk_remaining: u32,
}

#[derive(Serialize)]
struct UploadPreKeysWire {
    device_id: String,
    signed_prekey: SignedPreKeyWire,
    one_time_prekeys: Vec<OneTimePreKeyWire>,
}

#[derive(Serialize)]
struct SignedPreKeyWire {
    key_id: u32,
    public_key: String,
    signature: String,
}

#[derive(Serialize)]
struct OneTimePreKeyWire {
    key_id: u32,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreKeyCountResponseWire {
    devices: Vec<PreKeyDeviceCountWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreKeyDeviceCountWire {
    device_id: String,
    remaining: u32,
    #[serde(default)]
    signed_prekey_id: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreKeyUploadAckWire {
    stored: u32,
    opk_remaining: u32,
}

/// Serialize one immutable upload body with deterministic field order,
/// lowercase device hex, and padded RFC 4648 Base64.
pub(crate) fn canonical_own_prekey_request_body(
    device_id: &[u8; 16],
    signing_key: &[u8; 32],
    signed_prekey_id: u32,
    signed_prekey_public: &[u8; 32],
    signed_prekey_signature: &[u8; 64],
    one_time_prekeys: &[([u8; 32], u32)],
) -> Result<Vec<u8>, String> {
    if *device_id == [0u8; 16] {
        return Err("own prekey publication device is invalid".to_string());
    }
    if signed_prekey_id == 0 || *signed_prekey_public == [0u8; 32] {
        return Err("own signed prekey is invalid".to_string());
    }
    let signature_message =
        veil_crypto::x3dh::signed_prekey_signature_message(signed_prekey_public);
    if !veil_crypto::signature::verify(signing_key, &signature_message, signed_prekey_signature) {
        return Err("own signed prekey failed domain-separated verification".to_string());
    }
    if one_time_prekeys.len() != OWN_PREKEY_BATCH_SIZE {
        return Err("own prekey publication must contain 20 one-time prekeys".to_string());
    }

    let mut sorted = one_time_prekeys.to_vec();
    sorted.sort_unstable_by_key(|(_, key_id)| *key_id);
    let mut previous = None;
    let one_time_prekeys = sorted
        .into_iter()
        .map(|(public_key, key_id)| {
            if key_id == 0 || public_key == [0u8; 32] || previous == Some(key_id) {
                return Err("own prekey publication contains an invalid OPK".to_string());
            }
            previous = Some(key_id);
            Ok(OneTimePreKeyWire {
                key_id,
                public_key: BASE64_STANDARD.encode(public_key),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let body = serde_json::to_vec(&UploadPreKeysWire {
        device_id: hex::encode(device_id),
        signed_prekey: SignedPreKeyWire {
            key_id: signed_prekey_id,
            public_key: BASE64_STANDARD.encode(signed_prekey_public),
            signature: BASE64_STANDARD.encode(signed_prekey_signature),
        },
        one_time_prekeys,
    })
    .map_err(|error| format!("serialize own prekey publication: {error}"))?;
    if body.is_empty() || body.len() > OWN_PREKEY_RESPONSE_LIMIT {
        return Err("own prekey publication body exceeds the native limit".to_string());
    }
    Ok(body)
}

/// Validate `/count` and return only the exact local device inventory.
/// Every device id must be canonical and unique; the local id must occur once.
pub fn validate_own_prekey_count_response(
    response: &[u8],
    local_device_id: &[u8; 16],
) -> Result<OwnPreKeyCount, String> {
    if *local_device_id == [0u8; 16] {
        return Err("own prekey count device is invalid".to_string());
    }
    let wire: PreKeyCountResponseWire = decode_bounded_json(response, "own prekey count")?;
    let mut seen = HashSet::with_capacity(wire.devices.len());
    let mut local_count = None;
    for device in wire.devices {
        let device_id = decode_canonical_device_id(&device.device_id)?;
        if !seen.insert(device_id) {
            return Err("own prekey count contains a duplicate device".to_string());
        }
        if device.remaining > OWN_PREKEY_MAX_UNUSED {
            return Err("own prekey count exceeds the server inventory limit".to_string());
        }
        if device.signed_prekey_id == Some(0) {
            return Err("own prekey count contains a zero signed prekey id".to_string());
        }
        if device_id == *local_device_id {
            local_count = Some(OwnPreKeyCount {
                remaining: device.remaining,
                signed_prekey_id: device.signed_prekey_id,
            });
        }
    }
    local_count.ok_or_else(|| "own prekey count omits the exact local device".to_string())
}

/// Strictly validate a successful upload response. `stored` describes the
/// immutable one-SPK/twenty-OPK request shape, not newly inserted row count.
pub(crate) fn validate_own_prekey_upload_ack(
    response: &[u8],
) -> Result<ValidatedOwnPreKeyUploadAck, String> {
    let wire: PreKeyUploadAckWire = decode_bounded_json(response, "own prekey upload ACK")?;
    if wire.stored != OWN_PREKEY_UPLOAD_STORED_COUNT {
        return Err("own prekey upload ACK has an unexpected stored count".to_string());
    }
    if wire.opk_remaining > OWN_PREKEY_MAX_UNUSED {
        return Err("own prekey upload ACK exceeds the server inventory limit".to_string());
    }
    Ok(ValidatedOwnPreKeyUploadAck {
        opk_remaining: wire.opk_remaining,
    })
}

fn decode_bounded_json<T>(response: &[u8], kind: &str) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    if response.is_empty() || response.len() > OWN_PREKEY_RESPONSE_LIMIT {
        return Err(format!("{kind} response is empty or oversized"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(response);
    let value = T::deserialize(&mut deserializer)
        .map_err(|error| format!("invalid {kind} response: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("invalid {kind} response: {error}"))?;
    Ok(value)
}

fn decode_canonical_device_id(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("own prekey count contains a non-canonical device id".to_string());
    }
    let mut decoded = [0u8; 16];
    hex::decode_to_slice(value, &mut decoded)
        .map_err(|_| "own prekey count contains an invalid device id".to_string())?;
    if decoded == [0u8; 16] {
        return Err("own prekey count contains the zero device id".to_string());
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_crypto::keys::IdentityKeyPair;
    use veil_crypto::x3dh::{OneTimePreKey, SignedPreKey};

    fn canonical_body_fixture() -> (IdentityKeyPair, SignedPreKey, Vec<OneTimePreKey>) {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(&identity, 7);
        let opks = (20..40).rev().map(OneTimePreKey::generate).collect();
        (identity, spk, opks)
    }

    #[test]
    fn canonical_upload_is_sorted_padded_and_domain_verified() {
        let (identity, spk, opks) = canonical_body_fixture();
        let public_opks: Vec<_> = opks
            .iter()
            .map(|opk| (*opk.public.as_bytes(), opk.id))
            .collect();
        let body = canonical_own_prekey_request_body(
            &[0xAB; 16],
            &identity.ed25519_public_bytes(),
            spk.id,
            spk.public.as_bytes(),
            &spk.signature,
            &public_opks,
        )
        .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text
            .starts_with("{\"device_id\":\"abababababababababababababababab\",\"signed_prekey\":"));
        assert!(text.contains("\"one_time_prekeys\":[{\"key_id\":20,"));
        assert!(text.ends_with("}]}"));
        assert!(!text.contains("\"signature\":\"\",\"key_id\""));
        assert!(text.contains('='));

        let mut bad_signature = spk.signature;
        bad_signature[0] ^= 1;
        assert!(canonical_own_prekey_request_body(
            &[0xAB; 16],
            &identity.ed25519_public_bytes(),
            spk.id,
            spk.public.as_bytes(),
            &bad_signature,
            &public_opks,
        )
        .is_err());
    }

    #[test]
    fn count_requires_one_exact_local_device_and_strict_shape() {
        let local = [0x11; 16];
        assert_eq!(
            validate_own_prekey_count_response(
                br#"{"devices":[{"device_id":"11111111111111111111111111111111","remaining":10}]}"#,
                &local,
            )
            .unwrap(),
            OwnPreKeyCount {
                remaining: 10,
                signed_prekey_id: None,
            }
        );
        assert_eq!(
            validate_own_prekey_count_response(
                br#"{"devices":[{"device_id":"11111111111111111111111111111111","remaining":10,"signed_prekey_id":7}]}"#,
                &local,
            )
            .unwrap()
            .signed_prekey_id,
            Some(7)
        );
        for malformed in [
            br#"{"devices":[]}"#.as_slice(),
            br#"{"devices":[{"device_id":"11111111111111111111111111111111","remaining":101}]}"#,
            br#"{"devices":[{"device_id":"11111111111111111111111111111111","remaining":10,"extra":0}]}"#,
            br#"{"devices":[{"device_id":"11111111111111111111111111111111","remaining":10},{"device_id":"11111111111111111111111111111111","remaining":10}]}"#,
            br#"{"devices":[{"device_id":"1111111111111111111111111111111A","remaining":10}]}"#,
            br#"{"devices":[{"device_id":"11111111111111111111111111111111","remaining":10,"signed_prekey_id":0}]}"#,
        ] {
            assert!(validate_own_prekey_count_response(malformed, &local).is_err());
        }
    }

    #[test]
    fn upload_ack_requires_exact_counts_and_strict_shape() {
        assert_eq!(
            validate_own_prekey_upload_ack(br#"{"stored":21,"opk_remaining":0}"#)
                .unwrap()
                .opk_remaining,
            0
        );
        assert!(validate_own_prekey_upload_ack(br#"{"stored":21,"opk_remaining":100}"#).is_ok());
        for malformed in [
            br#"{"stored":20,"opk_remaining":20}"#.as_slice(),
            br#"{"stored":21,"opk_remaining":101}"#,
            br#"{"stored":21,"opk_remaining":20,"extra":true}"#,
            br#"{"stored":21}"#,
            br#"{"stored":21,"opk_remaining":20} trailing"#,
        ] {
            assert!(validate_own_prekey_upload_ack(malformed).is_err());
        }
    }
}
