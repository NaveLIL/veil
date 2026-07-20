//! Native client-side REST authentication v2 preparation.
//!
//! This module deliberately has no transport, API, FFI, or UI integration.
//! It validates the frozen v2 inputs, obtains native freshness, signs the
//! exact versioned transcript, and emits the five canonical header values.
//! The live REST v1 path remains unchanged.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use veil_crypto::{signature, IdentityKeyPair};
use zeroize::{Zeroize, Zeroizing};

use crate::auth_contract::{
    rest_auth_body_digest_v2, rest_auth_signing_bytes_v2, AuthContractError, CanonicalNodeOriginV1,
    CanonicalRequestTargetV2, CanonicalUserIdV1, RestAuthRequestV2,
};

pub(crate) const REST_AUTH_VERSION_HEADER_V2: &str = "X-Veil-REST-Auth-Version";
pub(crate) const REST_AUTH_USER_HEADER_V2: &str = "X-Veil-User";
pub(crate) const REST_AUTH_TIMESTAMP_HEADER_V2: &str = "X-Veil-Timestamp";
pub(crate) const REST_AUTH_NONCE_HEADER_V2: &str = "X-Veil-Nonce";
pub(crate) const REST_AUTH_SIGNATURE_HEADER_V2: &str = "X-Veil-Signature";

const REST_AUTH_VERSION_V2: &str = "2";
const NONCE_BYTES: usize = 32;
const NONCE_GENERATION_ATTEMPTS: usize = 4;

/// Stable, non-secret classification for rejected REST v2 preparation.
/// Peer-controlled values and cryptographic material are never retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestAuthV2Error {
    InvalidOrigin,
    InvalidUserId,
    InvalidMethod,
    InvalidRequestTarget,
    InvalidTimestamp,
    InvalidNonce,
    RandomnessUnavailable,
    SystemClockUnavailable,
    InvalidTranscript,
}

impl fmt::Display for RestAuthV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidOrigin => "invalid canonical Node origin",
            Self::InvalidUserId => "invalid canonical user id",
            Self::InvalidMethod => "invalid REST method",
            Self::InvalidRequestTarget => "invalid canonical REST request target",
            Self::InvalidTimestamp => "invalid REST timestamp",
            Self::InvalidNonce => "invalid REST nonce",
            Self::RandomnessUnavailable => "secure randomness unavailable",
            Self::SystemClockUnavailable => "system clock unavailable",
            Self::InvalidTranscript => "invalid REST authentication transcript",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RestAuthV2Error {}

/// Canonical wire values for one prepared REST v2 request.
///
/// This type intentionally implements neither `Clone` nor `Debug`. It exposes
/// only already-encoded public header values and retains no request body,
/// signing transcript, raw nonce, or signing key. The wire strings remain
/// copyable authentication material; this type is not a replay boundary.
pub(crate) struct RestAuthV2HeaderValues {
    version: &'static str,
    user_id: String,
    timestamp_ms: String,
    nonce: String,
    signature: String,
}

impl RestAuthV2HeaderValues {
    pub(crate) fn version(&self) -> &str {
        self.version
    }

    pub(crate) fn user_id(&self) -> &str {
        &self.user_id
    }

    pub(crate) fn timestamp_ms(&self) -> &str {
        &self.timestamp_ms
    }

    pub(crate) fn nonce(&self) -> &str {
        &self.nonce
    }

    pub(crate) fn signature(&self) -> &str {
        &self.signature
    }
}

/// One successfully prepared set of headers.
///
/// The output operation permits one consuming extraction from this wrapper.
/// It does not make the returned wire strings unrepeatable: only the durable
/// server replay store enforces a single accepted account-and-nonce claim. This
/// type intentionally implements neither `Clone` nor `Debug`.
pub(crate) struct PreparedRestAuthV2 {
    headers: Option<RestAuthV2HeaderValues>,
}

impl PreparedRestAuthV2 {
    pub(crate) fn into_headers(mut self) -> RestAuthV2HeaderValues {
        self.headers
            .take()
            .expect("prepared REST v2 headers are always present")
    }
}

/// Prepare one REST v2 proof using the native system clock and OS CSPRNG.
///
/// This remains private to `veil-client`; no live transport calls it in this
/// checkpoint.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_rest_auth_v2(
    account: &IdentityKeyPair,
    canonical_origin: &str,
    user_id: &str,
    method: &str,
    request_target: &str,
    body: &[u8],
) -> Result<PreparedRestAuthV2, RestAuthV2Error> {
    let timestamp_ms = system_timestamp_ms()?;
    let mut nonce = generate_nonzero_nonce(&mut OsRng)?;
    let result = prepare_rest_auth_v2_with_freshness_and_signer(
        canonical_origin,
        user_id,
        method,
        request_target,
        body,
        timestamp_ms,
        &nonce,
        |message| signature::sign(account, message),
    );
    nonce.zeroize();
    result
}

#[allow(clippy::too_many_arguments)]
fn prepare_rest_auth_v2_with_freshness_and_signer<F>(
    canonical_origin: &str,
    user_id: &str,
    method: &str,
    request_target: &str,
    body: &[u8],
    timestamp_ms: u64,
    nonce: &[u8; NONCE_BYTES],
    signer: F,
) -> Result<PreparedRestAuthV2, RestAuthV2Error>
where
    F: FnOnce(&[u8]) -> [u8; 64],
{
    let origin = CanonicalNodeOriginV1::parse(canonical_origin)
        .map_err(|_| RestAuthV2Error::InvalidOrigin)?;
    let canonical_user_id =
        CanonicalUserIdV1::parse(user_id).map_err(|_| RestAuthV2Error::InvalidUserId)?;
    let target = CanonicalRequestTargetV2::parse(request_target)
        .map_err(|_| RestAuthV2Error::InvalidRequestTarget)?;
    let body_sha256 = rest_auth_body_digest_v2(body);
    let request = RestAuthRequestV2 {
        origin: &origin,
        user_id: canonical_user_id,
        method,
        request_target: &target,
        timestamp_ms,
        nonce,
        body_sha256: &body_sha256,
    };
    let signing_bytes =
        Zeroizing::new(rest_auth_signing_bytes_v2(&request).map_err(map_contract_error)?);
    let mut raw_signature = signer(signing_bytes.as_slice());
    let nonce_header = URL_SAFE_NO_PAD.encode(nonce);
    let signature_header = URL_SAFE_NO_PAD.encode(raw_signature);
    raw_signature.zeroize();

    Ok(PreparedRestAuthV2 {
        headers: Some(RestAuthV2HeaderValues {
            version: REST_AUTH_VERSION_V2,
            user_id: user_id.to_owned(),
            timestamp_ms: timestamp_ms.to_string(),
            nonce: nonce_header,
            signature: signature_header,
        }),
    })
}

fn system_timestamp_ms() -> Result<u64, RestAuthV2Error> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RestAuthV2Error::SystemClockUnavailable)?;
    let timestamp_ms =
        u64::try_from(elapsed.as_millis()).map_err(|_| RestAuthV2Error::InvalidTimestamp)?;
    if timestamp_ms == 0 || timestamp_ms > i64::MAX as u64 {
        return Err(RestAuthV2Error::InvalidTimestamp);
    }
    Ok(timestamp_ms)
}

fn generate_nonzero_nonce<R>(rng: &mut R) -> Result<[u8; NONCE_BYTES], RestAuthV2Error>
where
    R: RngCore + ?Sized,
{
    for _ in 0..NONCE_GENERATION_ATTEMPTS {
        let mut nonce = [0u8; NONCE_BYTES];
        if rng.try_fill_bytes(&mut nonce).is_err() {
            nonce.zeroize();
            return Err(RestAuthV2Error::RandomnessUnavailable);
        }
        if nonce.iter().any(|byte| *byte != 0) {
            return Ok(nonce);
        }
        nonce.zeroize();
    }
    Err(RestAuthV2Error::RandomnessUnavailable)
}

fn map_contract_error(error: AuthContractError) -> RestAuthV2Error {
    match error {
        AuthContractError::InvalidOrigin => RestAuthV2Error::InvalidOrigin,
        AuthContractError::InvalidUserId => RestAuthV2Error::InvalidUserId,
        AuthContractError::InvalidMethod => RestAuthV2Error::InvalidMethod,
        AuthContractError::InvalidRequestTarget => RestAuthV2Error::InvalidRequestTarget,
        AuthContractError::InvalidTimestamp => RestAuthV2Error::InvalidTimestamp,
        AuthContractError::InvalidNonce => RestAuthV2Error::InvalidNonce,
        _ => RestAuthV2Error::InvalidTranscript,
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn prepare_rest_auth_v2_for_test<F>(
    canonical_origin: &str,
    user_id: &str,
    method: &str,
    request_target: &str,
    body: &[u8],
    timestamp_ms: u64,
    nonce: &[u8; NONCE_BYTES],
    signer: F,
) -> Result<PreparedRestAuthV2, RestAuthV2Error>
where
    F: FnOnce(&[u8]) -> [u8; 64],
{
    prepare_rest_auth_v2_with_freshness_and_signer(
        canonical_origin,
        user_id,
        method,
        request_target,
        body,
        timestamp_ms,
        nonce,
        signer,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use serde::Deserialize;

    use super::*;

    const ORIGIN: &str = "https://node-a.veil.test:443";
    const OTHER_ORIGIN: &str = "https://node-b.veil.test:443";
    const USER_ID: &str = "00112233-4455-4677-8899-aabbccddeeff";
    const METHOD: &str = "POST";
    const TARGET: &str = "/v2/messages?b=2&a=%2F";
    const TIMESTAMP_MS: u64 = 1_700_000_000_123;
    const BODY: &[u8] = br#"{"x":1}"#;
    const FIXTURE_NONCE_B64URL: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
    const FIXTURE_SIGNATURE_B64URL: &str =
        "Ewu90rchBVFAo89wzKG1L12Y-cyw7y37RorsdzVEXZXIc5VTUSgIMNXLm126Ur3_RSSkEtKHqaf7AtQOTaOoBQ";
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[derive(Deserialize)]
    struct Fixture {
        inputs: FixtureInputs,
        expected: FixtureExpected,
    }

    #[derive(Deserialize)]
    struct FixtureInputs {
        canonical_origin: String,
        account_signing_seed_hex: String,
        rest_user_id: String,
        rest_method: String,
        rest_request_target: String,
        rest_timestamp_ms: u64,
        rest_nonce_hex: String,
        rest_body_utf8: String,
    }

    #[derive(Deserialize)]
    struct FixtureExpected {
        rest_signature_hex: String,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../../test-vectors/transport-auth/v1.json"))
            .expect("parse reviewed synthetic transport-auth fixture")
    }

    fn decode_fixed_hex<const N: usize>(value: &str) -> [u8; N] {
        let decoded = hex::decode(value).expect("fixture hex");
        decoded.try_into().unwrap_or_else(|decoded: Vec<u8>| {
            panic!("expected {N} fixture bytes, got {}", decoded.len())
        })
    }

    fn fixture_signing_key(fixture: &Fixture) -> SigningKey {
        SigningKey::from_bytes(&decode_fixed_hex::<32>(
            &fixture.inputs.account_signing_seed_hex,
        ))
    }

    fn fixture_nonce(fixture: &Fixture) -> [u8; NONCE_BYTES] {
        decode_fixed_hex(&fixture.inputs.rest_nonce_hex)
    }

    fn strict_decode_header<const N: usize>(value: &str) -> [u8; N] {
        assert!(!value.contains('='), "header must be unpadded base64url");
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .expect("strict raw base64url header");
        assert_eq!(URL_SAFE_NO_PAD.encode(&decoded), value);
        decoded
            .try_into()
            .unwrap_or_else(|decoded: Vec<u8>| panic!("expected {N} bytes, got {}", decoded.len()))
    }

    #[test]
    fn fixture_emits_exact_frozen_header_names_and_values() {
        let fixture = fixture();
        let signing_key = fixture_signing_key(&fixture);
        let nonce = fixture_nonce(&fixture);
        let prepared = prepare_rest_auth_v2_for_test(
            &fixture.inputs.canonical_origin,
            &fixture.inputs.rest_user_id,
            &fixture.inputs.rest_method,
            &fixture.inputs.rest_request_target,
            fixture.inputs.rest_body_utf8.as_bytes(),
            fixture.inputs.rest_timestamp_ms,
            &nonce,
            |message| signing_key.sign(message).to_bytes(),
        )
        .expect("prepare fixture REST v2 headers");
        let headers = prepared.into_headers();

        assert_eq!(REST_AUTH_VERSION_HEADER_V2, "X-Veil-REST-Auth-Version");
        assert_eq!(REST_AUTH_USER_HEADER_V2, "X-Veil-User");
        assert_eq!(REST_AUTH_TIMESTAMP_HEADER_V2, "X-Veil-Timestamp");
        assert_eq!(REST_AUTH_NONCE_HEADER_V2, "X-Veil-Nonce");
        assert_eq!(REST_AUTH_SIGNATURE_HEADER_V2, "X-Veil-Signature");
        assert_eq!(headers.version(), "2");
        assert_eq!(headers.user_id(), USER_ID);
        assert_eq!(headers.timestamp_ms(), TIMESTAMP_MS.to_string());
        assert_eq!(headers.nonce(), FIXTURE_NONCE_B64URL);
        assert_eq!(headers.signature(), FIXTURE_SIGNATURE_B64URL);
        assert_eq!(strict_decode_header::<32>(headers.nonce()), nonce);
        assert_eq!(
            strict_decode_header::<64>(headers.signature()),
            decode_fixed_hex::<64>(&fixture.expected.rest_signature_hex)
        );
    }

    #[test]
    fn every_signed_field_and_body_mutation_invalidates_the_signature() {
        let fixture = fixture();
        let signing_key = fixture_signing_key(&fixture);
        let nonce = fixture_nonce(&fixture);
        let headers = prepare_rest_auth_v2_for_test(
            ORIGIN,
            USER_ID,
            METHOD,
            TARGET,
            BODY,
            TIMESTAMP_MS,
            &nonce,
            |message| signing_key.sign(message).to_bytes(),
        )
        .unwrap()
        .into_headers();
        let signature = Signature::from_bytes(&strict_decode_header::<64>(headers.signature()));
        let verifying_key = signing_key.verifying_key();

        let original = signing_bytes(ORIGIN, USER_ID, METHOD, TARGET, TIMESTAMP_MS, &nonce, BODY);
        assert!(verifying_key.verify_strict(&original, &signature).is_ok());

        let mut changed_nonce = nonce;
        changed_nonce[0] ^= 1;
        let mutations = [
            signing_bytes(
                OTHER_ORIGIN,
                USER_ID,
                METHOD,
                TARGET,
                TIMESTAMP_MS,
                &nonce,
                BODY,
            ),
            signing_bytes(
                ORIGIN,
                "10112233-4455-4677-8899-aabbccddeeff",
                METHOD,
                TARGET,
                TIMESTAMP_MS,
                &nonce,
                BODY,
            ),
            signing_bytes(ORIGIN, USER_ID, "PUT", TARGET, TIMESTAMP_MS, &nonce, BODY),
            signing_bytes(
                ORIGIN,
                USER_ID,
                METHOD,
                "/v2/messages?a=%2F&b=2",
                TIMESTAMP_MS,
                &nonce,
                BODY,
            ),
            signing_bytes(
                ORIGIN,
                USER_ID,
                METHOD,
                TARGET,
                TIMESTAMP_MS + 1,
                &nonce,
                BODY,
            ),
            signing_bytes(
                ORIGIN,
                USER_ID,
                METHOD,
                TARGET,
                TIMESTAMP_MS,
                &changed_nonce,
                BODY,
            ),
            signing_bytes(
                ORIGIN,
                USER_ID,
                METHOD,
                TARGET,
                TIMESTAMP_MS,
                &nonce,
                br#"{"x":2}"#,
            ),
        ];
        for changed in mutations {
            assert!(verifying_key.verify_strict(&changed, &signature).is_err());
        }
    }

    #[test]
    fn native_freshness_is_nonzero_unique_and_strictly_encoded() {
        let account = IdentityKeyPair::from_mnemonic(TEST_MNEMONIC).unwrap();
        let mut nonces = HashSet::new();

        for _ in 0..64 {
            let headers = prepare_rest_auth_v2(&account, ORIGIN, USER_ID, METHOD, TARGET, BODY)
                .unwrap()
                .into_headers();
            let nonce = strict_decode_header::<32>(headers.nonce());
            assert!(nonce.iter().any(|byte| *byte != 0));
            assert!(nonces.insert(nonce));
            assert_eq!(strict_decode_header::<64>(headers.signature()).len(), 64);
            let timestamp = headers.timestamp_ms().parse::<u64>().unwrap();
            assert!((1..=i64::MAX as u64).contains(&timestamp));
        }
    }

    #[test]
    fn timestamp_bounds_fail_closed_and_maximum_is_decimal() {
        let nonce = [7u8; NONCE_BYTES];
        for invalid in [0, i64::MAX as u64 + 1] {
            assert!(matches!(
                prepare_rest_auth_v2_for_test(
                    ORIGIN,
                    USER_ID,
                    METHOD,
                    TARGET,
                    BODY,
                    invalid,
                    &nonce,
                    |_| [9u8; 64],
                ),
                Err(RestAuthV2Error::InvalidTimestamp)
            ));
        }

        let headers = prepare_rest_auth_v2_for_test(
            ORIGIN,
            USER_ID,
            METHOD,
            TARGET,
            BODY,
            i64::MAX as u64,
            &nonce,
            |_| [9u8; 64],
        )
        .unwrap()
        .into_headers();
        assert_eq!(headers.timestamp_ms(), "9223372036854775807");
    }

    #[test]
    fn proof_is_bound_to_one_exact_origin() {
        let fixture = fixture();
        let signing_key = fixture_signing_key(&fixture);
        let nonce = fixture_nonce(&fixture);
        let signature = prepare_rest_auth_v2_for_test(
            ORIGIN,
            USER_ID,
            METHOD,
            TARGET,
            BODY,
            TIMESTAMP_MS,
            &nonce,
            |message| signing_key.sign(message).to_bytes(),
        )
        .unwrap()
        .into_headers();
        let signature = Signature::from_bytes(&strict_decode_header::<64>(signature.signature()));
        let other_origin_message = signing_bytes(
            OTHER_ORIGIN,
            USER_ID,
            METHOD,
            TARGET,
            TIMESTAMP_MS,
            &nonce,
            BODY,
        );
        assert!(signing_key
            .verifying_key()
            .verify_strict(&other_origin_message, &signature)
            .is_err());
    }

    #[test]
    fn invalid_inputs_are_classified_without_retaining_them() {
        let nonce = [7u8; NONCE_BYTES];
        let uppercase_user_id = USER_ID.to_uppercase();
        let prepare = |origin, user, method, target, nonce: &[u8; NONCE_BYTES]| {
            prepare_rest_auth_v2_for_test(
                origin,
                user,
                method,
                target,
                BODY,
                TIMESTAMP_MS,
                nonce,
                |_| [9u8; 64],
            )
        };
        assert!(matches!(
            prepare(
                "https://Node-a.veil.test:443",
                USER_ID,
                METHOD,
                TARGET,
                &nonce
            ),
            Err(RestAuthV2Error::InvalidOrigin)
        ));
        assert!(matches!(
            prepare(ORIGIN, &uppercase_user_id, METHOD, TARGET, &nonce),
            Err(RestAuthV2Error::InvalidUserId)
        ));
        assert!(matches!(
            prepare(ORIGIN, USER_ID, "post", TARGET, &nonce),
            Err(RestAuthV2Error::InvalidMethod)
        ));
        assert!(matches!(
            prepare(
                ORIGIN,
                USER_ID,
                METHOD,
                "https://node-a.veil.test:443/v2/messages",
                &nonce
            ),
            Err(RestAuthV2Error::InvalidRequestTarget)
        ));
        assert!(matches!(
            prepare(ORIGIN, USER_ID, METHOD, TARGET, &[0; NONCE_BYTES]),
            Err(RestAuthV2Error::InvalidNonce)
        ));
    }

    #[test]
    fn preparer_remains_private_and_has_no_live_client_call_site() {
        let crate_root = include_str!("lib.rs");

        assert_eq!(crate_root.matches("mod rest_auth_v2;").count(), 1);
        assert!(!crate_root.contains("pub mod rest_auth_v2;"));

        let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        assert_no_rest_auth_v2_call_site(&source_root);
    }

    fn assert_no_rest_auth_v2_call_site(directory: &std::path::Path) {
        for entry in std::fs::read_dir(directory).expect("client source directory must be readable")
        {
            let path = entry.expect("client source entry must be readable").path();
            if path.is_dir() {
                assert_no_rest_auth_v2_call_site(&path);
                continue;
            }
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs")
                || path.file_name().and_then(std::ffi::OsStr::to_str) == Some("rest_auth_v2.rs")
            {
                continue;
            }

            let source =
                std::fs::read_to_string(&path).expect("client source file must be readable");
            assert!(
                !source.contains("prepare_rest_auth_v2"),
                "REST auth v2 preparer must remain non-activated; unexpected reference in {}",
                path.display()
            );
        }
    }

    fn signing_bytes(
        origin: &str,
        user_id: &str,
        method: &str,
        target: &str,
        timestamp_ms: u64,
        nonce: &[u8; NONCE_BYTES],
        body: &[u8],
    ) -> Vec<u8> {
        let origin = CanonicalNodeOriginV1::parse(origin).unwrap();
        let user_id = CanonicalUserIdV1::parse(user_id).unwrap();
        let target = CanonicalRequestTargetV2::parse(target).unwrap();
        let body_sha256 = rest_auth_body_digest_v2(body);
        rest_auth_signing_bytes_v2(&RestAuthRequestV2 {
            origin: &origin,
            user_id,
            method,
            request_target: &target,
            timestamp_ms,
            nonce,
            body_sha256: &body_sha256,
        })
        .unwrap()
    }
}
