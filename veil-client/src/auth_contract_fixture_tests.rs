//! Cross-runtime transport-auth v1 fixture consumption.
//!
//! SECURITY: every seed, shared secret, nonce, Pass, key, and signature in
//! this fixture is deterministic public test data. It must never be used by a
//! live client or copied into production configuration.

use crate::auth_contract::{
    node_access_pass_commitment_v1, rest_auth_body_digest_v2, rest_auth_signing_bytes_v2,
    ws_account_auth_signing_bytes_v3, ws_auth_context_bytes_v3, ws_device_auth_signing_bytes_v3,
    CanonicalNodeOriginV1, CanonicalRequestTargetV2, CanonicalUserIdV1, RestAuthRequestV2,
    WsAuthContextV3, WsRegistrationIntentV3,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const FIXTURE_BYTES: &[u8] = include_bytes!("../../test-vectors/transport-auth/v1.json");
const FIXTURE_SUMS: &str = include_str!("../../test-vectors/transport-auth/SHA256SUMS");
const REVIEWED_FIXTURE_SHA256: &str =
    "c90f7aac7619d178e06c0ac0d7aab6084511ceffb505b8fcf7058ba6812ad9bc";
const MAX_FIXTURE_BYTES: usize = 64 * 1024;
const SYNTHETIC_NOTE: &str = "All keys, secrets, Passes, nonces, and signatures are deterministic public test data; never use them outside tests.";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportAuthFixtureV1 {
    schema_version: u32,
    synthetic_only: bool,
    note: String,
    inputs: TransportAuthFixtureInputsV1,
    expected: TransportAuthFixtureExpectedV1,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportAuthFixtureInputsV1 {
    canonical_origin: String,
    other_canonical_origin: String,
    server_ephemeral_hex: String,
    account_identity_key_hex: String,
    account_signing_seed_hex: String,
    account_signing_key_hex: String,
    device_signing_seed_hex: String,
    device_signing_key_hex: String,
    device_id_hex: String,
    verified_binding_commitment_hex: String,
    node_access_pass_hex: String,
    registration_intent: u8,
    account_shared_secret_hex: String,
    device_shared_secret_hex: String,
    rest_user_id: String,
    rest_method: String,
    rest_request_target: String,
    rest_timestamp_ms: u64,
    rest_nonce_hex: String,
    rest_body_utf8: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportAuthFixtureExpectedV1 {
    node_access_pass_commitment_hex: String,
    ws_context_hex: String,
    ws_context_sha256_hex: String,
    ws_account_proof_message_hex: String,
    ws_account_proof_signature_hex: String,
    ws_device_proof_message_hex: String,
    ws_device_proof_signature_hex: String,
    rest_body_sha256_hex: String,
    rest_signing_message_hex: String,
    rest_signing_message_sha256_hex: String,
    rest_signature_hex: String,
}

#[test]
fn shared_transport_auth_v1_fixture_matches_rust_contract_and_signatures() {
    let fixture = load_fixture();

    let origin = CanonicalNodeOriginV1::parse(&fixture.inputs.canonical_origin)
        .expect("fixture canonical origin");
    let other_origin = CanonicalNodeOriginV1::parse(&fixture.inputs.other_canonical_origin)
        .expect("fixture other canonical origin");
    let server_ephemeral = decode_fixed_hex::<32>(
        "inputs.server_ephemeral_hex",
        &fixture.inputs.server_ephemeral_hex,
    );
    let account_identity_key = decode_fixed_hex::<32>(
        "inputs.account_identity_key_hex",
        &fixture.inputs.account_identity_key_hex,
    );
    let account_signing_seed = decode_fixed_hex::<32>(
        "inputs.account_signing_seed_hex",
        &fixture.inputs.account_signing_seed_hex,
    );
    let account_signing_key = decode_fixed_hex::<32>(
        "inputs.account_signing_key_hex",
        &fixture.inputs.account_signing_key_hex,
    );
    let device_signing_seed = decode_fixed_hex::<32>(
        "inputs.device_signing_seed_hex",
        &fixture.inputs.device_signing_seed_hex,
    );
    let device_signing_key = decode_fixed_hex::<32>(
        "inputs.device_signing_key_hex",
        &fixture.inputs.device_signing_key_hex,
    );
    let device_id = decode_fixed_hex::<16>("inputs.device_id_hex", &fixture.inputs.device_id_hex);
    let binding_commitment = decode_fixed_hex::<32>(
        "inputs.verified_binding_commitment_hex",
        &fixture.inputs.verified_binding_commitment_hex,
    );
    let node_access_pass = decode_fixed_hex::<32>(
        "inputs.node_access_pass_hex",
        &fixture.inputs.node_access_pass_hex,
    );
    let account_shared = decode_fixed_hex::<32>(
        "inputs.account_shared_secret_hex",
        &fixture.inputs.account_shared_secret_hex,
    );
    let device_shared = decode_fixed_hex::<32>(
        "inputs.device_shared_secret_hex",
        &fixture.inputs.device_shared_secret_hex,
    );
    let rest_nonce =
        decode_fixed_hex::<32>("inputs.rest_nonce_hex", &fixture.inputs.rest_nonce_hex);

    let expected_pass_commitment = decode_fixed_hex::<32>(
        "expected.node_access_pass_commitment_hex",
        &fixture.expected.node_access_pass_commitment_hex,
    );
    let expected_context =
        decode_variable_hex("expected.ws_context_hex", &fixture.expected.ws_context_hex);
    let expected_context_sha256 = decode_fixed_hex::<32>(
        "expected.ws_context_sha256_hex",
        &fixture.expected.ws_context_sha256_hex,
    );
    let expected_account_message = decode_variable_hex(
        "expected.ws_account_proof_message_hex",
        &fixture.expected.ws_account_proof_message_hex,
    );
    let expected_account_signature = decode_fixed_hex::<64>(
        "expected.ws_account_proof_signature_hex",
        &fixture.expected.ws_account_proof_signature_hex,
    );
    let expected_device_message = decode_variable_hex(
        "expected.ws_device_proof_message_hex",
        &fixture.expected.ws_device_proof_message_hex,
    );
    let expected_device_signature = decode_fixed_hex::<64>(
        "expected.ws_device_proof_signature_hex",
        &fixture.expected.ws_device_proof_signature_hex,
    );
    let expected_rest_body_sha256 = decode_fixed_hex::<32>(
        "expected.rest_body_sha256_hex",
        &fixture.expected.rest_body_sha256_hex,
    );
    let expected_rest_message = decode_variable_hex(
        "expected.rest_signing_message_hex",
        &fixture.expected.rest_signing_message_hex,
    );
    let expected_rest_message_sha256 = decode_fixed_hex::<32>(
        "expected.rest_signing_message_sha256_hex",
        &fixture.expected.rest_signing_message_sha256_hex,
    );
    let expected_rest_signature = decode_fixed_hex::<64>(
        "expected.rest_signature_hex",
        &fixture.expected.rest_signature_hex,
    );

    let account_signing = SigningKey::from_bytes(&account_signing_seed);
    let account_verifying = account_signing.verifying_key();
    assert_eq!(
        account_verifying.to_bytes(),
        account_signing_key,
        "fixture account public key must derive from its synthetic seed"
    );
    let device_signing = SigningKey::from_bytes(&device_signing_seed);
    let device_verifying = device_signing.verifying_key();
    assert_eq!(
        device_verifying.to_bytes(),
        device_signing_key,
        "fixture device public key must derive from its synthetic seed"
    );

    let pass_commitment = node_access_pass_commitment_v1(&origin, &node_access_pass)
        .expect("rebuild fixture Pass commitment");
    assert_eq!(pass_commitment, expected_pass_commitment);
    assert_eq!(
        fixture.inputs.registration_intent, 3,
        "the reviewed fixture must exercise Pass registration intent"
    );
    let registration_intent = WsRegistrationIntentV3::Pass {
        commitment: pass_commitment,
    };
    let ws_context = WsAuthContextV3 {
        origin: &origin,
        server_ephemeral: &server_ephemeral,
        account_identity_key: &account_identity_key,
        account_signing_key: &account_signing_key,
        device_id: &device_id,
        verified_binding_commitment: &binding_commitment,
        registration_intent,
    };
    let context_bytes = ws_auth_context_bytes_v3(&ws_context).expect("rebuild fixture WS context");
    assert_eq!(context_bytes, expected_context);
    assert_eq!(sha256(&context_bytes), expected_context_sha256);

    let account_message = ws_account_auth_signing_bytes_v3(&ws_context, &account_shared)
        .expect("rebuild fixture account-proof message");
    assert_eq!(account_message, expected_account_message);
    let account_signature = account_signing.sign(&account_message).to_bytes();
    assert_eq!(account_signature, expected_account_signature);
    verify_strict(
        &account_verifying,
        &account_message,
        &expected_account_signature,
        "account proof",
    );

    let device_message =
        ws_device_auth_signing_bytes_v3(&ws_context, &device_shared, &account_signature)
            .expect("rebuild fixture device-proof message");
    assert_eq!(device_message, expected_device_message);
    let device_signature = device_signing.sign(&device_message).to_bytes();
    assert_eq!(device_signature, expected_device_signature);
    verify_strict(
        &device_verifying,
        &device_message,
        &expected_device_signature,
        "device proof",
    );

    let rest_body_sha256 = rest_auth_body_digest_v2(fixture.inputs.rest_body_utf8.as_bytes());
    assert_eq!(rest_body_sha256, expected_rest_body_sha256);
    let rest_user_id = CanonicalUserIdV1::parse(&fixture.inputs.rest_user_id)
        .expect("fixture canonical REST user id");
    let rest_target = CanonicalRequestTargetV2::parse(&fixture.inputs.rest_request_target)
        .expect("fixture canonical REST target");
    let rest_request = RestAuthRequestV2 {
        origin: &origin,
        user_id: rest_user_id,
        method: &fixture.inputs.rest_method,
        request_target: &rest_target,
        timestamp_ms: fixture.inputs.rest_timestamp_ms,
        nonce: &rest_nonce,
        body_sha256: &rest_body_sha256,
    };
    let rest_message =
        rest_auth_signing_bytes_v2(&rest_request).expect("rebuild fixture REST v2 message");
    assert_eq!(rest_message, expected_rest_message);
    assert_eq!(sha256(&rest_message), expected_rest_message_sha256);
    let rest_signature = account_signing.sign(&rest_message).to_bytes();
    assert_eq!(rest_signature, expected_rest_signature);
    verify_strict(
        &account_verifying,
        &rest_message,
        &expected_rest_signature,
        "REST proof",
    );

    prove_other_origin_rejects_captured_signatures(
        &fixture,
        &other_origin,
        &server_ephemeral,
        &account_identity_key,
        &account_signing_key,
        &device_id,
        &binding_commitment,
        &node_access_pass,
        &account_shared,
        &device_shared,
        &account_signature,
        &account_verifying,
        &device_verifying,
        rest_user_id,
        &rest_target,
        &rest_nonce,
        &rest_body_sha256,
        &expected_rest_signature,
    );
    prove_account_device_domain_substitution_fails(
        &account_message,
        &expected_account_signature,
        &account_verifying,
        &device_message,
        &expected_device_signature,
        &device_verifying,
    );
}

#[allow(clippy::too_many_arguments)]
fn prove_other_origin_rejects_captured_signatures(
    fixture: &TransportAuthFixtureV1,
    other_origin: &CanonicalNodeOriginV1,
    server_ephemeral: &[u8; 32],
    account_identity_key: &[u8; 32],
    account_signing_key: &[u8; 32],
    device_id: &[u8; 16],
    binding_commitment: &[u8; 32],
    node_access_pass: &[u8; 32],
    account_shared: &[u8; 32],
    device_shared: &[u8; 32],
    account_signature: &[u8; 64],
    account_verifying: &VerifyingKey,
    device_verifying: &VerifyingKey,
    rest_user_id: CanonicalUserIdV1,
    rest_target: &CanonicalRequestTargetV2,
    rest_nonce: &[u8; 32],
    rest_body_sha256: &[u8; 32],
    captured_rest_signature: &[u8; 64],
) {
    let other_pass_commitment = node_access_pass_commitment_v1(other_origin, node_access_pass)
        .expect("other-origin synthetic Pass commitment");
    assert_ne!(
        other_pass_commitment,
        decode_fixed_hex::<32>(
            "expected.node_access_pass_commitment_hex",
            &fixture.expected.node_access_pass_commitment_hex,
        )
    );
    let other_ws_context = WsAuthContextV3 {
        origin: other_origin,
        server_ephemeral,
        account_identity_key,
        account_signing_key,
        device_id,
        verified_binding_commitment: binding_commitment,
        registration_intent: WsRegistrationIntentV3::Pass {
            commitment: other_pass_commitment,
        },
    };
    let other_account_message = ws_account_auth_signing_bytes_v3(&other_ws_context, account_shared)
        .expect("other-origin account-proof message");
    assert!(
        account_verifying
            .verify_strict(
                &other_account_message,
                &ed25519_dalek::Signature::from_bytes(account_signature),
            )
            .is_err(),
        "Node A account proof must not verify for Node B"
    );
    let other_device_message =
        ws_device_auth_signing_bytes_v3(&other_ws_context, device_shared, account_signature)
            .expect("other-origin device-proof message");
    assert!(
        device_verifying
            .verify_strict(
                &other_device_message,
                &ed25519_dalek::Signature::from_bytes(&decode_fixed_hex::<64>(
                    "expected.ws_device_proof_signature_hex",
                    &fixture.expected.ws_device_proof_signature_hex,
                ),),
            )
            .is_err(),
        "Node A device proof must not verify for Node B"
    );

    let other_rest_request = RestAuthRequestV2 {
        origin: other_origin,
        user_id: rest_user_id,
        method: &fixture.inputs.rest_method,
        request_target: rest_target,
        timestamp_ms: fixture.inputs.rest_timestamp_ms,
        nonce: rest_nonce,
        body_sha256: rest_body_sha256,
    };
    let other_rest_message =
        rest_auth_signing_bytes_v2(&other_rest_request).expect("other-origin REST signing message");
    assert!(
        account_verifying
            .verify_strict(
                &other_rest_message,
                &ed25519_dalek::Signature::from_bytes(captured_rest_signature),
            )
            .is_err(),
        "Node A REST signature must not verify for Node B"
    );
}

fn prove_account_device_domain_substitution_fails(
    account_message: &[u8],
    account_signature: &[u8; 64],
    account_verifying: &VerifyingKey,
    device_message: &[u8],
    device_signature: &[u8; 64],
    device_verifying: &VerifyingKey,
) {
    let account_substituted = substitute_domain(
        account_message,
        b"veil-ws-auth-v3/account-proof\0",
        b"veil-ws-auth-v3/device-proof\0",
    );
    assert!(
        account_verifying
            .verify_strict(
                &account_substituted,
                &ed25519_dalek::Signature::from_bytes(account_signature),
            )
            .is_err(),
        "account signature must reject the device-proof domain"
    );
    let device_substituted = substitute_domain(
        device_message,
        b"veil-ws-auth-v3/device-proof\0",
        b"veil-ws-auth-v3/account-proof\0",
    );
    assert!(
        device_verifying
            .verify_strict(
                &device_substituted,
                &ed25519_dalek::Signature::from_bytes(device_signature),
            )
            .is_err(),
        "device signature must reject the account-proof domain"
    );
}

fn load_fixture() -> TransportAuthFixtureV1 {
    assert!(
        !FIXTURE_BYTES.is_empty() && FIXTURE_BYTES.len() <= MAX_FIXTURE_BYTES,
        "transport-auth fixture must be non-empty and no larger than 64 KiB"
    );
    require_lf_only_with_one_final_lf("v1.json", FIXTURE_BYTES);
    let reviewed_digest = hex::encode(Sha256::digest(FIXTURE_BYTES));
    assert_eq!(
        reviewed_digest, REVIEWED_FIXTURE_SHA256,
        "transport-auth fixture SHA-256 changed without review"
    );

    let sums = FIXTURE_SUMS.as_bytes();
    assert!(
        !sums.is_empty() && sums.len() <= MAX_FIXTURE_BYTES,
        "transport-auth SHA256SUMS must be non-empty and bounded"
    );
    require_lf_only_with_one_final_lf("SHA256SUMS", sums);
    assert_eq!(
        FIXTURE_SUMS,
        format!("{REVIEWED_FIXTURE_SHA256}  v1.json\n"),
        "transport-auth SHA256SUMS must contain the exact reviewed line"
    );

    let fixture: TransportAuthFixtureV1 =
        serde_json::from_slice(FIXTURE_BYTES).expect("strict typed transport-auth fixture JSON");
    assert_eq!(fixture.schema_version, 1, "unsupported fixture schema");
    assert!(
        fixture.synthetic_only,
        "transport-auth fixture must be explicitly synthetic_only"
    );
    assert_eq!(
        fixture.note, SYNTHETIC_NOTE,
        "transport-auth fixture must carry the reviewed synthetic-data warning"
    );
    fixture
}

fn require_lf_only_with_one_final_lf(name: &str, contents: &[u8]) {
    assert!(
        !contents.contains(&b'\r'),
        "{name} must contain LF line endings only"
    );
    assert_eq!(contents.last(), Some(&b'\n'), "{name} needs a final LF");
    assert!(
        contents.len() == 1 || contents[contents.len() - 2] != b'\n',
        "{name} must end in exactly one LF"
    );
}

fn decode_fixed_hex<const N: usize>(field: &str, value: &str) -> [u8; N] {
    assert_eq!(
        value.len(),
        N * 2,
        "{field} must contain exactly {N} bytes of hex"
    );
    let decoded = decode_canonical_lower_hex(field, value);
    decoded
        .try_into()
        .unwrap_or_else(|_| panic!("{field} decoded width changed after its exact-width check"))
}

fn decode_variable_hex(field: &str, value: &str) -> Vec<u8> {
    assert!(!value.is_empty(), "{field} must not be empty");
    assert!(
        value.len() <= MAX_FIXTURE_BYTES * 2,
        "{field} exceeds the fixture byte bound"
    );
    decode_canonical_lower_hex(field, value)
}

fn decode_canonical_lower_hex(field: &str, value: &str) -> Vec<u8> {
    assert!(
        value.len().is_multiple_of(2)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{field} must be canonical lowercase hex"
    );
    let decoded = hex::decode(value).unwrap_or_else(|error| panic!("decode {field}: {error}"));
    assert_eq!(
        hex::encode(&decoded),
        value,
        "{field} has a non-canonical hex alias"
    );
    decoded
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn verify_strict(verifying_key: &VerifyingKey, message: &[u8], signature: &[u8; 64], label: &str) {
    verifying_key
        .verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
        .unwrap_or_else(|error| panic!("fixture {label} signature did not verify: {error}"));
}

fn substitute_domain(message: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    assert!(
        message.starts_with(from),
        "message does not begin with the expected source domain"
    );
    let mut substituted = Vec::with_capacity(message.len() - from.len() + to.len());
    substituted.extend_from_slice(to);
    substituted.extend_from_slice(&message[from.len()..]);
    substituted
}
