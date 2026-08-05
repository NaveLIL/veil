//! Pure client-side WebSocket authentication v3 preparation.
//!
//! This module deliberately has no transport, API, FFI, or UI integration.
//! It validates the exact configured endpoint/origin pair, constructs the
//! frozen account and device proofs, and validates a future v3 result. The
//! legacy live `/ws` authentication path remains unchanged.

use std::fmt;

use ed25519_dalek::Signer;
use prost::Message;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;
use veil_crypto::{signature, IdentityKeyPair};
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::{Zeroize, Zeroizing};

use crate::auth_contract::{
    node_access_pass_commitment_v1, ws_account_auth_signing_bytes_v3,
    ws_device_auth_signing_bytes_v3, CanonicalNodeOriginV1, CanonicalUserIdV1, WsAuthContextV3,
    WsRegistrationIntentV3,
};
use crate::device_identity::{
    device_binding_signing_bytes, DeviceBindingPublicV1, DeviceIdentityV1,
    DEVICE_BINDING_STATUS_ACTIVE, REQUIRED_DEVICE_CAPABILITIES,
};
use crate::protocol::proto;

const WS_AUTH_PROTOCOL_VERSION_V3: u32 = 3;
const MAX_DEVICE_V1_INTEGER: u64 = i64::MAX as u64;
const MAX_DEVICE_NAME_BYTES: usize = 128;
const MAX_CLIENT_VERSION_BYTES: usize = 128;

/// Stable, non-secret classification for a rejected v3 client-auth input.
/// Peer-controlled values are deliberately not retained in this error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WsAuthV3Error {
    InvalidTarget,
    ProtocolVersion,
    OriginMismatch,
    InvalidChallenge,
    InvalidLocalBinding,
    InvalidRegistrationIntent,
    InvalidClientMetadata,
    NonContributoryDh,
    AuthenticationRejected,
    RegistrationClosed,
    NodeAccessPassInvalid,
    InvalidResult,
}

impl fmt::Display for WsAuthV3Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidTarget => "invalid exact WebSocket authentication target",
            Self::ProtocolVersion => "unsupported WebSocket authentication protocol version",
            Self::OriginMismatch => "WebSocket authentication origin mismatch",
            Self::InvalidChallenge => "invalid WebSocket authentication challenge",
            Self::InvalidLocalBinding => "invalid local device binding",
            Self::InvalidRegistrationIntent => "invalid registration intent",
            Self::InvalidClientMetadata => "invalid authentication client metadata",
            Self::NonContributoryDh => "non-contributory WebSocket authentication DH",
            Self::AuthenticationRejected => "WebSocket authentication was rejected",
            Self::RegistrationClosed => "Node registration is closed",
            Self::NodeAccessPassInvalid => "Node Access Pass was rejected",
            Self::InvalidResult => "invalid WebSocket authentication result",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for WsAuthV3Error {}

pub(crate) const WS_AUTH_V3_PATH: &str = "/v3/events";

/// An exact `/v3/events` endpoint paired with one already-canonical Node origin.
///
/// Validation happens against the original spelling before `url::Url` can
/// normalize it. Consequently uppercase hosts, trailing dots, leading-zero
/// ports, percent aliases, credentials, and path aliases are never accepted as
/// equivalent trust targets.
pub(crate) struct WsAuthV3Target {
    websocket_url: Url,
    canonical_origin: CanonicalNodeOriginV1,
}

impl WsAuthV3Target {
    pub(crate) fn parse(
        websocket_url: &str,
        canonical_origin: &str,
    ) -> Result<Self, WsAuthV3Error> {
        let canonical_origin = CanonicalNodeOriginV1::parse(canonical_origin)
            .map_err(|_| WsAuthV3Error::InvalidTarget)?;
        Self::from_canonical_origin(websocket_url, canonical_origin)
    }

    fn from_canonical_origin(
        websocket_url: &str,
        canonical_origin: CanonicalNodeOriginV1,
    ) -> Result<Self, WsAuthV3Error> {
        let (websocket_scheme, authority, default_port) = canonical_origin
            .as_str()
            .strip_prefix("https://")
            .map(|authority| ("wss", authority, 443u16))
            .or_else(|| {
                canonical_origin
                    .as_str()
                    .strip_prefix("http://")
                    .map(|authority| ("ws", authority, 80u16))
            })
            .ok_or(WsAuthV3Error::InvalidTarget)?;

        let explicit = format!("{websocket_scheme}://{authority}{WS_AUTH_V3_PATH}");
        let default_suffix = format!(":{default_port}");
        let implicit_default = authority
            .strip_suffix(&default_suffix)
            .map(|host| format!("{websocket_scheme}://{host}{WS_AUTH_V3_PATH}"));
        if websocket_url != explicit
            && implicit_default
                .as_deref()
                .is_none_or(|implicit| websocket_url != implicit)
        {
            return Err(WsAuthV3Error::InvalidTarget);
        }

        let parsed = Url::parse(websocket_url).map_err(|_| WsAuthV3Error::InvalidTarget)?;
        let origin =
            Url::parse(canonical_origin.as_str()).map_err(|_| WsAuthV3Error::InvalidTarget)?;
        if parsed.scheme() != websocket_scheme
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != WS_AUTH_V3_PATH
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.host_str() != origin.host_str()
            || parsed.port_or_known_default() != origin.port_or_known_default()
        {
            return Err(WsAuthV3Error::InvalidTarget);
        }

        // CanonicalNodeOriginV1 permits cleartext only for exact loopback
        // authorities, so this mapping also enforces loopback-only `ws://`.
        Ok(Self {
            websocket_url: parsed,
            canonical_origin,
        })
    }

    pub(crate) fn websocket_url(&self) -> &Url {
        &self.websocket_url
    }

    #[cfg(test)]
    pub(crate) fn canonical_origin(&self) -> &CanonicalNodeOriginV1 {
        &self.canonical_origin
    }
}

/// Registration is an explicit authenticated choice. In particular, absence
/// of a Pass is never used to infer whether account creation was intended.
pub(crate) enum WsRegistrationModeV3<'a> {
    Existing,
    // Retained for the reviewed enrollment proof path; production activation
    // remains intentionally limited to existing-account reconnects.
    #[allow(dead_code)]
    Open,
    #[allow(dead_code)]
    Pass(&'a [u8; 32]),
}

/// Non-secret local expectation used to validate that a typed failure is
/// coherent with the registration choice the client actually signed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WsRegistrationIntentKindV3 {
    Existing,
    Open,
    Pass,
}

/// Opaque non-secret type-state carried from one successfully prepared proof
/// attempt into validation of that attempt's result. Its fields are private so
/// callers cannot pair a result with a fabricated origin, binding, or intent.
pub(crate) struct WsAuthV3ResultExpectation {
    canonical_origin: CanonicalNodeOriginV1,
    binding_version: u64,
    binding_status: u8,
    registration_intent: WsRegistrationIntentKindV3,
}

/// A fully prepared response whose raw Pass copy is cleared on every drop.
///
/// This type intentionally implements neither `Clone` nor `Debug`. Its only
/// output operation consumes it and returns a zeroizing encoded envelope.
pub(crate) struct PreparedWsAuthResponseV3 {
    response: proto::AuthResponseV3,
    result_expectation: Option<WsAuthV3ResultExpectation>,
}

impl PreparedWsAuthResponseV3 {
    pub(crate) fn into_envelope_bytes(
        mut self,
        seq: u64,
    ) -> (Zeroizing<Vec<u8>>, WsAuthV3ResultExpectation) {
        let result_expectation = self
            .result_expectation
            .take()
            .expect("prepared v3 auth result expectation is always present");
        let response = std::mem::take(&mut self.response);
        let mut envelope = proto::Envelope {
            seq,
            timestamp: 0,
            payload: Some(proto::envelope::Payload::AuthResponseV3(response)),
        };
        let encoded = Zeroizing::new(envelope.encode_to_vec());
        if let Some(proto::envelope::Payload::AuthResponseV3(response)) = envelope.payload.as_mut()
        {
            response.node_access_pass.zeroize();
        }
        (encoded, result_expectation)
    }
}

impl Drop for PreparedWsAuthResponseV3 {
    fn drop(&mut self) {
        self.response.node_access_pass.zeroize();
    }
}

/// Validate a dedicated challenge and prepare both v3 possession proofs.
/// No network operation or live authentication-state transition occurs here.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_ws_auth_response_v3(
    target: &WsAuthV3Target,
    challenge: &proto::AuthChallengeV3,
    account: &IdentityKeyPair,
    device_identity: &DeviceIdentityV1,
    device_name: &str,
    client_version: &str,
    registration: WsRegistrationModeV3<'_>,
) -> Result<PreparedWsAuthResponseV3, WsAuthV3Error> {
    if challenge.protocol_version != WS_AUTH_PROTOCOL_VERSION_V3 {
        return Err(WsAuthV3Error::ProtocolVersion);
    }
    if challenge.canonical_node_origin != target.canonical_origin.as_str() {
        return Err(WsAuthV3Error::OriginMismatch);
    }
    let server_ephemeral: [u8; 32] = challenge
        .server_ephemeral
        .as_slice()
        .try_into()
        .map_err(|_| WsAuthV3Error::InvalidChallenge)?;
    if is_all_zero(&server_ephemeral) {
        return Err(WsAuthV3Error::InvalidChallenge);
    }
    validate_client_metadata(device_name, client_version)?;

    let account_identity_key = account.x25519_public_bytes();
    let account_signing_key = account.ed25519_public_bytes();
    let binding = device_identity.binding();
    let verified_binding_commitment = verify_local_binding(account, device_identity, binding)?;

    let (registration_intent, intent_kind, wire_intent, node_access_pass) = match registration {
        WsRegistrationModeV3::Existing => (
            WsRegistrationIntentV3::Existing,
            WsRegistrationIntentKindV3::Existing,
            proto::WsRegistrationIntentV3::Existing as i32,
            None,
        ),
        WsRegistrationModeV3::Open => (
            WsRegistrationIntentV3::Open,
            WsRegistrationIntentKindV3::Open,
            proto::WsRegistrationIntentV3::Open as i32,
            None,
        ),
        WsRegistrationModeV3::Pass(pass) => {
            let commitment = node_access_pass_commitment_v1(&target.canonical_origin, pass)
                .map_err(|_| WsAuthV3Error::InvalidRegistrationIntent)?;
            (
                WsRegistrationIntentV3::Pass { commitment },
                WsRegistrationIntentKindV3::Pass,
                proto::WsRegistrationIntentV3::Pass as i32,
                Some(pass),
            )
        }
    };

    let context = WsAuthContextV3 {
        origin: &target.canonical_origin,
        server_ephemeral: &server_ephemeral,
        account_identity_key: &account_identity_key,
        account_signing_key: &account_signing_key,
        device_id: &binding.device_id,
        verified_binding_commitment: &verified_binding_commitment,
        registration_intent,
    };

    let account_shared = Zeroizing::new(account.x25519_dh(&server_ephemeral));
    if is_all_zero(account_shared.as_ref()) {
        return Err(WsAuthV3Error::NonContributoryDh);
    }
    let account_proof_message = Zeroizing::new(
        ws_account_auth_signing_bytes_v3(&context, &account_shared)
            .map_err(|_| WsAuthV3Error::InvalidChallenge)?,
    );
    let account_proof_signature = signature::sign(account, &account_proof_message);

    let server_public = X25519PublicKey::from(server_ephemeral);
    let device_shared = Zeroizing::new(
        device_identity
            .x25519_secret()
            .diffie_hellman(&server_public)
            .to_bytes(),
    );
    if is_all_zero(device_shared.as_ref()) {
        return Err(WsAuthV3Error::NonContributoryDh);
    }
    let device_proof_message = Zeroizing::new(
        ws_device_auth_signing_bytes_v3(&context, &device_shared, &account_proof_signature)
            .map_err(|_| WsAuthV3Error::InvalidChallenge)?,
    );
    let device_proof_signature = device_identity
        .ed25519_signing_key()
        .sign(&device_proof_message)
        .to_bytes();

    Ok(PreparedWsAuthResponseV3 {
        response: proto::AuthResponseV3 {
            protocol_version: WS_AUTH_PROTOCOL_VERSION_V3,
            identity_key: account_identity_key.to_vec(),
            signing_key: account_signing_key.to_vec(),
            account_proof_signature: account_proof_signature.to_vec(),
            device_id: binding.device_id.to_vec(),
            device_name: device_name.to_owned(),
            client_version: client_version.to_owned(),
            device_binding: Some(binding_to_proto(binding)),
            device_proof_signature: device_proof_signature.to_vec(),
            registration_intent: wire_intent,
            // Delay this sole owned raw-Pass copy until every fallible proof
            // operation has succeeded. PreparedWsAuthResponseV3 owns and
            // clears it from this point onward.
            node_access_pass: node_access_pass.map_or_else(Vec::new, |pass| pass.to_vec()),
        },
        result_expectation: Some(WsAuthV3ResultExpectation {
            canonical_origin: target.canonical_origin.clone(),
            binding_version: binding.version,
            binding_status: binding.status,
            registration_intent: intent_kind,
        }),
    })
}

/// Validate the security-authoritative fields of a future v3 auth result.
/// Text supplied by the peer is never used to select retry or registration
/// behavior. Only coherent values from the dedicated failure enum map to
/// stable local classifications.
pub(crate) fn validate_ws_auth_result_v3(
    result: &proto::AuthResultV3,
    expectation: WsAuthV3ResultExpectation,
) -> Result<String, WsAuthV3Error> {
    if result.protocol_version != WS_AUTH_PROTOCOL_VERSION_V3 {
        return Err(WsAuthV3Error::ProtocolVersion);
    }
    if result.canonical_node_origin != expectation.canonical_origin.as_str() {
        return Err(WsAuthV3Error::OriginMismatch);
    }
    if !result.success {
        if result.user_id.is_some()
            || result.per_device_secure
            || result.device_binding_version != 0
            || result.device_binding_status != proto::DeviceBindingStatus::Unspecified as i32
        {
            return Err(WsAuthV3Error::InvalidResult);
        }
        return Err(
            match (
                proto::WsAuthFailureReasonV3::try_from(result.failure_reason),
                expectation.registration_intent,
            ) {
                (Ok(proto::WsAuthFailureReasonV3::AuthenticationFailed), _) => {
                    WsAuthV3Error::AuthenticationRejected
                }
                (
                    Ok(proto::WsAuthFailureReasonV3::RegistrationClosed),
                    WsRegistrationIntentKindV3::Open,
                ) => WsAuthV3Error::RegistrationClosed,
                (
                    Ok(proto::WsAuthFailureReasonV3::NodeAccessPassInvalid),
                    WsRegistrationIntentKindV3::Pass,
                ) => WsAuthV3Error::NodeAccessPassInvalid,
                _ => WsAuthV3Error::InvalidResult,
            },
        );
    }
    if expectation.binding_status != DEVICE_BINDING_STATUS_ACTIVE
        || !result.per_device_secure
        || result.device_binding_version != expectation.binding_version
        || result.device_binding_status != i32::from(expectation.binding_status)
        || result.device_binding_status != proto::DeviceBindingStatus::Active as i32
        || result.failure_reason != proto::WsAuthFailureReasonV3::Unspecified as i32
        || result.error_message.is_some()
    {
        return Err(WsAuthV3Error::InvalidResult);
    }
    let user_id = result
        .user_id
        .as_deref()
        .ok_or(WsAuthV3Error::InvalidResult)?;
    CanonicalUserIdV1::parse(user_id).map_err(|_| WsAuthV3Error::InvalidResult)?;
    Ok(user_id.to_owned())
}

fn validate_client_metadata(device_name: &str, client_version: &str) -> Result<(), WsAuthV3Error> {
    if device_name.is_empty()
        || device_name.len() > MAX_DEVICE_NAME_BYTES
        || device_name
            .chars()
            .any(|character| character.is_control() || matches!(character, '\u{2028}' | '\u{2029}'))
        || client_version.is_empty()
        || client_version.len() > MAX_CLIENT_VERSION_BYTES
        || !client_version.is_ascii()
        || client_version.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(WsAuthV3Error::InvalidClientMetadata);
    }
    Ok(())
}

fn verify_local_binding(
    account: &IdentityKeyPair,
    device_identity: &DeviceIdentityV1,
    binding: &DeviceBindingPublicV1,
) -> Result<[u8; 32], WsAuthV3Error> {
    let account_identity_key = account.x25519_public_bytes();
    let account_signing_key = account.ed25519_public_bytes();
    if is_all_zero(&account_identity_key)
        || !veil_crypto::public_key::valid_ed25519_public_key(&account_signing_key)
        || is_all_zero(&binding.device_id)
        || is_all_zero(&binding.device_identity_key)
        || !veil_crypto::public_key::valid_ed25519_public_key(&binding.device_signing_key)
        || binding.version == 0
        || binding.version > MAX_DEVICE_V1_INTEGER
        || binding.capabilities > MAX_DEVICE_V1_INTEGER
        || binding.capabilities & REQUIRED_DEVICE_CAPABILITIES != REQUIRED_DEVICE_CAPABILITIES
        || binding.status != DEVICE_BINDING_STATUS_ACTIVE
    {
        return Err(WsAuthV3Error::InvalidLocalBinding);
    }

    let derived_device_identity = X25519PublicKey::from(device_identity.x25519_secret());
    let derived_device_signing = device_identity
        .ed25519_signing_key()
        .verifying_key()
        .to_bytes();
    if !bool::from(
        derived_device_identity
            .as_bytes()
            .ct_eq(&binding.device_identity_key),
    ) || !bool::from(derived_device_signing.ct_eq(&binding.device_signing_key))
    {
        return Err(WsAuthV3Error::InvalidLocalBinding);
    }

    let binding_message = device_binding_signing_bytes(
        &account_identity_key,
        &account_signing_key,
        &binding.device_id,
        binding.version,
        &binding.device_identity_key,
        &binding.device_signing_key,
        binding.capabilities,
        binding.status,
    );
    if !signature::verify(
        &account_signing_key,
        &binding_message,
        &binding.account_signature,
    ) {
        return Err(WsAuthV3Error::InvalidLocalBinding);
    }
    let commitment: [u8; 32] = Sha256::digest(&binding_message).into();
    if is_all_zero(&commitment) {
        return Err(WsAuthV3Error::InvalidLocalBinding);
    }
    Ok(commitment)
}

fn binding_to_proto(binding: &DeviceBindingPublicV1) -> proto::DeviceBindingV1 {
    proto::DeviceBindingV1 {
        device_id: binding.device_id.to_vec(),
        device_identity_key: binding.device_identity_key.to_vec(),
        device_signing_key: binding.device_signing_key.to_vec(),
        version: binding.version,
        capabilities: binding.capabilities,
        status: i32::from(binding.status),
        account_signature: binding.account_signature.to_vec(),
    }
}

fn is_all_zero(value: &[u8]) -> bool {
    bool::from(
        value
            .iter()
            .fold(0u8, |aggregate, byte| aggregate | byte)
            .ct_eq(&0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret as X25519StaticSecret;

    const ORIGIN: &str = "https://chat.example.test:443";
    const USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    struct TestIdentity {
        account: IdentityKeyPair,
        device: DeviceIdentityV1,
        server_secret: X25519StaticSecret,
        challenge: proto::AuthChallengeV3,
        target: WsAuthV3Target,
    }

    fn test_identity() -> TestIdentity {
        let account = IdentityKeyPair::from_mnemonic(TEST_MNEMONIC).unwrap();
        let stored = DeviceIdentityV1::generate_stored(&account, [0x22; 16]).unwrap();
        let device = DeviceIdentityV1::from_stored(&account, stored).unwrap();
        let server_secret = X25519StaticSecret::from([0x31; 32]);
        let server_public = X25519PublicKey::from(&server_secret);
        TestIdentity {
            account,
            device,
            server_secret,
            challenge: proto::AuthChallengeV3 {
                protocol_version: WS_AUTH_PROTOCOL_VERSION_V3,
                server_ephemeral: server_public.as_bytes().to_vec(),
                canonical_node_origin: ORIGIN.to_owned(),
            },
            target: WsAuthV3Target::parse("wss://chat.example.test/v3/events", ORIGIN).unwrap(),
        }
    }

    fn decode_prepared(
        prepared: PreparedWsAuthResponseV3,
    ) -> (u64, proto::AuthResponseV3, WsAuthV3ResultExpectation) {
        let (wire, expectation) = prepared.into_envelope_bytes(7);
        let envelope = proto::Envelope::decode(wire.as_slice()).unwrap();
        let response = match envelope.payload.unwrap() {
            proto::envelope::Payload::AuthResponseV3(response) => response,
            _ => panic!("prepared v3 auth used the wrong envelope variant"),
        };
        (envelope.seq, response, expectation)
    }

    fn result_expectation(
        fixture: &TestIdentity,
        registration: WsRegistrationModeV3<'_>,
    ) -> WsAuthV3ResultExpectation {
        let prepared = prepare_ws_auth_response_v3(
            &fixture.target,
            &fixture.challenge,
            &fixture.account,
            &fixture.device,
            "Pixel 9",
            "veil-android/0.1.4",
            registration,
        )
        .unwrap();
        let (_seq, _response, expectation) = decode_prepared(prepared);
        expectation
    }

    fn result_expectation_for_kind(
        fixture: &TestIdentity,
        kind: WsRegistrationIntentKindV3,
        pass: &[u8; 32],
    ) -> WsAuthV3ResultExpectation {
        match kind {
            WsRegistrationIntentKindV3::Existing => {
                result_expectation(fixture, WsRegistrationModeV3::Existing)
            }
            WsRegistrationIntentKindV3::Open => {
                result_expectation(fixture, WsRegistrationModeV3::Open)
            }
            WsRegistrationIntentKindV3::Pass => {
                result_expectation(fixture, WsRegistrationModeV3::Pass(pass))
            }
        }
    }

    fn array<const N: usize>(value: &[u8]) -> Option<[u8; N]> {
        value.try_into().ok()
    }

    /// Independent server-side reconstruction used only to prove that every
    /// client response field is bound by the frozen transcripts.
    fn response_proofs_verify(
        response: &proto::AuthResponseV3,
        challenge: &proto::AuthChallengeV3,
        server_secret: &X25519StaticSecret,
    ) -> bool {
        if response.protocol_version != WS_AUTH_PROTOCOL_VERSION_V3
            || challenge.protocol_version != WS_AUTH_PROTOCOL_VERSION_V3
            || challenge.canonical_node_origin != ORIGIN
        {
            return false;
        }
        let Some(server_ephemeral) = array::<32>(&challenge.server_ephemeral) else {
            return false;
        };
        if X25519PublicKey::from(server_secret).as_bytes() != &server_ephemeral {
            return false;
        }
        let Some(account_identity_key) = array::<32>(&response.identity_key) else {
            return false;
        };
        let Some(account_signing_key) = array::<32>(&response.signing_key) else {
            return false;
        };
        let Some(device_id) = array::<16>(&response.device_id) else {
            return false;
        };
        let Some(account_proof_signature) = array::<64>(&response.account_proof_signature) else {
            return false;
        };
        let Some(device_proof_signature) = array::<64>(&response.device_proof_signature) else {
            return false;
        };
        let Some(binding) = response.device_binding.as_ref() else {
            return false;
        };
        let Some(binding_device_id) = array::<16>(&binding.device_id) else {
            return false;
        };
        let Some(device_identity_key) = array::<32>(&binding.device_identity_key) else {
            return false;
        };
        let Some(device_signing_key) = array::<32>(&binding.device_signing_key) else {
            return false;
        };
        let Some(account_binding_signature) = array::<64>(&binding.account_signature) else {
            return false;
        };
        if binding_device_id != device_id
            || binding.version == 0
            || binding.version > MAX_DEVICE_V1_INTEGER
            || binding.capabilities > MAX_DEVICE_V1_INTEGER
            || binding.capabilities & REQUIRED_DEVICE_CAPABILITIES != REQUIRED_DEVICE_CAPABILITIES
            || binding.status != proto::DeviceBindingStatus::Active as i32
        {
            return false;
        }

        let binding_message = device_binding_signing_bytes(
            &account_identity_key,
            &account_signing_key,
            &device_id,
            binding.version,
            &device_identity_key,
            &device_signing_key,
            binding.capabilities,
            DEVICE_BINDING_STATUS_ACTIVE,
        );
        if !signature::verify(
            &account_signing_key,
            &binding_message,
            &account_binding_signature,
        ) {
            return false;
        }
        let binding_commitment: [u8; 32] = Sha256::digest(&binding_message).into();
        let origin = CanonicalNodeOriginV1::parse(ORIGIN).unwrap();
        let registration_intent = match response.registration_intent {
            value if value == proto::WsRegistrationIntentV3::Existing as i32 => {
                if !response.node_access_pass.is_empty() {
                    return false;
                }
                WsRegistrationIntentV3::Existing
            }
            value if value == proto::WsRegistrationIntentV3::Open as i32 => {
                if !response.node_access_pass.is_empty() {
                    return false;
                }
                WsRegistrationIntentV3::Open
            }
            value if value == proto::WsRegistrationIntentV3::Pass as i32 => {
                let Some(pass) = array::<32>(&response.node_access_pass) else {
                    return false;
                };
                let Ok(commitment) = node_access_pass_commitment_v1(&origin, &pass) else {
                    return false;
                };
                WsRegistrationIntentV3::Pass { commitment }
            }
            _ => return false,
        };
        let context = WsAuthContextV3 {
            origin: &origin,
            server_ephemeral: &server_ephemeral,
            account_identity_key: &account_identity_key,
            account_signing_key: &account_signing_key,
            device_id: &device_id,
            verified_binding_commitment: &binding_commitment,
            registration_intent,
        };

        let account_shared = Zeroizing::new(
            server_secret
                .diffie_hellman(&X25519PublicKey::from(account_identity_key))
                .to_bytes(),
        );
        let Ok(account_message) = ws_account_auth_signing_bytes_v3(&context, &account_shared)
        else {
            return false;
        };
        let account_message = Zeroizing::new(account_message);
        if !signature::verify(
            &account_signing_key,
            &account_message,
            &account_proof_signature,
        ) {
            return false;
        }

        let device_shared = Zeroizing::new(
            server_secret
                .diffie_hellman(&X25519PublicKey::from(device_identity_key))
                .to_bytes(),
        );
        let Ok(device_message) =
            ws_device_auth_signing_bytes_v3(&context, &device_shared, &account_proof_signature)
        else {
            return false;
        };
        let device_message = Zeroizing::new(device_message);
        signature::verify(
            &device_signing_key,
            &device_message,
            &device_proof_signature,
        )
    }

    fn valid_result(binding: &DeviceBindingPublicV1) -> proto::AuthResultV3 {
        proto::AuthResultV3 {
            protocol_version: WS_AUTH_PROTOCOL_VERSION_V3,
            success: true,
            user_id: Some(USER_ID.to_owned()),
            error_message: None,
            per_device_secure: true,
            device_binding_version: binding.version,
            device_binding_status: proto::DeviceBindingStatus::Active as i32,
            failure_reason: proto::WsAuthFailureReasonV3::Unspecified as i32,
            canonical_node_origin: ORIGIN.to_owned(),
        }
    }

    #[test]
    fn exact_target_accepts_only_origin_preserving_v3_event_spellings() {
        for (websocket, origin) in [
            ("wss://chat.example.test:443/v3/events", ORIGIN),
            ("wss://chat.example.test/v3/events", ORIGIN),
            (
                "wss://chat.example.test:8443/v3/events",
                "https://chat.example.test:8443",
            ),
            (
                "wss://xn--bcher-kva.example:443/v3/events",
                "https://xn--bcher-kva.example:443",
            ),
            ("ws://localhost:80/v3/events", "http://localhost:80"),
            ("ws://localhost/v3/events", "http://localhost:80"),
            ("ws://127.0.0.1:8080/v3/events", "http://127.0.0.1:8080"),
            ("ws://[::1]:8080/v3/events", "http://[::1]:8080"),
        ] {
            let target = WsAuthV3Target::parse(websocket, origin).unwrap();
            assert_eq!(target.websocket_url().path(), WS_AUTH_V3_PATH);
            assert_eq!(
                target.websocket_url().port_or_known_default(),
                Url::parse(origin).unwrap().port_or_known_default()
            );
            assert_eq!(target.canonical_origin().as_str(), origin);
        }
    }

    #[test]
    fn exact_target_rejects_normalization_aliases_and_origin_mismatches() {
        for (websocket, origin) in [
            ("wss://Chat.example.test:443/v3/events", ORIGIN),
            ("wss://chat.example.test.:443/v3/events", ORIGIN),
            ("wss://chat.example.test:0443/v3/events", ORIGIN),
            ("wss://user@chat.example.test:443/v3/events", ORIGIN),
            ("wss://chat.example.test:443/v3/events?", ORIGIN),
            ("wss://chat.example.test:443/v3/events#fragment", ORIGIN),
            ("wss://chat.example.test:443/v3/events/", ORIGIN),
            ("wss://chat.example.test:443/V3/events", ORIGIN),
            ("wss://chat.example.test:443/%76%33/events", ORIGIN),
            ("wss://chat.example.test:443/ws", ORIGIN),
            ("wss://chat.example.test:8443/v3/events", ORIGIN),
            ("ws://chat.example.test:443/v3/events", ORIGIN),
            (
                "wss://bücher.example:443/v3/events",
                "https://xn--bcher-kva.example:443",
            ),
            (
                "ws://chat.example.test:80/v3/events",
                "http://chat.example.test:80",
            ),
            (
                "wss://xn--a-ecp.ru:443/v3/events",
                "https://xn--a-ecp.ru:443",
            ),
        ] {
            assert!(
                WsAuthV3Target::parse(websocket, origin).is_err(),
                "accepted alias {websocket} for {origin}"
            );
        }
    }

    #[test]
    fn challenge_version_origin_length_and_low_order_keys_fail_closed() {
        let fixture = test_identity();
        let pass = [0x77; 32];
        let prepare = |challenge: &proto::AuthChallengeV3| {
            prepare_ws_auth_response_v3(
                &fixture.target,
                challenge,
                &fixture.account,
                &fixture.device,
                "Pixel 9",
                "veil-android/0.1.4",
                WsRegistrationModeV3::Pass(&pass),
            )
        };

        let mut changed = fixture.challenge.clone();
        changed.protocol_version = 2;
        assert!(matches!(
            prepare(&changed),
            Err(WsAuthV3Error::ProtocolVersion)
        ));
        changed = fixture.challenge.clone();
        changed.canonical_node_origin = "https://other.example.test:443".to_owned();
        assert!(matches!(
            prepare(&changed),
            Err(WsAuthV3Error::OriginMismatch)
        ));
        for invalid in [vec![1; 31], vec![1; 33], vec![0; 32]] {
            changed = fixture.challenge.clone();
            changed.server_ephemeral = invalid;
            assert!(matches!(
                prepare(&changed),
                Err(WsAuthV3Error::InvalidChallenge)
            ));
        }
        changed = fixture.challenge.clone();
        changed.server_ephemeral = {
            let mut low_order = vec![0; 32];
            low_order[0] = 1;
            low_order
        };
        // The Pass has not been copied into an owned buffer on this failing
        // path; only the caller-owned test array exists.
        assert!(matches!(
            prepare(&changed),
            Err(WsAuthV3Error::NonContributoryDh)
        ));

        assert!(matches!(
            prepare_ws_auth_response_v3(
                &fixture.target,
                &fixture.challenge,
                &fixture.account,
                &fixture.device,
                "Pixel 9",
                "veil-android/0.1.4",
                WsRegistrationModeV3::Pass(&[0; 32]),
            ),
            Err(WsAuthV3Error::InvalidRegistrationIntent)
        ));
    }

    #[test]
    fn preparer_revalidates_authenticated_local_binding_fields() {
        let fixture = test_identity();
        let binding = fixture.device.binding();

        let mut changed = binding.clone();
        changed.account_signature[0] ^= 1;
        assert_eq!(
            verify_local_binding(&fixture.account, &fixture.device, &changed),
            Err(WsAuthV3Error::InvalidLocalBinding)
        );

        changed = binding.clone();
        changed.capabilities |= 4;
        assert_eq!(
            verify_local_binding(&fixture.account, &fixture.device, &changed),
            Err(WsAuthV3Error::InvalidLocalBinding)
        );

        changed = binding.clone();
        changed.device_identity_key[0] ^= 1;
        assert_eq!(
            verify_local_binding(&fixture.account, &fixture.device, &changed),
            Err(WsAuthV3Error::InvalidLocalBinding)
        );
    }

    #[test]
    fn all_explicit_intents_emit_exact_wire_shape_and_valid_chained_proofs() {
        let fixture = test_identity();
        let pass = [0x77; 32];
        for (mode, expected_intent, expected_pass) in [
            (
                WsRegistrationModeV3::Existing,
                proto::WsRegistrationIntentV3::Existing as i32,
                None,
            ),
            (
                WsRegistrationModeV3::Open,
                proto::WsRegistrationIntentV3::Open as i32,
                None,
            ),
            (
                WsRegistrationModeV3::Pass(&pass),
                proto::WsRegistrationIntentV3::Pass as i32,
                Some(pass.as_slice()),
            ),
        ] {
            let prepared = prepare_ws_auth_response_v3(
                &fixture.target,
                &fixture.challenge,
                &fixture.account,
                &fixture.device,
                "Pixel 9",
                "veil-android/0.1.4",
                mode,
            )
            .unwrap();
            let (seq, response, _expectation) = decode_prepared(prepared);
            assert_eq!(seq, 7);
            assert_eq!(response.protocol_version, WS_AUTH_PROTOCOL_VERSION_V3);
            assert_eq!(response.registration_intent, expected_intent);
            assert_eq!(
                response.node_access_pass.as_slice(),
                expected_pass.unwrap_or(&[])
            );
            assert!(response_proofs_verify(
                &response,
                &fixture.challenge,
                &fixture.server_secret
            ));
        }
    }

    #[test]
    fn response_challenge_binding_intent_and_pass_mutations_break_verification() {
        let fixture = test_identity();
        let pass = [0x77; 32];
        let prepared = prepare_ws_auth_response_v3(
            &fixture.target,
            &fixture.challenge,
            &fixture.account,
            &fixture.device,
            "Pixel 9",
            "veil-android/0.1.4",
            WsRegistrationModeV3::Pass(&pass),
        )
        .unwrap();
        let (_, response, _expectation) = decode_prepared(prepared);

        let mut changed_challenge = fixture.challenge.clone();
        changed_challenge.server_ephemeral[0] ^= 1;
        assert!(!response_proofs_verify(
            &response,
            &changed_challenge,
            &fixture.server_secret
        ));

        let mut changed = response.clone();
        changed.protocol_version = 2;
        assert!(!response_proofs_verify(
            &changed,
            &fixture.challenge,
            &fixture.server_secret
        ));

        changed = response.clone();
        changed.device_binding.as_mut().unwrap().capabilities ^= 1;
        assert!(!response_proofs_verify(
            &changed,
            &fixture.challenge,
            &fixture.server_secret
        ));

        changed = response.clone();
        changed.registration_intent = proto::WsRegistrationIntentV3::Open as i32;
        changed.node_access_pass.clear();
        assert!(!response_proofs_verify(
            &changed,
            &fixture.challenge,
            &fixture.server_secret
        ));

        changed = response;
        changed.node_access_pass[0] ^= 1;
        assert!(!response_proofs_verify(
            &changed,
            &fixture.challenge,
            &fixture.server_secret
        ));
        changed.node_access_pass.zeroize();
    }

    #[test]
    fn result_requires_exact_v3_origin_user_and_active_secure_binding() {
        let fixture = test_identity();
        let binding = fixture.device.binding();
        let valid = valid_result(binding);
        let validate = |result: &proto::AuthResultV3| {
            validate_ws_auth_result_v3(
                result,
                result_expectation(&fixture, WsRegistrationModeV3::Existing),
            )
        };
        assert_eq!(validate(&valid).unwrap(), USER_ID);

        let mut invalid = valid.clone();
        invalid.protocol_version = 2;
        assert_eq!(validate(&invalid), Err(WsAuthV3Error::ProtocolVersion));
        invalid = valid.clone();
        invalid.canonical_node_origin = "https://other.example.test:443".to_owned();
        assert_eq!(validate(&invalid), Err(WsAuthV3Error::OriginMismatch));

        for user_id in [
            None,
            Some(USER_ID.to_uppercase()),
            Some("00000000-0000-0000-0000-000000000000".to_owned()),
        ] {
            invalid = valid.clone();
            invalid.user_id = user_id;
            assert_eq!(validate(&invalid), Err(WsAuthV3Error::InvalidResult));
        }

        invalid = valid.clone();
        invalid.per_device_secure = false;
        assert_eq!(validate(&invalid), Err(WsAuthV3Error::InvalidResult));
        invalid = valid.clone();
        invalid.device_binding_version += 1;
        assert_eq!(validate(&invalid), Err(WsAuthV3Error::InvalidResult));
        invalid = valid.clone();
        invalid.device_binding_status = proto::DeviceBindingStatus::Revoked as i32;
        assert_eq!(validate(&invalid), Err(WsAuthV3Error::InvalidResult));
        invalid = valid.clone();
        invalid.failure_reason = proto::WsAuthFailureReasonV3::AuthenticationFailed as i32;
        assert_eq!(validate(&invalid), Err(WsAuthV3Error::InvalidResult));
        invalid = valid;
        invalid.error_message = Some("peer-controlled text".to_owned());
        assert_eq!(validate(&invalid), Err(WsAuthV3Error::InvalidResult));
    }

    #[test]
    fn result_failure_uses_only_typed_reason_after_version_and_origin_checks() {
        let fixture = test_identity();
        let pass = [0x77; 32];
        let binding = fixture.device.binding();
        let mut result = valid_result(binding);
        result.success = false;
        result.user_id = None;
        result.per_device_secure = false;
        result.device_binding_version = 0;
        result.device_binding_status = proto::DeviceBindingStatus::Unspecified as i32;
        result.error_message = Some("must never drive client behavior".to_owned());

        for (reason, expected_intent, expected) in [
            (
                proto::WsAuthFailureReasonV3::AuthenticationFailed as i32,
                WsRegistrationIntentKindV3::Existing,
                WsAuthV3Error::AuthenticationRejected,
            ),
            (
                proto::WsAuthFailureReasonV3::RegistrationClosed as i32,
                WsRegistrationIntentKindV3::Open,
                WsAuthV3Error::RegistrationClosed,
            ),
            (
                proto::WsAuthFailureReasonV3::NodeAccessPassInvalid as i32,
                WsRegistrationIntentKindV3::Pass,
                WsAuthV3Error::NodeAccessPassInvalid,
            ),
            (
                proto::WsAuthFailureReasonV3::Unspecified as i32,
                WsRegistrationIntentKindV3::Existing,
                WsAuthV3Error::InvalidResult,
            ),
            (
                99,
                WsRegistrationIntentKindV3::Existing,
                WsAuthV3Error::InvalidResult,
            ),
        ] {
            result.failure_reason = reason;
            assert_eq!(
                validate_ws_auth_result_v3(
                    &result,
                    result_expectation_for_kind(&fixture, expected_intent, &pass),
                ),
                Err(expected)
            );
        }

        for (reason, mismatched_intent) in [
            (
                proto::WsAuthFailureReasonV3::RegistrationClosed as i32,
                WsRegistrationIntentKindV3::Existing,
            ),
            (
                proto::WsAuthFailureReasonV3::RegistrationClosed as i32,
                WsRegistrationIntentKindV3::Pass,
            ),
            (
                proto::WsAuthFailureReasonV3::NodeAccessPassInvalid as i32,
                WsRegistrationIntentKindV3::Existing,
            ),
            (
                proto::WsAuthFailureReasonV3::NodeAccessPassInvalid as i32,
                WsRegistrationIntentKindV3::Open,
            ),
        ] {
            result.failure_reason = reason;
            assert_eq!(
                validate_ws_auth_result_v3(
                    &result,
                    result_expectation_for_kind(&fixture, mismatched_intent, &pass),
                ),
                Err(WsAuthV3Error::InvalidResult)
            );
        }

        result.failure_reason = proto::WsAuthFailureReasonV3::AuthenticationFailed as i32;
        let failure_shape_mutations: [fn(&mut proto::AuthResultV3); 4] = [
            |value: &mut proto::AuthResultV3| value.user_id = Some(USER_ID.to_owned()),
            |value: &mut proto::AuthResultV3| value.per_device_secure = true,
            |value: &mut proto::AuthResultV3| value.device_binding_version = 1,
            |value: &mut proto::AuthResultV3| {
                value.device_binding_status = proto::DeviceBindingStatus::Active as i32
            },
        ];
        for mutate in failure_shape_mutations {
            let mut incoherent = result.clone();
            mutate(&mut incoherent);
            assert_eq!(
                validate_ws_auth_result_v3(
                    &incoherent,
                    result_expectation(&fixture, WsRegistrationModeV3::Existing),
                ),
                Err(WsAuthV3Error::InvalidResult)
            );
        }

        result.failure_reason = proto::WsAuthFailureReasonV3::RegistrationClosed as i32;
        result.protocol_version = 2;
        assert_eq!(
            validate_ws_auth_result_v3(
                &result,
                result_expectation(&fixture, WsRegistrationModeV3::Open),
            ),
            Err(WsAuthV3Error::ProtocolVersion)
        );
        result.protocol_version = WS_AUTH_PROTOCOL_VERSION_V3;
        result.canonical_node_origin = "https://other.example.test:443".to_owned();
        assert_eq!(
            validate_ws_auth_result_v3(
                &result,
                result_expectation(&fixture, WsRegistrationModeV3::Open),
            ),
            Err(WsAuthV3Error::OriginMismatch)
        );
    }
}
