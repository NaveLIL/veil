//! Pure, versioned authentication transcripts.
//!
//! This module validates bounded transcript inputs and constructs the exact
//! bytes covered by authentication signatures. It performs no I/O, owns no
//! long-lived private keys, generates no randomness, and is not wired into the
//! live transports. WS proof messages contain caller-supplied DH results and
//! must be zeroized by their eventual signing/verification caller.

use sha2::{Digest, Sha256};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

const PASS_COMMITMENT_DOMAIN_V1: &[u8] = b"veil-node-access-pass-commitment-v1\0";
#[cfg_attr(not(test), allow(dead_code))]
const WS_AUTH_CONTEXT_DOMAIN_V3: &[u8] = b"veil-ws-auth-v3/context\0";
#[cfg_attr(not(test), allow(dead_code))]
const WS_ACCOUNT_PROOF_DOMAIN_V3: &[u8] = b"veil-ws-auth-v3/account-proof\0";
#[cfg_attr(not(test), allow(dead_code))]
const WS_DEVICE_PROOF_DOMAIN_V3: &[u8] = b"veil-ws-auth-v3/device-proof\0";
const REST_AUTH_DOMAIN_V2: &[u8] = b"veil-rest-auth-v2\0";

pub const MAX_CANONICAL_NODE_ORIGIN_BYTES: usize = 512;
pub const MAX_REST_METHOD_BYTES: usize = 32;
pub const MAX_REST_REQUEST_TARGET_BYTES: usize = 16 * 1024;

/// A stable, non-secret classification for rejected authentication-contract
/// input. Values supplied by a peer are deliberately not retained in errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthContractError {
    InvalidOrigin,
    InvalidUserId,
    InvalidMethod,
    InvalidRequestTarget,
    InvalidTimestamp,
    InvalidNonce,
    InvalidPass,
    InvalidAccountIdentityKey,
    InvalidAccountSigningKey,
    InvalidDeviceId,
    InvalidBindingCommitment,
    InvalidRegistrationIntent,
    NonContributoryDh,
    InvalidAccountProofSignature,
    LengthOverflow,
}

impl fmt::Display for AuthContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidOrigin => "invalid canonical Node origin",
            Self::InvalidUserId => "invalid canonical user id",
            Self::InvalidMethod => "invalid REST method",
            Self::InvalidRequestTarget => "invalid canonical REST request target",
            Self::InvalidTimestamp => "invalid REST timestamp",
            Self::InvalidNonce => "invalid REST nonce",
            Self::InvalidPass => "invalid Node Access Pass",
            Self::InvalidAccountIdentityKey => "invalid account X25519 public key",
            Self::InvalidAccountSigningKey => "invalid account Ed25519 public key",
            Self::InvalidDeviceId => "invalid device id",
            Self::InvalidBindingCommitment => "invalid verified device-binding commitment",
            Self::InvalidRegistrationIntent => "invalid registration intent",
            Self::NonContributoryDh => "non-contributory authentication DH result",
            Self::InvalidAccountProofSignature => "invalid account-proof signature",
            Self::LengthOverflow => "authentication transcript length overflow",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AuthContractError {}

/// Exact origin used as a cryptographic trust scope.
///
/// Accepted production values have the form `https://host:port`. Cleartext is
/// accepted only for canonical loopback hosts. No parser normalization is
/// applied silently: aliases and non-canonical spellings are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalNodeOriginV1(String);

impl CanonicalNodeOriginV1 {
    pub fn parse(value: &str) -> Result<Self, AuthContractError> {
        validate_canonical_node_origin(value)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl TryFrom<&str> for CanonicalNodeOriginV1 {
    type Error = AuthContractError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl AsRef<str> for CanonicalNodeOriginV1 {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for CanonicalNodeOriginV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Canonical lowercase, non-nil UUID encoded in network byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalUserIdV1([u8; 16]);

impl CanonicalUserIdV1 {
    pub fn parse(value: &str) -> Result<Self, AuthContractError> {
        if value.len() != 36
            || value.as_bytes().get(8) != Some(&b'-')
            || value.as_bytes().get(13) != Some(&b'-')
            || value.as_bytes().get(18) != Some(&b'-')
            || value.as_bytes().get(23) != Some(&b'-')
            || !value.bytes().enumerate().all(|(index, byte)| {
                matches!(index, 8 | 13 | 18 | 23)
                    || byte.is_ascii_digit()
                    || (b'a'..=b'f').contains(&byte)
            })
        {
            return Err(AuthContractError::InvalidUserId);
        }
        let parsed = uuid::Uuid::parse_str(value).map_err(|_| AuthContractError::InvalidUserId)?;
        if parsed.is_nil() || parsed.to_string() != value {
            return Err(AuthContractError::InvalidUserId);
        }
        Ok(Self(*parsed.as_bytes()))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl TryFrom<&str> for CanonicalUserIdV1 {
    type Error = AuthContractError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// Exact HTTP origin-form request target. Escaping and query ordering are part
/// of the signed bytes and are therefore never decoded or reordered here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalRequestTargetV2(String);

impl CanonicalRequestTargetV2 {
    pub fn parse(value: &str) -> Result<Self, AuthContractError> {
        validate_request_target(value)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl TryFrom<&str> for CanonicalRequestTargetV2 {
    type Error = AuthContractError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl AsRef<str> for CanonicalRequestTargetV2 {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for CanonicalRequestTargetV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Public inputs to the exact REST authentication v2 transcript.
#[derive(Clone, Copy)]
pub struct RestAuthRequestV2<'a> {
    pub origin: &'a CanonicalNodeOriginV1,
    pub user_id: CanonicalUserIdV1,
    pub method: &'a str,
    pub request_target: &'a CanonicalRequestTargetV2,
    pub timestamp_ms: u64,
    pub nonce: &'a [u8; 32],
    pub body_sha256: &'a [u8; 32],
}

/// Construct the exact bytes signed for a REST-authenticated v2 request.
pub fn rest_auth_signing_bytes_v2(
    request: &RestAuthRequestV2<'_>,
) -> Result<Vec<u8>, AuthContractError> {
    validate_http_method(request.method)?;
    if request.timestamp_ms == 0 || request.timestamp_ms > i64::MAX as u64 {
        return Err(AuthContractError::InvalidTimestamp);
    }
    if is_all_zero(request.nonce) {
        return Err(AuthContractError::InvalidNonce);
    }
    let mut transcript = Vec::with_capacity(
        REST_AUTH_DOMAIN_V2.len()
            + 4
            + request.origin.as_str().len()
            + 16
            + 4
            + request.method.len()
            + 4
            + request.request_target.as_str().len()
            + 8
            + 32
            + 32,
    );
    transcript.extend_from_slice(REST_AUTH_DOMAIN_V2);
    append_u32_len_prefixed(&mut transcript, request.origin.as_str().as_bytes())?;
    transcript.extend_from_slice(request.user_id.as_bytes());
    append_u32_len_prefixed(&mut transcript, request.method.as_bytes())?;
    append_u32_len_prefixed(&mut transcript, request.request_target.as_str().as_bytes())?;
    transcript.extend_from_slice(&request.timestamp_ms.to_be_bytes());
    transcript.extend_from_slice(request.nonce);
    transcript.extend_from_slice(request.body_sha256);
    Ok(transcript)
}

/// Compute the exact digest placed in a REST authentication v2 transcript.
pub fn rest_auth_body_digest_v2(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

/// Commit a 256-bit Node Access Pass to one exact Node origin without placing
/// the raw bearer in any long-lived contract structure.
pub fn node_access_pass_commitment_v1(
    origin: &CanonicalNodeOriginV1,
    pass: &[u8; 32],
) -> Result<[u8; 32], AuthContractError> {
    if is_all_zero(pass) {
        return Err(AuthContractError::InvalidPass);
    }
    let mut preimage = Vec::with_capacity(
        PASS_COMMITMENT_DOMAIN_V1.len() + 4 + origin.as_str().len() + pass.len(),
    );
    preimage.extend_from_slice(PASS_COMMITMENT_DOMAIN_V1);
    append_u32_len_prefixed(&mut preimage, origin.as_str().as_bytes())?;
    preimage.extend_from_slice(pass);
    let commitment: [u8; 32] = Sha256::digest(&preimage).into();
    use zeroize::Zeroize;
    preimage.zeroize();
    if is_all_zero(&commitment) {
        return Err(AuthContractError::InvalidPass);
    }
    Ok(commitment)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum WsRegistrationIntentV3 {
    Existing,
    Open,
    Pass { commitment: [u8; 32] },
}

#[cfg_attr(not(test), allow(dead_code))]
impl WsRegistrationIntentV3 {
    fn encoded(self) -> Result<(u8, [u8; 32]), AuthContractError> {
        match self {
            Self::Existing => Ok((1, [0u8; 32])),
            Self::Open => Ok((2, [0u8; 32])),
            Self::Pass { commitment } if !is_all_zero(&commitment) => Ok((3, commitment)),
            Self::Pass { .. } => Err(AuthContractError::InvalidRegistrationIntent),
        }
    }
}

/// Already-public and independently verified inputs shared by both WS v3
/// possession proofs. The binding commitment must be verified before this
/// structure is constructed; this module only enforces its fixed non-zero form.
#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct WsAuthContextV3<'a> {
    pub(crate) origin: &'a CanonicalNodeOriginV1,
    pub(crate) server_ephemeral: &'a [u8; 32],
    pub(crate) account_identity_key: &'a [u8; 32],
    pub(crate) account_signing_key: &'a [u8; 32],
    pub(crate) device_id: &'a [u8; 16],
    pub(crate) verified_binding_commitment: &'a [u8; 32],
    pub(crate) registration_intent: WsRegistrationIntentV3,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn ws_auth_context_bytes_v3(
    context: &WsAuthContextV3<'_>,
) -> Result<Vec<u8>, AuthContractError> {
    validate_ws_context(context)?;
    let (intent, pass_commitment) = context.registration_intent.encoded()?;
    let mut transcript = Vec::with_capacity(
        WS_AUTH_CONTEXT_DOMAIN_V3.len()
            + 4
            + context.origin.as_str().len()
            + 32
            + 32
            + 32
            + 16
            + 32
            + 1
            + 32,
    );
    transcript.extend_from_slice(WS_AUTH_CONTEXT_DOMAIN_V3);
    append_u32_len_prefixed(&mut transcript, context.origin.as_str().as_bytes())?;
    transcript.extend_from_slice(context.server_ephemeral);
    transcript.extend_from_slice(context.account_identity_key);
    transcript.extend_from_slice(context.account_signing_key);
    transcript.extend_from_slice(context.device_id);
    transcript.extend_from_slice(context.verified_binding_commitment);
    transcript.push(intent);
    transcript.extend_from_slice(&pass_commitment);
    Ok(transcript)
}

#[cfg_attr(not(test), allow(dead_code))]
/// Builds the account proof preimage. The returned buffer contains the supplied
/// DH result and must be zeroized immediately after signing or verification.
pub(crate) fn ws_account_auth_signing_bytes_v3(
    context: &WsAuthContextV3<'_>,
    account_shared: &[u8; 32],
) -> Result<Vec<u8>, AuthContractError> {
    if is_all_zero(account_shared) {
        return Err(AuthContractError::NonContributoryDh);
    }
    let context = ws_auth_context_bytes_v3(context)?;
    let mut transcript = Vec::with_capacity(
        WS_ACCOUNT_PROOF_DOMAIN_V3.len() + 4 + context.len() + account_shared.len(),
    );
    transcript.extend_from_slice(WS_ACCOUNT_PROOF_DOMAIN_V3);
    append_u32_len_prefixed(&mut transcript, &context)?;
    transcript.extend_from_slice(account_shared);
    Ok(transcript)
}

#[cfg_attr(not(test), allow(dead_code))]
/// Builds the device proof preimage. The returned buffer contains the supplied
/// DH result and must be zeroized immediately after signing or verification.
/// This byte builder checks only the signature field's fixed non-zero shape;
/// callers must supply a locally generated or already strictly verified account
/// proof signature.
pub(crate) fn ws_device_auth_signing_bytes_v3(
    context: &WsAuthContextV3<'_>,
    device_shared: &[u8; 32],
    account_proof_signature: &[u8; 64],
) -> Result<Vec<u8>, AuthContractError> {
    if is_all_zero(device_shared) {
        return Err(AuthContractError::NonContributoryDh);
    }
    if is_all_zero(account_proof_signature) {
        return Err(AuthContractError::InvalidAccountProofSignature);
    }
    let context = ws_auth_context_bytes_v3(context)?;
    let mut transcript = Vec::with_capacity(
        WS_DEVICE_PROOF_DOMAIN_V3.len()
            + 4
            + context.len()
            + device_shared.len()
            + account_proof_signature.len(),
    );
    transcript.extend_from_slice(WS_DEVICE_PROOF_DOMAIN_V3);
    append_u32_len_prefixed(&mut transcript, &context)?;
    transcript.extend_from_slice(device_shared);
    transcript.extend_from_slice(account_proof_signature);
    Ok(transcript)
}

#[cfg_attr(not(test), allow(dead_code))]
fn validate_ws_context(context: &WsAuthContextV3<'_>) -> Result<(), AuthContractError> {
    if is_all_zero(context.server_ephemeral) {
        return Err(AuthContractError::NonContributoryDh);
    }
    if is_all_zero(context.account_identity_key) {
        return Err(AuthContractError::InvalidAccountIdentityKey);
    }
    if !veil_crypto::public_key::valid_ed25519_public_key(context.account_signing_key) {
        return Err(AuthContractError::InvalidAccountSigningKey);
    }
    if is_all_zero(context.device_id) {
        return Err(AuthContractError::InvalidDeviceId);
    }
    if is_all_zero(context.verified_binding_commitment) {
        return Err(AuthContractError::InvalidBindingCommitment);
    }
    context.registration_intent.encoded()?;
    Ok(())
}

fn append_u32_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), AuthContractError> {
    let length = u32::try_from(value.len()).map_err(|_| AuthContractError::LengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn is_all_zero(value: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(
        value
            .iter()
            .fold(0u8, |accumulator, byte| accumulator | byte)
            .ct_eq(&0),
    )
}

fn validate_canonical_node_origin(value: &str) -> Result<(), AuthContractError> {
    if value.is_empty() || value.len() > MAX_CANONICAL_NODE_ORIGIN_BYTES || !value.is_ascii() {
        return Err(AuthContractError::InvalidOrigin);
    }
    let (scheme, authority) = if let Some(authority) = value.strip_prefix("https://") {
        ("https", authority)
    } else if let Some(authority) = value.strip_prefix("http://") {
        ("http", authority)
    } else {
        return Err(AuthContractError::InvalidOrigin);
    };
    if authority.is_empty()
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@' | b'\\'))
    {
        return Err(AuthContractError::InvalidOrigin);
    }

    let (host, port_text, bracketed) = if let Some(rest) = authority.strip_prefix('[') {
        let closing = rest.find(']').ok_or(AuthContractError::InvalidOrigin)?;
        let host = &rest[..closing];
        let suffix = &rest[closing + 1..];
        let port = suffix
            .strip_prefix(':')
            .ok_or(AuthContractError::InvalidOrigin)?;
        (host, port, true)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or(AuthContractError::InvalidOrigin)?;
        if host.contains(':') {
            return Err(AuthContractError::InvalidOrigin);
        }
        (host, port, false)
    };
    if host.is_empty()
        || host.ends_with('.')
        || host.contains('%')
        || port_text.is_empty()
        || !port_text.bytes().all(|byte| byte.is_ascii_digit())
        || (port_text.len() > 1 && port_text.starts_with('0'))
    {
        return Err(AuthContractError::InvalidOrigin);
    }
    let port = port_text
        .parse::<u16>()
        .map_err(|_| AuthContractError::InvalidOrigin)?;
    if port == 0 || port.to_string() != port_text {
        return Err(AuthContractError::InvalidOrigin);
    }

    let loopback = if bracketed {
        let address = Ipv6Addr::from_str(host).map_err(|_| AuthContractError::InvalidOrigin)?;
        if address.to_string() != host || address.to_ipv4_mapped().is_some() {
            return Err(AuthContractError::InvalidOrigin);
        }
        address.is_loopback()
    } else {
        match url::Host::parse(host).map_err(|_| AuthContractError::InvalidOrigin)? {
            url::Host::Ipv4(address) => {
                if address.to_string() != host {
                    return Err(AuthContractError::InvalidOrigin);
                }
                address == Ipv4Addr::LOCALHOST
            }
            url::Host::Ipv6(_) => return Err(AuthContractError::InvalidOrigin),
            url::Host::Domain(domain) => {
                if domain != host || !valid_lowercase_ldh_host(host) {
                    return Err(AuthContractError::InvalidOrigin);
                }
                host == "localhost"
            }
        }
    };
    if scheme == "http" && !loopback {
        return Err(AuthContractError::InvalidOrigin);
    }
    Ok(())
}

fn valid_lowercase_ldh_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

fn validate_http_method(method: &str) -> Result<(), AuthContractError> {
    if method.is_empty()
        || method.len() > MAX_REST_METHOD_BYTES
        || !method.bytes().all(|byte| {
            !byte.is_ascii_lowercase()
                && (byte.is_ascii_uppercase()
                    || byte.is_ascii_digit()
                    || b"!#$%&'*+-.^_`|~".contains(&byte))
        })
    {
        return Err(AuthContractError::InvalidMethod);
    }
    Ok(())
}

fn validate_request_target(value: &str) -> Result<(), AuthContractError> {
    if value.is_empty()
        || value.len() > MAX_REST_REQUEST_TARGET_BYTES
        || !value.is_ascii()
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('#')
        || value.contains('\\')
        || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
    {
        return Err(AuthContractError::InvalidRequestTarget);
    }
    let (path, query) = match value.split_once('?') {
        Some((_path, "")) => return Err(AuthContractError::InvalidRequestTarget),
        Some((path, query)) => (path, Some(query)),
        None => (value, None),
    };
    if path.as_bytes().windows(2).any(|pair| pair == b"//")
        || path
            .split('/')
            .skip(1)
            .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(AuthContractError::InvalidRequestTarget);
    }

    validate_percent_encoding(path, true)?;
    if let Some(query) = query {
        validate_percent_encoding(query, false)?;
    }
    Ok(())
}

fn validate_percent_encoding(value: &str, path: bool) -> Result<(), AuthContractError> {
    let bytes = value.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if byte != b'%' {
            if !(is_unreserved(byte)
                || byte == b'/'
                || b"!$&'()*+,;=:@".contains(&byte)
                || (!path && byte == b'?'))
            {
                return Err(AuthContractError::InvalidRequestTarget);
            }
            cursor += 1;
            continue;
        }
        let high = *bytes
            .get(cursor + 1)
            .ok_or(AuthContractError::InvalidRequestTarget)?;
        let low = *bytes
            .get(cursor + 2)
            .ok_or(AuthContractError::InvalidRequestTarget)?;
        let high = uppercase_hex_value(high).ok_or(AuthContractError::InvalidRequestTarget)?;
        let low = uppercase_hex_value(low).ok_or(AuthContractError::InvalidRequestTarget)?;
        let decoded = (high << 4) | low;
        if is_unreserved(decoded) || decoded == b'\\' || (path && decoded == b'/') {
            return Err(AuthContractError::InvalidRequestTarget);
        }
        cursor += 3;
    }
    Ok(())
}

fn uppercase_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const ORIGIN: &str = "https://node.example.test:443";
    const USER_ID: &str = "11111111-2222-4333-8444-555555555555";

    fn signing_key() -> [u8; 32] {
        SigningKey::from_bytes(&[0x61; 32])
            .verifying_key()
            .to_bytes()
    }

    #[test]
    fn canonical_origin_accepts_only_exact_secure_or_loopback_authorities() {
        for accepted in [
            ORIGIN,
            "https://127.0.0.1:443",
            "https://[2001:db8::1]:8443",
            "https://xn--bcher-kva.example:443",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert_eq!(
                CanonicalNodeOriginV1::parse(accepted).unwrap().as_str(),
                accepted
            );
        }

        for rejected in [
            "",
            "https://node.example.test",
            "https://node.example.test:0443",
            "https://node.example.test:0",
            "HTTPS://node.example.test:443",
            "https://Node.example.test:443",
            "https://node.example.test.:443",
            "https://node.example.test:443/",
            "https://user@node.example.test:443",
            "https://node.example.test:443?x=1",
            "https://node.example.test:443#fragment",
            "https://bad_host.example:443",
            "https://-bad.example:443",
            "https://bad-.example:443",
            "https://127.1:443",
            "https://0x7f000001:443",
            "https://999.1.1.1:443",
            "https://12345:443",
            "https://[2001:0DB8::1]:443",
            "https://[2001:db8:0:0:0:0:0:1]:443",
            "https://[::ffff:192.0.2.1]:443",
            "https://[fe80::1%25eth0]:443",
            "http://node.example.test:80",
            "http://127.0.0.2:8080",
            "http://192.0.2.1:80",
            "https://nøde.example:443",
        ] {
            assert_eq!(
                CanonicalNodeOriginV1::parse(rejected),
                Err(AuthContractError::InvalidOrigin),
                "unexpectedly accepted {rejected:?}"
            );
        }
        let oversized = format!("https://{}:443", "a".repeat(500));
        assert_eq!(
            CanonicalNodeOriginV1::parse(&oversized),
            Err(AuthContractError::InvalidOrigin)
        );
    }

    #[test]
    fn canonical_user_id_is_lowercase_non_nil_and_binary_stable() {
        let user = CanonicalUserIdV1::parse(USER_ID).unwrap();
        assert_eq!(
            hex::encode(user.as_bytes()),
            "11111111222243338444555555555555"
        );
        for rejected in [
            "00000000-0000-0000-0000-000000000000",
            "11111111-2222-4333-8444-55555555555A",
            "11111111222243338444555555555555",
            "not-a-uuid",
        ] {
            assert_eq!(
                CanonicalUserIdV1::parse(rejected),
                Err(AuthContractError::InvalidUserId)
            );
        }
    }

    #[test]
    fn request_target_rejects_aliases_and_ambiguous_escaping() {
        for accepted in [
            "/",
            "/v1/prekeys?device=7&cursor=a%3Ab",
            "/v1/items/%3A?q=%2F%3F",
            "/v1/path/?q=a?b",
            "/v1/items?q=/nested?value",
        ] {
            assert_eq!(
                CanonicalRequestTargetV2::parse(accepted).unwrap().as_str(),
                accepted
            );
        }
        for rejected in [
            "",
            "v1/items",
            "https://node.example.test:443/v1/items",
            "//node.example.test/v1/items",
            "/v1//items",
            "/./v1/items",
            "/v1/../items",
            "/v1/items?",
            "/v1/items#fragment",
            "/v1\\items",
            "/v1/items with-space",
            "/v1/тест",
            "/v1/%",
            "/v1/%2",
            "/v1/%2f",
            "/v1/%41",
            "/v1/%2E",
            "/v1/%2F",
            "/v1/%5C",
            "/v1/items?q=%5C",
            "/v1/[items]",
            "/v1/items?[alias]",
            "/v1/items^alias",
            "/v1/items`alias",
            "/v1/{items}",
            "/v1/items|alias",
        ] {
            assert_eq!(
                CanonicalRequestTargetV2::parse(rejected),
                Err(AuthContractError::InvalidRequestTarget),
                "unexpectedly accepted {rejected:?}"
            );
        }
        let oversized = format!("/{}", "x".repeat(MAX_REST_REQUEST_TARGET_BYTES));
        assert_eq!(
            CanonicalRequestTargetV2::parse(&oversized),
            Err(AuthContractError::InvalidRequestTarget)
        );
    }

    #[test]
    fn pass_commitment_is_origin_bound_and_has_frozen_layout() {
        let origin = CanonicalNodeOriginV1::parse(ORIGIN).unwrap();
        let pass = [0x42; 32];
        let commitment = node_access_pass_commitment_v1(&origin, &pass).unwrap();
        assert_eq!(
            hex::encode(commitment),
            "7a6c0b773d2468cb6ecd2caf86f323307365b19d07e009c78668f2badda5c90b"
        );

        let mut independent = Vec::new();
        independent.extend_from_slice(b"veil-node-access-pass-commitment-v1\0");
        independent.extend_from_slice(&(ORIGIN.len() as u32).to_be_bytes());
        independent.extend_from_slice(ORIGIN.as_bytes());
        independent.extend_from_slice(&pass);
        assert_eq!(commitment, <[u8; 32]>::from(Sha256::digest(independent)));
        assert_ne!(
            commitment,
            node_access_pass_commitment_v1(
                &CanonicalNodeOriginV1::parse("https://other.example.test:443").unwrap(),
                &pass,
            )
            .unwrap()
        );
        assert_eq!(
            node_access_pass_commitment_v1(&origin, &[0u8; 32]),
            Err(AuthContractError::InvalidPass)
        );
    }

    #[test]
    fn rest_v2_layout_and_all_security_fields_are_authenticated() {
        let origin = CanonicalNodeOriginV1::parse(ORIGIN).unwrap();
        let user_id = CanonicalUserIdV1::parse(USER_ID).unwrap();
        let target = CanonicalRequestTargetV2::parse("/v1/prekeys?device=7").unwrap();
        let nonce = [0x71; 32];
        let body_sha256 = [0x82; 32];
        let request = RestAuthRequestV2 {
            origin: &origin,
            user_id,
            method: "POST",
            request_target: &target,
            timestamp_ms: 1_700_000_000_123,
            nonce: &nonce,
            body_sha256: &body_sha256,
        };
        let actual = rest_auth_signing_bytes_v2(&request).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"veil-rest-auth-v2\0");
        expected.extend_from_slice(&(ORIGIN.len() as u32).to_be_bytes());
        expected.extend_from_slice(ORIGIN.as_bytes());
        expected.extend_from_slice(user_id.as_bytes());
        expected.extend_from_slice(&4u32.to_be_bytes());
        expected.extend_from_slice(b"POST");
        expected.extend_from_slice(&(target.as_str().len() as u32).to_be_bytes());
        expected.extend_from_slice(target.as_str().as_bytes());
        expected.extend_from_slice(&request.timestamp_ms.to_be_bytes());
        expected.extend_from_slice(&nonce);
        expected.extend_from_slice(&body_sha256);
        assert_eq!(actual, expected);
        assert_eq!(
            hex::encode(rest_auth_body_digest_v2(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        for invalid_method in ["", "post", "GE T", "GET:", &"A".repeat(33)] {
            let invalid = RestAuthRequestV2 {
                method: invalid_method,
                ..request
            };
            assert_eq!(
                rest_auth_signing_bytes_v2(&invalid),
                Err(AuthContractError::InvalidMethod)
            );
        }
        assert_eq!(
            rest_auth_signing_bytes_v2(&RestAuthRequestV2 {
                timestamp_ms: 0,
                ..request
            }),
            Err(AuthContractError::InvalidTimestamp)
        );
        assert_eq!(
            rest_auth_signing_bytes_v2(&RestAuthRequestV2 {
                timestamp_ms: i64::MAX as u64 + 1,
                ..request
            }),
            Err(AuthContractError::InvalidTimestamp)
        );
        assert_eq!(
            rest_auth_signing_bytes_v2(&RestAuthRequestV2 {
                nonce: &[0u8; 32],
                ..request
            }),
            Err(AuthContractError::InvalidNonce)
        );
        assert!(rest_auth_signing_bytes_v2(&RestAuthRequestV2 {
            body_sha256: &[0u8; 32],
            ..request
        })
        .is_ok());
    }

    #[test]
    fn ws_v3_layout_binds_context_account_and_device_proofs() {
        let origin = CanonicalNodeOriginV1::parse(ORIGIN).unwrap();
        let server_ephemeral = [0x11; 32];
        let account_identity_key = [0x22; 32];
        let account_signing_key = signing_key();
        let device_id = [0x33; 16];
        let binding_commitment = [0x44; 32];
        let pass_commitment = [0x55; 32];
        let context = WsAuthContextV3 {
            origin: &origin,
            server_ephemeral: &server_ephemeral,
            account_identity_key: &account_identity_key,
            account_signing_key: &account_signing_key,
            device_id: &device_id,
            verified_binding_commitment: &binding_commitment,
            registration_intent: WsRegistrationIntentV3::Pass {
                commitment: pass_commitment,
            },
        };
        let context_bytes = ws_auth_context_bytes_v3(&context).unwrap();
        let mut expected_context = Vec::new();
        expected_context.extend_from_slice(b"veil-ws-auth-v3/context\0");
        expected_context.extend_from_slice(&(ORIGIN.len() as u32).to_be_bytes());
        expected_context.extend_from_slice(ORIGIN.as_bytes());
        expected_context.extend_from_slice(&server_ephemeral);
        expected_context.extend_from_slice(&account_identity_key);
        expected_context.extend_from_slice(&account_signing_key);
        expected_context.extend_from_slice(&device_id);
        expected_context.extend_from_slice(&binding_commitment);
        expected_context.push(3);
        expected_context.extend_from_slice(&pass_commitment);
        assert_eq!(context_bytes, expected_context);

        let account_shared = [0x66; 32];
        let account_proof = ws_account_auth_signing_bytes_v3(&context, &account_shared).unwrap();
        let mut expected_account = Vec::new();
        expected_account.extend_from_slice(b"veil-ws-auth-v3/account-proof\0");
        expected_account.extend_from_slice(&(context_bytes.len() as u32).to_be_bytes());
        expected_account.extend_from_slice(&context_bytes);
        expected_account.extend_from_slice(&account_shared);
        assert_eq!(account_proof, expected_account);

        let device_shared = [0x77; 32];
        let account_signature = [0x88; 64];
        let device_proof =
            ws_device_auth_signing_bytes_v3(&context, &device_shared, &account_signature).unwrap();
        let mut expected_device = Vec::new();
        expected_device.extend_from_slice(b"veil-ws-auth-v3/device-proof\0");
        expected_device.extend_from_slice(&(context_bytes.len() as u32).to_be_bytes());
        expected_device.extend_from_slice(&context_bytes);
        expected_device.extend_from_slice(&device_shared);
        expected_device.extend_from_slice(&account_signature);
        assert_eq!(device_proof, expected_device);

        for (intent, expected_tag) in [
            (WsRegistrationIntentV3::Existing, 1),
            (WsRegistrationIntentV3::Open, 2),
        ] {
            let no_pass = WsAuthContextV3 {
                registration_intent: intent,
                ..context
            };
            let encoded = ws_auth_context_bytes_v3(&no_pass).unwrap();
            let tag_offset = encoded.len() - 33;
            assert_eq!(encoded[tag_offset], expected_tag);
            assert_eq!(&encoded[tag_offset + 1..], &[0u8; 32]);
        }
    }

    #[test]
    fn ws_v3_rejects_unverified_or_noncontributory_fixed_values() {
        let origin = CanonicalNodeOriginV1::parse(ORIGIN).unwrap();
        let server_ephemeral = [0x11; 32];
        let account_identity_key = [0x22; 32];
        let account_signing_key = signing_key();
        let device_id = [0x33; 16];
        let binding_commitment = [0x44; 32];
        let valid = WsAuthContextV3 {
            origin: &origin,
            server_ephemeral: &server_ephemeral,
            account_identity_key: &account_identity_key,
            account_signing_key: &account_signing_key,
            device_id: &device_id,
            verified_binding_commitment: &binding_commitment,
            registration_intent: WsRegistrationIntentV3::Existing,
        };
        assert_eq!(
            ws_account_auth_signing_bytes_v3(&valid, &[0u8; 32]),
            Err(AuthContractError::NonContributoryDh)
        );
        assert_eq!(
            ws_device_auth_signing_bytes_v3(&valid, &[0u8; 32], &[1u8; 64]),
            Err(AuthContractError::NonContributoryDh)
        );
        assert_eq!(
            ws_device_auth_signing_bytes_v3(&valid, &[1u8; 32], &[0u8; 64]),
            Err(AuthContractError::InvalidAccountProofSignature)
        );

        let zero_ephemeral = WsAuthContextV3 {
            server_ephemeral: &[0u8; 32],
            ..valid
        };
        assert_eq!(
            ws_auth_context_bytes_v3(&zero_ephemeral),
            Err(AuthContractError::NonContributoryDh)
        );
        let zero_identity = WsAuthContextV3 {
            account_identity_key: &[0u8; 32],
            ..valid
        };
        assert_eq!(
            ws_auth_context_bytes_v3(&zero_identity),
            Err(AuthContractError::InvalidAccountIdentityKey)
        );
        let weak_signing = WsAuthContextV3 {
            account_signing_key: &[0u8; 32],
            ..valid
        };
        assert_eq!(
            ws_auth_context_bytes_v3(&weak_signing),
            Err(AuthContractError::InvalidAccountSigningKey)
        );
        let zero_device = WsAuthContextV3 {
            device_id: &[0u8; 16],
            ..valid
        };
        assert_eq!(
            ws_auth_context_bytes_v3(&zero_device),
            Err(AuthContractError::InvalidDeviceId)
        );
        let zero_binding = WsAuthContextV3 {
            verified_binding_commitment: &[0u8; 32],
            ..valid
        };
        assert_eq!(
            ws_auth_context_bytes_v3(&zero_binding),
            Err(AuthContractError::InvalidBindingCommitment)
        );
        let zero_pass = WsAuthContextV3 {
            registration_intent: WsRegistrationIntentV3::Pass {
                commitment: [0u8; 32],
            },
            ..valid
        };
        assert_eq!(
            ws_auth_context_bytes_v3(&zero_pass),
            Err(AuthContractError::InvalidRegistrationIntent)
        );
    }
}
