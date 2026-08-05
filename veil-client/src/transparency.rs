//! Strict client boundary for Node-signed identity-transparency proofs.
//!
//! JSON parsing and canonical event reconstruction happen before SQLCipher is
//! allowed to advance its per-origin head. The store then repeats signature,
//! inclusion and append-only checks atomically against the current durable pin.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use veil_crypto::transparency::{
    account_registration_event_v1, device_binding_event_v1, log_id_v1,
    witness_checkpoint_message_v1, witness_policy_hash_v1, TransparencyTreeHeadV1,
    MAX_TRANSPARENCY_PROOF_NODES_V1, MAX_TRANSPARENCY_WITNESSES_V1,
};
use veil_store::db::{
    IdentityTransparencyAcceptanceV1, IdentityTransparencyPinnedHeadV1,
    IdentityTransparencyProofV1, VeilDb,
};

use crate::device_identity::device_binding_signing_bytes;

pub const IDENTITY_TRANSPARENCY_RESPONSE_LIMIT_V1: usize = 64 * 1024;
pub const IDENTITY_TRANSPARENCY_GOSSIP_LIMIT_V1: usize = 8 * 1024;
const TREE_HEAD_MAX_AGE_MS_V1: u64 = 24 * 60 * 60 * 1000;
const TREE_HEAD_MAX_FUTURE_SKEW_MS_V1: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentAccountExpectedV1 {
    pub user_id: String,
    pub identity_key: [u8; 32],
    pub signing_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentDeviceBindingExpectedV1 {
    pub account_user_id: String,
    pub account_identity_key: [u8; 32],
    pub account_signing_key: [u8; 32],
    pub device_key: [u8; 16],
    pub device_identity_key: [u8; 32],
    pub device_signing_key: [u8; 32],
    pub binding_version: u64,
    pub capabilities: u64,
    pub status: u8,
    pub account_signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparencyWitnessPolicyV1 {
    threshold: u16,
    witness_signing_keys: Vec<[u8; 32]>,
    policy_hash: [u8; 32],
}

impl TransparencyWitnessPolicyV1 {
    pub fn new(threshold: u16, mut witness_signing_keys: Vec<[u8; 32]>) -> Result<Self, String> {
        witness_signing_keys.sort_unstable();
        let policy_hash = witness_policy_hash_v1(threshold, &witness_signing_keys)?;
        Ok(Self {
            threshold,
            witness_signing_keys,
            policy_hash,
        })
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn witness_signing_keys(&self) -> &[[u8; 32]] {
        &self.witness_signing_keys
    }

    pub fn policy_hash(&self) -> [u8; 32] {
        self.policy_hash
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessSignatureWireV1 {
    witness_signing_key: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TreeHeadWireV1 {
    log_id: String,
    node_signing_key: String,
    tree_size: String,
    root_hash: String,
    issued_at_ms: String,
    signature: String,
    #[serde(default)]
    witnesses: Vec<WitnessSignatureWireV1>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountProofWireV1 {
    version: u8,
    canonical_origin: String,
    account_user_id: String,
    canonical_event: String,
    leaf_index: String,
    tree_head: TreeHeadWireV1,
    inclusion_proof: Vec<String>,
    consistency_from: String,
    consistency_proof: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceBindingProofWireV1 {
    version: u8,
    canonical_origin: String,
    device_key: String,
    device_binding_version: String,
    canonical_event: String,
    leaf_index: String,
    tree_head: TreeHeadWireV1,
    inclusion_proof: Vec<String>,
    consistency_from: String,
    consistency_proof: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GossipCheckpointWireV1 {
    version: u8,
    canonical_origin: String,
    log_id: String,
    node_signing_key: String,
    tree_size: String,
    root_hash: String,
    issued_at_ms: String,
    signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityTransparencyGossipComparisonV1 {
    NoLocalPin {
        peer_tree_size: u64,
    },
    ExactHeadAgreement {
        tree_size: u64,
    },
    LocalHeadAhead {
        local_tree_size: u64,
        peer_tree_size: u64,
    },
    PeerHeadAhead {
        local_tree_size: u64,
        peer_tree_size: u64,
    },
    PinnedLogIdentityMismatch,
    ConfirmedSplitView {
        tree_size: u64,
    },
}

fn decode_lower_hex<const N: usize>(label: &str, value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} is not exact lowercase hex"));
    }
    let decoded = hex::decode(value).map_err(|_| format!("{label} is not valid hex"))?;
    if hex::encode(&decoded) != value {
        return Err(format!("{label} is not canonical lowercase hex"));
    }
    decoded
        .try_into()
        .map_err(|_| format!("{label} has an invalid length"))
}

fn decode_base64url(label: &str, value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.contains('=') || !value.is_ascii() {
        return Err(format!("{label} is not canonical unpadded base64url"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("{label} is not valid base64url"))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(format!("{label} is not canonical unpadded base64url"));
    }
    Ok(decoded)
}

fn parse_decimal(label: &str, value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{label} is not a decimal integer"));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{label} exceeds u64"))?;
    if parsed.to_string() != value {
        return Err(format!("{label} is not canonical decimal"));
    }
    Ok(parsed)
}

fn parse_proof_hashes(label: &str, values: &[String]) -> Result<Vec<[u8; 32]>, String> {
    if values.len() > MAX_TRANSPARENCY_PROOF_NODES_V1 {
        return Err(format!("{label} exceeds the proof bound"));
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| decode_lower_hex(&format!("{label}[{index}]"), value))
        .collect()
}

fn current_time_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes the Unix epoch".to_string())?
        .as_millis();
    u64::try_from(millis).map_err(|_| "system clock exceeds u64 milliseconds".to_string())
}

struct ParsedProofInputV1 {
    canonical_origin: String,
    canonical_event: String,
    leaf_index: String,
    tree_head: TreeHeadWireV1,
    inclusion_proof: Vec<String>,
    consistency_from: String,
    consistency_proof: Vec<String>,
}

fn parsed_proof(
    expected_origin: &str,
    input: ParsedProofInputV1,
    now_ms: u64,
    witness_policy: Option<&TransparencyWitnessPolicyV1>,
) -> Result<IdentityTransparencyProofV1, String> {
    if input.canonical_origin != expected_origin {
        return Err("identity transparency response changed the authenticated origin".to_string());
    }
    let issued_at_ms = parse_decimal(
        "identity transparency issued_at_ms",
        &input.tree_head.issued_at_ms,
    )?;
    if issued_at_ms > now_ms.saturating_add(TREE_HEAD_MAX_FUTURE_SKEW_MS_V1)
        || issued_at_ms.saturating_add(TREE_HEAD_MAX_AGE_MS_V1) < now_ms
    {
        return Err("identity transparency tree head is stale or future-dated".to_string());
    }
    if input.tree_head.witnesses.len() > MAX_TRANSPARENCY_WITNESSES_V1 {
        return Err("identity transparency witness list exceeds the bound".to_string());
    }
    let log_id = decode_lower_hex("identity transparency log_id", &input.tree_head.log_id)?;
    let node_signing_key = decode_lower_hex(
        "identity transparency node_signing_key",
        &input.tree_head.node_signing_key,
    )?;
    let tree_size = parse_decimal(
        "identity transparency tree_size",
        &input.tree_head.tree_size,
    )?;
    let root_hash = decode_lower_hex(
        "identity transparency root_hash",
        &input.tree_head.root_hash,
    )?;
    let tree_head_signature = decode_lower_hex(
        "identity transparency signature",
        &input.tree_head.signature,
    )?;
    let head = TransparencyTreeHeadV1 {
        log_id,
        tree_size,
        root_hash,
        issued_at_ms,
    };
    let checkpoint_message = witness_checkpoint_message_v1(
        expected_origin,
        &node_signing_key,
        &head,
        &tree_head_signature,
    )?;
    let mut previous_key = None;
    let mut matched_witnesses = 0u32;
    for (index, witness) in input.tree_head.witnesses.iter().enumerate() {
        let key = decode_lower_hex::<32>(
            &format!("identity transparency witness[{index}] key"),
            &witness.witness_signing_key,
        )?;
        let signature = decode_lower_hex::<64>(
            &format!("identity transparency witness[{index}] signature"),
            &witness.signature,
        )?;
        if previous_key.is_some_and(|previous| previous >= key)
            || !veil_crypto::signature::verify(&key, &checkpoint_message, &signature)
        {
            return Err(
                "identity transparency witness signatures are invalid or unordered".to_string(),
            );
        }
        previous_key = Some(key);
        if witness_policy
            .is_some_and(|policy| policy.witness_signing_keys.binary_search(&key).is_ok())
        {
            matched_witnesses = matched_witnesses.saturating_add(1);
        }
    }
    let (witness_policy_hash, witness_quorum) = match witness_policy {
        Some(policy) if matched_witnesses >= u32::from(policy.threshold) => {
            (policy.policy_hash, matched_witnesses)
        }
        Some(_) => return Err("identity transparency witness quorum is not satisfied".to_string()),
        None => ([0u8; 32], 0),
    };
    Ok(IdentityTransparencyProofV1 {
        canonical_server_origin: input.canonical_origin,
        log_id,
        node_signing_key,
        tree_size,
        root_hash,
        issued_at_ms,
        tree_head_signature,
        canonical_event: decode_base64url(
            "identity transparency canonical_event",
            &input.canonical_event,
        )?,
        leaf_index: parse_decimal("identity transparency leaf_index", &input.leaf_index)?,
        inclusion_proof: parse_proof_hashes(
            "identity transparency inclusion_proof",
            &input.inclusion_proof,
        )?,
        consistency_from: parse_decimal(
            "identity transparency consistency_from",
            &input.consistency_from,
        )?,
        consistency_proof: parse_proof_hashes(
            "identity transparency consistency_proof",
            &input.consistency_proof,
        )?,
        witness_policy_hash,
        witness_quorum,
    })
}

pub fn identity_transparency_request_from_size_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
) -> Result<u64, String> {
    Ok(db
        .identity_transparency_pinned_head_v1(canonical_server_origin)?
        .map_or(0, |head| head.tree_size))
}

pub fn identity_transparency_request_from_size_with_anchor_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
    rollback_anchor: &IdentityTransparencyPinnedHeadV1,
) -> Result<u64, String> {
    if rollback_anchor.canonical_server_origin != canonical_server_origin {
        return Err("identity transparency rollback anchor changed origin".to_string());
    }
    Ok(
        identity_transparency_request_from_size_v1(db, canonical_server_origin)?
            .max(rollback_anchor.tree_size),
    )
}

/// Exports a compact Node-signed checkpoint suitable for an optional QR or
/// authenticated device-to-device gossip channel. No local secret is exposed.
pub fn export_identity_transparency_gossip_checkpoint_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
) -> Result<Option<String>, String> {
    let Some(head) = db.identity_transparency_pinned_head_v1(canonical_server_origin)? else {
        return Ok(None);
    };
    let wire = GossipCheckpointWireV1 {
        version: 1,
        canonical_origin: head.canonical_server_origin.clone(),
        log_id: hex::encode(head.log_id),
        node_signing_key: hex::encode(head.node_signing_key),
        tree_size: head.tree_size.to_string(),
        root_hash: hex::encode(head.root_hash),
        issued_at_ms: head.issued_at_ms.to_string(),
        signature: hex::encode(head.tree_head_signature),
    };
    let encoded = serde_json::to_vec(&wire)
        .map_err(|error| format!("encode identity transparency gossip checkpoint: {error}"))?;
    if encoded.len() > IDENTITY_TRANSPARENCY_GOSSIP_LIMIT_V1 {
        return Err("identity transparency gossip checkpoint is oversized".to_string());
    }
    Ok(Some(URL_SAFE_NO_PAD.encode(encoded)))
}

/// Validates and compares a peer checkpoint without mutating local trust. A
/// same-size, differently rooted pair of valid Node signatures is conclusive
/// split-view evidence; different sizes require a normal consistency proof.
pub fn compare_identity_transparency_gossip_checkpoint_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
    encoded: &str,
) -> Result<IdentityTransparencyGossipComparisonV1, String> {
    if encoded.is_empty()
        || encoded.contains('=')
        || encoded.len() > IDENTITY_TRANSPARENCY_GOSSIP_LIMIT_V1 * 2
    {
        return Err("identity transparency gossip encoding is invalid".to_string());
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "identity transparency gossip is not base64url".to_string())?;
    if decoded.is_empty()
        || decoded.len() > IDENTITY_TRANSPARENCY_GOSSIP_LIMIT_V1
        || URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err("identity transparency gossip is not canonical".to_string());
    }
    let wire: GossipCheckpointWireV1 = serde_json::from_slice(&decoded)
        .map_err(|error| format!("invalid identity transparency gossip checkpoint: {error}"))?;
    if serde_json::to_vec(&wire)
        .map_err(|error| format!("encode identity transparency gossip checkpoint: {error}"))?
        != decoded
        || wire.version != 1
        || wire.canonical_origin != canonical_server_origin
    {
        return Err("identity transparency gossip checkpoint is non-canonical".to_string());
    }
    let log_id = decode_lower_hex("gossip log_id", &wire.log_id)?;
    let node_signing_key = decode_lower_hex("gossip node_signing_key", &wire.node_signing_key)?;
    let tree_size = parse_decimal("gossip tree_size", &wire.tree_size)?;
    let root_hash = decode_lower_hex("gossip root_hash", &wire.root_hash)?;
    let issued_at_ms = parse_decimal("gossip issued_at_ms", &wire.issued_at_ms)?;
    let signature = decode_lower_hex("gossip signature", &wire.signature)?;
    let head = TransparencyTreeHeadV1 {
        log_id,
        tree_size,
        root_hash,
        issued_at_ms,
    };
    if log_id_v1(canonical_server_origin, &node_signing_key)? != log_id
        || !head.verify_node_signature(canonical_server_origin, &node_signing_key, &signature)
    {
        return Err("identity transparency gossip signature is invalid".to_string());
    }
    let Some(local) = db.identity_transparency_pinned_head_v1(canonical_server_origin)? else {
        return Ok(IdentityTransparencyGossipComparisonV1::NoLocalPin {
            peer_tree_size: tree_size,
        });
    };
    if local.log_id != log_id || local.node_signing_key != node_signing_key {
        return Ok(IdentityTransparencyGossipComparisonV1::PinnedLogIdentityMismatch);
    }
    if local.tree_size == tree_size {
        return Ok(if local.root_hash == root_hash {
            IdentityTransparencyGossipComparisonV1::ExactHeadAgreement { tree_size }
        } else {
            IdentityTransparencyGossipComparisonV1::ConfirmedSplitView { tree_size }
        });
    }
    Ok(if local.tree_size > tree_size {
        IdentityTransparencyGossipComparisonV1::LocalHeadAhead {
            local_tree_size: local.tree_size,
            peer_tree_size: tree_size,
        }
    } else {
        IdentityTransparencyGossipComparisonV1::PeerHeadAhead {
            local_tree_size: local.tree_size,
            peer_tree_size: tree_size,
        }
    })
}

pub fn verify_account_transparency_response_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
    expected: &TransparentAccountExpectedV1,
    response: &[u8],
) -> Result<IdentityTransparencyAcceptanceV1, String> {
    verify_account_transparency_response_at_v1(
        db,
        canonical_server_origin,
        expected,
        response,
        current_time_ms()?,
    )
}

pub fn verify_account_transparency_response_with_anchor_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
    expected: &TransparentAccountExpectedV1,
    response: &[u8],
    rollback_anchor: &IdentityTransparencyPinnedHeadV1,
) -> Result<IdentityTransparencyAcceptanceV1, String> {
    verify_account_transparency_response_at_with_anchor_v1(
        db,
        canonical_server_origin,
        expected,
        response,
        current_time_ms()?,
        Some(rollback_anchor),
        None,
    )
}

pub fn verify_account_transparency_response_with_security_policy_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
    expected: &TransparentAccountExpectedV1,
    response: &[u8],
    rollback_anchor: Option<&IdentityTransparencyPinnedHeadV1>,
    witness_policy: Option<&TransparencyWitnessPolicyV1>,
) -> Result<IdentityTransparencyAcceptanceV1, String> {
    verify_account_transparency_response_at_with_anchor_v1(
        db,
        canonical_server_origin,
        expected,
        response,
        current_time_ms()?,
        rollback_anchor,
        witness_policy,
    )
}

fn verify_account_transparency_response_at_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
    expected: &TransparentAccountExpectedV1,
    response: &[u8],
    now_ms: u64,
) -> Result<IdentityTransparencyAcceptanceV1, String> {
    verify_account_transparency_response_at_with_anchor_v1(
        db,
        canonical_server_origin,
        expected,
        response,
        now_ms,
        None,
        None,
    )
}

fn verify_account_transparency_response_at_with_anchor_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
    expected: &TransparentAccountExpectedV1,
    response: &[u8],
    now_ms: u64,
    rollback_anchor: Option<&IdentityTransparencyPinnedHeadV1>,
    witness_policy: Option<&TransparencyWitnessPolicyV1>,
) -> Result<IdentityTransparencyAcceptanceV1, String> {
    if response.is_empty() || response.len() > IDENTITY_TRANSPARENCY_RESPONSE_LIMIT_V1 {
        return Err("identity transparency response size is invalid".to_string());
    }
    let wire: AccountProofWireV1 = serde_json::from_slice(response)
        .map_err(|error| format!("invalid account transparency response: {error}"))?;
    if wire.version != 1 || wire.account_user_id != expected.user_id {
        return Err("account transparency response subject is invalid".to_string());
    }
    let account_id = uuid::Uuid::parse_str(&expected.user_id)
        .map_err(|_| "transparent account user id is invalid".to_string())?;
    if account_id.is_nil() || account_id.hyphenated().to_string() != expected.user_id {
        return Err("transparent account user id is not canonical".to_string());
    }
    let proof = parsed_proof(
        canonical_server_origin,
        ParsedProofInputV1 {
            canonical_origin: wire.canonical_origin,
            canonical_event: wire.canonical_event,
            leaf_index: wire.leaf_index,
            tree_head: wire.tree_head,
            inclusion_proof: wire.inclusion_proof,
            consistency_from: wire.consistency_from,
            consistency_proof: wire.consistency_proof,
        },
        now_ms,
        witness_policy,
    )?;
    let expected_event = account_registration_event_v1(
        canonical_server_origin,
        account_id.as_bytes(),
        &expected.identity_key,
        &expected.signing_key,
    )?;
    if proof.canonical_event != expected_event {
        return Err("account transparency event differs from directory keys".to_string());
    }
    db.verify_and_pin_identity_transparency_proof_with_anchor_v1(&proof, rollback_anchor)
}

pub fn verify_device_binding_transparency_response_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
    expected: &TransparentDeviceBindingExpectedV1,
    response: &[u8],
) -> Result<IdentityTransparencyAcceptanceV1, String> {
    verify_device_binding_transparency_response_at_v1(
        db,
        canonical_server_origin,
        expected,
        response,
        current_time_ms()?,
    )
}

pub fn verify_device_binding_transparency_response_with_anchor_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
    expected: &TransparentDeviceBindingExpectedV1,
    response: &[u8],
    rollback_anchor: &IdentityTransparencyPinnedHeadV1,
) -> Result<IdentityTransparencyAcceptanceV1, String> {
    verify_device_binding_transparency_response_at_with_anchor_v1(
        db,
        canonical_server_origin,
        expected,
        response,
        current_time_ms()?,
        Some(rollback_anchor),
        None,
    )
}

pub fn verify_device_binding_transparency_response_with_security_policy_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
    expected: &TransparentDeviceBindingExpectedV1,
    response: &[u8],
    rollback_anchor: Option<&IdentityTransparencyPinnedHeadV1>,
    witness_policy: Option<&TransparencyWitnessPolicyV1>,
) -> Result<IdentityTransparencyAcceptanceV1, String> {
    verify_device_binding_transparency_response_at_with_anchor_v1(
        db,
        canonical_server_origin,
        expected,
        response,
        current_time_ms()?,
        rollback_anchor,
        witness_policy,
    )
}

fn verify_device_binding_transparency_response_at_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
    expected: &TransparentDeviceBindingExpectedV1,
    response: &[u8],
    now_ms: u64,
) -> Result<IdentityTransparencyAcceptanceV1, String> {
    verify_device_binding_transparency_response_at_with_anchor_v1(
        db,
        canonical_server_origin,
        expected,
        response,
        now_ms,
        None,
        None,
    )
}

fn verify_device_binding_transparency_response_at_with_anchor_v1(
    db: &VeilDb,
    canonical_server_origin: &str,
    expected: &TransparentDeviceBindingExpectedV1,
    response: &[u8],
    now_ms: u64,
    rollback_anchor: Option<&IdentityTransparencyPinnedHeadV1>,
    witness_policy: Option<&TransparencyWitnessPolicyV1>,
) -> Result<IdentityTransparencyAcceptanceV1, String> {
    if response.is_empty() || response.len() > IDENTITY_TRANSPARENCY_RESPONSE_LIMIT_V1 {
        return Err("identity transparency response size is invalid".to_string());
    }
    let wire: DeviceBindingProofWireV1 = serde_json::from_slice(response)
        .map_err(|error| format!("invalid device-binding transparency response: {error}"))?;
    if wire.version != 1
        || decode_lower_hex::<16>("device transparency subject", &wire.device_key)?
            != expected.device_key
        || parse_decimal(
            "device transparency binding version",
            &wire.device_binding_version,
        )? != expected.binding_version
    {
        return Err("device-binding transparency response subject is invalid".to_string());
    }
    let account_id = uuid::Uuid::parse_str(&expected.account_user_id)
        .map_err(|_| "device-binding account user id is invalid".to_string())?;
    if account_id.is_nil() || account_id.hyphenated().to_string() != expected.account_user_id {
        return Err("device-binding account user id is not canonical".to_string());
    }
    let binding_message = device_binding_signing_bytes(
        &expected.account_identity_key,
        &expected.account_signing_key,
        &expected.device_key,
        expected.binding_version,
        &expected.device_identity_key,
        &expected.device_signing_key,
        expected.capabilities,
        expected.status,
    );
    if !veil_crypto::signature::verify(
        &expected.account_signing_key,
        &binding_message,
        &expected.account_signature,
    ) {
        return Err("device transparency account signature is invalid".to_string());
    }
    let commitment: [u8; 32] = Sha256::digest(&binding_message).into();
    let expected_event = device_binding_event_v1(
        canonical_server_origin,
        account_id.as_bytes(),
        &expected.device_key,
        &expected.device_identity_key,
        &expected.device_signing_key,
        expected.binding_version,
        expected.capabilities,
        expected.status,
        &expected.account_signature,
        &commitment,
    )?;
    let proof = parsed_proof(
        canonical_server_origin,
        ParsedProofInputV1 {
            canonical_origin: wire.canonical_origin,
            canonical_event: wire.canonical_event,
            leaf_index: wire.leaf_index,
            tree_head: wire.tree_head,
            inclusion_proof: wire.inclusion_proof,
            consistency_from: wire.consistency_from,
            consistency_proof: wire.consistency_proof,
        },
        now_ms,
        witness_policy,
    )?;
    if proof.canonical_event != expected_event {
        return Err("device transparency event differs from the authenticated binding".to_string());
    }
    db.verify_and_pin_identity_transparency_proof_with_anchor_v1(&proof, rollback_anchor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use veil_crypto::transparency::{
        inclusion_proof_v1, log_id_v1, tree_root_v1, TransparencyTreeHeadV1,
    };

    const ORIGIN: &str = "https://node.example:443";
    const USER_ID: &str = "550e8400-e29b-41d4-a716-446655440001";

    fn response_json(
        signing: &SigningKey,
        event: &[u8],
        subject: serde_json::Value,
        now_ms: u64,
    ) -> Vec<u8> {
        response_json_for_tree(signing, event, subject, now_ms, &[])
    }

    fn response_json_for_tree(
        signing: &SigningKey,
        event: &[u8],
        subject: serde_json::Value,
        now_ms: u64,
        additional_events: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut events = vec![event.to_vec()];
        events.extend_from_slice(additional_events);
        let root = tree_root_v1(&events).unwrap();
        let key = signing.verifying_key().to_bytes();
        let head = TransparencyTreeHeadV1 {
            log_id: log_id_v1(ORIGIN, &key).unwrap(),
            tree_size: events.len() as u64,
            root_hash: root,
            issued_at_ms: now_ms,
        };
        let signature = signing
            .sign(&head.signing_message(ORIGIN).unwrap())
            .to_bytes();
        let mut value = json!({
            "version": 1,
            "canonical_origin": ORIGIN,
            "canonical_event": URL_SAFE_NO_PAD.encode(event),
            "leaf_index": "0",
            "tree_head": {
                "log_id": hex::encode(head.log_id),
                "node_signing_key": hex::encode(key),
                "tree_size": events.len().to_string(),
                "root_hash": hex::encode(root),
                "issued_at_ms": now_ms.to_string(),
                "signature": hex::encode(signature),
            },
            "inclusion_proof": inclusion_proof_v1(&events, 0).unwrap().iter().map(hex::encode).collect::<Vec<_>>(),
            "consistency_from": "0",
            "consistency_proof": [],
        });
        value
            .as_object_mut()
            .unwrap()
            .extend(subject.as_object().unwrap().clone());
        serde_json::to_vec(&value).unwrap()
    }

    fn response_json_with_witnesses(
        signing: &SigningKey,
        event: &[u8],
        subject: serde_json::Value,
        now_ms: u64,
        witnesses: &[SigningKey],
    ) -> Vec<u8> {
        let raw = response_json(signing, event, subject, now_ms);
        let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let events = vec![event.to_vec()];
        let node_signing_key = signing.verifying_key().to_bytes();
        let head = TransparencyTreeHeadV1 {
            log_id: log_id_v1(ORIGIN, &node_signing_key).unwrap(),
            tree_size: 1,
            root_hash: tree_root_v1(&events).unwrap(),
            issued_at_ms: now_ms,
        };
        let node_signature = signing
            .sign(&head.signing_message(ORIGIN).unwrap())
            .to_bytes();
        let checkpoint =
            witness_checkpoint_message_v1(ORIGIN, &node_signing_key, &head, &node_signature)
                .unwrap();
        let mut signatures = witnesses
            .iter()
            .map(|witness| {
                let key = witness.verifying_key().to_bytes();
                json!({
                    "witness_signing_key": hex::encode(key),
                    "signature": hex::encode(witness.sign(&checkpoint).to_bytes()),
                })
            })
            .collect::<Vec<_>>();
        signatures.sort_by(|left, right| {
            left["witness_signing_key"]
                .as_str()
                .cmp(&right["witness_signing_key"].as_str())
        });
        value["tree_head"]["witnesses"] = signatures.into();
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn account_response_binds_directory_tuple_before_pinning() {
        let db = VeilDb::open_memory(&[0xA5; 32]).unwrap();
        let account_signing = SigningKey::from_bytes(&[0x41; 32]);
        let expected = TransparentAccountExpectedV1 {
            user_id: USER_ID.to_string(),
            identity_key: [0x42; 32],
            signing_key: account_signing.verifying_key().to_bytes(),
        };
        let user_id = uuid::Uuid::parse_str(USER_ID).unwrap();
        let event = account_registration_event_v1(
            ORIGIN,
            user_id.as_bytes(),
            &expected.identity_key,
            &expected.signing_key,
        )
        .unwrap();
        let now_ms = 1_800_000_000_000;
        let response = response_json(
            &SigningKey::from_bytes(&[0x51; 32]),
            &event,
            json!({"account_user_id": USER_ID}),
            now_ms,
        );
        assert_eq!(
            verify_account_transparency_response_at_v1(&db, ORIGIN, &expected, &response, now_ms)
                .unwrap(),
            IdentityTransparencyAcceptanceV1::FirstContactPinned
        );
        let mut substituted = expected.clone();
        substituted.identity_key[0] ^= 1;
        let other_db = VeilDb::open_memory(&[0xA6; 32]).unwrap();
        assert!(verify_account_transparency_response_at_v1(
            &other_db,
            ORIGIN,
            &substituted,
            &response,
            now_ms,
        )
        .is_err());
        assert!(other_db
            .identity_transparency_pinned_head_v1(ORIGIN)
            .unwrap()
            .is_none());
    }

    #[test]
    fn witness_quorum_is_verified_and_sticky_without_changing_default_ux() {
        let db = VeilDb::open_memory(&[0xC5; 32]).unwrap();
        let account_signing = SigningKey::from_bytes(&[0x31; 32]);
        let expected = TransparentAccountExpectedV1 {
            user_id: USER_ID.to_string(),
            identity_key: [0x32; 32],
            signing_key: account_signing.verifying_key().to_bytes(),
        };
        let event = account_registration_event_v1(
            ORIGIN,
            uuid::Uuid::parse_str(USER_ID).unwrap().as_bytes(),
            &expected.identity_key,
            &expected.signing_key,
        )
        .unwrap();
        let node_signing = SigningKey::from_bytes(&[0x33; 32]);
        let witnesses = [
            SigningKey::from_bytes(&[0x34; 32]),
            SigningKey::from_bytes(&[0x35; 32]),
            SigningKey::from_bytes(&[0x36; 32]),
        ];
        let policy = TransparencyWitnessPolicyV1::new(
            2,
            witnesses
                .iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
        )
        .unwrap();
        let now_ms = 1_800_000_000_000;
        let witnessed = response_json_with_witnesses(
            &node_signing,
            &event,
            json!({"account_user_id": USER_ID}),
            now_ms,
            &witnesses[..2],
        );
        assert_eq!(
            verify_account_transparency_response_at_with_anchor_v1(
                &db,
                ORIGIN,
                &expected,
                &witnessed,
                now_ms,
                None,
                Some(&policy),
            )
            .unwrap(),
            IdentityTransparencyAcceptanceV1::FirstContactPinned
        );
        let pinned = db
            .identity_transparency_pinned_head_v1(ORIGIN)
            .unwrap()
            .unwrap();
        assert_eq!(pinned.witness_policy_hash, policy.policy_hash());
        assert_eq!(pinned.witness_quorum, 2);

        let unwitnessed = response_json(
            &node_signing,
            &event,
            json!({"account_user_id": USER_ID}),
            now_ms,
        );
        assert!(verify_account_transparency_response_at_v1(
            &db,
            ORIGIN,
            &expected,
            &unwitnessed,
            now_ms,
        )
        .is_err());

        // A client without an operator-configured witness policy remains
        // compatible, but still validates every witness signature it sees.
        let compatibility_db = VeilDb::open_memory(&[0xC6; 32]).unwrap();
        assert!(verify_account_transparency_response_at_v1(
            &compatibility_db,
            ORIGIN,
            &expected,
            &witnessed,
            now_ms,
        )
        .is_ok());
        let mut forged: serde_json::Value = serde_json::from_slice(&witnessed).unwrap();
        forged["tree_head"]["witnesses"][0]["signature"] = "00".repeat(64).into();
        let forged = serde_json::to_vec(&forged).unwrap();
        let forged_db = VeilDb::open_memory(&[0xC7; 32]).unwrap();
        assert!(verify_account_transparency_response_at_v1(
            &forged_db, ORIGIN, &expected, &forged, now_ms,
        )
        .is_err());
    }

    #[test]
    fn gossip_detects_same_size_split_view_without_mutating_trust() {
        let expected_signing = SigningKey::from_bytes(&[0x21; 32]);
        let expected = TransparentAccountExpectedV1 {
            user_id: USER_ID.to_string(),
            identity_key: [0x22; 32],
            signing_key: expected_signing.verifying_key().to_bytes(),
        };
        let event = account_registration_event_v1(
            ORIGIN,
            uuid::Uuid::parse_str(USER_ID).unwrap().as_bytes(),
            &expected.identity_key,
            &expected.signing_key,
        )
        .unwrap();
        let node_signing = SigningKey::from_bytes(&[0x23; 32]);
        let now_ms = 1_800_000_000_000;
        let local_db = VeilDb::open_memory(&[0xD5; 32]).unwrap();
        let peer_db = VeilDb::open_memory(&[0xD6; 32]).unwrap();
        let local_response = response_json_for_tree(
            &node_signing,
            &event,
            json!({"account_user_id": USER_ID}),
            now_ms,
            &[b"local-branch".to_vec()],
        );
        let peer_response = response_json_for_tree(
            &node_signing,
            &event,
            json!({"account_user_id": USER_ID}),
            now_ms,
            &[b"peer-branch".to_vec()],
        );
        verify_account_transparency_response_at_v1(
            &local_db,
            ORIGIN,
            &expected,
            &local_response,
            now_ms,
        )
        .unwrap();
        verify_account_transparency_response_at_v1(
            &peer_db,
            ORIGIN,
            &expected,
            &peer_response,
            now_ms,
        )
        .unwrap();

        let peer_checkpoint = export_identity_transparency_gossip_checkpoint_v1(&peer_db, ORIGIN)
            .unwrap()
            .unwrap();
        assert_eq!(
            compare_identity_transparency_gossip_checkpoint_v1(
                &local_db,
                ORIGIN,
                &peer_checkpoint,
            )
            .unwrap(),
            IdentityTransparencyGossipComparisonV1::ConfirmedSplitView { tree_size: 2 }
        );
        assert_eq!(
            compare_identity_transparency_gossip_checkpoint_v1(&peer_db, ORIGIN, &peer_checkpoint,)
                .unwrap(),
            IdentityTransparencyGossipComparisonV1::ExactHeadAgreement { tree_size: 2 }
        );
        let empty_db = VeilDb::open_memory(&[0xD7; 32]).unwrap();
        assert_eq!(
            compare_identity_transparency_gossip_checkpoint_v1(
                &empty_db,
                ORIGIN,
                &peer_checkpoint,
            )
            .unwrap(),
            IdentityTransparencyGossipComparisonV1::NoLocalPin { peer_tree_size: 2 }
        );

        let mut forged: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&peer_checkpoint).unwrap()).unwrap();
        forged["root_hash"] = "00".repeat(32).into();
        let forged = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
        assert!(
            compare_identity_transparency_gossip_checkpoint_v1(&local_db, ORIGIN, &forged,)
                .is_err()
        );
    }

    #[test]
    fn device_response_binds_account_signature_and_commitment() {
        let db = VeilDb::open_memory(&[0xB5; 32]).unwrap();
        let account_signing = SigningKey::from_bytes(&[0x61; 32]);
        let device_signing = SigningKey::from_bytes(&[0x62; 32]);
        let mut expected = TransparentDeviceBindingExpectedV1 {
            account_user_id: USER_ID.to_string(),
            account_identity_key: [0x63; 32],
            account_signing_key: account_signing.verifying_key().to_bytes(),
            device_key: [0x64; 16],
            device_identity_key: [0x65; 32],
            device_signing_key: device_signing.verifying_key().to_bytes(),
            binding_version: 1,
            capabilities: 3,
            status: 1,
            account_signature: [0u8; 64],
        };
        let message = device_binding_signing_bytes(
            &expected.account_identity_key,
            &expected.account_signing_key,
            &expected.device_key,
            expected.binding_version,
            &expected.device_identity_key,
            &expected.device_signing_key,
            expected.capabilities,
            expected.status,
        );
        expected.account_signature = account_signing.sign(&message).to_bytes();
        let commitment: [u8; 32] = Sha256::digest(&message).into();
        let event = device_binding_event_v1(
            ORIGIN,
            uuid::Uuid::parse_str(USER_ID).unwrap().as_bytes(),
            &expected.device_key,
            &expected.device_identity_key,
            &expected.device_signing_key,
            expected.binding_version,
            expected.capabilities,
            expected.status,
            &expected.account_signature,
            &commitment,
        )
        .unwrap();
        let now_ms = 1_800_000_000_000;
        let response = response_json(
            &SigningKey::from_bytes(&[0x71; 32]),
            &event,
            json!({
                "device_key": hex::encode(expected.device_key),
                "device_binding_version": "1",
            }),
            now_ms,
        );
        assert_eq!(
            verify_device_binding_transparency_response_at_v1(
                &db, ORIGIN, &expected, &response, now_ms,
            )
            .unwrap(),
            IdentityTransparencyAcceptanceV1::FirstContactPinned
        );
        let other_db = VeilDb::open_memory(&[0xB6; 32]).unwrap();
        expected.account_signature[0] ^= 1;
        assert!(verify_device_binding_transparency_response_at_v1(
            &other_db, ORIGIN, &expected, &response, now_ms,
        )
        .is_err());
    }
}
