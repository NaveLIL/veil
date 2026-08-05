//! Domain-separated Merkle proof primitives for Veil Transparency v1.
//!
//! This module deliberately contains no network or trust-policy shortcuts. A
//! valid Node signature is only one input to client policy; consistency,
//! witness/gossip checks, and local pinning are enforced by higher layers.

use sha2::{Digest, Sha256};

const EMPTY_DOMAIN_V1: &[u8] = b"veil-transparency-empty-v1\0";
const LEAF_DOMAIN_V1: &[u8] = b"veil-transparency-leaf-v1\0";
const NODE_DOMAIN_V1: &[u8] = b"veil-transparency-node-v1\0";
const TREE_HEAD_DOMAIN_V1: &[u8] = b"veil-transparency-sth-v1\0";
const LOG_ID_DOMAIN_V1: &[u8] = b"veil-transparency-log-id-v1\0";
const WITNESS_CHECKPOINT_DOMAIN_V1: &[u8] = b"veil-transparency-witness-checkpoint-v1\0";
const WITNESS_POLICY_DOMAIN_V1: &[u8] = b"veil-transparency-witness-policy-v1\0";
const ACCOUNT_REGISTRATION_DOMAIN_V1: &[u8] = b"veil-transparency-account-registration-v1\0";
const DEVICE_BINDING_DOMAIN_V1: &[u8] = b"veil-transparency-device-binding-v1\0";

pub const MAX_TRANSPARENCY_EVENT_BYTES_V1: usize = 4096;
pub const MAX_TRANSPARENCY_PROOF_NODES_V1: usize = 63;
pub const MAX_TRANSPARENCY_TREE_SIZE_V1: u64 = i64::MAX as u64;
pub const MAX_TRANSPARENCY_ORIGIN_BYTES_V1: usize = 2048;
pub const MAX_TRANSPARENCY_WITNESSES_V1: usize = 32;

pub type TransparencyHashV1 = [u8; 32];

fn sha256(parts: &[&[u8]]) -> TransparencyHashV1 {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

pub fn empty_root_v1() -> TransparencyHashV1 {
    sha256(&[EMPTY_DOMAIN_V1])
}

pub fn leaf_hash_v1(event: &[u8]) -> Result<TransparencyHashV1, String> {
    if event.is_empty() || event.len() > MAX_TRANSPARENCY_EVENT_BYTES_V1 {
        return Err("transparency event length is invalid".to_string());
    }
    let event_len = u32::try_from(event.len())
        .map_err(|_| "transparency event length is invalid".to_string())?
        .to_be_bytes();
    Ok(sha256(&[LEAF_DOMAIN_V1, &event_len, event]))
}

pub fn node_hash_v1(left: &TransparencyHashV1, right: &TransparencyHashV1) -> TransparencyHashV1 {
    sha256(&[NODE_DOMAIN_V1, left, right])
}

fn largest_power_of_two_less_than(value: usize) -> usize {
    debug_assert!(value > 1);
    let highest = 1usize << (usize::BITS - 1 - value.leading_zeros());
    if highest == value {
        highest >> 1
    } else {
        highest
    }
}

fn root_from_hashes(hashes: &[TransparencyHashV1]) -> TransparencyHashV1 {
    match hashes.len() {
        0 => empty_root_v1(),
        1 => hashes[0],
        len => {
            let split = largest_power_of_two_less_than(len);
            node_hash_v1(
                &root_from_hashes(&hashes[..split]),
                &root_from_hashes(&hashes[split..]),
            )
        }
    }
}

fn checked_leaf_hashes(events: &[Vec<u8>]) -> Result<Vec<TransparencyHashV1>, String> {
    if events.len() as u64 > MAX_TRANSPARENCY_TREE_SIZE_V1 {
        return Err("transparency tree size is invalid".to_string());
    }
    events.iter().map(|event| leaf_hash_v1(event)).collect()
}

pub fn tree_root_v1(events: &[Vec<u8>]) -> Result<TransparencyHashV1, String> {
    Ok(root_from_hashes(&checked_leaf_hashes(events)?))
}

fn inclusion_path_from_hashes(
    hashes: &[TransparencyHashV1],
    leaf_index: usize,
) -> Vec<TransparencyHashV1> {
    if hashes.len() == 1 {
        return Vec::new();
    }
    let split = largest_power_of_two_less_than(hashes.len());
    if leaf_index < split {
        let mut proof = inclusion_path_from_hashes(&hashes[..split], leaf_index);
        proof.push(root_from_hashes(&hashes[split..]));
        proof
    } else {
        let mut proof = inclusion_path_from_hashes(&hashes[split..], leaf_index - split);
        proof.push(root_from_hashes(&hashes[..split]));
        proof
    }
}

pub fn inclusion_proof_v1(
    events: &[Vec<u8>],
    leaf_index: usize,
) -> Result<Vec<TransparencyHashV1>, String> {
    if events.is_empty() || leaf_index >= events.len() {
        return Err("transparency inclusion coordinates are invalid".to_string());
    }
    let hashes = checked_leaf_hashes(events)?;
    let proof = inclusion_path_from_hashes(&hashes, leaf_index);
    if proof.len() > MAX_TRANSPARENCY_PROOF_NODES_V1 {
        return Err("transparency inclusion proof is oversized".to_string());
    }
    Ok(proof)
}

pub fn verify_inclusion_v1(
    event: &[u8],
    leaf_index: u64,
    tree_size: u64,
    proof: &[TransparencyHashV1],
    expected_root: &TransparencyHashV1,
) -> bool {
    if tree_size == 0
        || tree_size > MAX_TRANSPARENCY_TREE_SIZE_V1
        || leaf_index >= tree_size
        || proof.len() > MAX_TRANSPARENCY_PROOF_NODES_V1
    {
        return false;
    }
    let Ok(mut calculated) = leaf_hash_v1(event) else {
        return false;
    };
    let mut leaf = leaf_index;
    let mut last = tree_size - 1;
    for sibling in proof {
        if leaf & 1 == 1 || leaf == last {
            calculated = node_hash_v1(sibling, &calculated);
            while leaf != 0 && leaf & 1 == 0 {
                leaf >>= 1;
                last >>= 1;
            }
        } else {
            calculated = node_hash_v1(&calculated, sibling);
        }
        leaf >>= 1;
        last >>= 1;
    }
    last == 0 && calculated == *expected_root
}

fn consistency_path_from_hashes(
    hashes: &[TransparencyHashV1],
    old_size: usize,
    complete_subtree: bool,
) -> Vec<TransparencyHashV1> {
    if old_size == hashes.len() {
        return if complete_subtree {
            Vec::new()
        } else {
            vec![root_from_hashes(hashes)]
        };
    }
    let split = largest_power_of_two_less_than(hashes.len());
    if old_size <= split {
        let mut proof = consistency_path_from_hashes(&hashes[..split], old_size, complete_subtree);
        proof.push(root_from_hashes(&hashes[split..]));
        proof
    } else {
        let mut proof = consistency_path_from_hashes(&hashes[split..], old_size - split, false);
        proof.push(root_from_hashes(&hashes[..split]));
        proof
    }
}

pub fn consistency_proof_v1(
    events: &[Vec<u8>],
    old_size: usize,
) -> Result<Vec<TransparencyHashV1>, String> {
    if old_size == 0 || old_size > events.len() {
        return Err("transparency consistency coordinates are invalid".to_string());
    }
    if old_size == events.len() {
        return Ok(Vec::new());
    }
    let hashes = checked_leaf_hashes(events)?;
    let proof = consistency_path_from_hashes(&hashes, old_size, true);
    if proof.len() > MAX_TRANSPARENCY_PROOF_NODES_V1 {
        return Err("transparency consistency proof is oversized".to_string());
    }
    Ok(proof)
}

pub fn verify_consistency_v1(
    old_size: u64,
    new_size: u64,
    old_root: &TransparencyHashV1,
    new_root: &TransparencyHashV1,
    proof: &[TransparencyHashV1],
) -> bool {
    if old_size == 0
        || old_size > new_size
        || new_size > MAX_TRANSPARENCY_TREE_SIZE_V1
        || proof.len() > MAX_TRANSPARENCY_PROOF_NODES_V1
    {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }

    let mut old_cursor = old_size - 1;
    let mut new_cursor = new_size - 1;
    while old_cursor & 1 == 1 {
        old_cursor >>= 1;
        new_cursor >>= 1;
    }

    let (mut old_hash, mut new_hash, proof_tail) = if old_cursor == 0 {
        (*old_root, *old_root, proof)
    } else {
        let Some((first, tail)) = proof.split_first() else {
            return false;
        };
        (*first, *first, tail)
    };

    for sibling in proof_tail {
        if new_cursor == 0 {
            return false;
        }
        if old_cursor & 1 == 1 || old_cursor == new_cursor {
            old_hash = node_hash_v1(sibling, &old_hash);
            new_hash = node_hash_v1(sibling, &new_hash);
            while old_cursor != 0 && old_cursor & 1 == 0 {
                old_cursor >>= 1;
                new_cursor >>= 1;
            }
        } else {
            new_hash = node_hash_v1(&new_hash, sibling);
        }
        old_cursor >>= 1;
        new_cursor >>= 1;
    }

    new_cursor == 0 && old_hash == *old_root && new_hash == *new_root
}

fn validated_origin_bytes(canonical_origin: &str) -> Result<&[u8], String> {
    if canonical_origin.is_empty()
        || canonical_origin.len() > MAX_TRANSPARENCY_ORIGIN_BYTES_V1
        || canonical_origin.len() > u16::MAX as usize
        || !canonical_origin.is_ascii()
    {
        return Err("transparency canonical origin is invalid".to_string());
    }
    Ok(canonical_origin.as_bytes())
}

pub fn log_id_v1(
    canonical_origin: &str,
    node_signing_key: &[u8; 32],
) -> Result<TransparencyHashV1, String> {
    let origin = validated_origin_bytes(canonical_origin)?;
    if !crate::public_key::valid_ed25519_public_key(node_signing_key) {
        return Err("transparency Node signing key is invalid".to_string());
    }
    let origin_len = u16::try_from(origin.len())
        .map_err(|_| "transparency canonical origin is invalid".to_string())?
        .to_be_bytes();
    Ok(sha256(&[
        LOG_ID_DOMAIN_V1,
        &origin_len,
        origin,
        node_signing_key,
    ]))
}

pub fn account_registration_event_v1(
    canonical_origin: &str,
    account_id: &[u8; 16],
    identity_key: &[u8; 32],
    signing_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let origin = validated_origin_bytes(canonical_origin)?;
    if *account_id == [0u8; 16]
        || *identity_key == [0u8; 32]
        || !crate::public_key::valid_ed25519_public_key(signing_key)
    {
        return Err("transparency account registration is invalid".to_string());
    }
    let origin_len = u16::try_from(origin.len())
        .map_err(|_| "transparency canonical origin is invalid".to_string())?
        .to_be_bytes();
    let mut event =
        Vec::with_capacity(ACCOUNT_REGISTRATION_DOMAIN_V1.len() + 2 + origin.len() + 16 + 32 + 32);
    event.extend_from_slice(ACCOUNT_REGISTRATION_DOMAIN_V1);
    event.extend_from_slice(&origin_len);
    event.extend_from_slice(origin);
    event.extend_from_slice(account_id);
    event.extend_from_slice(identity_key);
    event.extend_from_slice(signing_key);
    Ok(event)
}

#[allow(clippy::too_many_arguments)]
pub fn device_binding_event_v1(
    canonical_origin: &str,
    account_id: &[u8; 16],
    device_key: &[u8; 16],
    device_identity_key: &[u8; 32],
    device_signing_key: &[u8; 32],
    version: u64,
    capabilities: u64,
    status: u8,
    account_signature: &[u8; 64],
    commitment: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let origin = validated_origin_bytes(canonical_origin)?;
    if *account_id == [0u8; 16]
        || *device_key == [0u8; 16]
        || *device_identity_key == [0u8; 32]
        || !crate::public_key::valid_ed25519_public_key(device_signing_key)
        || version == 0
        || version > MAX_TRANSPARENCY_TREE_SIZE_V1
        || capabilities > i64::MAX as u64
        || !(1..=3).contains(&status)
        || *account_signature == [0u8; 64]
        || *commitment == [0u8; 32]
    {
        return Err("transparency device binding is invalid".to_string());
    }
    let origin_len = u16::try_from(origin.len())
        .map_err(|_| "transparency canonical origin is invalid".to_string())?
        .to_be_bytes();
    let mut event = Vec::with_capacity(
        DEVICE_BINDING_DOMAIN_V1.len() + 2 + origin.len() + 16 + 16 + 32 + 32 + 8 + 8 + 1 + 64 + 32,
    );
    event.extend_from_slice(DEVICE_BINDING_DOMAIN_V1);
    event.extend_from_slice(&origin_len);
    event.extend_from_slice(origin);
    event.extend_from_slice(account_id);
    event.extend_from_slice(device_key);
    event.extend_from_slice(device_identity_key);
    event.extend_from_slice(device_signing_key);
    event.extend_from_slice(&version.to_be_bytes());
    event.extend_from_slice(&capabilities.to_be_bytes());
    event.push(status);
    event.extend_from_slice(account_signature);
    event.extend_from_slice(commitment);
    Ok(event)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransparencyTreeHeadV1 {
    pub log_id: [u8; 32],
    pub tree_size: u64,
    pub root_hash: TransparencyHashV1,
    pub issued_at_ms: u64,
}

impl TransparencyTreeHeadV1 {
    pub fn signing_message(&self, canonical_origin: &str) -> Result<Vec<u8>, String> {
        let origin = validated_origin_bytes(canonical_origin)?;
        if self.log_id == [0u8; 32]
            || self.tree_size > MAX_TRANSPARENCY_TREE_SIZE_V1
            || self.issued_at_ms == 0
            || (self.tree_size == 0 && self.root_hash != empty_root_v1())
        {
            return Err("transparency tree head is invalid".to_string());
        }
        let origin_len = u16::try_from(origin.len())
            .map_err(|_| "transparency canonical origin is invalid".to_string())?
            .to_be_bytes();
        let mut message =
            Vec::with_capacity(TREE_HEAD_DOMAIN_V1.len() + 2 + origin.len() + 32 + 8 + 32 + 8);
        message.extend_from_slice(TREE_HEAD_DOMAIN_V1);
        message.extend_from_slice(&origin_len);
        message.extend_from_slice(origin);
        message.extend_from_slice(&self.log_id);
        message.extend_from_slice(&self.tree_size.to_be_bytes());
        message.extend_from_slice(&self.root_hash);
        message.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        Ok(message)
    }

    pub fn verify_node_signature(
        &self,
        canonical_origin: &str,
        node_signing_key: &[u8; 32],
        signature: &[u8; 64],
    ) -> bool {
        self.signing_message(canonical_origin)
            .is_ok_and(|message| crate::signature::verify(node_signing_key, &message, signature))
    }
}

pub fn witness_checkpoint_message_v1(
    canonical_origin: &str,
    node_signing_key: &[u8; 32],
    head: &TransparencyTreeHeadV1,
    node_signature: &[u8; 64],
) -> Result<Vec<u8>, String> {
    let origin = validated_origin_bytes(canonical_origin)?;
    if log_id_v1(canonical_origin, node_signing_key)? != head.log_id
        || !head.verify_node_signature(canonical_origin, node_signing_key, node_signature)
    {
        return Err("transparency witness checkpoint is invalid".to_string());
    }
    let origin_len = u16::try_from(origin.len())
        .map_err(|_| "transparency canonical origin is invalid".to_string())?
        .to_be_bytes();
    let mut message = Vec::with_capacity(
        WITNESS_CHECKPOINT_DOMAIN_V1.len() + 2 + origin.len() + 32 + 32 + 8 + 32 + 8 + 64,
    );
    message.extend_from_slice(WITNESS_CHECKPOINT_DOMAIN_V1);
    message.extend_from_slice(&origin_len);
    message.extend_from_slice(origin);
    message.extend_from_slice(node_signing_key);
    message.extend_from_slice(&head.log_id);
    message.extend_from_slice(&head.tree_size.to_be_bytes());
    message.extend_from_slice(&head.root_hash);
    message.extend_from_slice(&head.issued_at_ms.to_be_bytes());
    message.extend_from_slice(node_signature);
    Ok(message)
}

pub fn witness_policy_hash_v1(
    threshold: u16,
    witness_signing_keys: &[[u8; 32]],
) -> Result<TransparencyHashV1, String> {
    if threshold == 0
        || usize::from(threshold) > witness_signing_keys.len()
        || witness_signing_keys.is_empty()
        || witness_signing_keys.len() > MAX_TRANSPARENCY_WITNESSES_V1
    {
        return Err("transparency witness policy is invalid".to_string());
    }
    let mut previous = None;
    for key in witness_signing_keys {
        if !crate::public_key::valid_ed25519_public_key(key)
            || previous.is_some_and(|prior: [u8; 32]| prior >= *key)
        {
            return Err("transparency witness policy is not canonical".to_string());
        }
        previous = Some(*key);
    }
    let threshold = threshold.to_be_bytes();
    let count = u16::try_from(witness_signing_keys.len())
        .map_err(|_| "transparency witness policy is oversized".to_string())?
        .to_be_bytes();
    let mut digest = Sha256::new();
    digest.update(WITNESS_POLICY_DOMAIN_V1);
    digest.update(threshold);
    digest.update(count);
    for key in witness_signing_keys {
        digest.update(key);
    }
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::Deserialize;

    const FIXTURE_BYTES: &[u8] = include_bytes!("../../test-vectors/transparency/v1.json");
    const REVIEWED_FIXTURE_SHA256: &str =
        "d450d353f4472d630e37c74e6ea692461c001a31a1ad31b612856ad3efebb3a1";

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        schema_version: u32,
        synthetic_only: bool,
        note: String,
        inputs: FixtureInputs,
        expected: FixtureExpected,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureInputs {
        canonical_origin: String,
        account_id_hex: String,
        account_identity_key_hex: String,
        account_signing_seed_hex: String,
        device_key_hex: String,
        device_identity_key_hex: String,
        device_signing_seed_hex: String,
        device_binding_version: u64,
        device_capabilities: u64,
        device_binding_status: u8,
        device_account_signature_hex: String,
        device_binding_commitment_hex: String,
        additional_event_hex: Vec<String>,
        inclusion_leaf_index: usize,
        consistency_old_size: usize,
        issued_at_ms: u64,
        witness_signing_seed_hex: Vec<String>,
        witness_threshold: u16,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureExpected {
        account_signing_key_hex: String,
        account_registration_event_hex: String,
        device_signing_key_hex: String,
        device_binding_event_hex: String,
        leaf_hash_hex: Vec<String>,
        tree_root_hex: Vec<String>,
        inclusion_proof_hex: Vec<String>,
        consistency_proof_hex: Vec<String>,
        log_id_hex: String,
        tree_head_signing_message_hex: String,
        tree_head_signature_hex: String,
        witness_checkpoint_message_hex: String,
        witness_signing_key_hex: Vec<String>,
        witness_signature_hex: Vec<String>,
        witness_policy_hash_hex: String,
    }

    fn fixture_bytes<const N: usize>(label: &str, encoded: &str) -> [u8; N] {
        let decoded = hex::decode(encoded).unwrap_or_else(|_| panic!("invalid {label} hex"));
        decoded
            .try_into()
            .unwrap_or_else(|_| panic!("invalid {label} length"))
    }

    fn fixture_hash(label: &str, encoded: &str) -> TransparencyHashV1 {
        fixture_bytes(label, encoded)
    }

    #[test]
    fn shared_go_rust_transparency_v1_vector_is_frozen() {
        assert!(FIXTURE_BYTES.len() <= 64 * 1024);
        assert_eq!(
            hex::encode(Sha256::digest(FIXTURE_BYTES)),
            REVIEWED_FIXTURE_SHA256
        );
        let fixture: Fixture = serde_json::from_slice(FIXTURE_BYTES).unwrap();
        assert_eq!(fixture.schema_version, 1);
        assert!(fixture.synthetic_only);
        assert!(!fixture.note.is_empty());

        let seed = fixture_bytes::<32>(
            "account signing seed",
            &fixture.inputs.account_signing_seed_hex,
        );
        let signing = SigningKey::from_bytes(&seed);
        assert_eq!(
            signing.verifying_key().to_bytes(),
            fixture_bytes::<32>(
                "account signing key",
                &fixture.expected.account_signing_key_hex
            ),
        );
        let account_id = fixture_bytes::<16>("account id", &fixture.inputs.account_id_hex);
        let identity_key = fixture_bytes::<32>(
            "account identity key",
            &fixture.inputs.account_identity_key_hex,
        );
        let event = account_registration_event_v1(
            &fixture.inputs.canonical_origin,
            &account_id,
            &identity_key,
            &signing.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(
            event,
            hex::decode(&fixture.expected.account_registration_event_hex).unwrap(),
        );

        let device_signing = SigningKey::from_bytes(&fixture_bytes::<32>(
            "device signing seed",
            &fixture.inputs.device_signing_seed_hex,
        ));
        assert_eq!(
            device_signing.verifying_key().to_bytes(),
            fixture_bytes::<32>(
                "device signing key",
                &fixture.expected.device_signing_key_hex,
            ),
        );
        let device_event = device_binding_event_v1(
            &fixture.inputs.canonical_origin,
            &account_id,
            &fixture_bytes::<16>("device key", &fixture.inputs.device_key_hex),
            &fixture_bytes::<32>(
                "device identity key",
                &fixture.inputs.device_identity_key_hex,
            ),
            &device_signing.verifying_key().to_bytes(),
            fixture.inputs.device_binding_version,
            fixture.inputs.device_capabilities,
            fixture.inputs.device_binding_status,
            &fixture_bytes::<64>(
                "device account signature",
                &fixture.inputs.device_account_signature_hex,
            ),
            &fixture_bytes::<32>(
                "device binding commitment",
                &fixture.inputs.device_binding_commitment_hex,
            ),
        )
        .unwrap();
        assert_eq!(
            device_event,
            hex::decode(&fixture.expected.device_binding_event_hex).unwrap(),
        );

        let mut events = vec![event];
        events.extend(
            fixture
                .inputs
                .additional_event_hex
                .iter()
                .map(|encoded| hex::decode(encoded).unwrap()),
        );
        assert_eq!(fixture.expected.leaf_hash_hex.len(), events.len());
        assert_eq!(fixture.expected.tree_root_hex.len(), events.len() + 1);
        for (index, item) in events.iter().enumerate() {
            assert_eq!(
                leaf_hash_v1(item).unwrap(),
                fixture_hash(
                    &format!("leaf hash {index}"),
                    &fixture.expected.leaf_hash_hex[index],
                ),
            );
        }
        for size in 0..=events.len() {
            assert_eq!(
                tree_root_v1(&events[..size]).unwrap(),
                fixture_hash(
                    &format!("tree root {size}"),
                    &fixture.expected.tree_root_hex[size],
                ),
            );
        }

        let inclusion = inclusion_proof_v1(&events, fixture.inputs.inclusion_leaf_index).unwrap();
        assert_eq!(inclusion.len(), fixture.expected.inclusion_proof_hex.len());
        for (index, item) in inclusion.iter().enumerate() {
            assert_eq!(
                *item,
                fixture_hash(
                    &format!("inclusion proof {index}"),
                    &fixture.expected.inclusion_proof_hex[index],
                ),
            );
        }
        let consistency =
            consistency_proof_v1(&events, fixture.inputs.consistency_old_size).unwrap();
        assert_eq!(
            consistency.len(),
            fixture.expected.consistency_proof_hex.len()
        );
        for (index, item) in consistency.iter().enumerate() {
            assert_eq!(
                *item,
                fixture_hash(
                    &format!("consistency proof {index}"),
                    &fixture.expected.consistency_proof_hex[index],
                ),
            );
        }

        let root = tree_root_v1(&events).unwrap();
        let expected_log_id = fixture_hash("log id", &fixture.expected.log_id_hex);
        assert_eq!(
            log_id_v1(
                &fixture.inputs.canonical_origin,
                &signing.verifying_key().to_bytes(),
            )
            .unwrap(),
            expected_log_id,
        );
        let head = TransparencyTreeHeadV1 {
            log_id: expected_log_id,
            tree_size: events.len() as u64,
            root_hash: root,
            issued_at_ms: fixture.inputs.issued_at_ms,
        };
        let message = head
            .signing_message(&fixture.inputs.canonical_origin)
            .unwrap();
        assert_eq!(
            message,
            hex::decode(&fixture.expected.tree_head_signing_message_hex).unwrap(),
        );
        let signature = signing.sign(&message).to_bytes();
        assert_eq!(
            signature,
            fixture_bytes::<64>(
                "tree-head signature",
                &fixture.expected.tree_head_signature_hex
            ),
        );
        assert!(head.verify_node_signature(
            &fixture.inputs.canonical_origin,
            &signing.verifying_key().to_bytes(),
            &signature,
        ));

        let checkpoint = witness_checkpoint_message_v1(
            &fixture.inputs.canonical_origin,
            &signing.verifying_key().to_bytes(),
            &head,
            &signature,
        )
        .unwrap();
        assert_eq!(
            checkpoint,
            hex::decode(&fixture.expected.witness_checkpoint_message_hex).unwrap()
        );
        let mut witnesses = fixture
            .inputs
            .witness_signing_seed_hex
            .iter()
            .map(|encoded| {
                let signing =
                    SigningKey::from_bytes(&fixture_bytes::<32>("witness signing seed", encoded));
                (signing.verifying_key().to_bytes(), signing)
            })
            .collect::<Vec<_>>();
        witnesses.sort_unstable_by_key(|(key, _)| *key);
        assert_eq!(
            witnesses.len(),
            fixture.expected.witness_signing_key_hex.len()
        );
        assert_eq!(
            witnesses.len(),
            fixture.expected.witness_signature_hex.len()
        );
        for (index, (key, witness)) in witnesses.iter().enumerate() {
            assert_eq!(
                *key,
                fixture_bytes::<32>(
                    "witness signing key",
                    &fixture.expected.witness_signing_key_hex[index],
                )
            );
            assert_eq!(
                witness.sign(&checkpoint).to_bytes(),
                fixture_bytes::<64>(
                    "witness signature",
                    &fixture.expected.witness_signature_hex[index],
                )
            );
        }
        let witness_keys = witnesses.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        assert_eq!(
            witness_policy_hash_v1(fixture.inputs.witness_threshold, &witness_keys).unwrap(),
            fixture_hash(
                "witness policy hash",
                &fixture.expected.witness_policy_hash_hex,
            )
        );
    }

    fn events(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| format!("canonical-event-{index:04}").into_bytes())
            .collect()
    }

    #[test]
    fn inclusion_and_consistency_are_exhaustive_for_small_unbalanced_trees() {
        let all = events(80);
        for size in 1..=all.len() {
            let current = &all[..size];
            let root = tree_root_v1(current).unwrap();
            for index in 0..size {
                let proof = inclusion_proof_v1(current, index).unwrap();
                assert!(
                    verify_inclusion_v1(&current[index], index as u64, size as u64, &proof, &root,),
                    "inclusion failed for index {index}, size {size}, proof {}",
                    proof.len(),
                );
                let mut forged = proof.clone();
                if let Some(first) = forged.first_mut() {
                    first[0] ^= 1;
                    assert!(!verify_inclusion_v1(
                        &current[index],
                        index as u64,
                        size as u64,
                        &forged,
                        &root,
                    ));
                }
            }

            for old_size in 1..=size {
                let old_root = tree_root_v1(&current[..old_size]).unwrap();
                let proof = consistency_proof_v1(current, old_size).unwrap();
                assert!(verify_consistency_v1(
                    old_size as u64,
                    size as u64,
                    &old_root,
                    &root,
                    &proof,
                ));
                if old_size != size {
                    let mut wrong_root = old_root;
                    wrong_root[0] ^= 1;
                    assert!(!verify_consistency_v1(
                        old_size as u64,
                        size as u64,
                        &wrong_root,
                        &root,
                        &proof,
                    ));
                }
            }
        }
    }

    #[test]
    fn proof_bounds_and_coordinates_fail_closed() {
        let current = events(3);
        let root = tree_root_v1(&current).unwrap();
        assert!(inclusion_proof_v1(&current, 3).is_err());
        assert!(consistency_proof_v1(&current, 0).is_err());
        assert!(!verify_inclusion_v1(&current[0], 3, 3, &[], &root));
        assert!(!verify_consistency_v1(4, 3, &root, &root, &[]));
        assert!(!verify_consistency_v1(3, 3, &root, &root, &[[0u8; 32]]));
        assert!(leaf_hash_v1(&[]).is_err());
        assert!(leaf_hash_v1(&vec![0u8; MAX_TRANSPARENCY_EVENT_BYTES_V1 + 1]).is_err());
    }
}
