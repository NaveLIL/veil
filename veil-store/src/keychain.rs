use keyring::Entry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::db::IdentityTransparencyPinnedHeadV1;

const SERVICE_NAME: &str = "veil-messenger";
const TRANSPARENCY_SERVICE_NAME: &str = "veil-messenger-transparency-v1";
const MLS_ROLLBACK_SERVICE_NAME: &str = "veil-messenger-mls-rollback-v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsRollbackAnchorWireV1 {
    version: u8,
    leaf_hash: String,
    generation: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityTransparencyAnchorWireV1 {
    version: u8,
    canonical_server_origin: String,
    log_id: String,
    node_signing_key: String,
    tree_size: String,
    root_hash: String,
    issued_at_ms: String,
    tree_head_signature: String,
    witness_policy_hash: String,
    witness_quorum: u32,
}

fn transparency_anchor_account_v1(canonical_server_origin: &str) -> Result<String, String> {
    if canonical_server_origin.is_empty()
        || canonical_server_origin.len() > 2048
        || !canonical_server_origin.is_ascii()
    {
        return Err("identity transparency rollback-anchor origin is invalid".to_string());
    }
    Ok(format!(
        "origin-{}",
        hex::encode(Sha256::digest(canonical_server_origin.as_bytes()))
    ))
}

fn parse_exact_decimal_v1(label: &str, encoded: &str) -> Result<u64, String> {
    let value = encoded
        .parse::<u64>()
        .map_err(|_| format!("{label} is not a valid unsigned decimal"))?;
    if value.to_string() != encoded {
        return Err(format!("{label} is not canonical unsigned decimal"));
    }
    Ok(value)
}

fn parse_exact_hex_v1<const N: usize>(label: &str, encoded: &str) -> Result<[u8; N], String> {
    if encoded.len() != N * 2 {
        return Err(format!("{label} has an invalid length"));
    }
    let decoded = hex::decode(encoded).map_err(|_| format!("{label} is not valid hex"))?;
    if hex::encode(&decoded) != encoded {
        return Err(format!("{label} is not canonical lowercase hex"));
    }
    decoded
        .try_into()
        .map_err(|_| format!("{label} has an invalid length"))
}

fn mls_rollback_anchor_account_v1(leaf: &[u8]) -> Result<String, String> {
    if leaf.len() != 32 {
        return Err("MLS rollback-anchor leaf must be exactly 32 bytes".to_string());
    }
    Ok(format!("leaf-{}", hex::encode(Sha256::digest(leaf))))
}

fn encode_mls_rollback_anchor_v1(leaf: &[u8], generation: u64) -> Result<String, String> {
    mls_rollback_anchor_account_v1(leaf)?;
    if generation > i64::MAX as u64 {
        return Err("MLS rollback-anchor generation exceeds SQLite range".to_string());
    }
    serde_json::to_string(&MlsRollbackAnchorWireV1 {
        version: 1,
        leaf_hash: hex::encode(Sha256::digest(leaf)),
        generation: generation.to_string(),
    })
    .map_err(|error| format!("encode MLS rollback anchor: {error}"))
}

fn decode_mls_rollback_anchor_v1(leaf: &[u8], encoded: &str) -> Result<u64, String> {
    mls_rollback_anchor_account_v1(leaf)?;
    let wire: MlsRollbackAnchorWireV1 = serde_json::from_str(encoded)
        .map_err(|error| format!("decode MLS rollback anchor: {error}"))?;
    if wire.version != 1
        || wire.leaf_hash != hex::encode(Sha256::digest(leaf))
        || wire.leaf_hash.len() != 64
    {
        return Err("MLS rollback-anchor scope is invalid".to_string());
    }
    let generation = parse_exact_decimal_v1("MLS rollback-anchor generation", &wire.generation)?;
    if generation > i64::MAX as u64 {
        return Err("MLS rollback-anchor generation exceeds SQLite range".to_string());
    }
    Ok(generation)
}

/// Load one monotonic MLS generation kept outside the replaceable SQLCipher
/// database. Only a genuinely absent credential maps to `None`; keychain
/// availability and malformed values fail closed.
pub fn get_mls_rollback_anchor_v1(leaf: &[u8]) -> Result<Option<u64>, String> {
    let account = mls_rollback_anchor_account_v1(leaf)?;
    let entry = Entry::new(MLS_ROLLBACK_SERVICE_NAME, &account)
        .map_err(|error| format!("MLS rollback-anchor keychain entry: {error}"))?;
    match entry.get_password() {
        Ok(mut encoded) => {
            let decoded = decode_mls_rollback_anchor_v1(leaf, &encoded);
            encoded.zeroize();
            decoded.map(Some)
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!("MLS rollback-anchor keychain access: {error}")),
    }
}

/// Create or monotonically advance the external MLS generation anchor.
/// Decrease attempts never overwrite stronger evidence.
pub fn store_mls_rollback_anchor_v1(leaf: &[u8], generation: u64) -> Result<(), String> {
    if let Some(existing) = get_mls_rollback_anchor_v1(leaf)? {
        if generation < existing {
            return Err("MLS rollback-anchor decrease rejected".to_string());
        }
        if generation == existing {
            return Ok(());
        }
    }
    let account = mls_rollback_anchor_account_v1(leaf)?;
    let entry = Entry::new(MLS_ROLLBACK_SERVICE_NAME, &account)
        .map_err(|error| format!("MLS rollback-anchor keychain entry: {error}"))?;
    let mut encoded = encode_mls_rollback_anchor_v1(leaf, generation)?;
    let result = entry
        .set_password(&encoded)
        .map_err(|error| format!("store MLS rollback anchor: {error}"));
    encoded.zeroize();
    result
}

fn validate_transparency_anchor_v1(
    anchor: &IdentityTransparencyPinnedHeadV1,
) -> Result<(), String> {
    use veil_crypto::transparency::{
        log_id_v1, TransparencyTreeHeadV1, MAX_TRANSPARENCY_TREE_SIZE_V1,
    };

    transparency_anchor_account_v1(&anchor.canonical_server_origin)?;
    if anchor.tree_size == 0
        || anchor.tree_size > MAX_TRANSPARENCY_TREE_SIZE_V1
        || anchor.issued_at_ms == 0
        || anchor.issued_at_ms > i64::MAX as u64
        || anchor.witness_quorum > 32
        || (anchor.witness_policy_hash == [0u8; 32]) != (anchor.witness_quorum == 0)
        || log_id_v1(&anchor.canonical_server_origin, &anchor.node_signing_key)? != anchor.log_id
    {
        return Err("identity transparency rollback anchor is invalid".to_string());
    }
    let head = TransparencyTreeHeadV1 {
        log_id: anchor.log_id,
        tree_size: anchor.tree_size,
        root_hash: anchor.root_hash,
        issued_at_ms: anchor.issued_at_ms,
    };
    if !head.verify_node_signature(
        &anchor.canonical_server_origin,
        &anchor.node_signing_key,
        &anchor.tree_head_signature,
    ) {
        return Err("identity transparency rollback anchor signature is invalid".to_string());
    }
    Ok(())
}

fn decode_transparency_anchor_v1(
    expected_origin: &str,
    encoded: &str,
) -> Result<IdentityTransparencyPinnedHeadV1, String> {
    let wire: IdentityTransparencyAnchorWireV1 = serde_json::from_str(encoded)
        .map_err(|error| format!("decode identity transparency rollback anchor: {error}"))?;
    if wire.version != 1 || wire.canonical_server_origin != expected_origin {
        return Err("identity transparency rollback anchor scope is invalid".to_string());
    }
    let anchor = IdentityTransparencyPinnedHeadV1 {
        canonical_server_origin: wire.canonical_server_origin,
        log_id: parse_exact_hex_v1("identity transparency anchor log id", &wire.log_id)?,
        node_signing_key: parse_exact_hex_v1(
            "identity transparency anchor Node key",
            &wire.node_signing_key,
        )?,
        tree_size: parse_exact_decimal_v1(
            "identity transparency anchor tree size",
            &wire.tree_size,
        )?,
        root_hash: parse_exact_hex_v1("identity transparency anchor root hash", &wire.root_hash)?,
        issued_at_ms: parse_exact_decimal_v1(
            "identity transparency anchor issue time",
            &wire.issued_at_ms,
        )?,
        tree_head_signature: parse_exact_hex_v1(
            "identity transparency anchor signature",
            &wire.tree_head_signature,
        )?,
        witness_policy_hash: parse_exact_hex_v1(
            "identity transparency anchor witness policy",
            &wire.witness_policy_hash,
        )?,
        witness_quorum: wire.witness_quorum,
    };
    validate_transparency_anchor_v1(&anchor)?;
    Ok(anchor)
}

fn encode_transparency_anchor_v1(
    anchor: &IdentityTransparencyPinnedHeadV1,
) -> Result<String, String> {
    validate_transparency_anchor_v1(anchor)?;
    serde_json::to_string(&IdentityTransparencyAnchorWireV1 {
        version: 1,
        canonical_server_origin: anchor.canonical_server_origin.clone(),
        log_id: hex::encode(anchor.log_id),
        node_signing_key: hex::encode(anchor.node_signing_key),
        tree_size: anchor.tree_size.to_string(),
        root_hash: hex::encode(anchor.root_hash),
        issued_at_ms: anchor.issued_at_ms.to_string(),
        tree_head_signature: hex::encode(anchor.tree_head_signature),
        witness_policy_hash: hex::encode(anchor.witness_policy_hash),
        witness_quorum: anchor.witness_quorum,
    })
    .map_err(|error| format!("encode identity transparency rollback anchor: {error}"))
}

/// Load the monotonic transparency head kept outside SQLCipher. Only a truly
/// absent credential maps to `None`; a locked/unavailable keychain or malformed
/// anchor fails closed so database rollback cannot masquerade as first contact.
pub fn get_identity_transparency_rollback_anchor_v1(
    canonical_server_origin: &str,
) -> Result<Option<IdentityTransparencyPinnedHeadV1>, String> {
    let account = transparency_anchor_account_v1(canonical_server_origin)?;
    let entry = Entry::new(TRANSPARENCY_SERVICE_NAME, &account)
        .map_err(|error| format!("identity transparency keychain entry: {error}"))?;
    match entry.get_password() {
        Ok(mut encoded) => {
            let decoded = decode_transparency_anchor_v1(canonical_server_origin, &encoded);
            encoded.zeroize();
            decoded.map(Some)
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!(
            "identity transparency rollback-anchor keychain access: {error}"
        )),
    }
}

/// Advance the OS-secure transparency anchor after the exact head has already
/// passed signature, inclusion and append-only verification. Replacement,
/// rollback and same-size split attempts never overwrite stronger evidence.
pub fn store_identity_transparency_rollback_anchor_v1(
    candidate: &IdentityTransparencyPinnedHeadV1,
) -> Result<(), String> {
    validate_transparency_anchor_v1(candidate)?;
    let mut stored_candidate = candidate.clone();
    if let Some(existing) =
        get_identity_transparency_rollback_anchor_v1(&candidate.canonical_server_origin)?
    {
        if existing.log_id != candidate.log_id
            || existing.node_signing_key != candidate.node_signing_key
        {
            return Err("identity transparency rollback-anchor replacement rejected".to_string());
        }
        if candidate.tree_size < existing.tree_size {
            return Err("identity transparency rollback-anchor decrease rejected".to_string());
        }
        if existing.witness_policy_hash != [0u8; 32]
            && candidate.witness_policy_hash != existing.witness_policy_hash
        {
            return Err("identity transparency rollback-anchor witness policy changed".to_string());
        }
        if candidate.tree_size == existing.tree_size {
            if candidate.root_hash != existing.root_hash {
                return Err("identity transparency rollback-anchor split view rejected".to_string());
            }
            if candidate.issued_at_ms <= existing.issued_at_ms
                && candidate.witness_quorum <= existing.witness_quorum
            {
                return Ok(());
            }
            stored_candidate.witness_quorum = candidate.witness_quorum.max(existing.witness_quorum);
            if stored_candidate.witness_policy_hash == [0u8; 32] {
                stored_candidate.witness_policy_hash = existing.witness_policy_hash;
            }
        }
    }
    let account = transparency_anchor_account_v1(&candidate.canonical_server_origin)?;
    let entry = Entry::new(TRANSPARENCY_SERVICE_NAME, &account)
        .map_err(|error| format!("identity transparency keychain entry: {error}"))?;
    let mut encoded = encode_transparency_anchor_v1(&stored_candidate)?;
    let result = entry
        .set_password(&encoded)
        .map_err(|error| format!("store identity transparency rollback anchor: {error}"));
    encoded.zeroize();
    result
}

/// Store the user's seed phrase securely in the OS keychain.
pub fn store_seed(account: &str, seed: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, account).map_err(|e| format!("keychain entry: {e}"))?;
    entry
        .set_password(seed)
        .map_err(|e| format!("keychain store: {e}"))
}

/// Retrieve the user's seed phrase from the OS keychain.
pub fn get_seed(account: &str) -> Result<String, String> {
    let entry = Entry::new(SERVICE_NAME, account).map_err(|e| format!("keychain entry: {e}"))?;
    entry
        .get_password()
        .map_err(|e| format!("keychain get: {e}"))
}

/// Retrieve an optional credential from the OS keychain.
///
/// Only a genuinely missing entry maps to `None`. Backend, permission and
/// availability failures remain explicit so callers cannot silently replace a
/// persisted security policy with a fallback value.
pub fn get_optional_seed(account: &str) -> Result<Option<String>, String> {
    let entry = Entry::new(SERVICE_NAME, account).map_err(|e| format!("keychain entry: {e}"))?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!("keychain get: {error}")),
    }
}

/// Delete the user's seed from the OS keychain.
pub fn delete_seed(account: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, account).map_err(|e| format!("keychain entry: {e}"))?;
    entry
        .delete_credential()
        .map_err(|e| format!("keychain delete: {e}"))
}

/// Check if a credential exists without treating secure-storage failures as
/// absence. Callers use this for lock decisions, so only `NoEntry` may map to
/// `false`; a locked or unavailable OS credential store must fail closed.
pub fn has_seed(account: &str) -> Result<bool, String> {
    let entry = Entry::new(SERVICE_NAME, account).map_err(|e| format!("keychain entry: {e}"))?;
    match entry.get_password() {
        Ok(mut value) => {
            value.zeroize();
            Ok(true)
        }
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(error) => Err(format!("keychain access: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use veil_crypto::transparency::{log_id_v1, TransparencyTreeHeadV1};

    const ORIGIN: &str = "https://anchor.example.test:443";

    fn signed_anchor() -> IdentityTransparencyPinnedHeadV1 {
        let signing = SigningKey::from_bytes(&[0x71; 32]);
        let node_signing_key = signing.verifying_key().to_bytes();
        let head = TransparencyTreeHeadV1 {
            log_id: log_id_v1(ORIGIN, &node_signing_key).unwrap(),
            tree_size: 7,
            root_hash: [0x72; 32],
            issued_at_ms: 1_800_000_000_000,
        };
        IdentityTransparencyPinnedHeadV1 {
            canonical_server_origin: ORIGIN.to_string(),
            log_id: head.log_id,
            node_signing_key,
            tree_size: head.tree_size,
            root_hash: head.root_hash,
            issued_at_ms: head.issued_at_ms,
            tree_head_signature: signing
                .sign(&head.signing_message(ORIGIN).unwrap())
                .to_bytes(),
            witness_policy_hash: [0u8; 32],
            witness_quorum: 0,
        }
    }

    #[test]
    fn transparency_rollback_anchor_codec_is_canonical_and_signature_bound() {
        let anchor = signed_anchor();
        let encoded = encode_transparency_anchor_v1(&anchor).unwrap();
        let decoded = decode_transparency_anchor_v1(ORIGIN, &encoded).unwrap();
        assert_eq!(
            decoded.canonical_server_origin,
            anchor.canonical_server_origin
        );
        assert_eq!(decoded.log_id, anchor.log_id);
        assert_eq!(decoded.tree_size, anchor.tree_size);
        assert_eq!(decoded.root_hash, anchor.root_hash);
        assert_eq!(decoded.tree_head_signature, anchor.tree_head_signature);

        let mut unknown: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(decode_transparency_anchor_v1(ORIGIN, &unknown.to_string()).is_err());
        let mut noncanonical: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        noncanonical["tree_size"] = serde_json::json!("07");
        assert!(decode_transparency_anchor_v1(ORIGIN, &noncanonical.to_string()).is_err());
        assert!(decode_transparency_anchor_v1("https://other.example.test:443", &encoded).is_err());

        let mut forged = anchor;
        forged.root_hash[0] ^= 1;
        assert!(validate_transparency_anchor_v1(&forged).is_err());
    }

    #[test]
    fn mls_rollback_anchor_codec_is_canonical_and_leaf_bound() {
        let leaf = [0x81; 32];
        let encoded = encode_mls_rollback_anchor_v1(&leaf, 17).unwrap();
        assert_eq!(decode_mls_rollback_anchor_v1(&leaf, &encoded).unwrap(), 17);
        assert!(decode_mls_rollback_anchor_v1(&[0x82; 32], &encoded).is_err());

        let mut unknown: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(decode_mls_rollback_anchor_v1(&leaf, &unknown.to_string()).is_err());

        let mut noncanonical: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        noncanonical["generation"] = serde_json::json!("017");
        assert!(decode_mls_rollback_anchor_v1(&leaf, &noncanonical.to_string()).is_err());
        assert!(encode_mls_rollback_anchor_v1(&leaf[..31], 0).is_err());
        assert!(encode_mls_rollback_anchor_v1(&leaf, i64::MAX as u64 + 1).is_err());
    }
}
