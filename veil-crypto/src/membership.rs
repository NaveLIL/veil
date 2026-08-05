//! Client-authorized membership epochs for encrypted group conversations.
//!
//! A membership epoch does not trust a Node-computed ACL as authorization to
//! reveal fresh Sender-Key/MLS material. The exact roster and successor policy
//! are committed by a predecessor-linked hash, then signed by the previous
//! epoch's account-key policy. Server persistence, transparency resolution,
//! local pinning, and product mutation orchestration live in higher layers.

use sha2::{Digest, Sha256};
use std::collections::HashSet;

const EPOCH_DOMAIN_V1: &[u8] = b"veil-membership-epoch-v1\0";
const SIGNATURE_DOMAIN_V1: &[u8] = b"veil-membership-epoch-signature-v1\0";

pub const MAX_MEMBERSHIP_ORIGIN_BYTES_V1: usize = 2048;
pub const MAX_MEMBERSHIP_POLICY_SIGNERS_V1: usize = 1024;
pub const MEMBERSHIP_CONVERSATION_KIND_GROUP_V1: u8 = 1;
pub const MEMBERSHIP_CONVERSATION_KIND_CHANNEL_V1: u8 = 2;
pub const MEMBERSHIP_CRYPTO_PROFILE_SENDER_KEY_V6: u8 = 1;
pub const MEMBERSHIP_CRYPTO_ERA_V1: u16 = 1;

pub type MembershipEpochHashV1 = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipPolicySignerV1 {
    pub account_id: [u8; 16],
    pub account_signing_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipPolicyV1 {
    pub threshold: u16,
    /// Canonical ascending account-id order. Every id and Ed25519 key is
    /// unique, so one account cannot contribute multiple threshold votes.
    pub signers: Vec<MembershipPolicySignerV1>,
}

impl MembershipPolicyV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.signers.is_empty()
            || self.signers.len() > MAX_MEMBERSHIP_POLICY_SIGNERS_V1
            || usize::from(self.threshold) == 0
            || usize::from(self.threshold) > self.signers.len()
        {
            return Err("membership authorization policy is invalid".to_string());
        }
        let mut prior_account = None;
        let mut signing_keys = HashSet::with_capacity(self.signers.len());
        for signer in &self.signers {
            if signer.account_id == [0u8; 16]
                || prior_account.is_some_and(|prior| prior >= signer.account_id)
                || !crate::public_key::valid_ed25519_public_key(&signer.account_signing_key)
                || !signing_keys.insert(signer.account_signing_key)
            {
                return Err("membership authorization policy is not canonical".to_string());
            }
            prior_account = Some(signer.account_id);
        }
        Ok(())
    }

    fn signer(&self, account_id: &[u8; 16]) -> Option<&MembershipPolicySignerV1> {
        self.signers
            .binary_search_by_key(account_id, |signer| signer.account_id)
            .ok()
            .map(|index| &self.signers[index])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipEpochV1 {
    pub canonical_origin: String,
    pub conversation_id: [u8; 16],
    pub conversation_kind: u8,
    pub epoch: u64,
    pub predecessor_hash: MembershipEpochHashV1,
    pub roster_version: u64,
    pub roster_commitment: [u8; 32],
    /// Policy which authorizes the next epoch. The current epoch itself is
    /// authorized by the preceding policy (or the exact owner at bootstrap).
    pub successor_policy: MembershipPolicyV1,
    pub crypto_profile: u8,
    pub crypto_era: u16,
    pub mutation_nonce: [u8; 32],
}

impl MembershipEpochV1 {
    pub fn validate(&self) -> Result<(), String> {
        let origin = self.canonical_origin.as_bytes();
        if origin.is_empty()
            || origin.len() > MAX_MEMBERSHIP_ORIGIN_BYTES_V1
            || origin.len() > u16::MAX as usize
            || !self.canonical_origin.is_ascii()
            || self.conversation_id == [0u8; 16]
            || !matches!(
                self.conversation_kind,
                MEMBERSHIP_CONVERSATION_KIND_GROUP_V1 | MEMBERSHIP_CONVERSATION_KIND_CHANNEL_V1
            )
            || self.epoch == 0
            || self.epoch > i64::MAX as u64
            || (self.epoch == 1) != (self.predecessor_hash == [0u8; 32])
            || self.roster_version == 0
            || self.roster_version > i64::MAX as u64
            || self.roster_commitment == [0u8; 32]
            || self.crypto_profile != MEMBERSHIP_CRYPTO_PROFILE_SENDER_KEY_V6
            || self.crypto_era != MEMBERSHIP_CRYPTO_ERA_V1
            || self.mutation_nonce == [0u8; 32]
        {
            return Err("membership epoch coordinates are invalid".to_string());
        }
        self.successor_policy.validate()
    }

    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let origin = self.canonical_origin.as_bytes();
        let origin_len = u16::try_from(origin.len())
            .map_err(|_| "membership origin length is invalid".to_string())?;
        let signer_count = u16::try_from(self.successor_policy.signers.len())
            .map_err(|_| "membership policy signer count is invalid".to_string())?;
        let mut encoded = Vec::with_capacity(
            EPOCH_DOMAIN_V1.len()
                + 2
                + origin.len()
                + 16
                + 1
                + 8
                + 32
                + 8
                + 32
                + 2
                + 2
                + self.successor_policy.signers.len() * 48
                + 1
                + 2
                + 32,
        );
        encoded.extend_from_slice(EPOCH_DOMAIN_V1);
        encoded.extend_from_slice(&origin_len.to_be_bytes());
        encoded.extend_from_slice(origin);
        encoded.extend_from_slice(&self.conversation_id);
        encoded.push(self.conversation_kind);
        encoded.extend_from_slice(&self.epoch.to_be_bytes());
        encoded.extend_from_slice(&self.predecessor_hash);
        encoded.extend_from_slice(&self.roster_version.to_be_bytes());
        encoded.extend_from_slice(&self.roster_commitment);
        encoded.extend_from_slice(&self.successor_policy.threshold.to_be_bytes());
        encoded.extend_from_slice(&signer_count.to_be_bytes());
        for signer in &self.successor_policy.signers {
            encoded.extend_from_slice(&signer.account_id);
            encoded.extend_from_slice(&signer.account_signing_key);
        }
        encoded.push(self.crypto_profile);
        encoded.extend_from_slice(&self.crypto_era.to_be_bytes());
        encoded.extend_from_slice(&self.mutation_nonce);
        Ok(encoded)
    }

    pub fn hash(&self) -> Result<MembershipEpochHashV1, String> {
        Ok(Sha256::digest(self.canonical_unsigned_bytes()?).into())
    }

    pub fn signature_message(&self) -> Result<Vec<u8>, String> {
        let hash = self.hash()?;
        let mut message = Vec::with_capacity(SIGNATURE_DOMAIN_V1.len() + hash.len());
        message.extend_from_slice(SIGNATURE_DOMAIN_V1);
        message.extend_from_slice(&hash);
        Ok(message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipEpochSignatureV1 {
    pub signer_account_id: [u8; 16],
    pub signature: [u8; 64],
}

fn validate_signature_order(signatures: &[MembershipEpochSignatureV1]) -> Result<(), String> {
    let mut prior = None;
    for signature in signatures {
        if signature.signer_account_id == [0u8; 16]
            || signature.signature == [0u8; 64]
            || prior.is_some_and(|previous| previous >= signature.signer_account_id)
        {
            return Err("membership epoch signatures are not canonical".to_string());
        }
        prior = Some(signature.signer_account_id);
    }
    Ok(())
}

pub fn verify_membership_epoch_bootstrap_v1(
    epoch: &MembershipEpochV1,
    expected_owner: &MembershipPolicySignerV1,
    signatures: &[MembershipEpochSignatureV1],
) -> Result<(), String> {
    epoch.validate()?;
    if epoch.epoch != 1
        || expected_owner.account_id == [0u8; 16]
        || !crate::public_key::valid_ed25519_public_key(&expected_owner.account_signing_key)
        || signatures.len() != 1
        || signatures[0].signer_account_id != expected_owner.account_id
    {
        return Err("membership epoch bootstrap authority is invalid".to_string());
    }
    validate_signature_order(signatures)?;
    let message = epoch.signature_message()?;
    if !crate::signature::verify(
        &expected_owner.account_signing_key,
        &message,
        &signatures[0].signature,
    ) {
        return Err("membership epoch bootstrap signature is invalid".to_string());
    }
    Ok(())
}

pub fn verify_membership_epoch_transition_v1(
    predecessor: &MembershipEpochV1,
    successor: &MembershipEpochV1,
    signatures: &[MembershipEpochSignatureV1],
) -> Result<(), String> {
    predecessor.validate()?;
    successor.validate()?;
    let expected_epoch = predecessor
        .epoch
        .checked_add(1)
        .ok_or("membership epoch number is exhausted")?;
    if successor.canonical_origin != predecessor.canonical_origin
        || successor.conversation_id != predecessor.conversation_id
        || successor.conversation_kind != predecessor.conversation_kind
        || successor.epoch != expected_epoch
        || successor.predecessor_hash != predecessor.hash()?
        || successor.roster_version < predecessor.roster_version
        || (successor.roster_version == predecessor.roster_version
            && successor.roster_commitment != predecessor.roster_commitment)
    {
        return Err("membership epoch does not exactly extend its predecessor".to_string());
    }
    if signatures.len() < usize::from(predecessor.successor_policy.threshold)
        || signatures.len() > predecessor.successor_policy.signers.len()
    {
        return Err("membership epoch signature threshold is not satisfied".to_string());
    }
    validate_signature_order(signatures)?;
    let message = successor.signature_message()?;
    for signature in signatures {
        let signer = predecessor
            .successor_policy
            .signer(&signature.signer_account_id)
            .ok_or("membership epoch signature is outside the predecessor policy")?;
        if !crate::signature::verify(&signer.account_signing_key, &message, &signature.signature) {
            return Err("membership epoch transition signature is invalid".to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::Deserialize;

    const FIXTURE_BYTES: &[u8] = include_bytes!("../../test-vectors/membership/v1.json");
    const REVIEWED_FIXTURE_SHA256: &str =
        "3f51612291ab9ddfe353292b04fe8088087312dd495eec67e68909bfcf551ece";

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureSigner {
        account_id: String,
        account_signing_key: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureSignature {
        signer_account_id: String,
        signature: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureEpoch {
        number: String,
        predecessor_hash: String,
        roster_version: String,
        roster_commitment: String,
        policy_threshold: u16,
        policy_signers: Vec<FixtureSigner>,
        crypto_profile: u8,
        crypto_era: String,
        mutation_nonce: String,
        epoch_hash: String,
        signatures: Vec<FixtureSignature>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        version: u32,
        canonical_origin: String,
        conversation_id: String,
        conversation_kind: u8,
        owner: FixtureSigner,
        epochs: Vec<FixtureEpoch>,
    }

    fn fixture_bytes<const N: usize>(label: &str, encoded: &str) -> [u8; N] {
        let decoded = hex::decode(encoded).unwrap_or_else(|_| panic!("invalid {label} hex"));
        assert_eq!(hex::encode(&decoded), encoded, "non-canonical {label} hex");
        decoded
            .try_into()
            .unwrap_or_else(|_| panic!("invalid {label} length"))
    }

    fn fixture_u64(label: &str, encoded: &str) -> u64 {
        let value = encoded
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("invalid {label} decimal"));
        assert_eq!(value.to_string(), encoded, "non-canonical {label} decimal");
        value
    }

    fn fixture_signer(encoded: &FixtureSigner) -> MembershipPolicySignerV1 {
        MembershipPolicySignerV1 {
            account_id: fixture_bytes("policy account id", &encoded.account_id),
            account_signing_key: fixture_bytes(
                "policy account signing key",
                &encoded.account_signing_key,
            ),
        }
    }

    fn fixture_epoch(
        fixture: &Fixture,
        encoded: &FixtureEpoch,
    ) -> (MembershipEpochV1, Vec<MembershipEpochSignatureV1>) {
        let crypto_era = fixture_u64("crypto era", &encoded.crypto_era);
        let epoch = MembershipEpochV1 {
            canonical_origin: fixture.canonical_origin.clone(),
            conversation_id: fixture_bytes("conversation id", &fixture.conversation_id),
            conversation_kind: fixture.conversation_kind,
            epoch: fixture_u64("epoch number", &encoded.number),
            predecessor_hash: fixture_bytes("predecessor hash", &encoded.predecessor_hash),
            roster_version: fixture_u64("roster version", &encoded.roster_version),
            roster_commitment: fixture_bytes("roster commitment", &encoded.roster_commitment),
            successor_policy: MembershipPolicyV1 {
                threshold: encoded.policy_threshold,
                signers: encoded.policy_signers.iter().map(fixture_signer).collect(),
            },
            crypto_profile: encoded.crypto_profile,
            crypto_era: u16::try_from(crypto_era).expect("fixture crypto era overflows"),
            mutation_nonce: fixture_bytes("mutation nonce", &encoded.mutation_nonce),
        };
        let signatures = encoded
            .signatures
            .iter()
            .map(|signature| MembershipEpochSignatureV1 {
                signer_account_id: fixture_bytes(
                    "signature account id",
                    &signature.signer_account_id,
                ),
                signature: fixture_bytes("membership signature", &signature.signature),
            })
            .collect();
        (epoch, signatures)
    }

    fn account(id: u8, seed: u8) -> (MembershipPolicySignerV1, SigningKey) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let mut account_id = [0u8; 16];
        account_id[15] = id;
        (
            MembershipPolicySignerV1 {
                account_id,
                account_signing_key: signing.verifying_key().to_bytes(),
            },
            signing,
        )
    }

    fn sign(
        epoch: &MembershipEpochV1,
        signer: &MembershipPolicySignerV1,
        key: &SigningKey,
    ) -> MembershipEpochSignatureV1 {
        MembershipEpochSignatureV1 {
            signer_account_id: signer.account_id,
            signature: key.sign(&epoch.signature_message().unwrap()).to_bytes(),
        }
    }

    fn epoch_one() -> (
        MembershipEpochV1,
        MembershipPolicySignerV1,
        SigningKey,
        MembershipPolicySignerV1,
        SigningKey,
    ) {
        let (owner, owner_key) = account(1, 7);
        let (admin, admin_key) = account(2, 9);
        let mut conversation_id = [0u8; 16];
        conversation_id[0] = 0x44;
        conversation_id[15] = 0x55;
        (
            MembershipEpochV1 {
                canonical_origin: "https://node.example:443".to_string(),
                conversation_id,
                conversation_kind: MEMBERSHIP_CONVERSATION_KIND_GROUP_V1,
                epoch: 1,
                predecessor_hash: [0u8; 32],
                roster_version: 7,
                roster_commitment: [0x33; 32],
                successor_policy: MembershipPolicyV1 {
                    threshold: 2,
                    signers: vec![owner, admin],
                },
                crypto_profile: MEMBERSHIP_CRYPTO_PROFILE_SENDER_KEY_V6,
                crypto_era: MEMBERSHIP_CRYPTO_ERA_V1,
                mutation_nonce: [0x77; 32],
            },
            owner,
            owner_key,
            admin,
            admin_key,
        )
    }

    #[test]
    fn shared_go_rust_membership_epoch_v1_vector_is_frozen() {
        assert!(FIXTURE_BYTES.len() <= 64 * 1024);
        assert_eq!(
            hex::encode(Sha256::digest(FIXTURE_BYTES)),
            REVIEWED_FIXTURE_SHA256
        );
        let fixture: Fixture = serde_json::from_slice(FIXTURE_BYTES).unwrap();
        assert_eq!(fixture.version, 1);
        assert_eq!(fixture.epochs.len(), 2);
        let (first, first_signatures) = fixture_epoch(&fixture, &fixture.epochs[0]);
        let (second, second_signatures) = fixture_epoch(&fixture, &fixture.epochs[1]);
        assert_eq!(
            first.hash().unwrap(),
            fixture_bytes("first epoch hash", &fixture.epochs[0].epoch_hash)
        );
        assert_eq!(
            second.hash().unwrap(),
            fixture_bytes("second epoch hash", &fixture.epochs[1].epoch_hash)
        );
        let owner = fixture_signer(&fixture.owner);
        verify_membership_epoch_bootstrap_v1(&first, &owner, &first_signatures).unwrap();
        verify_membership_epoch_transition_v1(&first, &second, &second_signatures).unwrap();
    }

    #[test]
    fn bootstrap_and_threshold_transition_are_predecessor_authorized() {
        let (first, owner, owner_key, admin, admin_key) = epoch_one();
        let bootstrap = [sign(&first, &owner, &owner_key)];
        verify_membership_epoch_bootstrap_v1(&first, &owner, &bootstrap).unwrap();

        let mut second = first.clone();
        second.epoch = 2;
        second.predecessor_hash = first.hash().unwrap();
        second.roster_version = 8;
        second.roster_commitment = [0x45; 32];
        second.mutation_nonce = [0x88; 32];
        second.successor_policy = MembershipPolicyV1 {
            threshold: 1,
            signers: vec![owner],
        };
        let signatures = [
            sign(&second, &owner, &owner_key),
            sign(&second, &admin, &admin_key),
        ];
        verify_membership_epoch_transition_v1(&first, &second, &signatures).unwrap();

        assert!(verify_membership_epoch_transition_v1(&first, &second, &signatures[..1]).is_err());
        second.predecessor_hash[0] ^= 1;
        assert!(verify_membership_epoch_transition_v1(&first, &second, &signatures).is_err());
    }

    #[test]
    fn policy_and_signature_canonicalization_fail_closed() {
        let (mut first, _, _, _, _) = epoch_one();
        first.successor_policy.signers.swap(0, 1);
        assert!(first.validate().is_err());

        let (first, owner, owner_key, admin, admin_key) = epoch_one();
        let mut second = first.clone();
        second.epoch = 2;
        second.predecessor_hash = first.hash().unwrap();
        second.mutation_nonce = [0x88; 32];
        let reversed = [
            sign(&second, &admin, &admin_key),
            sign(&second, &owner, &owner_key),
        ];
        assert!(verify_membership_epoch_transition_v1(&first, &second, &reversed).is_err());

        let mut cross_origin = second.clone();
        cross_origin.canonical_origin = "https://other.example:443".to_string();
        let signatures = [
            sign(&cross_origin, &owner, &owner_key),
            sign(&cross_origin, &admin, &admin_key),
        ];
        assert!(verify_membership_epoch_transition_v1(&first, &cross_origin, &signatures).is_err());
    }
}
