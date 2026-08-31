//! # veil-mls
//!
//! Phase 6 of the Veil roadmap. A thin, opinionated wrapper around
//! [OpenMLS](https://github.com/openmls/openmls) that exposes only the
//! operations the messenger actually needs.
//!
//! ## Design choices (locked, do not change without a migration plan)
//!
//! * **Cipher suite:** `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
//!   ([`CIPHERSUITE`]). Documented in `INTEGRATION_ROADMAP.md` Phase 6.
//! * **Credential type:** `BasicCredential` carrying an exact 32-byte
//!   application-derived [`LeafIdentity`]. The future runtime binding must
//!   include canonical origin, account, device, binding version and accepted
//!   transparency state; this crate rejects every other leaf length.
//! * **Storage:** opaque, compare-and-swap [`MlsKeyStore`] checkpoints.
//!   Production must wire this to SQLCipher; tests use [`InMemoryStore`].
//! * **Serialization:** all wire types ([`KeyPackageBlob`],
//!   [`WelcomeBlob`], [`CommitBlob`], [`MlsCiphertext`]) are TLS-encoded
//!   opaque blobs that the server stores verbatim and never inspects.
//!
//! The crate is purely additive: existing `ratchet.rs` / `sender_key.rs`
//! code paths in `veil-crypto` are untouched. Conversations opt into MLS
//! via the `conversations.crypto_mode = 'mls'` column added in migration
//! `008_mls.sql`.

use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub mod store;

use store::{decode_checkpoint, encode_checkpoint};
pub use store::{CheckpointBlob, InMemoryStore, MlsKeyStore};

/// The single cipher suite Veil supports. Locked at the protocol layer
/// — changing this number is a hard fork.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Domain label used to derive auxiliary secrets (e.g. for LiveKit in
/// Phase 7) from the MLS exporter.
pub const EXPORTER_LABEL: &str = "veil-exporter-v1";
pub const MLS_GROUP_ID_BYTES: usize = 16;
pub const MLS_LEAF_IDENTITY_BYTES: usize = 32;
pub const MAX_KEY_PACKAGE_BYTES: usize = 64 * 1024;
pub const MAX_MLS_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EXPORTER_CONTEXT_BYTES: usize = 64 * 1024;
pub const MAX_EXPORTER_SECRET_BYTES: usize = 1024;

/// Error type for all MLS operations.
#[derive(Debug, Error)]
pub enum MlsError {
    #[error("crypto provider error: {0}")]
    Crypto(String),
    #[error("mls protocol error: {0}")]
    Protocol(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("group not found: {0}")]
    GroupNotFound(String),
    #[error("invalid input: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, MlsError>;

fn tls_err<E: std::fmt::Display>(e: E) -> MlsError {
    MlsError::Encoding(e.to_string())
}

fn ensure_max_len(label: &str, actual: usize, maximum: usize) -> Result<()> {
    if actual > maximum {
        return Err(MlsError::Invalid(format!(
            "{label} exceeds the {maximum}-byte limit"
        )));
    }
    Ok(())
}

/// A serialized KeyPackage published to the server so other clients can
/// add this device to a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackageBlob(pub Vec<u8>);

/// A serialized Welcome message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeBlob(pub Vec<u8>);

/// A serialized Commit. Fanned out to existing membership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitBlob(pub Vec<u8>);

/// A serialized application message (encrypted payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsCiphertext(pub Vec<u8>);

/// Group identifier round-tripped as raw bytes (server uses the
/// conversation UUID directly).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MlsGroupId(Vec<u8>);

impl MlsGroupId {
    pub fn from_uuid_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLS_GROUP_ID_BYTES {
            return Err(MlsError::Invalid(
                "MLS group id must be exactly 16 UUID bytes".into(),
            ));
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn as_openmls(&self) -> Result<GroupId> {
        if self.0.len() != MLS_GROUP_ID_BYTES {
            return Err(MlsError::Invalid(
                "MLS group id must be exactly 16 UUID bytes".into(),
            ));
        }
        Ok(GroupId::from_slice(&self.0))
    }
}

/// Stable per-device identity used in the BasicCredential.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct LeafIdentity(Vec<u8>);

impl LeafIdentity {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        if bytes.len() != MLS_LEAF_IDENTITY_BYTES {
            return Err(MlsError::Invalid(
                "MLS leaf identity must be exactly 32 derived bytes".into(),
            ));
        }
        Ok(Self(bytes))
    }
}

/// One MLS-capable client identity.
pub struct MlsClient<S: MlsKeyStore> {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    leaf: LeafIdentity,
    store: S,
    generation: u64,
}

impl<S: MlsKeyStore> MlsClient<S> {
    /// Create a brand-new client.
    pub fn create(leaf: LeafIdentity, store: S) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| MlsError::Crypto(e.to_string()))?;
        signer
            .store(provider.storage())
            .map_err(|e| MlsError::Storage(format!("persist signer: {e:?}")))?;

        let me = Self {
            provider,
            signer,
            leaf,
            store,
            generation: 0,
        };
        let checkpoint = me.checkpoint(0)?;
        me.store
            .save_checkpoint(&me.leaf.0, None, checkpoint)
            .map_err(|e| MlsError::Storage(format!("persist initial MLS checkpoint: {e}")))?;
        Ok(me)
    }

    /// Restore a previously created client, rejecting a checkpoint older than
    /// the caller's non-rollbackable generation anchor.
    pub fn restore(leaf: LeafIdentity, store: S, minimum_generation: u64) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let checkpoint = store
            .load_checkpoint(&leaf.0)
            .map_err(|e| MlsError::Storage(e.to_string()))?
            .ok_or_else(|| MlsError::Storage("MLS checkpoint not found".into()))?;
        if checkpoint.generation() < minimum_generation {
            return Err(MlsError::Storage(
                "MLS checkpoint is older than the rollback anchor".into(),
            ));
        }
        let decoded = decode_checkpoint(&leaf.0, &checkpoint).map_err(MlsError::Storage)?;
        {
            let mut values = provider
                .storage()
                .values
                .write()
                .map_err(|_| MlsError::Storage("provider rwlock poisoned".into()))?;
            values.extend(decoded.entries.iter().cloned());
        }
        let signer =
            SignatureKeyPair::tls_deserialize_exact_bytes(&decoded.signer).map_err(tls_err)?;
        Ok(Self {
            provider,
            signer,
            leaf,
            store,
            generation: decoded.generation,
        })
    }

    /// Public signature key (for fingerprinting / display).
    pub fn signature_public(&self) -> &[u8] {
        self.signer.public()
    }

    /// Generation of the latest durable checkpoint.
    pub fn checkpoint_generation(&self) -> u64 {
        self.generation
    }

    /// Generate a fresh KeyPackage for publication.
    pub fn generate_key_package(&mut self) -> Result<KeyPackageBlob> {
        let leaf = self.leaf.0.clone();
        self.transact(|provider, signer| {
            let credential = BasicCredential::new(leaf);
            let credential_with_key = CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.public().into(),
            };
            let kp_bundle = KeyPackage::builder()
                .build(CIPHERSUITE, provider, signer, credential_with_key)
                .map_err(|e| MlsError::Protocol(format!("build key_package: {e:?}")))?;
            let serialized = kp_bundle
                .key_package()
                .tls_serialize_detached()
                .map_err(tls_err)?;
            ensure_max_len("MLS KeyPackage", serialized.len(), MAX_KEY_PACKAGE_BYTES)?;
            Ok(KeyPackageBlob(serialized))
        })
    }

    /// Create a brand-new group.
    pub fn create_group(&mut self, group_id: &MlsGroupId) -> Result<()> {
        let leaf = self.leaf.0.clone();
        let openmls_group_id = group_id.as_openmls()?;
        self.transact(|provider, signer| {
            let credential = BasicCredential::new(leaf);
            let credential_with_key = CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.public().into(),
            };
            let cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(CIPHERSUITE)
                .use_ratchet_tree_extension(true)
                .build();

            MlsGroup::new_with_group_id(
                provider,
                signer,
                &cfg,
                openmls_group_id,
                credential_with_key,
            )
            .map_err(|e| MlsError::Protocol(format!("create group: {e:?}")))?;
            Ok(())
        })
    }

    /// Add a member to an existing group. Returns the Commit and Welcome.
    pub fn add_member(
        &mut self,
        group_id: &MlsGroupId,
        joiner_kp: &KeyPackageBlob,
    ) -> Result<(CommitBlob, WelcomeBlob)> {
        ensure_max_len("MLS KeyPackage", joiner_kp.0.len(), MAX_KEY_PACKAGE_BYTES)?;
        self.transact(|provider, signer| {
            let mut group = Self::load_group_from(provider, group_id)?;
            let kp_in = KeyPackageIn::tls_deserialize_exact_bytes(joiner_kp.0.as_slice())
                .map_err(tls_err)?;
            let kp = kp_in
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|e| MlsError::Protocol(format!("kp validate: {e:?}")))?;

            let (commit, welcome, _group_info) = group
                .add_members(provider, signer, &[kp])
                .map_err(|e| MlsError::Protocol(format!("add_members: {e:?}")))?;

            group
                .merge_pending_commit(provider)
                .map_err(|e| MlsError::Protocol(format!("merge: {e:?}")))?;

            let commit_bytes = commit.tls_serialize_detached().map_err(tls_err)?;
            let welcome_bytes = welcome.tls_serialize_detached().map_err(tls_err)?;
            ensure_max_len("MLS Commit", commit_bytes.len(), MAX_MLS_MESSAGE_BYTES)?;
            ensure_max_len("MLS Welcome", welcome_bytes.len(), MAX_MLS_MESSAGE_BYTES)?;
            Ok((CommitBlob(commit_bytes), WelcomeBlob(welcome_bytes)))
        })
    }

    /// Process an incoming Welcome and join the group it carries.
    pub fn process_welcome(&mut self, welcome: &WelcomeBlob) -> Result<MlsGroupId> {
        ensure_max_len("MLS Welcome", welcome.0.len(), MAX_MLS_MESSAGE_BYTES)?;
        self.transact(|provider, _signer| {
            let msg =
                MlsMessageIn::tls_deserialize_exact_bytes(welcome.0.as_slice()).map_err(tls_err)?;
            let welcome = match msg.extract() {
                MlsMessageBodyIn::Welcome(w) => w,
                _ => return Err(MlsError::Invalid("expected Welcome message".into())),
            };

            let cfg = MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build();
            let staged = StagedWelcome::new_from_welcome(provider, &cfg, welcome, None)
                .map_err(|e| MlsError::Protocol(format!("stage welcome: {e:?}")))?;
            let group = staged
                .into_group(provider)
                .map_err(|e| MlsError::Protocol(format!("install welcome: {e:?}")))?;
            MlsGroupId::from_uuid_bytes(group.group_id().as_slice())
        })
    }

    /// Process an incoming Commit. Advances the group epoch.
    pub fn process_commit(&mut self, group_id: &MlsGroupId, commit: &CommitBlob) -> Result<()> {
        ensure_max_len("MLS Commit", commit.0.len(), MAX_MLS_MESSAGE_BYTES)?;
        self.transact(|provider, _signer| {
            let mut group = Self::load_group_from(provider, group_id)?;
            let msg =
                MlsMessageIn::tls_deserialize_exact_bytes(commit.0.as_slice()).map_err(tls_err)?;
            let protocol_msg: ProtocolMessage = match msg.extract() {
                MlsMessageBodyIn::PrivateMessage(m) => m.into(),
                MlsMessageBodyIn::PublicMessage(m) => m.into(),
                _ => return Err(MlsError::Invalid("expected handshake message".into())),
            };
            let processed = group
                .process_message(provider, protocol_msg)
                .map_err(|e| MlsError::Protocol(format!("process: {e:?}")))?;
            match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(staged_commit) => group
                    .merge_staged_commit(provider, *staged_commit)
                    .map_err(|e| MlsError::Protocol(format!("merge: {e:?}"))),
                _ => Err(MlsError::Invalid(
                    "handshake message is not an MLS Commit".into(),
                )),
            }
        })
    }

    /// Encrypt an application message.
    pub fn encrypt(&mut self, group_id: &MlsGroupId, plaintext: &[u8]) -> Result<MlsCiphertext> {
        ensure_max_len("MLS plaintext", plaintext.len(), MAX_MLS_MESSAGE_BYTES)?;
        self.transact(|provider, signer| {
            let mut group = Self::load_group_from(provider, group_id)?;
            let msg = group
                .create_message(provider, signer, plaintext)
                .map_err(|e| MlsError::Protocol(format!("encrypt: {e:?}")))?;
            let bytes = msg.tls_serialize_detached().map_err(tls_err)?;
            ensure_max_len("MLS ciphertext", bytes.len(), MAX_MLS_MESSAGE_BYTES)?;
            Ok(MlsCiphertext(bytes))
        })
    }

    /// Decrypt an application message.
    pub fn decrypt(
        &mut self,
        group_id: &MlsGroupId,
        ciphertext: &MlsCiphertext,
    ) -> Result<Vec<u8>> {
        ensure_max_len("MLS ciphertext", ciphertext.0.len(), MAX_MLS_MESSAGE_BYTES)?;
        self.transact(|provider, _signer| {
            let mut group = Self::load_group_from(provider, group_id)?;
            let msg = MlsMessageIn::tls_deserialize_exact_bytes(ciphertext.0.as_slice())
                .map_err(tls_err)?;
            let protocol_msg: ProtocolMessage = match msg.extract() {
                MlsMessageBodyIn::PrivateMessage(m) => m.into(),
                MlsMessageBodyIn::PublicMessage(m) => m.into(),
                _ => return Err(MlsError::Invalid("expected application message".into())),
            };
            let processed = group
                .process_message(provider, protocol_msg)
                .map_err(|e| MlsError::Protocol(format!("decrypt: {e:?}")))?;
            match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(app) => {
                    let plaintext = app.into_bytes();
                    ensure_max_len("MLS plaintext", plaintext.len(), MAX_MLS_MESSAGE_BYTES)?;
                    Ok(plaintext)
                }
                _ => Err(MlsError::Invalid("not an application message".into())),
            }
        })
    }

    /// Derive a fresh secret bound to the current epoch.
    pub fn export_secret(
        &self,
        group_id: &MlsGroupId,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        ensure_max_len(
            "MLS exporter context",
            context.len(),
            MAX_EXPORTER_CONTEXT_BYTES,
        )?;
        if length == 0 || length > MAX_EXPORTER_SECRET_BYTES {
            return Err(MlsError::Invalid(
                "MLS exporter length must be between 1 and 1024 bytes".into(),
            ));
        }
        let group = Self::load_group_from(&self.provider, group_id)?;
        group
            .export_secret(self.provider.crypto(), EXPORTER_LABEL, context, length)
            .map_err(|e| MlsError::Protocol(format!("export: {e:?}")))
    }

    /// Look up the current epoch for a group.
    pub fn epoch(&self, group_id: &MlsGroupId) -> Result<u64> {
        let group = Self::load_group_from(&self.provider, group_id)?;
        Ok(group.epoch().as_u64())
    }

    fn checkpoint(&self, generation: u64) -> Result<CheckpointBlob> {
        let signer = Zeroizing::new(self.signer.tls_serialize_detached().map_err(tls_err)?);
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| MlsError::Storage("provider rwlock poisoned".into()))?;
        encode_checkpoint(&self.leaf.0, generation, &signer, &values).map_err(MlsError::Storage)
    }

    fn provider_values(&self) -> Result<std::collections::HashMap<Vec<u8>, Vec<u8>>> {
        self.provider
            .storage()
            .values
            .read()
            .map(|values| values.clone())
            .map_err(|_| MlsError::Storage("provider rwlock poisoned".into()))
    }

    fn restore_provider_values(
        &self,
        values: std::collections::HashMap<Vec<u8>, Vec<u8>>,
    ) -> Result<()> {
        *self
            .provider
            .storage()
            .values
            .write()
            .map_err(|_| MlsError::Storage("provider rwlock poisoned".into()))? = values;
        Ok(())
    }

    /// Apply one OpenMLS mutation and make its complete checkpoint durable
    /// before releasing any output to the caller. On a protocol, encoding, or
    /// persistence failure the in-memory provider is restored exactly.
    fn transact<R>(
        &mut self,
        operation: impl FnOnce(&OpenMlsRustCrypto, &SignatureKeyPair) -> Result<R>,
    ) -> Result<R> {
        let previous_values = self.provider_values()?;
        let output = match operation(&self.provider, &self.signer) {
            Ok(output) => output,
            Err(error) => {
                self.restore_provider_values(previous_values)?;
                return Err(error);
            }
        };

        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| MlsError::Storage("MLS checkpoint generation exhausted".into()))?;
        let checkpoint = match self.checkpoint(next_generation) {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                self.restore_provider_values(previous_values)?;
                return Err(error);
            }
        };
        if let Err(error) =
            self.store
                .save_checkpoint(&self.leaf.0, Some(self.generation), checkpoint)
        {
            self.restore_provider_values(previous_values)?;
            return Err(MlsError::Storage(format!(
                "persist MLS checkpoint: {error}"
            )));
        }
        self.generation = next_generation;
        Ok(output)
    }

    fn load_group_from(provider: &OpenMlsRustCrypto, group_id: &MlsGroupId) -> Result<MlsGroup> {
        MlsGroup::load(provider.storage(), &group_id.as_openmls()?)
            .map_err(|e| MlsError::Storage(format!("load group: {e:?}")))?
            .ok_or_else(|| MlsError::GroupNotFound(hex::encode(&group_id.0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct RejectingStore {
        inner: InMemoryStore,
        reject_writes: Arc<AtomicBool>,
    }

    impl MlsKeyStore for RejectingStore {
        fn save_checkpoint(
            &self,
            leaf: &[u8],
            expected_previous_generation: Option<u64>,
            checkpoint: CheckpointBlob,
        ) -> std::result::Result<(), String> {
            if self.reject_writes.load(Ordering::SeqCst) {
                return Err("injected persistence failure".into());
            }
            self.inner
                .save_checkpoint(leaf, expected_previous_generation, checkpoint)
        }

        fn load_checkpoint(
            &self,
            leaf: &[u8],
        ) -> std::result::Result<Option<CheckpointBlob>, String> {
            self.inner.load_checkpoint(leaf)
        }
    }

    fn test_leaf(label: &str) -> LeafIdentity {
        LeafIdentity::new(Sha256::digest(label.as_bytes()).to_vec()).expect("test leaf")
    }

    fn test_group(label: &str) -> MlsGroupId {
        let digest = Sha256::digest(label.as_bytes());
        MlsGroupId::from_uuid_bytes(&digest[..MLS_GROUP_ID_BYTES]).expect("test group")
    }

    fn fresh_client(label: &str) -> MlsClient<InMemoryStore> {
        MlsClient::create(test_leaf(label), InMemoryStore::default()).expect("create client")
    }

    #[test]
    fn two_party_round_trip() {
        let mut alice = fresh_client("alice::desktop");
        let mut bob = fresh_client("bob::desktop");

        let bob_kp = bob.generate_key_package().expect("kp");
        let group_id = test_group("two-party");

        alice.create_group(&group_id).expect("create");
        let (_commit, welcome) = alice.add_member(&group_id, &bob_kp).expect("add");
        let bob_group = bob.process_welcome(&welcome).expect("welcome");
        assert_eq!(bob_group.0, group_id.0);

        // Sanity: alice can already encrypt at epoch 1.
        assert_eq!(alice.epoch(&group_id).expect("epoch"), 1);
        let ct = alice.encrypt(&group_id, b"hello bob").expect("enc");
        let pt = bob.decrypt(&group_id, &ct).expect("dec");
        assert_eq!(pt, b"hello bob");

        // Bob replies, alice decrypts.
        let ct = bob.encrypt(&group_id, b"hello alice").expect("enc");
        let pt = alice.decrypt(&group_id, &ct).expect("dec");
        assert_eq!(pt, b"hello alice");

        // A private application message is not a Commit. Rejecting it through
        // the handshake API must also roll back the receive secret tree so the
        // same ciphertext remains decryptable through the correct API.
        let application = alice.encrypt(&group_id, b"not a commit").expect("enc");
        let bob_generation = bob.checkpoint_generation();
        assert!(bob
            .process_commit(&group_id, &CommitBlob(application.0.clone()))
            .is_err());
        assert_eq!(bob.checkpoint_generation(), bob_generation);
        assert_eq!(
            bob.decrypt(&group_id, &application)
                .expect("correct decrypt"),
            b"not a commit"
        );
    }

    #[test]
    fn identifiers_and_public_inputs_are_bounded() {
        assert!(LeafIdentity::new(vec![0; MLS_LEAF_IDENTITY_BYTES - 1]).is_err());
        assert!(MlsGroupId::from_uuid_bytes(&[0; MLS_GROUP_ID_BYTES - 1]).is_err());

        let mut client = fresh_client("bounded-inputs");
        let group_id = test_group("bounded-inputs");
        client.create_group(&group_id).expect("group");
        assert!(client
            .decrypt(
                &group_id,
                &MlsCiphertext(vec![0; MAX_MLS_MESSAGE_BYTES + 1]),
            )
            .is_err());
        assert!(client
            .export_secret(&group_id, b"context", MAX_EXPORTER_SECRET_BYTES + 1)
            .is_err());
    }

    /// Async-add catch-up: alice adds bob, then later adds charlie.
    /// Bob must apply alice's second commit before he can talk to charlie.
    /// This is the scenario INTEGRATION_ROADMAP.md flags as "Charlie
    /// returns and must process commits in order".
    #[test]
    fn three_party_async_catch_up() {
        let mut alice = fresh_client("alice::desktop");
        let mut bob = fresh_client("bob::desktop");
        let mut charlie = fresh_client("charlie::desktop");

        let group_id = test_group("async-catch-up");
        alice.create_group(&group_id).expect("create");

        // Round 1: bob joins.
        let bob_kp = bob.generate_key_package().expect("kp1");
        let (_c1, w1) = alice.add_member(&group_id, &bob_kp).expect("add bob");
        bob.process_welcome(&w1).expect("bob welcome");
        assert_eq!(alice.epoch(&group_id).unwrap(), 1);
        assert_eq!(bob.epoch(&group_id).unwrap(), 1);

        // Round 2: alice adds charlie. Bob is "offline" — he hasn't seen
        // the new commit yet.
        let charlie_kp = charlie.generate_key_package().expect("kp2");
        let (c2, w2) = alice
            .add_member(&group_id, &charlie_kp)
            .expect("add charlie");
        charlie.process_welcome(&w2).expect("charlie welcome");
        assert_eq!(alice.epoch(&group_id).unwrap(), 2);
        assert_eq!(charlie.epoch(&group_id).unwrap(), 2);
        assert_eq!(bob.epoch(&group_id).unwrap(), 1, "bob not yet caught up");

        // Bob comes back online and pulls commits with epoch > 1. He
        // applies c2 and advances to epoch 2.
        bob.process_commit(&group_id, &c2).expect("bob applies c2");
        assert_eq!(bob.epoch(&group_id).unwrap(), 2);

        // All three can now exchange messages at the new epoch.
        let from_alice = alice.encrypt(&group_id, b"team meeting").expect("enc");
        assert_eq!(
            bob.decrypt(&group_id, &from_alice).expect("bob dec"),
            b"team meeting"
        );
        assert_eq!(
            charlie
                .decrypt(&group_id, &from_alice)
                .expect("charlie dec"),
            b"team meeting"
        );

        let from_charlie = charlie.encrypt(&group_id, b"hi all").expect("enc");
        assert_eq!(
            alice.decrypt(&group_id, &from_charlie).expect("alice dec"),
            b"hi all"
        );
        assert_eq!(
            bob.decrypt(&group_id, &from_charlie).expect("bob dec"),
            b"hi all"
        );
    }

    /// Generating many KeyPackages: each one must be unique and
    /// independently deserializable. This is the KeyPackage replenishment
    /// loop a client runs when its server-side pool drops below 10.
    #[test]
    fn key_package_pool_replenish() {
        let mut bob = fresh_client("bob::pool");
        let mut blobs = Vec::with_capacity(20);
        for _ in 0..20 {
            blobs.push(bob.generate_key_package().expect("kp"));
        }
        // All distinct.
        let mut seen = std::collections::HashSet::new();
        for kp in &blobs {
            assert!(seen.insert(kp.0.clone()), "duplicate key_package generated");
        }

        // Each can be consumed independently to add bob to a fresh group.
        for (i, kp) in blobs.iter().enumerate() {
            let mut alice = fresh_client(&format!("alice::pool::{i}"));
            let mut gid = b"pool-test-uuid-".to_vec();
            gid.push(i as u8);
            gid.resize(16, 0);
            let group_id = MlsGroupId::from_uuid_bytes(&gid).expect("group id");
            alice.create_group(&group_id).expect("create");
            alice.add_member(&group_id, kp).expect("consume kp");
        }
    }

    /// Restoring a client from its atomic checkpoint keeps the same public
    /// signature key, so peers continue to recognise it.
    #[test]
    fn restore_preserves_identity() {
        let store = InMemoryStore::default();
        let restore_store = store.clone();
        let leaf = test_leaf("persistent::desktop");

        let original = MlsClient::create(leaf.clone(), store).expect("create");
        let pub_key = original.signature_public().to_vec();
        let restored = MlsClient::restore(leaf, restore_store, 0).expect("restore");
        assert_eq!(restored.signature_public(), &pub_key[..]);
        assert_eq!(restored.checkpoint_generation(), 0);
    }

    #[test]
    fn persistence_failure_rolls_back_before_output_is_released() {
        let store = RejectingStore::default();
        let controls = store.clone();
        let leaf = test_leaf("rollback::desktop");
        let mut client = MlsClient::create(leaf, store).expect("create");
        let group_id = test_group("rollback-group");

        controls.reject_writes.store(true, Ordering::SeqCst);
        assert!(client.create_group(&group_id).is_err());
        assert_eq!(client.checkpoint_generation(), 0);
        assert!(matches!(
            client.epoch(&group_id),
            Err(MlsError::GroupNotFound(_))
        ));

        controls.reject_writes.store(false, Ordering::SeqCst);
        client.create_group(&group_id).expect("retry create");
        assert_eq!(client.checkpoint_generation(), 1);
        assert_eq!(client.epoch(&group_id).expect("epoch"), 0);
    }

    #[test]
    fn restore_rejects_checkpoint_older_than_external_anchor() {
        let store = InMemoryStore::default();
        let restore_store = store.clone();
        let leaf = test_leaf("anchored::desktop");
        let client = MlsClient::create(leaf.clone(), store).expect("create");
        assert_eq!(client.checkpoint_generation(), 0);

        let error = MlsClient::restore(leaf, restore_store, 1)
            .err()
            .expect("stale checkpoint must fail");
        assert!(error.to_string().contains("rollback anchor"));
    }

    /// Atomic checkpoint restore must preserve group state:
    /// after a "restart" Bob can still decrypt messages addressed to
    /// the group he was a member of.
    #[test]
    fn snapshot_restore_preserves_group_state() {
        let mut alice = fresh_client("alice::snap");
        let bob_leaf = test_leaf("bob::snap");
        let bob_store = InMemoryStore::default();
        let bob_restore_store = bob_store.clone();
        let mut bob = MlsClient::create(bob_leaf.clone(), bob_store).expect("bob");

        let bob_kp = bob.generate_key_package().expect("kp");
        let group_id = test_group("snapshot-restore");
        alice.create_group(&group_id).expect("create");
        let (_c, w) = alice.add_member(&group_id, &bob_kp).expect("add");
        bob.process_welcome(&w).expect("welcome");

        // An exporter is a compact assertion that the persisted epoch secret
        // survives the storage round trip, rather than merely proving that a
        // group record can be deserialized.
        let exporter_before = bob
            .export_secret(&group_id, b"storage-compat-v1", 32)
            .expect("export before snapshot");

        // Simulate a restart from the latest atomic checkpoint.
        let durable_generation = bob.checkpoint_generation();
        let mut bob2 = MlsClient::restore(bob_leaf, bob_restore_store, durable_generation)
            .expect("restore checkpoint");

        assert_eq!(
            bob2.export_secret(&group_id, b"storage-compat-v1", 32)
                .expect("export after restore"),
            exporter_before,
            "epoch secret changed across snapshot restore"
        );

        // Alice sends a fresh message; bob2 (the restored client) can
        // still decrypt it because the group state survived the restart.
        let ct = alice.encrypt(&group_id, b"after restart").expect("enc");
        let pt = bob2.decrypt(&group_id, &ct).expect("dec after restore");
        assert_eq!(pt, b"after restart");
        assert_eq!(bob2.epoch(&group_id).unwrap(), 1);

        // The restored state must also remain usable for future protocol
        // evolution. Advance to epoch 2 and exchange messages in both
        // directions using only the restored Bob instance.
        let mut charlie = fresh_client("charlie::snap");
        let charlie_kp = charlie.generate_key_package().expect("charlie kp");
        let (commit, welcome) = alice
            .add_member(&group_id, &charlie_kp)
            .expect("add charlie after restore");
        charlie.process_welcome(&welcome).expect("charlie welcome");
        bob2.process_commit(&group_id, &commit)
            .expect("restored bob applies epoch 2 commit");
        assert_eq!(bob2.epoch(&group_id).unwrap(), 2);

        let from_alice = alice
            .encrypt(&group_id, b"after epoch advance")
            .expect("alice encrypts at epoch 2");
        assert_eq!(
            bob2.decrypt(&group_id, &from_alice)
                .expect("restored bob decrypts at epoch 2"),
            b"after epoch advance"
        );

        let from_bob = bob2
            .encrypt(&group_id, b"reply from restored state")
            .expect("restored bob encrypts at epoch 2");
        assert_eq!(
            alice
                .decrypt(&group_id, &from_bob)
                .expect("alice decrypts restored bob reply"),
            b"reply from restored state"
        );
    }
}
