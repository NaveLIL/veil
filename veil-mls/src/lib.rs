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
//! * **Credential type:** `BasicCredential` carrying
//!   `user_id::device_label` (the caller is expected to blake3-hash the
//!   pair before constructing [`LeafIdentity`]).
//! * **Storage:** opaque [`MlsKeyStore`] trait. Production wires this to
//!   SQLCipher; tests use [`InMemoryStore`].
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
use zeroize::Zeroize;

pub mod store;

pub use store::{InMemoryStore, MlsKeyStore, SignerBlob};

/// The single cipher suite Veil supports. Locked at the protocol layer
/// — changing this number is a hard fork.
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Domain label used to derive auxiliary secrets (e.g. for LiveKit in
/// Phase 7) from the MLS exporter.
pub const EXPORTER_LABEL: &str = "veil-exporter-v1";

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
pub struct MlsGroupId(pub Vec<u8>);

impl MlsGroupId {
    pub fn from_uuid_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
    fn as_openmls(&self) -> GroupId {
        GroupId::from_slice(&self.0)
    }
}

/// Stable per-device identity used in the BasicCredential.
#[derive(Debug, Clone, Zeroize)]
pub struct LeafIdentity(pub Vec<u8>);

impl LeafIdentity {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

/// One MLS-capable client identity.
pub struct MlsClient<S: MlsKeyStore> {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    leaf: LeafIdentity,
    store: S,
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

        let mut me = Self {
            provider,
            signer,
            leaf,
            store,
        };
        me.persist_identity()?;
        Ok(me)
    }

    /// Restore a previously created client.
    pub fn restore(leaf: LeafIdentity, store: S) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let blob = store
            .load_signer(&leaf.0)
            .map_err(|e| MlsError::Storage(e.to_string()))?
            .ok_or_else(|| MlsError::Storage("signer not found".into()))?;
        let signer = SignatureKeyPair::tls_deserialize_exact_bytes(&blob.0).map_err(tls_err)?;
        Ok(Self {
            provider,
            signer,
            leaf,
            store,
        })
    }

    fn persist_identity(&mut self) -> Result<()> {
        let blob = self.signer.tls_serialize_detached().map_err(tls_err)?;
        self.store
            .save_signer(&self.leaf.0, SignerBlob(blob))
            .map_err(|e| MlsError::Storage(e.to_string()))
    }

    /// Public signature key (for fingerprinting / display).
    pub fn signature_public(&self) -> &[u8] {
        self.signer.public()
    }

    /// Borrow the underlying [`MlsKeyStore`]. Useful for callers that
    /// need to mirror persisted material (e.g. the freshly-saved signer
    /// blob) into a secondary at-rest store such as SQLCipher.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Generate a fresh KeyPackage for publication.
    pub fn generate_key_package(&self) -> Result<KeyPackageBlob> {
        let credential = BasicCredential::new(self.leaf.0.clone());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: self.signer.public().into(),
        };
        let kp_bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                credential_with_key,
            )
            .map_err(|e| MlsError::Protocol(format!("build key_package: {e:?}")))?;
        let serialized = kp_bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(tls_err)?;
        Ok(KeyPackageBlob(serialized))
    }

    /// Create a brand-new group.
    pub fn create_group(&self, group_id: &MlsGroupId) -> Result<()> {
        let credential = BasicCredential::new(self.leaf.0.clone());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: self.signer.public().into(),
        };
        let cfg = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();

        MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &cfg,
            group_id.as_openmls(),
            credential_with_key,
        )
        .map_err(|e| MlsError::Protocol(format!("create group: {e:?}")))?;
        Ok(())
    }

    /// Add a member to an existing group. Returns the Commit and Welcome.
    pub fn add_member(
        &self,
        group_id: &MlsGroupId,
        joiner_kp: &KeyPackageBlob,
    ) -> Result<(CommitBlob, WelcomeBlob)> {
        let mut group = self.load_group(group_id)?;
        let kp_in =
            KeyPackageIn::tls_deserialize_exact_bytes(joiner_kp.0.as_slice()).map_err(tls_err)?;
        let kp = kp_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| MlsError::Protocol(format!("kp validate: {e:?}")))?;

        let (commit, welcome, _group_info) = group
            .add_members(&self.provider, &self.signer, &[kp])
            .map_err(|e| MlsError::Protocol(format!("add_members: {e:?}")))?;

        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| MlsError::Protocol(format!("merge: {e:?}")))?;

        let commit_bytes = commit.tls_serialize_detached().map_err(tls_err)?;
        let welcome_bytes = welcome.tls_serialize_detached().map_err(tls_err)?;
        Ok((CommitBlob(commit_bytes), WelcomeBlob(welcome_bytes)))
    }

    /// Process an incoming Welcome and join the group it carries.
    pub fn process_welcome(&self, welcome: &WelcomeBlob) -> Result<MlsGroupId> {
        let msg =
            MlsMessageIn::tls_deserialize_exact_bytes(welcome.0.as_slice()).map_err(tls_err)?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::Invalid("expected Welcome message".into())),
        };

        let cfg = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&self.provider, &cfg, welcome, None)
            .map_err(|e| MlsError::Protocol(format!("stage welcome: {e:?}")))?;
        let group = staged
            .into_group(&self.provider)
            .map_err(|e| MlsError::Protocol(format!("install welcome: {e:?}")))?;
        Ok(MlsGroupId(group.group_id().as_slice().to_vec()))
    }

    /// Process an incoming Commit. Advances the group epoch.
    pub fn process_commit(&self, group_id: &MlsGroupId, commit: &CommitBlob) -> Result<()> {
        let mut group = self.load_group(group_id)?;
        let msg =
            MlsMessageIn::tls_deserialize_exact_bytes(commit.0.as_slice()).map_err(tls_err)?;
        let protocol_msg: ProtocolMessage = match msg.extract() {
            MlsMessageBodyIn::PrivateMessage(m) => m.into(),
            MlsMessageBodyIn::PublicMessage(m) => m.into(),
            _ => return Err(MlsError::Invalid("expected handshake message".into())),
        };
        let processed = group
            .process_message(&self.provider, protocol_msg)
            .map_err(|e| MlsError::Protocol(format!("process: {e:?}")))?;
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            processed.into_content()
        {
            group
                .merge_staged_commit(&self.provider, *staged_commit)
                .map_err(|e| MlsError::Protocol(format!("merge: {e:?}")))?;
        }
        Ok(())
    }

    /// Encrypt an application message.
    pub fn encrypt(&self, group_id: &MlsGroupId, plaintext: &[u8]) -> Result<MlsCiphertext> {
        let mut group = self.load_group(group_id)?;
        let msg = group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(|e| MlsError::Protocol(format!("encrypt: {e:?}")))?;
        let bytes = msg.tls_serialize_detached().map_err(tls_err)?;
        Ok(MlsCiphertext(bytes))
    }

    /// Decrypt an application message.
    pub fn decrypt(&self, group_id: &MlsGroupId, ciphertext: &MlsCiphertext) -> Result<Vec<u8>> {
        let mut group = self.load_group(group_id)?;
        let msg = MlsMessageIn::tls_deserialize_exact_bytes(ciphertext.0.as_slice())
            .map_err(tls_err)?;
        let protocol_msg: ProtocolMessage = match msg.extract() {
            MlsMessageBodyIn::PrivateMessage(m) => m.into(),
            MlsMessageBodyIn::PublicMessage(m) => m.into(),
            _ => return Err(MlsError::Invalid("expected application message".into())),
        };
        let processed = group
            .process_message(&self.provider, protocol_msg)
            .map_err(|e| MlsError::Protocol(format!("decrypt: {e:?}")))?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(app.into_bytes()),
            _ => Err(MlsError::Invalid("not an application message".into())),
        }
    }

    /// Derive a fresh secret bound to the current epoch.
    pub fn export_secret(
        &self,
        group_id: &MlsGroupId,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        let group = self.load_group(group_id)?;
        group
            .export_secret(self.provider.crypto(), EXPORTER_LABEL, context, length)
            .map_err(|e| MlsError::Protocol(format!("export: {e:?}")))
    }

    /// Look up the current epoch for a group.
    pub fn epoch(&self, group_id: &MlsGroupId) -> Result<u64> {
        let group = self.load_group(group_id)?;
        Ok(group.epoch().as_u64())
    }

    /// Snapshot the entire openmls storage (all groups, secrets, key
    /// material). Used by callers that want to persist state between
    /// process restarts. The returned bytes are opaque and safe to
    /// store at rest **only if the storage layer is encrypted**
    /// (SQLCipher in our case) — they contain raw key material.
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        // openmls_memory_storage gates its serialize/deserialize behind
        // the `test-utils` feature, so we re-implement the same simple
        // length-prefixed layout against the public `values: RwLock<HashMap<..>>`
        // field. Format: u64 BE entry count, then for each entry
        // u64 BE key_len, u64 BE value_len, key bytes, value bytes.
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| MlsError::Storage("provider rwlock poisoned".into()))?;
        let mut buf = Vec::with_capacity(8 + values.len() * 32);
        buf.extend_from_slice(&(values.len() as u64).to_be_bytes());
        for (k, v) in values.iter() {
            buf.extend_from_slice(&(k.len() as u64).to_be_bytes());
            buf.extend_from_slice(&(v.len() as u64).to_be_bytes());
            buf.extend_from_slice(k);
            buf.extend_from_slice(v);
        }
        Ok(buf)
    }

    /// Construct an `MlsClient` from a previously-persisted signer
    /// blob and storage snapshot. The signer must already live in
    /// `store`; this is the symmetric counterpart to [`Self::create`]
    /// + [`Self::snapshot`].
    pub fn restore_with_snapshot(
        leaf: LeafIdentity,
        store: S,
        snapshot: &[u8],
    ) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        // Parse the snapshot bytes (same format as `snapshot()`) and
        // load them into the new provider's storage HashMap via interior
        // mutability of the public `values: RwLock<HashMap<..>>`.
        let mut cursor: &[u8] = snapshot;
        fn read_u64(c: &mut &[u8]) -> Result<u64> {
            if c.len() < 8 {
                return Err(MlsError::Storage("snapshot truncated".into()));
            }
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&c[..8]);
            *c = &c[8..];
            Ok(u64::from_be_bytes(tmp))
        }
        fn read_bytes<'a>(c: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
            if c.len() < n {
                return Err(MlsError::Storage("snapshot truncated".into()));
            }
            let (head, tail) = c.split_at(n);
            *c = tail;
            Ok(head)
        }
        let count = read_u64(&mut cursor)? as usize;
        {
            let mut dst = provider
                .storage()
                .values
                .write()
                .map_err(|_| MlsError::Storage("provider rwlock poisoned".into()))?;
            for _ in 0..count {
                let k_len = read_u64(&mut cursor)? as usize;
                let v_len = read_u64(&mut cursor)? as usize;
                let k = read_bytes(&mut cursor, k_len)?.to_vec();
                let v = read_bytes(&mut cursor, v_len)?.to_vec();
                dst.insert(k, v);
            }
        }
        let blob = store
            .load_signer(&leaf.0)
            .map_err(|e| MlsError::Storage(e.to_string()))?
            .ok_or_else(|| MlsError::Storage("signer not found".into()))?;
        let signer = SignatureKeyPair::tls_deserialize_exact_bytes(&blob.0).map_err(tls_err)?;
        Ok(Self {
            provider,
            signer,
            leaf,
            store,
        })
    }

    fn load_group(&self, group_id: &MlsGroupId) -> Result<MlsGroup> {
        MlsGroup::load(self.provider.storage(), &group_id.as_openmls())
            .map_err(|e| MlsError::Storage(format!("load group: {e:?}")))?
            .ok_or_else(|| MlsError::GroupNotFound(hex::encode(&group_id.0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_client(label: &str) -> MlsClient<InMemoryStore> {
        MlsClient::create(
            LeafIdentity::new(label.as_bytes().to_vec()),
            InMemoryStore::default(),
        )
        .expect("create client")
    }

    #[test]
    fn two_party_round_trip() {
        let alice = fresh_client("alice::desktop");
        let bob = fresh_client("bob::desktop");

        let bob_kp = bob.generate_key_package().expect("kp");
        let group_id = MlsGroupId::from_uuid_bytes(b"test-group-uuid-aaaa");

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
    }

    /// Async-add catch-up: alice adds bob, then later adds charlie.
    /// Bob must apply alice's second commit before he can talk to charlie.
    /// This is the scenario INTEGRATION_ROADMAP.md flags as "Charlie
    /// returns and must process commits in order".
    #[test]
    fn three_party_async_catch_up() {
        let alice = fresh_client("alice::desktop");
        let bob = fresh_client("bob::desktop");
        let charlie = fresh_client("charlie::desktop");

        let group_id = MlsGroupId::from_uuid_bytes(b"async-catch-up-uuid-");
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
            charlie.decrypt(&group_id, &from_alice).expect("charlie dec"),
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
        let bob = fresh_client("bob::pool");
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
            let alice = fresh_client(&format!("alice::pool::{i}"));
            let mut gid = b"pool-test-uuid-".to_vec();
            gid.push(i as u8);
            gid.resize(16, 0);
            let group_id = MlsGroupId(gid);
            alice.create_group(&group_id).expect("create");
            alice.add_member(&group_id, kp).expect("consume kp");
        }
    }

    /// Restoring a client from its persisted SignerBlob keeps the same
    /// public signature key, so peers continue to recognise it.
    #[test]
    fn restore_preserves_identity() {
        let store = InMemoryStore::default();
        let leaf = LeafIdentity::new(b"persistent::desktop".to_vec());

        let original = MlsClient::create(leaf.clone(), store).expect("create");
        let pub_key = original.signature_public().to_vec();
        let store2 = InMemoryStore::default();
        // Move the persisted blob across stores to simulate a restart.
        if let Some(blob) = original.store.load_signer(&leaf.0).unwrap() {
            let mut s = store2;
            s.save_signer(&leaf.0, blob).unwrap();
            let restored = MlsClient::restore(leaf, s).expect("restore");
            assert_eq!(restored.signature_public(), &pub_key[..]);
        } else {
            panic!("signer blob missing after create");
        }
    }

    /// Snapshot + restore_with_snapshot must preserve group state:
    /// after a "restart" Bob can still decrypt messages addressed to
    /// the group he was a member of.
    #[test]
    fn snapshot_restore_preserves_group_state() {
        let alice = fresh_client("alice::snap");
        let bob_leaf = LeafIdentity::new(b"bob::snap".to_vec());
        let bob_store = InMemoryStore::default();
        let bob = MlsClient::create(bob_leaf.clone(), bob_store).expect("bob");

        let bob_kp = bob.generate_key_package().expect("kp");
        let group_id = MlsGroupId::from_uuid_bytes(b"snap-restore-uuid-aa");
        alice.create_group(&group_id).expect("create");
        let (_c, w) = alice.add_member(&group_id, &bob_kp).expect("add");
        bob.process_welcome(&w).expect("welcome");

        // Snapshot bob's full state, including the persisted signer.
        let snapshot = bob.snapshot().expect("snapshot");
        let signer_blob = bob
            .store
            .load_signer(&bob_leaf.0)
            .unwrap()
            .expect("signer present");

        // Simulate a restart with a brand-new store.
        let mut bob_store2 = InMemoryStore::default();
        bob_store2.save_signer(&bob_leaf.0, signer_blob).unwrap();
        let bob2 = MlsClient::restore_with_snapshot(bob_leaf, bob_store2, &snapshot)
            .expect("restore with snapshot");

        // Alice sends a fresh message; bob2 (the restored client) can
        // still decrypt it because the group state survived the restart.
        let ct = alice.encrypt(&group_id, b"after restart").expect("enc");
        let pt = bob2.decrypt(&group_id, &ct).expect("dec after restore");
        assert_eq!(pt, b"after restart");
        assert_eq!(bob2.epoch(&group_id).unwrap(), 1);
    }
}
