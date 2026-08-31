//! Production SQLCipher + OS-keychain persistence adapter for OpenMLS.
//!
//! SQLCipher commits the complete checkpoint, exact network outbox, and any
//! decrypted inbox projection in one transaction. A monotonic generation is
//! then advanced in OS secure storage.
//! The only permitted split is `database generation > anchor generation`: it
//! means SQLCipher committed before an OS-keychain failure or process death and
//! is healed before restore. `anchor > database` is a rollback and fails closed.

use crate::store::{
    decode_checkpoint, derive_inbox_id, derive_outbox_id, CheckpointBlob, MlsInboxId,
    MlsInboxProjection, MlsKeyStore, MlsOutboxId, MlsOutboxKind, MlsOutboxPayload, MlsPersistError,
    StoredMlsInboxProjection, StoredMlsOutboxItem, MAX_INBOX_PROJECTIONS_PER_GENERATION,
    MAX_OUTBOX_ITEMS_PER_GENERATION,
};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex, MutexGuard};
use veil_store::db::{MlsInboxWriteV1, MlsOutboxWriteV1, VeilDb};

/// Independent monotonic generation authority. Production uses the OS
/// keychain; tests can supply a deterministic in-memory implementation.
pub trait MlsRollbackAnchor: Clone + Send + Sync + 'static {
    fn load_generation(&self, leaf: &[u8]) -> Result<Option<u64>, String>;
    fn advance_generation(&self, leaf: &[u8], generation: u64) -> Result<(), String>;
    fn delete_generation(&self, leaf: &[u8]) -> Result<(), String>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OsKeychainMlsRollbackAnchor;

impl MlsRollbackAnchor for OsKeychainMlsRollbackAnchor {
    fn load_generation(&self, leaf: &[u8]) -> Result<Option<u64>, String> {
        veil_store::keychain::get_mls_rollback_anchor_v1(leaf)
    }

    fn advance_generation(&self, leaf: &[u8], generation: u64) -> Result<(), String> {
        veil_store::keychain::store_mls_rollback_anchor_v1(leaf, generation)
    }

    fn delete_generation(&self, leaf: &[u8]) -> Result<(), String> {
        veil_store::keychain::delete_mls_rollback_anchor_v1(leaf)
    }
}

/// Thread-safe adapter over the application's existing SQLCipher authority.
/// No second SQLite database or plaintext provider store is introduced.
#[derive(Clone)]
pub struct VeilDbMlsStore<A: MlsRollbackAnchor = OsKeychainMlsRollbackAnchor> {
    db: Arc<Mutex<VeilDb>>,
    anchor: A,
}

impl VeilDbMlsStore<OsKeychainMlsRollbackAnchor> {
    pub fn production(db: Arc<Mutex<VeilDb>>) -> Self {
        Self::new(db, OsKeychainMlsRollbackAnchor)
    }
}

impl<A: MlsRollbackAnchor> VeilDbMlsStore<A> {
    pub fn new(db: Arc<Mutex<VeilDb>>, anchor: A) -> Self {
        Self { db, anchor }
    }

    pub fn shared_db(&self) -> Arc<Mutex<VeilDb>> {
        Arc::clone(&self.db)
    }

    /// Explicitly reset one MLS leaf so it may safely start again at
    /// generation zero. SQLCipher is cleared first; a keychain failure then
    /// leaves a fail-closed anchor that makes the partial reset retryable.
    pub fn delete_leaf_state(&self, leaf: &[u8]) -> Result<(), String> {
        self.lock_db()?.mls_delete_leaf_state_v1(leaf)?;
        self.anchor.delete_generation(leaf)
    }

    fn lock_db(&self) -> Result<MutexGuard<'_, VeilDb>, String> {
        self.db
            .lock()
            .map_err(|_| "VeilDb MLS store mutex poisoned".to_string())
    }

    fn prepare_outbox(
        leaf: &[u8],
        generation: u64,
        outbox: &[MlsOutboxPayload],
    ) -> Result<Vec<MlsOutboxWriteV1>, String> {
        if outbox.len() > MAX_OUTBOX_ITEMS_PER_GENERATION {
            return Err("MLS outbox batch has too many items".into());
        }
        outbox
            .iter()
            .enumerate()
            .map(|(index, payload)| {
                let item_index = u8::try_from(index)
                    .map_err(|_| "MLS outbox item index overflow".to_string())?;
                let payload_digest: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
                let item_id = derive_outbox_id(
                    leaf,
                    generation,
                    item_index,
                    payload.kind(),
                    payload.group_id(),
                    &payload_digest,
                );
                Ok(MlsOutboxWriteV1 {
                    item_id: *item_id.as_bytes(),
                    item_index,
                    kind: payload.kind().as_u8(),
                    group_id: payload.group_id().copied(),
                    payload_digest,
                    exact_payload: payload.as_bytes().to_vec(),
                })
            })
            .collect()
    }

    fn prepare_inbox(
        leaf: &[u8],
        generation: u64,
        inbox: &[MlsInboxProjection],
    ) -> Result<Vec<MlsInboxWriteV1>, String> {
        if inbox.len() > MAX_INBOX_PROJECTIONS_PER_GENERATION {
            return Err("MLS inbox batch has too many projections".into());
        }
        inbox
            .iter()
            .map(|projection| {
                let id = derive_inbox_id(
                    leaf,
                    generation,
                    projection.group_id(),
                    projection.source_digest(),
                );
                Ok(MlsInboxWriteV1 {
                    item_id: *id.as_bytes(),
                    group_id: *projection.group_id(),
                    source_digest: *projection.source_digest(),
                    plaintext: projection.plaintext().to_vec(),
                })
            })
            .collect()
    }

    fn require_or_heal_anchor(&self, leaf: &[u8], database_generation: u64) -> Result<(), String> {
        match self.anchor.load_generation(leaf)? {
            None => Err("MLS rollback anchor is missing for an existing checkpoint".into()),
            Some(anchor) if anchor > database_generation => {
                Err("MLS checkpoint is older than the external rollback anchor".into())
            }
            Some(anchor) if anchor < database_generation => self
                .anchor
                .advance_generation(leaf, database_generation)
                .map_err(|error| format!("heal MLS rollback anchor: {error}")),
            Some(_) => Ok(()),
        }
    }
}

impl<A: MlsRollbackAnchor> MlsKeyStore for VeilDbMlsStore<A> {
    fn save_checkpoint(
        &self,
        leaf: &[u8],
        expected_previous_generation: Option<u64>,
        checkpoint: CheckpointBlob,
        outbox: Vec<MlsOutboxPayload>,
        inbox: Vec<MlsInboxProjection>,
    ) -> Result<(), MlsPersistError> {
        if leaf.len() != 32 {
            return Err(MlsPersistError::Rejected(
                "MLS leaf must be exactly 32 bytes".into(),
            ));
        }
        decode_checkpoint(leaf, &checkpoint).map_err(MlsPersistError::Rejected)?;
        let generation = checkpoint.generation();
        let prepared =
            Self::prepare_outbox(leaf, generation, &outbox).map_err(MlsPersistError::Rejected)?;
        let prepared_inbox =
            Self::prepare_inbox(leaf, generation, &inbox).map_err(MlsPersistError::Rejected)?;

        match expected_previous_generation {
            None => {
                if self
                    .lock_db()
                    .map_err(MlsPersistError::Rejected)?
                    .mls_load_checkpoint(leaf)
                    .map_err(MlsPersistError::Rejected)?
                    .is_some()
                {
                    return Err(MlsPersistError::Rejected(
                        "MLS checkpoint already exists for initial generation".into(),
                    ));
                }
                match self
                    .anchor
                    .load_generation(leaf)
                    .map_err(MlsPersistError::Rejected)?
                {
                    None => self
                        .anchor
                        .advance_generation(leaf, 0)
                        .map_err(MlsPersistError::Rejected)?,
                    Some(0) => {}
                    Some(_) => {
                        return Err(MlsPersistError::Rejected(
                            "MLS rollback anchor conflicts with initial checkpoint".into(),
                        ))
                    }
                }
            }
            Some(previous) => match self
                .anchor
                .load_generation(leaf)
                .map_err(MlsPersistError::Rejected)?
            {
                None => {
                    return Err(MlsPersistError::Rejected(
                        "MLS rollback anchor is missing".into(),
                    ))
                }
                Some(anchor) if anchor > previous => {
                    return Err(MlsPersistError::Rejected(
                        "MLS checkpoint is older than the external rollback anchor".into(),
                    ))
                }
                Some(anchor) if anchor < previous => {
                    let database_generation = self
                        .lock_db()
                        .map_err(MlsPersistError::Rejected)?
                        .mls_load_checkpoint(leaf)
                        .map_err(MlsPersistError::Rejected)?
                        .map(|(generation, _)| generation);
                    if database_generation != Some(previous) {
                        return Err(MlsPersistError::Rejected(
                            "MLS rollback anchor cannot heal from an unverified client generation"
                                .into(),
                        ));
                    }
                    self.anchor
                        .advance_generation(leaf, previous)
                        .map_err(MlsPersistError::Rejected)?;
                }
                Some(_) => {}
            },
        }

        self.lock_db()
            .map_err(MlsPersistError::Rejected)?
            .mls_commit_checkpoint_and_outputs_v1(
                leaf,
                expected_previous_generation,
                generation,
                checkpoint.as_bytes(),
                &prepared,
                &prepared_inbox,
            )
            .map_err(MlsPersistError::Rejected)?;

        if expected_previous_generation.is_some() {
            self.anchor
                .advance_generation(leaf, generation)
                .map_err(|error| {
                    MlsPersistError::CommittedAnchorPending(format!(
                        "SQLCipher generation {generation} and its durable outputs are committed; {error}"
                    ))
                })?;
        }
        Ok(())
    }

    fn load_checkpoint(&self, leaf: &[u8]) -> Result<Option<CheckpointBlob>, String> {
        if leaf.len() != 32 {
            return Err("MLS leaf must be exactly 32 bytes".into());
        }
        let stored = self.lock_db()?.mls_load_checkpoint(leaf)?;
        let Some((generation, bytes)) = stored else {
            return match self.anchor.load_generation(leaf)? {
                None => Ok(None),
                Some(_) => Err("MLS rollback anchor exists without its checkpoint".into()),
            };
        };
        let checkpoint = CheckpointBlob::from_parts(generation, bytes)?;
        decode_checkpoint(leaf, &checkpoint)?;
        self.require_or_heal_anchor(leaf, generation)?;
        Ok(Some(checkpoint))
    }

    fn load_pending_outbox(
        &self,
        leaf: &[u8],
        limit: usize,
    ) -> Result<Vec<StoredMlsOutboxItem>, String> {
        self.load_checkpoint(leaf)?
            .ok_or_else(|| "MLS checkpoint not found for outbox load".to_string())?;
        self.lock_db()?
            .mls_load_pending_outbox_v1(leaf, limit)?
            .into_iter()
            .map(|mut item| {
                let exact_payload = std::mem::take(&mut item.exact_payload);
                StoredMlsOutboxItem::from_parts(
                    leaf,
                    MlsOutboxId::from_bytes(item.item_id),
                    item.generation,
                    item.item_index,
                    MlsOutboxKind::from_u8(item.kind)?,
                    item.group_id,
                    item.payload_digest,
                    exact_payload,
                )
            })
            .collect()
    }

    fn acknowledge_outbox(
        &self,
        leaf: &[u8],
        id: MlsOutboxId,
        payload_digest: &[u8; 32],
    ) -> Result<(), String> {
        self.load_checkpoint(leaf)?
            .ok_or_else(|| "MLS checkpoint not found for outbox acknowledgement".to_string())?;
        self.lock_db()?
            .mls_acknowledge_outbox_v1(leaf, id.as_bytes(), payload_digest)
    }

    fn load_pending_inbox(
        &self,
        leaf: &[u8],
        limit: usize,
    ) -> Result<Vec<StoredMlsInboxProjection>, String> {
        self.load_checkpoint(leaf)?
            .ok_or_else(|| "MLS checkpoint not found for inbox load".to_string())?;
        self.lock_db()?
            .mls_load_pending_inbox_v1(leaf, limit)?
            .into_iter()
            .map(|mut item| {
                let plaintext = std::mem::take(&mut item.plaintext);
                StoredMlsInboxProjection::from_parts(
                    leaf,
                    MlsInboxId::from_bytes(item.item_id),
                    item.generation,
                    item.group_id,
                    item.source_digest,
                    plaintext,
                )
            })
            .collect()
    }

    fn acknowledge_inbox(&self, leaf: &[u8], id: MlsInboxId) -> Result<(), String> {
        self.load_checkpoint(leaf)?
            .ok_or_else(|| "MLS checkpoint not found for inbox acknowledgement".to_string())?;
        self.lock_db()?
            .mls_acknowledge_inbox_v1(leaf, id.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InMemoryStore, LeafIdentity, MlsClient, MlsError, MlsGroupId};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    const NO_FAILURE: u64 = u64::MAX;

    #[derive(Clone, Default)]
    struct MemoryAnchor {
        generations: Arc<Mutex<HashMap<Vec<u8>, u64>>>,
        fail_generation: Arc<AtomicU64>,
        fail_delete: Arc<AtomicBool>,
    }

    impl MemoryAnchor {
        fn allow_writes(&self) {
            self.fail_generation.store(NO_FAILURE, Ordering::SeqCst);
        }

        fn fail_at(&self, generation: u64) {
            self.fail_generation.store(generation, Ordering::SeqCst);
        }

        fn force(&self, leaf: &[u8], generation: u64) {
            self.generations
                .lock()
                .unwrap()
                .insert(leaf.to_vec(), generation);
        }

        fn fail_deletes(&self, fail: bool) {
            self.fail_delete.store(fail, Ordering::SeqCst);
        }
    }

    impl MlsRollbackAnchor for MemoryAnchor {
        fn load_generation(&self, leaf: &[u8]) -> Result<Option<u64>, String> {
            Ok(self.generations.lock().unwrap().get(leaf).copied())
        }

        fn advance_generation(&self, leaf: &[u8], generation: u64) -> Result<(), String> {
            if self.fail_generation.load(Ordering::SeqCst) == generation {
                return Err("injected OS-anchor failure".into());
            }
            let mut anchors = self.generations.lock().unwrap();
            if anchors
                .get(leaf)
                .is_some_and(|existing| *existing > generation)
            {
                return Err("rollback-anchor decrease rejected".into());
            }
            anchors.insert(leaf.to_vec(), generation);
            Ok(())
        }

        fn delete_generation(&self, leaf: &[u8]) -> Result<(), String> {
            if self.fail_delete.load(Ordering::SeqCst) {
                return Err("injected OS-anchor deletion failure".into());
            }
            self.generations.lock().unwrap().remove(leaf);
            Ok(())
        }
    }

    fn leaf(label: &[u8]) -> LeafIdentity {
        LeafIdentity::new(Sha256::digest(label).to_vec()).unwrap()
    }

    fn group(label: &[u8]) -> MlsGroupId {
        let digest = Sha256::digest(label);
        MlsGroupId::from_uuid_bytes(&digest[..16]).unwrap()
    }

    #[test]
    fn veil_db_adapter_persists_exact_output_and_restores_from_its_own_anchor() {
        let anchor = MemoryAnchor::default();
        anchor.allow_writes();
        let store = VeilDbMlsStore::new(
            Arc::new(Mutex::new(VeilDb::open_memory(&[0x91; 32]).unwrap())),
            anchor,
        );
        let identity = leaf(b"sqlcipher-adapter");
        let mut client = MlsClient::create(identity.clone(), store.clone()).unwrap();
        let key_package = client.generate_key_package().unwrap();

        let pending = store.load_pending_outbox(identity.as_bytes(), 8).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind(), MlsOutboxKind::KeyPackage);
        assert_eq!(pending[0].as_bytes(), key_package.0);
        assert_eq!(pending[0].generation(), 1);

        let restored = MlsClient::restore(identity, store).unwrap();
        assert_eq!(restored.checkpoint_generation(), 1);
    }

    #[test]
    fn committed_anchor_gap_keeps_state_and_outbox_then_heals_on_restore() {
        let anchor = MemoryAnchor::default();
        anchor.allow_writes();
        let store = VeilDbMlsStore::new(
            Arc::new(Mutex::new(VeilDb::open_memory(&[0x92; 32]).unwrap())),
            anchor.clone(),
        );
        let identity = leaf(b"anchor-gap");
        let mut client = MlsClient::create(identity.clone(), store.clone()).unwrap();
        let group = group(b"anchor-gap-group");
        client.create_group(&group).unwrap();
        assert_eq!(client.checkpoint_generation(), 1);

        anchor.fail_at(2);
        let error = client
            .encrypt(&group, b"durable despite keychain failure")
            .unwrap_err();
        assert!(matches!(error, MlsError::DurableCommitPending(_)));
        assert_eq!(client.checkpoint_generation(), 2);
        let pending = store
            .load_pending_outbox(identity.as_bytes(), 8)
            .unwrap_err();
        assert!(pending.contains("heal MLS rollback anchor"));

        anchor.allow_writes();
        let restored = MlsClient::restore(identity.clone(), store.clone()).unwrap();
        assert_eq!(restored.checkpoint_generation(), 2);
        let pending = store.load_pending_outbox(identity.as_bytes(), 8).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind(), MlsOutboxKind::Ciphertext);
        assert_ne!(
            pending[0].as_bytes(),
            b"durable despite keychain failure".as_slice()
        );
        let expected_group: &[u8; 16] = group.as_bytes().try_into().unwrap();
        assert_eq!(pending[0].group_id(), Some(expected_group));

        anchor.force(identity.as_bytes(), 9);
        let rollback = MlsClient::restore(identity, store)
            .err()
            .expect("rollback must fail");
        assert!(rollback
            .to_string()
            .contains("older than the external rollback anchor"));
    }

    #[test]
    fn unverified_client_generation_cannot_poison_the_external_anchor() {
        let anchor = MemoryAnchor::default();
        anchor.allow_writes();
        let store = VeilDbMlsStore::new(
            Arc::new(Mutex::new(VeilDb::open_memory(&[0x95; 32]).unwrap())),
            anchor.clone(),
        );
        let identity = leaf(b"stale-client-anchor-poisoning");
        MlsClient::create(identity.clone(), store.clone()).unwrap();

        let source = InMemoryStore::default();
        let mut source_client = MlsClient::create(identity.clone(), source.clone()).unwrap();
        for _ in 0..10 {
            source_client.generate_key_package().unwrap();
        }
        let forged_future = source
            .load_checkpoint(identity.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(forged_future.generation(), 10);

        let error = store
            .save_checkpoint(
                identity.as_bytes(),
                Some(9),
                forged_future,
                Vec::new(),
                Vec::new(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("unverified client generation"));
        assert_eq!(
            anchor.load_generation(identity.as_bytes()).unwrap(),
            Some(0)
        );
        assert_eq!(
            store
                .load_checkpoint(identity.as_bytes())
                .unwrap()
                .unwrap()
                .generation(),
            0
        );
    }

    #[test]
    fn decrypt_anchor_gap_keeps_plaintext_in_sqlcipher_inbox() {
        let anchor = MemoryAnchor::default();
        anchor.allow_writes();
        let store = VeilDbMlsStore::new(
            Arc::new(Mutex::new(VeilDb::open_memory(&[0x93; 32]).unwrap())),
            anchor.clone(),
        );
        let bob_identity = leaf(b"inbox-anchor-gap-bob");
        let mut bob = MlsClient::create(bob_identity.clone(), store.clone()).unwrap();
        let mut alice =
            MlsClient::create(leaf(b"inbox-anchor-gap-alice"), InMemoryStore::default()).unwrap();
        let group = group(b"inbox-anchor-gap-group");
        let bob_key_package = bob.generate_key_package().unwrap();
        alice.create_group(&group).unwrap();
        let (_, welcome) = alice.add_member(&group, &bob_key_package).unwrap();
        bob.process_welcome(&welcome).unwrap();
        let ciphertext = alice
            .encrypt(&group, b"recoverable staged plaintext")
            .unwrap();

        let receive_generation = bob.checkpoint_generation() + 1;
        anchor.fail_at(receive_generation);
        let error = bob.decrypt(&group, &ciphertext).unwrap_err();
        assert!(matches!(error, MlsError::DurableCommitPending(_)));
        assert_eq!(bob.checkpoint_generation(), receive_generation);

        anchor.allow_writes();
        let restored = MlsClient::restore(bob_identity.clone(), store.clone()).unwrap();
        assert_eq!(restored.checkpoint_generation(), receive_generation);
        let pending = store
            .load_pending_inbox(bob_identity.as_bytes(), 8)
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].plaintext(), b"recoverable staged plaintext");
        store
            .acknowledge_inbox(bob_identity.as_bytes(), pending[0].id())
            .unwrap();
        assert!(store
            .load_pending_inbox(bob_identity.as_bytes(), 8)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn explicit_leaf_reset_is_fail_closed_retryable_and_reusable() {
        let anchor = MemoryAnchor::default();
        anchor.allow_writes();
        let store = VeilDbMlsStore::new(
            Arc::new(Mutex::new(VeilDb::open_memory(&[0x94; 32]).unwrap())),
            anchor.clone(),
        );
        let identity = leaf(b"explicit-leaf-reset");
        let mut client = MlsClient::create(identity.clone(), store.clone()).unwrap();
        client.generate_key_package().unwrap();

        anchor.fail_deletes(true);
        let error = store.delete_leaf_state(identity.as_bytes()).unwrap_err();
        assert!(error.contains("deletion failure"));
        assert!(MlsClient::restore(identity.clone(), store.clone()).is_err());

        anchor.fail_deletes(false);
        store.delete_leaf_state(identity.as_bytes()).unwrap();
        let recreated = MlsClient::create(identity, store).unwrap();
        assert_eq!(recreated.checkpoint_generation(), 0);
    }
}
