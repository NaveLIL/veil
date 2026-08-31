//! Production SQLCipher + OS-keychain persistence adapter for OpenMLS.
//!
//! SQLCipher commits the complete checkpoint and exact network outbox in one
//! transaction. A monotonic generation is then advanced in OS secure storage.
//! The only permitted split is `database generation > anchor generation`: it
//! means SQLCipher committed before an OS-keychain failure or process death and
//! is healed before restore. `anchor > database` is a rollback and fails closed.

use crate::store::{
    decode_checkpoint, derive_outbox_id, CheckpointBlob, MlsKeyStore, MlsOutboxId, MlsOutboxKind,
    MlsOutboxPayload, MlsPersistError, StoredMlsOutboxItem, MAX_OUTBOX_ITEMS_PER_GENERATION,
};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex, MutexGuard};
use veil_store::db::{MlsOutboxWriteV1, VeilDb};

/// Independent monotonic generation authority. Production uses the OS
/// keychain; tests can supply a deterministic in-memory implementation.
pub trait MlsRollbackAnchor: Clone + Send + Sync + 'static {
    fn load_generation(&self, leaf: &[u8]) -> Result<Option<u64>, String>;
    fn advance_generation(&self, leaf: &[u8], generation: u64) -> Result<(), String>;
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

        match expected_previous_generation {
            None => match self
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
            },
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
                Some(anchor) if anchor < previous => self
                    .anchor
                    .advance_generation(leaf, previous)
                    .map_err(MlsPersistError::Rejected)?,
                Some(_) => {}
            },
        }

        self.lock_db()
            .map_err(MlsPersistError::Rejected)?
            .mls_commit_checkpoint_and_outbox_v1(
                leaf,
                expected_previous_generation,
                generation,
                checkpoint.as_bytes(),
                &prepared,
            )
            .map_err(MlsPersistError::Rejected)?;

        if expected_previous_generation.is_some() {
            self.anchor
                .advance_generation(leaf, generation)
                .map_err(|error| {
                    MlsPersistError::CommittedAnchorPending(format!(
                        "SQLCipher generation {generation} and its outbox are durable; {error}"
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
            .map(|item| {
                StoredMlsOutboxItem::from_parts(
                    leaf,
                    MlsOutboxId::from_bytes(item.item_id),
                    item.generation,
                    item.item_index,
                    MlsOutboxKind::from_u8(item.kind)?,
                    item.group_id,
                    item.payload_digest,
                    item.exact_payload,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LeafIdentity, MlsClient, MlsError, MlsGroupId};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    const NO_FAILURE: u64 = u64::MAX;

    #[derive(Clone, Default)]
    struct MemoryAnchor {
        generations: Arc<Mutex<HashMap<Vec<u8>, u64>>>,
        fail_generation: Arc<AtomicU64>,
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
}
