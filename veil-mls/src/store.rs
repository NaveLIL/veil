//! Pluggable storage adapter for the MLS signature key.
//!
//! OpenMLS itself owns persistence of group/key state via its own
//! [`StorageProvider`](openmls_traits::storage::StorageProvider) trait;
//! we don't reinvent it here. What openmls does **not** persist is the
//! long-lived [`SignatureKeyPair`](openmls_basic_credential::SignatureKeyPair)
//! — that's our responsibility, hence this trait.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

/// TLS-encoded `SignatureKeyPair`.
#[derive(Debug, Clone)]
pub struct SignerBlob(pub Vec<u8>);

/// Storage adapter for the long-lived MLS signature keypair.
pub trait MlsKeyStore: Send + Sync + 'static {
    fn save_signer(&mut self, leaf: &[u8], signer: SignerBlob) -> Result<(), String>;
    fn load_signer(&self, leaf: &[u8]) -> Result<Option<SignerBlob>, String>;
}

/// In-memory implementation for tests and local-only flows.
#[derive(Default)]
pub struct InMemoryStore {
    inner: Mutex<HashMap<Vec<u8>, SignerBlob>>,
}

impl InMemoryStore {
    fn lock(&self) -> MutexGuard<'_, HashMap<Vec<u8>, SignerBlob>> {
        self.inner.lock().expect("InMemoryStore mutex poisoned")
    }
}

impl MlsKeyStore for InMemoryStore {
    fn save_signer(&mut self, leaf: &[u8], signer: SignerBlob) -> Result<(), String> {
        self.lock().insert(leaf.to_vec(), signer);
        Ok(())
    }
    fn load_signer(&self, leaf: &[u8]) -> Result<Option<SignerBlob>, String> {
        Ok(self.lock().get(leaf).cloned())
    }
}
