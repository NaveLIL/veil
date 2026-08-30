//! Atomic persistence boundary for Veil MLS state.
//!
//! OpenMLS owns the shape of its provider records. Veil wraps those records and
//! the long-lived signature key in one bounded, versioned checkpoint. A store
//! must compare-and-swap the generation atomically so an older writer cannot
//! overwrite newer cryptographic state.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::{Zeroize, ZeroizeOnDrop};

const CHECKPOINT_MAGIC: &[u8; 8] = b"VMLSCP01";
const CHECKPOINT_VERSION: u16 = 1;
const CHECKPOINT_FLAGS: u16 = 0;
const CHECKPOINT_HEADER_BYTES: usize = 8 + 2 + 2 + 8 + 32 + 4 + 4 + 8 + 32;

pub const MAX_CHECKPOINT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CHECKPOINT_ENTRIES: usize = 100_000;
pub const MAX_CHECKPOINT_KEY_BYTES: usize = 64 * 1024;
pub const MAX_CHECKPOINT_VALUE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CHECKPOINT_SIGNER_BYTES: usize = 64 * 1024;

/// Opaque, secret-bearing checkpoint stored in an encrypted persistence layer.
///
/// The explicit generation is repeated inside `bytes` and verified on restore.
/// Keeping it outside lets SQL stores perform an atomic compare-and-swap without
/// understanding the rest of the format.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CheckpointBlob {
    generation: u64,
    bytes: Vec<u8>,
}

impl CheckpointBlob {
    pub fn from_parts(generation: u64, bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err("MLS checkpoint exceeds the maximum size".into());
        }
        Ok(Self { generation, bytes })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Atomic storage adapter for one complete MLS client checkpoint.
///
/// Implementations MUST encrypt `checkpoint` at rest and atomically enforce the
/// compare-and-swap precondition. `None` means that no checkpoint may exist;
/// `Some(n)` means the stored generation must equal `n`. Returning `Ok(())`
/// means the whole new checkpoint is durable. Returning `Err` must never expose
/// a partial checkpoint.
pub trait MlsKeyStore: Send + Sync + 'static {
    fn save_checkpoint(
        &self,
        leaf: &[u8],
        expected_previous_generation: Option<u64>,
        checkpoint: CheckpointBlob,
    ) -> Result<(), String>;

    fn load_checkpoint(&self, leaf: &[u8]) -> Result<Option<CheckpointBlob>, String>;
}

/// In-memory implementation for tests and local-only flows.
#[derive(Clone, Default)]
pub struct InMemoryStore {
    inner: Arc<Mutex<HashMap<Vec<u8>, CheckpointBlob>>>,
}

impl InMemoryStore {
    fn lock(&self) -> Result<MutexGuard<'_, HashMap<Vec<u8>, CheckpointBlob>>, String> {
        self.inner
            .lock()
            .map_err(|_| "InMemoryStore mutex poisoned".to_string())
    }
}

impl MlsKeyStore for InMemoryStore {
    fn save_checkpoint(
        &self,
        leaf: &[u8],
        expected_previous_generation: Option<u64>,
        checkpoint: CheckpointBlob,
    ) -> Result<(), String> {
        let expected_next = match expected_previous_generation {
            Some(previous) => previous
                .checked_add(1)
                .ok_or_else(|| "MLS checkpoint generation exhausted".to_string())?,
            None => 0,
        };
        if checkpoint.generation() != expected_next {
            return Err("MLS checkpoint generation is not consecutive".into());
        }

        let mut checkpoints = self.lock()?;
        let actual_previous = checkpoints.get(leaf).map(CheckpointBlob::generation);
        if actual_previous != expected_previous_generation {
            return Err("MLS checkpoint compare-and-swap conflict".into());
        }
        checkpoints.insert(leaf.to_vec(), checkpoint);
        Ok(())
    }

    fn load_checkpoint(&self, leaf: &[u8]) -> Result<Option<CheckpointBlob>, String> {
        Ok(self.lock()?.get(leaf).cloned())
    }
}

pub(crate) struct DecodedCheckpoint {
    pub generation: u64,
    pub signer: Vec<u8>,
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Drop for DecodedCheckpoint {
    fn drop(&mut self) {
        self.signer.zeroize();
        for (key, value) in &mut self.entries {
            key.zeroize();
            value.zeroize();
        }
    }
}

pub(crate) fn encode_checkpoint(
    leaf: &[u8],
    generation: u64,
    signer: &[u8],
    values: &HashMap<Vec<u8>, Vec<u8>>,
) -> Result<CheckpointBlob, String> {
    if signer.len() > MAX_CHECKPOINT_SIGNER_BYTES {
        return Err("MLS signer exceeds the checkpoint limit".into());
    }
    if values.len() > MAX_CHECKPOINT_ENTRIES {
        return Err("MLS checkpoint has too many entries".into());
    }

    let mut entries: Vec<_> = values.iter().collect();
    entries.sort_unstable_by_key(|(key, _)| *key);

    let mut body_len = signer.len();
    for (key, value) in &entries {
        if key.len() > MAX_CHECKPOINT_KEY_BYTES {
            return Err("MLS checkpoint key exceeds the limit".into());
        }
        if value.len() > MAX_CHECKPOINT_VALUE_BYTES {
            return Err("MLS checkpoint value exceeds the limit".into());
        }
        body_len = body_len
            .checked_add(8)
            .and_then(|length| length.checked_add(key.len()))
            .and_then(|length| length.checked_add(value.len()))
            .ok_or_else(|| "MLS checkpoint size overflow".to_string())?;
    }
    let total_len = CHECKPOINT_HEADER_BYTES
        .checked_add(body_len)
        .ok_or_else(|| "MLS checkpoint size overflow".to_string())?;
    if total_len > MAX_CHECKPOINT_BYTES {
        return Err("MLS checkpoint exceeds the maximum size".into());
    }

    let signer_len = u32::try_from(signer.len())
        .map_err(|_| "MLS signer length does not fit the checkpoint format".to_string())?;
    let entry_count = u32::try_from(entries.len())
        .map_err(|_| "MLS entry count does not fit the checkpoint format".to_string())?;
    let encoded_body_len = u64::try_from(body_len)
        .map_err(|_| "MLS checkpoint length does not fit the format".to_string())?;

    let mut body = Vec::with_capacity(body_len);
    body.extend_from_slice(signer);
    for (key, value) in entries {
        let key_len = u32::try_from(key.len())
            .map_err(|_| "MLS key length does not fit the checkpoint format".to_string())?;
        let value_len = u32::try_from(value.len())
            .map_err(|_| "MLS value length does not fit the checkpoint format".to_string())?;
        body.extend_from_slice(&key_len.to_be_bytes());
        body.extend_from_slice(&value_len.to_be_bytes());
        body.extend_from_slice(key);
        body.extend_from_slice(value);
    }

    let leaf_digest = Sha256::digest(leaf);
    let body_digest = Sha256::digest(&body);
    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(CHECKPOINT_MAGIC);
    bytes.extend_from_slice(&CHECKPOINT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&CHECKPOINT_FLAGS.to_be_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(&leaf_digest);
    bytes.extend_from_slice(&signer_len.to_be_bytes());
    bytes.extend_from_slice(&entry_count.to_be_bytes());
    bytes.extend_from_slice(&encoded_body_len.to_be_bytes());
    bytes.extend_from_slice(&body_digest);
    bytes.extend_from_slice(&body);
    body.zeroize();

    CheckpointBlob::from_parts(generation, bytes)
}

pub(crate) fn decode_checkpoint(
    expected_leaf: &[u8],
    checkpoint: &CheckpointBlob,
) -> Result<DecodedCheckpoint, String> {
    let bytes = checkpoint.as_bytes();
    if bytes.len() < CHECKPOINT_HEADER_BYTES {
        return Err("MLS checkpoint is truncated".into());
    }
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err("MLS checkpoint exceeds the maximum size".into());
    }

    let mut cursor = bytes;
    let magic = take(&mut cursor, CHECKPOINT_MAGIC.len())?;
    if magic != CHECKPOINT_MAGIC {
        return Err("unsupported MLS checkpoint format".into());
    }
    let version = read_u16(&mut cursor)?;
    if version != CHECKPOINT_VERSION {
        return Err("unsupported MLS checkpoint version".into());
    }
    if read_u16(&mut cursor)? != CHECKPOINT_FLAGS {
        return Err("unsupported MLS checkpoint flags".into());
    }

    let generation = read_u64(&mut cursor)?;
    if generation != checkpoint.generation() {
        return Err("MLS checkpoint generation mismatch".into());
    }
    let expected_leaf_digest = Sha256::digest(expected_leaf);
    if take(&mut cursor, expected_leaf_digest.len())? != expected_leaf_digest.as_slice() {
        return Err("MLS checkpoint belongs to a different leaf identity".into());
    }

    let signer_len = usize::try_from(read_u32(&mut cursor)?)
        .map_err(|_| "MLS signer length overflow".to_string())?;
    let entry_count = usize::try_from(read_u32(&mut cursor)?)
        .map_err(|_| "MLS entry count overflow".to_string())?;
    let body_len = usize::try_from(read_u64(&mut cursor)?)
        .map_err(|_| "MLS checkpoint length overflow".to_string())?;
    let expected_body_digest = take(&mut cursor, 32)?;

    if signer_len > MAX_CHECKPOINT_SIGNER_BYTES {
        return Err("MLS signer exceeds the checkpoint limit".into());
    }
    if entry_count > MAX_CHECKPOINT_ENTRIES {
        return Err("MLS checkpoint has too many entries".into());
    }
    if body_len != cursor.len() {
        return Err("MLS checkpoint length or trailing bytes are invalid".into());
    }
    if Sha256::digest(cursor).as_slice() != expected_body_digest {
        return Err("MLS checkpoint digest mismatch".into());
    }

    let mut body = cursor;
    let signer = take(&mut body, signer_len)?.to_vec();
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let key_len = usize::try_from(read_u32(&mut body)?)
            .map_err(|_| "MLS key length overflow".to_string())?;
        let value_len = usize::try_from(read_u32(&mut body)?)
            .map_err(|_| "MLS value length overflow".to_string())?;
        if key_len > MAX_CHECKPOINT_KEY_BYTES {
            return Err("MLS checkpoint key exceeds the limit".into());
        }
        if value_len > MAX_CHECKPOINT_VALUE_BYTES {
            return Err("MLS checkpoint value exceeds the limit".into());
        }
        let key = take(&mut body, key_len)?.to_vec();
        let value = take(&mut body, value_len)?.to_vec();
        if let Some((previous, _)) = entries.last() {
            if previous >= &key {
                return Err("MLS checkpoint entries are duplicate or non-canonical".into());
            }
        }
        entries.push((key, value));
    }
    if !body.is_empty() {
        return Err("MLS checkpoint contains trailing entry data".into());
    }

    Ok(DecodedCheckpoint {
        generation,
        signer,
        entries,
    })
}

fn take<'a>(cursor: &mut &'a [u8], length: usize) -> Result<&'a [u8], String> {
    if cursor.len() < length {
        return Err("MLS checkpoint is truncated".into());
    }
    let (head, tail) = cursor.split_at(length);
    *cursor = tail;
    Ok(head)
}

fn read_u16(cursor: &mut &[u8]) -> Result<u16, String> {
    let bytes: [u8; 2] = take(cursor, 2)?
        .try_into()
        .map_err(|_| "MLS checkpoint u16 decode failed".to_string())?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(cursor: &mut &[u8]) -> Result<u32, String> {
    let bytes: [u8; 4] = take(cursor, 4)?
        .try_into()
        .map_err(|_| "MLS checkpoint u32 decode failed".to_string())?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(cursor: &mut &[u8]) -> Result<u64, String> {
    let bytes: [u8; 8] = take(cursor, 8)?
        .try_into()
        .map_err(|_| "MLS checkpoint u64 decode failed".to_string())?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_checkpoint() -> CheckpointBlob {
        let values = HashMap::from([
            (b"beta".to_vec(), b"two".to_vec()),
            (b"alpha".to_vec(), b"one".to_vec()),
        ]);
        encode_checkpoint(b"leaf-a", 7, b"signer", &values).expect("encode")
    }

    #[test]
    fn checkpoint_is_canonical_and_bound_to_leaf_and_generation() {
        let first = sample_checkpoint();
        let second = sample_checkpoint();
        assert_eq!(first.as_bytes(), second.as_bytes());

        let decoded = decode_checkpoint(b"leaf-a", &first).expect("decode");
        assert_eq!(decoded.generation, 7);
        assert_eq!(decoded.signer, b"signer");
        assert_eq!(decoded.entries[0].0, b"alpha");
        assert_eq!(decoded.entries[1].0, b"beta");

        assert!(decode_checkpoint(b"leaf-b", &first).is_err());
        let wrong_generation =
            CheckpointBlob::from_parts(8, first.as_bytes().to_vec()).expect("blob");
        assert!(decode_checkpoint(b"leaf-a", &wrong_generation).is_err());
    }

    #[test]
    fn checkpoint_rejects_corruption_truncation_and_trailing_bytes() {
        let checkpoint = sample_checkpoint();

        let mut corrupt = checkpoint.as_bytes().to_vec();
        *corrupt.last_mut().expect("body") ^= 1;
        let corrupt = CheckpointBlob::from_parts(7, corrupt).expect("blob");
        assert!(decode_checkpoint(b"leaf-a", &corrupt).is_err());

        let truncated = CheckpointBlob::from_parts(
            7,
            checkpoint.as_bytes()[..checkpoint.as_bytes().len() - 1].to_vec(),
        )
        .expect("blob");
        assert!(decode_checkpoint(b"leaf-a", &truncated).is_err());

        let mut trailing = checkpoint.as_bytes().to_vec();
        trailing.push(0);
        let trailing = CheckpointBlob::from_parts(7, trailing).expect("blob");
        assert!(decode_checkpoint(b"leaf-a", &trailing).is_err());
    }

    #[test]
    fn memory_store_enforces_consecutive_compare_and_swap() {
        let store = InMemoryStore::default();
        let checkpoint = sample_checkpoint();
        assert!(store
            .save_checkpoint(b"leaf-a", Some(6), checkpoint.clone())
            .is_err());
        assert!(store
            .save_checkpoint(b"leaf-a", None, checkpoint.clone())
            .is_err());

        let initial = encode_checkpoint(b"leaf-a", 0, b"signer", &HashMap::new()).unwrap();
        store
            .save_checkpoint(b"leaf-a", None, initial)
            .expect("initial save");
        assert!(store
            .save_checkpoint(b"leaf-a", None, checkpoint.clone())
            .is_err());
        assert!(store
            .save_checkpoint(b"leaf-a", Some(0), checkpoint)
            .is_err());
    }
}
