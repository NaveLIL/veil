//! Atomic persistence boundary for Veil MLS state.
//!
//! OpenMLS owns the shape of its provider records. Veil wraps those records and
//! the long-lived signature key in one bounded, versioned checkpoint. A store
//! must compare-and-swap the generation atomically so an older writer cannot
//! overwrite newer cryptographic state.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
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
pub const MAX_OUTBOX_ITEMS_PER_GENERATION: usize = 16;
pub const MAX_OUTBOX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

const OUTBOX_ID_DOMAIN: &[u8] = b"veil-mls-outbox-v1";

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

/// Network payload kind persisted with the exact MLS state that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MlsOutboxKind {
    KeyPackage = 1,
    Welcome = 2,
    Commit = 3,
    Ciphertext = 4,
}

impl MlsOutboxKind {
    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::KeyPackage),
            2 => Ok(Self::Welcome),
            3 => Ok(Self::Commit),
            4 => Ok(Self::Ciphertext),
            _ => Err("MLS outbox kind is invalid".into()),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    fn requires_group(self) -> bool {
        !matches!(self, Self::KeyPackage)
    }
}

/// One exact payload that must be durable before it can be published.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlsOutboxPayload {
    #[zeroize(skip)]
    kind: MlsOutboxKind,
    group_id: Option<[u8; 16]>,
    bytes: Vec<u8>,
}

impl MlsOutboxPayload {
    pub fn new(
        kind: MlsOutboxKind,
        group_id: Option<[u8; 16]>,
        bytes: Vec<u8>,
    ) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_OUTBOX_PAYLOAD_BYTES {
            return Err("MLS outbox payload size is invalid".into());
        }
        if kind.requires_group() != group_id.is_some() {
            return Err("MLS outbox payload group scope is invalid".into());
        }
        Ok(Self {
            kind,
            group_id,
            bytes,
        })
    }

    pub fn kind(&self) -> MlsOutboxKind {
        self.kind
    }

    pub fn group_id(&self) -> Option<&[u8; 16]> {
        self.group_id.as_ref()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Stable identifier for one exact outbox payload.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlsOutboxId([u8; 32]);

impl MlsOutboxId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MlsOutboxId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MlsOutboxId(")?;
        formatter.write_str(&hex::encode(self.0))?;
        formatter.write_str(")")
    }
}

/// Durable payload loaded for retry after a crash or transport failure.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StoredMlsOutboxItem {
    #[zeroize(skip)]
    id: MlsOutboxId,
    generation: u64,
    item_index: u8,
    #[zeroize(skip)]
    kind: MlsOutboxKind,
    group_id: Option<[u8; 16]>,
    payload_digest: [u8; 32],
    bytes: Vec<u8>,
}

impl StoredMlsOutboxItem {
    pub fn from_parts(
        leaf: &[u8],
        id: MlsOutboxId,
        generation: u64,
        item_index: u8,
        kind: MlsOutboxKind,
        group_id: Option<[u8; 16]>,
        payload_digest: [u8; 32],
        bytes: Vec<u8>,
    ) -> Result<Self, String> {
        MlsOutboxPayload::new(kind, group_id, bytes.clone())?;
        if Sha256::digest(&bytes).as_slice() != payload_digest {
            return Err("MLS outbox payload digest mismatch".into());
        }
        if leaf.len() != 32 {
            return Err("MLS outbox leaf must be exactly 32 bytes".into());
        }
        if id
            != derive_outbox_id(
                leaf,
                generation,
                item_index,
                kind,
                group_id.as_ref(),
                &payload_digest,
            )
        {
            return Err("MLS outbox identifier mismatch".into());
        }
        Ok(Self {
            id,
            generation,
            item_index,
            kind,
            group_id,
            payload_digest,
            bytes,
        })
    }

    pub fn id(&self) -> MlsOutboxId {
        self.id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn item_index(&self) -> u8 {
        self.item_index
    }

    pub fn kind(&self) -> MlsOutboxKind {
        self.kind
    }

    pub fn group_id(&self) -> Option<&[u8; 16]> {
        self.group_id.as_ref()
    }

    pub fn payload_digest(&self) -> &[u8; 32] {
        &self.payload_digest
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) fn derive_outbox_id(
    leaf: &[u8],
    generation: u64,
    item_index: u8,
    kind: MlsOutboxKind,
    group_id: Option<&[u8; 16]>,
    payload_digest: &[u8; 32],
) -> MlsOutboxId {
    let mut digest = Sha256::new();
    digest.update(OUTBOX_ID_DOMAIN);
    digest.update(leaf);
    digest.update(generation.to_be_bytes());
    digest.update([item_index, kind.as_u8()]);
    digest.update(group_id.map_or(&[][..], |value| value.as_slice()));
    digest.update(payload_digest);
    MlsOutboxId(digest.finalize().into())
}

/// Failure from the durable checkpoint boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsPersistError {
    /// Nothing from the proposed mutation became durable.
    Rejected(String),
    /// Checkpoint and outbox committed, but the external rollback anchor could
    /// not be advanced. The caller must keep the new in-memory state and retry
    /// through the durable outbox instead of repeating the protocol mutation.
    CommittedAnchorPending(String),
}

impl fmt::Display for MlsPersistError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(message) => formatter.write_str(message),
            Self::CommittedAnchorPending(message) => formatter.write_str(message),
        }
    }
}

/// Atomic storage adapter for one complete MLS client checkpoint and every
/// exact network payload produced by the same mutation.
///
/// Implementations MUST encrypt `checkpoint` at rest and atomically enforce the
/// compare-and-swap precondition. `None` means that no checkpoint may exist;
/// `Some(n)` means the stored generation must equal `n`. Returning `Ok(())`
/// means the whole new checkpoint and outbox batch are durable. A `Rejected`
/// error must never expose partial state. `CommittedAnchorPending` is reserved
/// for the post-commit OS-anchor gap and still guarantees durable outbox bytes.
pub trait MlsKeyStore: Send + Sync + 'static {
    fn save_checkpoint(
        &self,
        leaf: &[u8],
        expected_previous_generation: Option<u64>,
        checkpoint: CheckpointBlob,
        outbox: Vec<MlsOutboxPayload>,
    ) -> Result<(), MlsPersistError>;

    fn load_checkpoint(&self, leaf: &[u8]) -> Result<Option<CheckpointBlob>, String>;

    fn load_pending_outbox(
        &self,
        leaf: &[u8],
        limit: usize,
    ) -> Result<Vec<StoredMlsOutboxItem>, String>;

    fn acknowledge_outbox(
        &self,
        leaf: &[u8],
        id: MlsOutboxId,
        payload_digest: &[u8; 32],
    ) -> Result<(), String>;
}

/// In-memory implementation for tests and local-only flows.
#[derive(Clone, Default)]
pub struct InMemoryStore {
    inner: Arc<Mutex<InMemoryState>>,
}

#[derive(Default)]
struct InMemoryState {
    checkpoints: HashMap<Vec<u8>, CheckpointBlob>,
    anchors: HashMap<Vec<u8>, u64>,
    outbox: Vec<(Vec<u8>, StoredMlsOutboxItem)>,
}

impl InMemoryStore {
    fn lock(&self) -> Result<MutexGuard<'_, InMemoryState>, String> {
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
        outbox: Vec<MlsOutboxPayload>,
    ) -> Result<(), MlsPersistError> {
        if leaf.len() != 32 {
            return Err(MlsPersistError::Rejected(
                "MLS leaf must be exactly 32 bytes".into(),
            ));
        }
        if outbox.len() > MAX_OUTBOX_ITEMS_PER_GENERATION {
            return Err(MlsPersistError::Rejected(
                "MLS outbox batch has too many items".into(),
            ));
        }
        let expected_next = match expected_previous_generation {
            Some(previous) => previous.checked_add(1).ok_or_else(|| {
                MlsPersistError::Rejected("MLS checkpoint generation exhausted".into())
            })?,
            None => 0,
        };
        if checkpoint.generation() != expected_next {
            return Err(MlsPersistError::Rejected(
                "MLS checkpoint generation is not consecutive".into(),
            ));
        }

        let mut state = self.lock().map_err(MlsPersistError::Rejected)?;
        let actual_previous = state.checkpoints.get(leaf).map(CheckpointBlob::generation);
        if actual_previous != expected_previous_generation {
            return Err(MlsPersistError::Rejected(
                "MLS checkpoint compare-and-swap conflict".into(),
            ));
        }
        let anchor = state.anchors.get(leaf).copied();
        if expected_previous_generation.is_none() {
            if anchor.is_some_and(|generation| generation != 0) {
                return Err(MlsPersistError::Rejected(
                    "MLS rollback anchor conflicts with initial checkpoint".into(),
                ));
            }
        } else if anchor != expected_previous_generation {
            return Err(MlsPersistError::Rejected(
                "MLS rollback anchor does not match the previous checkpoint".into(),
            ));
        }

        let mut stored = Vec::with_capacity(outbox.len());
        for (index, payload) in outbox.into_iter().enumerate() {
            let item_index = u8::try_from(index)
                .map_err(|_| MlsPersistError::Rejected("MLS outbox item index overflow".into()))?;
            let payload_digest: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
            let id = derive_outbox_id(
                leaf,
                expected_next,
                item_index,
                payload.kind(),
                payload.group_id(),
                &payload_digest,
            );
            let item = StoredMlsOutboxItem::from_parts(
                leaf,
                id,
                expected_next,
                item_index,
                payload.kind(),
                payload.group_id().copied(),
                payload_digest,
                payload.as_bytes().to_vec(),
            )
            .map_err(MlsPersistError::Rejected)?;
            stored.push((leaf.to_vec(), item));
        }

        state.checkpoints.insert(leaf.to_vec(), checkpoint);
        state.outbox.extend(stored);
        state.anchors.insert(leaf.to_vec(), expected_next);
        Ok(())
    }

    fn load_checkpoint(&self, leaf: &[u8]) -> Result<Option<CheckpointBlob>, String> {
        let state = self.lock()?;
        let checkpoint = state.checkpoints.get(leaf).cloned();
        match (checkpoint.as_ref(), state.anchors.get(leaf)) {
            (None, None) => Ok(None),
            (Some(checkpoint), Some(anchor)) if checkpoint.generation() == *anchor => {
                Ok(checkpoint.cloned())
            }
            (Some(_), None) => Err("MLS rollback anchor is missing".into()),
            (None, Some(_)) => Err("MLS rollback anchor exists without a checkpoint".into()),
            (Some(_), Some(_)) => Err("MLS checkpoint conflicts with rollback anchor".into()),
        }
    }

    fn load_pending_outbox(
        &self,
        leaf: &[u8],
        limit: usize,
    ) -> Result<Vec<StoredMlsOutboxItem>, String> {
        if limit == 0 || limit > 256 {
            return Err("MLS outbox page limit is invalid".into());
        }
        Ok(self
            .lock()?
            .outbox
            .iter()
            .filter(|(stored_leaf, _)| stored_leaf.as_slice() == leaf)
            .take(limit)
            .map(|(_, item)| item.clone())
            .collect())
    }

    fn acknowledge_outbox(
        &self,
        leaf: &[u8],
        id: MlsOutboxId,
        payload_digest: &[u8; 32],
    ) -> Result<(), String> {
        let mut state = self.lock()?;
        let index = state
            .outbox
            .iter()
            .position(|(stored_leaf, item)| stored_leaf.as_slice() == leaf && item.id() == id)
            .ok_or_else(|| "MLS outbox item is unknown".to_string())?;
        if state.outbox[index].1.payload_digest() != payload_digest {
            return Err("MLS outbox acknowledgement digest mismatch".into());
        }
        state.outbox.remove(index);
        Ok(())
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

    const LEAF: &[u8; 32] = &[0xA1; 32];

    fn sample_checkpoint() -> CheckpointBlob {
        let values = HashMap::from([
            (b"bravo".to_vec(), b"two".to_vec()),
            (b"alpha".to_vec(), b"one".to_vec()),
        ]);
        encode_checkpoint(LEAF, 7, b"signer", &values).expect("encode")
    }

    #[test]
    fn checkpoint_is_canonical_and_bound_to_leaf_and_generation() {
        let first = sample_checkpoint();
        let second = sample_checkpoint();
        assert_eq!(first.as_bytes(), second.as_bytes());

        let decoded = decode_checkpoint(LEAF, &first).expect("decode");
        assert_eq!(decoded.generation, 7);
        assert_eq!(decoded.signer, b"signer");
        assert_eq!(decoded.entries[0].0, b"alpha");
        assert_eq!(decoded.entries[1].0, b"bravo");

        assert!(decode_checkpoint(&[0xB2; 32], &first).is_err());
        let wrong_generation =
            CheckpointBlob::from_parts(8, first.as_bytes().to_vec()).expect("blob");
        assert!(decode_checkpoint(LEAF, &wrong_generation).is_err());
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
    fn checkpoint_rejects_declared_oversize_and_duplicate_keys() {
        let checkpoint = sample_checkpoint();

        let mut oversized = checkpoint.as_bytes().to_vec();
        let signer_length_offset = 8 + 2 + 2 + 8 + 32;
        oversized[signer_length_offset..signer_length_offset + 4]
            .copy_from_slice(&((MAX_CHECKPOINT_SIGNER_BYTES as u32) + 1).to_be_bytes());
        let oversized = CheckpointBlob::from_parts(7, oversized).expect("blob");
        assert!(decode_checkpoint(b"leaf-a", &oversized).is_err());

        let mut duplicate = checkpoint.as_bytes().to_vec();
        let signer_len = 6;
        let first_record_len = 8 + 5 + 3;
        let second_key_offset = CHECKPOINT_HEADER_BYTES + signer_len + first_record_len + 8;
        duplicate[second_key_offset..second_key_offset + 5].copy_from_slice(b"alpha");
        let body_digest = Sha256::digest(&duplicate[CHECKPOINT_HEADER_BYTES..]);
        let digest_offset = CHECKPOINT_HEADER_BYTES - 32;
        duplicate[digest_offset..CHECKPOINT_HEADER_BYTES].copy_from_slice(&body_digest);
        let duplicate = CheckpointBlob::from_parts(7, duplicate).expect("blob");
        assert!(decode_checkpoint(b"leaf-a", &duplicate).is_err());
    }

    #[test]
    fn memory_store_enforces_consecutive_compare_and_swap() {
        let store = InMemoryStore::default();
        let checkpoint = sample_checkpoint();
        assert!(store
            .save_checkpoint(LEAF, Some(6), checkpoint.clone(), Vec::new())
            .is_err());
        assert!(store
            .save_checkpoint(LEAF, None, checkpoint.clone(), Vec::new())
            .is_err());

        let initial = encode_checkpoint(LEAF, 0, b"signer", &HashMap::new()).unwrap();
        store
            .save_checkpoint(LEAF, None, initial, Vec::new())
            .expect("initial save");
        assert!(store
            .save_checkpoint(LEAF, None, checkpoint.clone(), Vec::new())
            .is_err());
        assert!(store
            .save_checkpoint(LEAF, Some(0), checkpoint, Vec::new())
            .is_err());
    }
}
