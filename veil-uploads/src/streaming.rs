//! Bounded-memory resumable upload and download pipeline.
//!
//! A [`StreamingUploadPlan`] is prepared once, before the tus resource is
//! created. It fixes the v2 format, nonce prefix, ciphertext geometry, source
//! chunk digests and a binding to the content key. Resume must reuse that plan;
//! preparing a new plan for an existing tus resource is intentionally unsafe
//! and unsupported.

use std::io;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use futures_util::TryStreamExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::fs::{File, OpenOptions};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter, SeekFrom,
};
use tokio_util::io::StreamReader;
use zeroize::Zeroizing;

use veil_crypto::chunked_aead::{
    open_chunk, random_nonce_prefix, seal_chunk, ChunkedAeadError, CHUNK_FORMAT_VERSION,
    CHUNK_PLAINTEXT_SIZE, FULL_CHUNK_CIPHERTEXT_SIZE, TAG_LEN,
};

use crate::client::{TusClient, TusClientError, TusUploadHandle, TusUploadInit};
use crate::stream::EncryptedFileMeta;

/// Largest plaintext accepted by the streaming API: exactly 2 GiB.
pub const MAX_STREAM_PLAINTEXT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

const PLAN_BINDING_DOMAIN: &[u8] = b"veil/upload-plan/v2";

#[derive(Debug, Error)]
pub enum StreamingError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("aead: {0}")]
    Aead(#[from] ChunkedAeadError),
    #[error("tus: {0}")]
    Tus(#[from] TusClientError),
    #[error("plaintext exceeds the streaming {0}-byte limit")]
    FileTooLarge(u64),
    #[error("invalid streaming metadata: {0}")]
    InvalidMetadata(String),
    #[error("upload plan is not bound to the supplied content key")]
    KeyMismatch,
    #[error("source file no longer matches upload plan at chunk {chunk_index}")]
    SourceChanged { chunk_index: u64 },
    #[error("server offset {offset} exceeds ciphertext length {ciphertext_size}")]
    OffsetOutOfRange { offset: u64, ciphertext_size: u64 },
    #[error("server acknowledged offset {actual}, expected {expected}")]
    UnexpectedServerOffset { expected: u64, actual: u64 },
    #[error("tus resource length {actual} does not match plan length {expected}")]
    UnexpectedUploadLength { expected: u64, actual: u64 },
    #[error("ciphertext stream length does not match metadata")]
    CiphertextLength,
    #[error("destination already exists")]
    DestinationExists,
    #[error("transfer cancelled")]
    Cancelled,
}

/// Fully checked ciphertext geometry. It is arithmetic-only and can represent
/// the 2 GiB boundary without allocating file-sized buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamingGeometry {
    pub plaintext_size: u64,
    pub ciphertext_size: u64,
    pub chunk_count: u64,
    pub final_plaintext_size: u64,
    pub final_ciphertext_size: u64,
}

impl StreamingGeometry {
    pub fn chunk_plaintext_size(&self, chunk_index: u64) -> Result<usize, StreamingError> {
        if chunk_index >= self.chunk_count {
            return Err(StreamingError::InvalidMetadata(format!(
                "chunk index {chunk_index} is outside {} chunks",
                self.chunk_count
            )));
        }
        let bytes = if chunk_index + 1 == self.chunk_count {
            self.final_plaintext_size
        } else {
            u64::try_from(CHUNK_PLAINTEXT_SIZE).expect("chunk size fits u64")
        };
        usize::try_from(bytes)
            .map_err(|_| StreamingError::InvalidMetadata("chunk length overflow".to_string()))
    }

    pub fn chunk_ciphertext_size(&self, chunk_index: u64) -> Result<usize, StreamingError> {
        let plaintext = self.chunk_plaintext_size(chunk_index)?;
        plaintext
            .checked_add(TAG_LEN)
            .ok_or_else(|| StreamingError::InvalidMetadata("ciphertext chunk overflow".to_string()))
    }
}

/// Map of a server-confirmed ciphertext offset back to the deterministic v2
/// chunk that must be regenerated. `within_chunk` may point into ciphertext or
/// its authentication tag; the exact suffix is safe to resend because the
/// complete chunk is reproduced with the same key, prefix, index and plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumePosition {
    pub chunk_index: u64,
    pub within_chunk: usize,
    pub confirmed_plaintext: u64,
    pub complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaintextRangePlan {
    pub plaintext_start: u64,
    pub plaintext_end_inclusive: u64,
    pub first_chunk: u64,
    pub last_chunk: u64,
    pub ciphertext_start: u64,
    pub ciphertext_end_inclusive: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStage {
    Preparing,
    Verifying,
    Uploading,
    Downloading,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferProgress {
    pub stage: TransferStage,
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
    pub total_plaintext_bytes: u64,
    pub total_ciphertext_bytes: u64,
}

/// Synchronous hooks deliberately run only between bounded chunks. A caller can
/// back `is_cancelled` with an atomic flag; an in-flight HTTP read is additionally
/// bounded by the tus client's read timeout.
pub trait TransferControl {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn on_progress(&mut self, _progress: TransferProgress) {}
}

impl TransferControl for () {}

/// Sensitive local resume state. Persist it only alongside the wrapped content
/// key in encrypted client storage; `source_chunk_sha256` must not be sent as
/// plaintext tus metadata because it fingerprints the local file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingUploadPlan {
    pub metadata: EncryptedFileMeta,
    pub source_chunk_sha256: Vec<[u8; 32]>,
    pub key_binding: [u8; 32],
}

impl StreamingUploadPlan {
    pub fn validate(&self, key: &[u8; 32]) -> Result<StreamingGeometry, StreamingError> {
        let geometry = validate_streaming_metadata(&self.metadata)?;
        if self.source_chunk_sha256.len()
            != usize::try_from(geometry.chunk_count).map_err(|_| {
                StreamingError::InvalidMetadata("chunk digest count overflow".to_string())
            })?
        {
            return Err(StreamingError::InvalidMetadata(
                "source chunk digest count does not match geometry".to_string(),
            ));
        }
        if compute_key_binding(key, &self.metadata, &self.source_chunk_sha256) != self.key_binding {
            return Err(StreamingError::KeyMismatch);
        }
        Ok(geometry)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamingUploadResult {
    pub resumed_from: u64,
    pub final_offset: u64,
}

pub fn geometry_for_plaintext(plaintext_size: u64) -> Result<StreamingGeometry, StreamingError> {
    if plaintext_size > MAX_STREAM_PLAINTEXT_BYTES {
        return Err(StreamingError::FileTooLarge(MAX_STREAM_PLAINTEXT_BYTES));
    }
    let chunk_size = u64::try_from(CHUNK_PLAINTEXT_SIZE).expect("chunk size fits u64");
    let chunk_count = if plaintext_size == 0 {
        1
    } else {
        plaintext_size.div_ceil(chunk_size)
    };
    let final_plaintext_size = if plaintext_size == 0 {
        0
    } else {
        plaintext_size
            .checked_sub((chunk_count - 1).checked_mul(chunk_size).ok_or_else(|| {
                StreamingError::InvalidMetadata("plaintext geometry overflow".to_string())
            })?)
            .ok_or_else(|| {
                StreamingError::InvalidMetadata("plaintext geometry underflow".to_string())
            })?
    };
    let authentication_bytes = chunk_count
        .checked_mul(u64::try_from(TAG_LEN).expect("tag size fits u64"))
        .ok_or_else(|| StreamingError::InvalidMetadata("tag geometry overflow".to_string()))?;
    let ciphertext_size = plaintext_size
        .checked_add(authentication_bytes)
        .ok_or_else(|| {
            StreamingError::InvalidMetadata("ciphertext geometry overflow".to_string())
        })?;
    let final_ciphertext_size = final_plaintext_size
        .checked_add(u64::try_from(TAG_LEN).expect("tag size fits u64"))
        .ok_or_else(|| {
            StreamingError::InvalidMetadata("final chunk geometry overflow".to_string())
        })?;
    Ok(StreamingGeometry {
        plaintext_size,
        ciphertext_size,
        chunk_count,
        final_plaintext_size,
        final_ciphertext_size,
    })
}

pub fn validate_streaming_metadata(
    metadata: &EncryptedFileMeta,
) -> Result<StreamingGeometry, StreamingError> {
    if metadata.format_version != CHUNK_FORMAT_VERSION {
        return Err(StreamingError::InvalidMetadata(format!(
            "unsupported chunked-AEAD format version {} (expected {})",
            metadata.format_version, CHUNK_FORMAT_VERSION
        )));
    }
    let geometry = geometry_for_plaintext(metadata.plaintext_size)?;
    if metadata.chunk_count != geometry.chunk_count
        || metadata.ciphertext_size != geometry.ciphertext_size
    {
        return Err(StreamingError::InvalidMetadata(
            "chunk count or ciphertext size does not match plaintext geometry".to_string(),
        ));
    }
    Ok(geometry)
}

pub fn ciphertext_resume_position(
    metadata: &EncryptedFileMeta,
    offset: u64,
) -> Result<ResumePosition, StreamingError> {
    let geometry = validate_streaming_metadata(metadata)?;
    if offset > geometry.ciphertext_size {
        return Err(StreamingError::OffsetOutOfRange {
            offset,
            ciphertext_size: geometry.ciphertext_size,
        });
    }
    if offset == geometry.ciphertext_size {
        return Ok(ResumePosition {
            chunk_index: geometry.chunk_count,
            within_chunk: 0,
            confirmed_plaintext: geometry.plaintext_size,
            complete: true,
        });
    }

    let full_ciphertext_size =
        u64::try_from(FULL_CHUNK_CIPHERTEXT_SIZE).expect("chunk size fits u64");
    let chunk_index = offset / full_ciphertext_size;
    if chunk_index >= geometry.chunk_count {
        return Err(StreamingError::OffsetOutOfRange {
            offset,
            ciphertext_size: geometry.ciphertext_size,
        });
    }
    let within_chunk = usize::try_from(offset % full_ciphertext_size)
        .map_err(|_| StreamingError::InvalidMetadata("resume offset overflow".to_string()))?;
    if within_chunk >= geometry.chunk_ciphertext_size(chunk_index)? {
        return Err(StreamingError::OffsetOutOfRange {
            offset,
            ciphertext_size: geometry.ciphertext_size,
        });
    }
    let confirmed_plaintext = chunk_index
        .checked_mul(u64::try_from(CHUNK_PLAINTEXT_SIZE).expect("chunk size fits u64"))
        .ok_or_else(|| {
            StreamingError::InvalidMetadata("resume plaintext offset overflow".to_string())
        })?;
    Ok(ResumePosition {
        chunk_index,
        within_chunk,
        confirmed_plaintext,
        complete: false,
    })
}

/// Map one inclusive plaintext HTTP range to the minimum complete encrypted
/// chunks required to authenticate it. Callers must fetch the exact returned
/// ciphertext range; partial AEAD chunks are never decrypted.
pub fn ciphertext_range_for_plaintext(
    metadata: &EncryptedFileMeta,
    plaintext_start: u64,
    plaintext_end_inclusive: u64,
) -> Result<PlaintextRangePlan, StreamingError> {
    let geometry = validate_streaming_metadata(metadata)?;
    if geometry.plaintext_size == 0
        || plaintext_start > plaintext_end_inclusive
        || plaintext_end_inclusive >= geometry.plaintext_size
    {
        return Err(StreamingError::InvalidMetadata(
            "plaintext range is outside the attachment".to_string(),
        ));
    }
    let chunk_size = u64::try_from(CHUNK_PLAINTEXT_SIZE).expect("chunk size fits u64");
    let full_ciphertext =
        u64::try_from(FULL_CHUNK_CIPHERTEXT_SIZE).expect("full ciphertext chunk size fits u64");
    let first_chunk = plaintext_start / chunk_size;
    let last_chunk = plaintext_end_inclusive / chunk_size;
    let ciphertext_start = first_chunk
        .checked_mul(full_ciphertext)
        .ok_or_else(|| StreamingError::InvalidMetadata("range offset overflow".to_string()))?;
    let last_offset = last_chunk
        .checked_mul(full_ciphertext)
        .ok_or_else(|| StreamingError::InvalidMetadata("range offset overflow".to_string()))?;
    let last_length = u64::try_from(geometry.chunk_ciphertext_size(last_chunk)?)
        .expect("ciphertext chunk size fits u64");
    let ciphertext_end_inclusive = last_offset
        .checked_add(last_length)
        .and_then(|exclusive| exclusive.checked_sub(1))
        .ok_or_else(|| StreamingError::InvalidMetadata("range end overflow".to_string()))?;
    Ok(PlaintextRangePlan {
        plaintext_start,
        plaintext_end_inclusive,
        first_chunk,
        last_chunk,
        ciphertext_start,
        ciphertext_end_inclusive,
    })
}

/// Authenticate complete fetched chunks and return only the requested
/// plaintext slice. This never writes decrypted media to disk.
pub fn decrypt_fetched_plaintext_range(
    key: &[u8; 32],
    metadata: &EncryptedFileMeta,
    plan: &PlaintextRangePlan,
    fetched_ciphertext: &[u8],
) -> Result<Vec<u8>, StreamingError> {
    let geometry = validate_streaming_metadata(metadata)?;
    let expected = plan
        .ciphertext_end_inclusive
        .checked_sub(plan.ciphertext_start)
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| StreamingError::InvalidMetadata("range length overflow".to_string()))?;
    if u64::try_from(fetched_ciphertext.len()).unwrap_or(u64::MAX) != expected {
        return Err(StreamingError::CiphertextLength);
    }
    let chunk_size = u64::try_from(CHUNK_PLAINTEXT_SIZE).expect("chunk size fits u64");
    let mut decrypted = Zeroizing::new(Vec::new());
    let mut cursor = 0usize;
    for chunk_index in plan.first_chunk..=plan.last_chunk {
        let ciphertext_length = geometry.chunk_ciphertext_size(chunk_index)?;
        let next = cursor
            .checked_add(ciphertext_length)
            .ok_or_else(|| StreamingError::InvalidMetadata("chunk cursor overflow".to_string()))?;
        if next > fetched_ciphertext.len() {
            return Err(StreamingError::CiphertextLength);
        }
        let is_final = chunk_index + 1 == geometry.chunk_count;
        let plaintext = open_chunk(
            key,
            &metadata.nonce_prefix,
            chunk_index,
            is_final,
            &fetched_ciphertext[cursor..next],
        )?;
        decrypted.extend_from_slice(&plaintext);
        cursor = next;
    }
    if cursor != fetched_ciphertext.len() {
        return Err(StreamingError::CiphertextLength);
    }
    let fetched_plaintext_start = plan
        .first_chunk
        .checked_mul(chunk_size)
        .ok_or_else(|| StreamingError::InvalidMetadata("plaintext offset overflow".to_string()))?;
    let relative_start = usize::try_from(
        plan.plaintext_start
            .checked_sub(fetched_plaintext_start)
            .ok_or_else(|| StreamingError::InvalidMetadata("range start underflow".to_string()))?,
    )
    .map_err(|_| StreamingError::InvalidMetadata("range start overflow".to_string()))?;
    let output_length = usize::try_from(
        plan.plaintext_end_inclusive
            .checked_sub(plan.plaintext_start)
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| StreamingError::InvalidMetadata("range output overflow".to_string()))?,
    )
    .map_err(|_| StreamingError::InvalidMetadata("range output overflow".to_string()))?;
    let relative_end = relative_start
        .checked_add(output_length)
        .ok_or_else(|| StreamingError::InvalidMetadata("range slice overflow".to_string()))?;
    if relative_end > decrypted.len() {
        return Err(StreamingError::CiphertextLength);
    }
    Ok(decrypted[relative_start..relative_end].to_vec())
}

pub async fn prepare_streaming_upload(
    key: &[u8; 32],
    source: &Path,
) -> Result<StreamingUploadPlan, StreamingError> {
    prepare_streaming_upload_with_control(key, source, &mut ()).await
}

pub async fn prepare_streaming_upload_with_control<C: TransferControl + ?Sized>(
    key: &[u8; 32],
    source: &Path,
    control: &mut C,
) -> Result<StreamingUploadPlan, StreamingError> {
    ensure_not_cancelled(control)?;
    let file = File::open(source).await?;
    let plaintext_size = file.metadata().await?.len();
    let geometry = geometry_for_plaintext(plaintext_size)?;
    let nonce_prefix = random_nonce_prefix();
    let metadata = EncryptedFileMeta {
        format_version: CHUNK_FORMAT_VERSION,
        nonce_prefix,
        chunk_count: geometry.chunk_count,
        plaintext_size,
        ciphertext_size: geometry.ciphertext_size,
    };
    let source_chunk_sha256 = collect_source_digests(
        BufReader::new(file),
        &geometry,
        TransferStage::Preparing,
        control,
    )
    .await?;
    let key_binding = compute_key_binding(key, &metadata, &source_chunk_sha256);
    Ok(StreamingUploadPlan {
        metadata,
        source_chunk_sha256,
        key_binding,
    })
}

async fn verify_source_against_plan<C: TransferControl + ?Sized>(
    source: &Path,
    plan: &StreamingUploadPlan,
    geometry: &StreamingGeometry,
    control: &mut C,
) -> Result<(), StreamingError> {
    let file = File::open(source).await?;
    if file.metadata().await?.len() != geometry.plaintext_size {
        return Err(StreamingError::SourceChanged { chunk_index: 0 });
    }
    let actual = collect_source_digests(
        BufReader::new(file),
        geometry,
        TransferStage::Verifying,
        control,
    )
    .await?;
    if actual != plan.source_chunk_sha256 {
        let mismatch = actual
            .iter()
            .zip(&plan.source_chunk_sha256)
            .position(|(left, right)| left != right)
            .unwrap_or(0);
        return Err(StreamingError::SourceChanged {
            chunk_index: u64::try_from(mismatch).unwrap_or(u64::MAX),
        });
    }
    Ok(())
}

async fn collect_source_digests<R: AsyncRead + Unpin, C: TransferControl + ?Sized>(
    mut reader: R,
    geometry: &StreamingGeometry,
    stage: TransferStage,
    control: &mut C,
) -> Result<Vec<[u8; 32]>, StreamingError> {
    let capacity = usize::try_from(geometry.chunk_count)
        .map_err(|_| StreamingError::InvalidMetadata("digest count overflow".to_string()))?;
    let mut digests = Vec::with_capacity(capacity);
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_PLAINTEXT_SIZE]);
    let mut plaintext_bytes = 0u64;

    for chunk_index in 0..geometry.chunk_count {
        ensure_not_cancelled(control)?;
        let length = geometry.chunk_plaintext_size(chunk_index)?;
        read_source_exact(&mut reader, &mut buffer[..length], chunk_index).await?;
        digests.push(Sha256::digest(&buffer[..length]).into());
        plaintext_bytes = plaintext_bytes
            .checked_add(u64::try_from(length).expect("chunk size fits u64"))
            .ok_or_else(|| StreamingError::InvalidMetadata("progress overflow".to_string()))?;
        control.on_progress(TransferProgress {
            stage,
            plaintext_bytes,
            ciphertext_bytes: 0,
            total_plaintext_bytes: geometry.plaintext_size,
            total_ciphertext_bytes: geometry.ciphertext_size,
        });
    }
    let mut extra = [0u8; 1];
    if reader.read(&mut extra).await? != 0 {
        return Err(StreamingError::SourceChanged {
            chunk_index: geometry.chunk_count,
        });
    }
    Ok(digests)
}

async fn read_source_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
    chunk_index: u64,
) -> Result<(), StreamingError> {
    if buffer.is_empty() {
        return Ok(());
    }
    match reader.read_exact(buffer).await {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(StreamingError::SourceChanged { chunk_index })
        }
        Err(error) => Err(StreamingError::Io(error)),
    }
}

fn compute_key_binding(
    key: &[u8; 32],
    metadata: &EncryptedFileMeta,
    source_chunk_sha256: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_BINDING_DOMAIN);
    hasher.update([metadata.format_version]);
    hasher.update(metadata.nonce_prefix);
    hasher.update(metadata.chunk_count.to_be_bytes());
    hasher.update(metadata.plaintext_size.to_be_bytes());
    hasher.update(metadata.ciphertext_size.to_be_bytes());
    for digest in source_chunk_sha256 {
        hasher.update(digest);
    }
    hasher.update(key);
    hasher.finalize().into()
}

fn ensure_not_cancelled<C: TransferControl + ?Sized>(control: &C) -> Result<(), StreamingError> {
    if control.is_cancelled() {
        Err(StreamingError::Cancelled)
    } else {
        Ok(())
    }
}

impl TusClient {
    /// Create a tus resource with the exact ciphertext length fixed by `plan`.
    pub async fn create_streaming_upload(
        &self,
        key: &[u8; 32],
        plan: &StreamingUploadPlan,
        init: &TusUploadInit<'_>,
    ) -> Result<TusUploadHandle, StreamingError> {
        plan.validate(key)?;
        Ok(self
            .create_upload(plan.metadata.ciphertext_size, init)
            .await?)
    }

    /// Verify the source and plan, HEAD the tus resource and regenerate only
    /// the ciphertext suffix not yet confirmed by the server.
    pub async fn upload_file_streaming<C: TransferControl + ?Sized>(
        &self,
        handle: &TusUploadHandle,
        key: &[u8; 32],
        plan: &StreamingUploadPlan,
        source: &Path,
        control: &mut C,
    ) -> Result<StreamingUploadResult, StreamingError> {
        ensure_not_cancelled(control)?;
        let geometry = plan.validate(key)?;
        verify_source_against_plan(source, plan, &geometry, control).await?;
        ensure_not_cancelled(control)?;

        let state = self.upload_state(handle).await?;
        if state.length != geometry.ciphertext_size {
            return Err(StreamingError::UnexpectedUploadLength {
                expected: geometry.ciphertext_size,
                actual: state.length,
            });
        }
        let resumed_from = state.offset;
        let mut position = ciphertext_resume_position(&plan.metadata, resumed_from)?;
        control.on_progress(TransferProgress {
            stage: TransferStage::Uploading,
            plaintext_bytes: position.confirmed_plaintext,
            ciphertext_bytes: resumed_from,
            total_plaintext_bytes: geometry.plaintext_size,
            total_ciphertext_bytes: geometry.ciphertext_size,
        });
        if position.complete {
            return Ok(StreamingUploadResult {
                resumed_from,
                final_offset: resumed_from,
            });
        }

        let mut file = BufReader::new(File::open(source).await?);
        let plaintext_offset = position
            .chunk_index
            .checked_mul(u64::try_from(CHUNK_PLAINTEXT_SIZE).expect("chunk size fits u64"))
            .ok_or_else(|| StreamingError::InvalidMetadata("source seek overflow".to_string()))?;
        file.seek(SeekFrom::Start(plaintext_offset)).await?;
        let mut plaintext = Zeroizing::new(vec![0u8; CHUNK_PLAINTEXT_SIZE]);
        let mut confirmed_offset = resumed_from;

        while position.chunk_index < geometry.chunk_count {
            ensure_not_cancelled(control)?;
            let chunk_index = position.chunk_index;
            let plaintext_length = geometry.chunk_plaintext_size(chunk_index)?;
            read_source_exact(&mut file, &mut plaintext[..plaintext_length], chunk_index).await?;
            let digest: [u8; 32] = Sha256::digest(&plaintext[..plaintext_length]).into();
            if digest
                != plan.source_chunk_sha256[usize::try_from(chunk_index).map_err(|_| {
                    StreamingError::InvalidMetadata("chunk index overflow".to_string())
                })?]
            {
                return Err(StreamingError::SourceChanged { chunk_index });
            }

            let is_final = chunk_index + 1 == geometry.chunk_count;
            let ciphertext = seal_chunk(
                key,
                &plan.metadata.nonce_prefix,
                chunk_index,
                is_final,
                &plaintext[..plaintext_length],
            )?;
            if position.within_chunk >= ciphertext.len() {
                return Err(StreamingError::OffsetOutOfRange {
                    offset: confirmed_offset,
                    ciphertext_size: geometry.ciphertext_size,
                });
            }
            let payload = Bytes::from(ciphertext).slice(position.within_chunk..);
            let expected_offset = confirmed_offset
                .checked_add(u64::try_from(payload.len()).expect("chunk size fits u64"))
                .ok_or_else(|| {
                    StreamingError::InvalidMetadata("upload offset overflow".to_string())
                })?;
            let actual_offset = self.write_chunk(handle, confirmed_offset, payload).await?;
            if actual_offset != expected_offset || actual_offset > geometry.ciphertext_size {
                return Err(StreamingError::UnexpectedServerOffset {
                    expected: expected_offset,
                    actual: actual_offset,
                });
            }
            confirmed_offset = actual_offset;
            let plaintext_bytes = plaintext_offset_for_completed_chunk(&geometry, chunk_index)?;
            control.on_progress(TransferProgress {
                stage: TransferStage::Uploading,
                plaintext_bytes,
                ciphertext_bytes: confirmed_offset,
                total_plaintext_bytes: geometry.plaintext_size,
                total_ciphertext_bytes: geometry.ciphertext_size,
            });
            position = ResumePosition {
                chunk_index: chunk_index + 1,
                within_chunk: 0,
                confirmed_plaintext: plaintext_bytes,
                complete: confirmed_offset == geometry.ciphertext_size,
            };
        }

        if confirmed_offset != geometry.ciphertext_size {
            return Err(StreamingError::UnexpectedServerOffset {
                expected: geometry.ciphertext_size,
                actual: confirmed_offset,
            });
        }
        Ok(StreamingUploadResult {
            resumed_from,
            final_offset: confirmed_offset,
        })
    }

    /// Download ciphertext as an HTTP byte stream and decrypt it directly into
    /// an atomic destination temp file. No complete ciphertext blob is built.
    pub async fn download_file_streaming<C: TransferControl + ?Sized>(
        &self,
        file_id: &str,
        key: &[u8; 32],
        metadata: &EncryptedFileMeta,
        destination: &Path,
        control: &mut C,
    ) -> Result<(), StreamingError> {
        ensure_not_cancelled(control)?;
        let geometry = validate_streaming_metadata(metadata)?;
        let response = self.download_stream_response(file_id).await?;
        if response
            .content_length()
            .is_some_and(|length| length != geometry.ciphertext_size)
        {
            return Err(StreamingError::CiphertextLength);
        }
        let stream = response.bytes_stream().map_err(io::Error::other);
        let reader = StreamReader::new(stream);
        decrypt_reader_to_file(key, metadata, reader, destination, control).await
    }
}

fn plaintext_offset_for_completed_chunk(
    geometry: &StreamingGeometry,
    chunk_index: u64,
) -> Result<u64, StreamingError> {
    if chunk_index + 1 == geometry.chunk_count {
        return Ok(geometry.plaintext_size);
    }
    (chunk_index + 1)
        .checked_mul(u64::try_from(CHUNK_PLAINTEXT_SIZE).expect("chunk size fits u64"))
        .ok_or_else(|| StreamingError::InvalidMetadata("progress overflow".to_string()))
}

pub async fn decrypt_file_streaming<C: TransferControl + ?Sized>(
    key: &[u8; 32],
    metadata: &EncryptedFileMeta,
    ciphertext_path: &Path,
    destination: &Path,
    control: &mut C,
) -> Result<(), StreamingError> {
    ensure_not_cancelled(control)?;
    let file = File::open(ciphertext_path).await?;
    decrypt_reader_to_file(key, metadata, BufReader::new(file), destination, control).await
}

pub async fn decrypt_reader_to_file<R: AsyncRead + Unpin, C: TransferControl + ?Sized>(
    key: &[u8; 32],
    metadata: &EncryptedFileMeta,
    mut ciphertext: R,
    destination: &Path,
    control: &mut C,
) -> Result<(), StreamingError> {
    ensure_not_cancelled(control)?;
    let geometry = validate_streaming_metadata(metadata)?;
    if tokio::fs::try_exists(destination).await? {
        return Err(StreamingError::DestinationExists);
    }
    let (temporary_path, temporary_file) = create_temporary_destination(destination).await?;
    let mut writer = BufWriter::new(temporary_file);

    let operation: Result<(), StreamingError> = async {
        let mut ciphertext_buffer = vec![0u8; FULL_CHUNK_CIPHERTEXT_SIZE];
        let mut plaintext_bytes = 0u64;
        let mut ciphertext_bytes = 0u64;
        for chunk_index in 0..geometry.chunk_count {
            ensure_not_cancelled(control)?;
            let ciphertext_length = geometry.chunk_ciphertext_size(chunk_index)?;
            read_ciphertext_exact(&mut ciphertext, &mut ciphertext_buffer[..ciphertext_length])
                .await?;
            let is_final = chunk_index + 1 == geometry.chunk_count;
            let mut plaintext = Zeroizing::new(open_chunk(
                key,
                &metadata.nonce_prefix,
                chunk_index,
                is_final,
                &ciphertext_buffer[..ciphertext_length],
            )?);
            writer.write_all(&plaintext).await?;
            plaintext.fill(0);
            plaintext_bytes = plaintext_offset_for_completed_chunk(&geometry, chunk_index)?;
            ciphertext_bytes = ciphertext_bytes
                .checked_add(u64::try_from(ciphertext_length).expect("chunk size fits u64"))
                .ok_or_else(|| {
                    StreamingError::InvalidMetadata("download progress overflow".to_string())
                })?;
            control.on_progress(TransferProgress {
                stage: TransferStage::Downloading,
                plaintext_bytes,
                ciphertext_bytes,
                total_plaintext_bytes: geometry.plaintext_size,
                total_ciphertext_bytes: geometry.ciphertext_size,
            });
        }
        let mut extra = [0u8; 1];
        if ciphertext.read(&mut extra).await? != 0 {
            return Err(StreamingError::CiphertextLength);
        }
        if plaintext_bytes != geometry.plaintext_size
            || ciphertext_bytes != geometry.ciphertext_size
        {
            return Err(StreamingError::CiphertextLength);
        }
        writer.flush().await?;
        writer.get_ref().sync_all().await?;
        Ok(())
    }
    .await;

    drop(writer);
    if let Err(error) = operation {
        let _ = tokio::fs::remove_file(&temporary_path).await;
        return Err(error);
    }
    if tokio::fs::try_exists(destination).await? {
        let _ = tokio::fs::remove_file(&temporary_path).await;
        return Err(StreamingError::DestinationExists);
    }
    if let Err(error) = tokio::fs::rename(&temporary_path, destination).await {
        let _ = tokio::fs::remove_file(&temporary_path).await;
        return Err(StreamingError::Io(error));
    }
    Ok(())
}

async fn read_ciphertext_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
) -> Result<(), StreamingError> {
    match reader.read_exact(buffer).await {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(StreamingError::CiphertextLength)
        }
        Err(error) => Err(StreamingError::Io(error)),
    }
}

async fn create_temporary_destination(
    destination: &Path,
) -> Result<(PathBuf, File), StreamingError> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let mut random = rand::rngs::OsRng;
    for _ in 0..8 {
        let suffix = random.next_u64();
        let candidate = parent.join(format!(".veil-decrypt-{suffix:016x}.tmp"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        // Decrypted attachments are sensitive local data. On Unix, do not
        // depend on the process umask to keep the temporary and final inode
        // private; the rename preserves this mode.
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&candidate).await {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(StreamingError::Io(error)),
        }
    }
    Err(StreamingError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique temporary decrypt file",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_range_fetches_complete_chunks_and_authenticates_before_slicing() {
        let key = [0x31u8; 32];
        let prefix = [0x42u8; 16];
        let mut plaintext = vec![0x55u8; CHUNK_PLAINTEXT_SIZE + 23];
        for (index, byte) in plaintext.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let first =
            seal_chunk(&key, &prefix, 0, false, &plaintext[..CHUNK_PLAINTEXT_SIZE]).unwrap();
        let second =
            seal_chunk(&key, &prefix, 1, true, &plaintext[CHUNK_PLAINTEXT_SIZE..]).unwrap();
        let mut ciphertext = first;
        ciphertext.extend_from_slice(&second);
        let metadata = EncryptedFileMeta {
            format_version: CHUNK_FORMAT_VERSION,
            nonce_prefix: prefix,
            chunk_count: 2,
            plaintext_size: plaintext.len() as u64,
            ciphertext_size: ciphertext.len() as u64,
        };
        let start = (CHUNK_PLAINTEXT_SIZE - 7) as u64;
        let end = (CHUNK_PLAINTEXT_SIZE + 9) as u64;
        let plan = ciphertext_range_for_plaintext(&metadata, start, end).unwrap();
        assert_eq!(plan.first_chunk, 0);
        assert_eq!(plan.last_chunk, 1);
        let fetched =
            &ciphertext[plan.ciphertext_start as usize..=plan.ciphertext_end_inclusive as usize];
        let opened = decrypt_fetched_plaintext_range(&key, &metadata, &plan, fetched).unwrap();
        assert_eq!(opened, plaintext[start as usize..=end as usize]);

        let mut tampered = fetched.to_vec();
        tampered[3] ^= 1;
        assert!(decrypt_fetched_plaintext_range(&key, &metadata, &plan, &tampered).is_err());
    }
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

    fn key() -> [u8; 32] {
        [0x42; 32]
    }

    fn metadata_for(plaintext_size: u64) -> EncryptedFileMeta {
        let geometry = geometry_for_plaintext(plaintext_size).unwrap();
        EncryptedFileMeta {
            format_version: CHUNK_FORMAT_VERSION,
            nonce_prefix: [7; 16],
            chunk_count: geometry.chunk_count,
            plaintext_size,
            ciphertext_size: geometry.ciphertext_size,
        }
    }

    async fn write_source(contents: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("source.bin");
        tokio::fs::write(&path, contents).await.unwrap();
        (directory, path)
    }

    #[test]
    fn geometry_covers_boundaries_and_two_gib_without_allocation() {
        let chunk = u64::try_from(CHUNK_PLAINTEXT_SIZE).unwrap();
        let cases = [
            (0, 1, 0),
            (1, 1, 1),
            (chunk - 1, 1, chunk - 1),
            (chunk, 1, chunk),
            (chunk + 1, 2, 1),
            (2 * chunk, 2, chunk),
        ];
        for (plaintext, chunks, final_plaintext) in cases {
            let geometry = geometry_for_plaintext(plaintext).unwrap();
            assert_eq!(geometry.chunk_count, chunks);
            assert_eq!(geometry.final_plaintext_size, final_plaintext);
            assert_eq!(
                geometry.ciphertext_size,
                plaintext + chunks * u64::try_from(TAG_LEN).unwrap()
            );
        }

        let maximum = geometry_for_plaintext(MAX_STREAM_PLAINTEXT_BYTES).unwrap();
        assert_eq!(maximum.chunk_count, 2048);
        assert_eq!(maximum.final_plaintext_size, chunk);
        assert_eq!(
            maximum.ciphertext_size,
            MAX_STREAM_PLAINTEXT_BYTES + 2048 * u64::try_from(TAG_LEN).unwrap()
        );
        assert!(matches!(
            geometry_for_plaintext(MAX_STREAM_PLAINTEXT_BYTES + 1),
            Err(StreamingError::FileTooLarge(MAX_STREAM_PLAINTEXT_BYTES))
        ));
    }

    #[test]
    fn ciphertext_offsets_map_to_exact_chunk_suffixes() {
        let chunk = u64::try_from(CHUNK_PLAINTEXT_SIZE).unwrap();
        let full = u64::try_from(FULL_CHUNK_CIPHERTEXT_SIZE).unwrap();
        let metadata = metadata_for(2 * chunk + 17);

        assert_eq!(
            ciphertext_resume_position(&metadata, 0).unwrap(),
            ResumePosition {
                chunk_index: 0,
                within_chunk: 0,
                confirmed_plaintext: 0,
                complete: false,
            }
        );
        assert_eq!(
            ciphertext_resume_position(&metadata, full - 1).unwrap(),
            ResumePosition {
                chunk_index: 0,
                within_chunk: usize::try_from(full - 1).unwrap(),
                confirmed_plaintext: 0,
                complete: false,
            }
        );
        assert_eq!(
            ciphertext_resume_position(&metadata, full).unwrap(),
            ResumePosition {
                chunk_index: 1,
                within_chunk: 0,
                confirmed_plaintext: chunk,
                complete: false,
            }
        );
        let tail = ciphertext_resume_position(&metadata, metadata.ciphertext_size - 1).unwrap();
        assert_eq!(tail.chunk_index, 2);
        assert_eq!(tail.within_chunk, 17 + TAG_LEN - 1);
        assert!(!tail.complete);
        assert!(
            ciphertext_resume_position(&metadata, metadata.ciphertext_size)
                .unwrap()
                .complete
        );
        assert!(matches!(
            ciphertext_resume_position(&metadata, metadata.ciphertext_size + 1),
            Err(StreamingError::OffsetOutOfRange { .. })
        ));
    }

    #[derive(Default)]
    struct RecordingControl {
        cancelled: bool,
        progress: Vec<TransferProgress>,
    }

    impl TransferControl for RecordingControl {
        fn is_cancelled(&self) -> bool {
            self.cancelled
        }

        fn on_progress(&mut self, progress: TransferProgress) {
            self.progress.push(progress);
        }
    }

    #[tokio::test]
    async fn plan_binds_key_v2_prefix_and_each_source_chunk() {
        let plaintext = vec![3u8; CHUNK_PLAINTEXT_SIZE + 31];
        let (_directory, source) = write_source(&plaintext).await;
        let mut control = RecordingControl::default();
        let plan = prepare_streaming_upload_with_control(&key(), &source, &mut control)
            .await
            .unwrap();

        assert_eq!(plan.metadata.format_version, CHUNK_FORMAT_VERSION);
        assert_eq!(plan.source_chunk_sha256.len(), 2);
        assert!(plan.validate(&key()).is_ok());
        assert!(matches!(
            plan.validate(&[9u8; 32]),
            Err(StreamingError::KeyMismatch)
        ));
        assert!(control
            .progress
            .iter()
            .all(|event| event.stage == TransferStage::Preparing));

        let mut changed = plaintext;
        changed[CHUNK_PLAINTEXT_SIZE + 1] ^= 1;
        tokio::fs::write(&source, changed).await.unwrap();
        let geometry = plan.validate(&key()).unwrap();
        let error = verify_source_against_plan(&source, &plan, &geometry, &mut ())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            StreamingError::SourceChanged { chunk_index: 1 }
        ));
    }

    #[tokio::test]
    async fn cancellation_is_checked_before_source_io() {
        let (directory, source) = write_source(b"cancel").await;
        let mut control = RecordingControl {
            cancelled: true,
            progress: Vec::new(),
        };
        assert!(matches!(
            prepare_streaming_upload_with_control(&key(), &source, &mut control).await,
            Err(StreamingError::Cancelled)
        ));
        assert!(control.progress.is_empty());

        let destination = directory.path().join("cancelled-decrypt.bin");
        assert!(matches!(
            decrypt_reader_to_file(
                &key(),
                &metadata_for(0),
                std::io::Cursor::new(Vec::<u8>::new()),
                &destination,
                &mut control,
            )
            .await,
            Err(StreamingError::Cancelled)
        ));
        assert!(!tokio::fs::try_exists(destination).await.unwrap());
    }

    #[tokio::test]
    async fn streaming_decrypt_is_atomic_and_rejects_tampered_tail() {
        let plaintext = vec![0x5a; CHUNK_PLAINTEXT_SIZE + 19];
        let metadata = metadata_for(u64::try_from(plaintext.len()).unwrap());
        let first = seal_chunk(
            &key(),
            &metadata.nonce_prefix,
            0,
            false,
            &plaintext[..CHUNK_PLAINTEXT_SIZE],
        )
        .unwrap();
        let second = seal_chunk(
            &key(),
            &metadata.nonce_prefix,
            1,
            true,
            &plaintext[CHUNK_PLAINTEXT_SIZE..],
        )
        .unwrap();
        let mut ciphertext = [first, second].concat();
        let directory = tempdir().unwrap();
        let destination = directory.path().join("plain.bin");

        let mut control = RecordingControl::default();
        decrypt_reader_to_file(
            &key(),
            &metadata,
            std::io::Cursor::new(ciphertext.clone()),
            &destination,
            &mut control,
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), plaintext);
        assert_eq!(
            control.progress.last().unwrap().ciphertext_bytes,
            metadata.ciphertext_size
        );

        tokio::fs::remove_file(&destination).await.unwrap();
        *ciphertext.last_mut().unwrap() ^= 1;
        assert!(decrypt_reader_to_file(
            &key(),
            &metadata,
            std::io::Cursor::new(ciphertext),
            &destination,
            &mut (),
        )
        .await
        .is_err());
        assert!(!tokio::fs::try_exists(&destination).await.unwrap());
        let leftovers: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".veil-decrypt-")
            })
            .collect();
        assert!(leftovers.is_empty());
    }

    struct CapturedRequest {
        request_line: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl CapturedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    async fn read_http_request(socket: &mut TcpStream) -> CapturedRequest {
        let mut bytes = Vec::new();
        let header_end = loop {
            let mut buffer = [0u8; 4096];
            let count = socket.read(&mut buffer).await.unwrap();
            assert!(count > 0, "connection ended before request headers");
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let headers_text = std::str::from_utf8(&bytes[..header_end]).unwrap();
        let mut lines = headers_text.split("\r\n");
        let request_line = lines.next().unwrap().to_string();
        let headers: Vec<(String, String)> = lines
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (name, value) = line.split_once(':').unwrap();
                (name.trim().to_string(), value.trim().to_string())
            })
            .collect();
        let content_length = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
            .map(|(_, value)| value.parse::<usize>().unwrap())
            .unwrap_or(0);
        while bytes.len() - header_end < content_length {
            let mut buffer = [0u8; 4096];
            let count = socket.read(&mut buffer).await.unwrap();
            assert!(count > 0, "connection ended before request body");
            bytes.extend_from_slice(&buffer[..count]);
        }
        CapturedRequest {
            request_line,
            headers,
            body: bytes[header_end..header_end + content_length].to_vec(),
        }
    }

    async fn write_response(socket: &mut TcpStream, response: &str) {
        socket.write_all(response.as_bytes()).await.unwrap();
        socket.shutdown().await.unwrap();
    }

    async fn listen_loopback() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        (listener, format!("http://{address}"))
    }

    #[tokio::test]
    async fn tus_resume_replays_only_the_authenticated_chunk_suffix() {
        let plaintext = b"deterministic resume payload".to_vec();
        let (_directory, source) = write_source(&plaintext).await;
        let plan = prepare_streaming_upload(&key(), &source).await.unwrap();
        let expected_ciphertext =
            seal_chunk(&key(), &plan.metadata.nonce_prefix, 0, true, &plaintext).unwrap();
        let resume_offset = 7u64;
        let expected_suffix =
            expected_ciphertext[usize::try_from(resume_offset).unwrap()..].to_vec();
        let total = plan.metadata.ciphertext_size;
        let (listener, base_url) = listen_loopback().await;
        let (captured_tx, captured_rx) = oneshot::channel();

        let server = tokio::spawn(async move {
            let (mut head_socket, _) = listener.accept().await.unwrap();
            let head = read_http_request(&mut head_socket).await;
            assert!(head.request_line.starts_with("HEAD /v1/uploads/files/"));
            write_response(
                &mut head_socket,
                &format!(
                    "HTTP/1.1 200 OK\r\nTus-Resumable: 1.0.0\r\nUpload-Offset: {resume_offset}\r\nUpload-Length: {total}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ),
            )
            .await;

            let (mut patch_socket, _) = listener.accept().await.unwrap();
            let patch = read_http_request(&mut patch_socket).await;
            assert!(patch.request_line.starts_with("PATCH /v1/uploads/files/"));
            assert_eq!(patch.header("Upload-Offset"), Some("7"));
            let new_offset = resume_offset + u64::try_from(patch.body.len()).unwrap();
            write_response(
                &mut patch_socket,
                &format!(
                    "HTTP/1.1 204 No Content\r\nTus-Resumable: 1.0.0\r\nUpload-Offset: {new_offset}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ),
            )
            .await;
            captured_tx.send(patch.body).unwrap();
        });

        let file_id = "0123456789abcdef0123456789abcdef";
        let client = TusClient::new(&base_url, "test-bearer").unwrap();
        let handle = TusUploadHandle {
            file_id: file_id.to_string(),
            absolute_url: format!("{base_url}/v1/uploads/files/{file_id}"),
        };
        let mut control = RecordingControl::default();
        let result = client
            .upload_file_streaming(&handle, &key(), &plan, &source, &mut control)
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(captured_rx.await.unwrap(), expected_suffix);
        assert_eq!(result.resumed_from, resume_offset);
        assert_eq!(result.final_offset, total);
        assert_eq!(control.progress.last().unwrap().ciphertext_bytes, total);
    }

    #[tokio::test]
    async fn tus_head_offset_beyond_plan_is_rejected_before_patch() {
        let (_directory, source) = write_source(b"offset validation").await;
        let plan = prepare_streaming_upload(&key(), &source).await.unwrap();
        let total = plan.metadata.ciphertext_size;
        let (listener, base_url) = listen_loopback().await;
        let listener = Arc::new(listener);
        let server_listener = Arc::clone(&listener);
        let server = tokio::spawn(async move {
            let (mut socket, _) = server_listener.accept().await.unwrap();
            let request = read_http_request(&mut socket).await;
            assert!(request.request_line.starts_with("HEAD /v1/uploads/files/"));
            write_response(
                &mut socket,
                &format!(
                    "HTTP/1.1 200 OK\r\nUpload-Offset: {}\r\nUpload-Length: {total}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    total + 1
                ),
            )
            .await;
        });

        let file_id = "abcdef0123456789abcdef0123456789";
        let client = TusClient::new(&base_url, "test-bearer").unwrap();
        let handle = TusUploadHandle {
            file_id: file_id.to_string(),
            absolute_url: format!("{base_url}/v1/uploads/files/{file_id}"),
        };
        let error = client
            .upload_file_streaming(&handle, &key(), &plan, &source, &mut ())
            .await
            .unwrap_err();
        server.await.unwrap();
        assert!(matches!(error, StreamingError::OffsetOutOfRange { .. }));
    }

    #[test]
    fn v1_metadata_has_no_streaming_fallback() {
        let mut metadata = metadata_for(1);
        metadata.format_version = 1;
        assert!(matches!(
            validate_streaming_metadata(&metadata),
            Err(StreamingError::InvalidMetadata(message)) if message.contains("format version 1")
        ));
    }
}
