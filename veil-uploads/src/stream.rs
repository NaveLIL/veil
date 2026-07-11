//! Streaming encryption helpers.
//!
//! The core function [`encrypt_file_to_chunks`] reads the source file
//! in [`CHUNK_PLAINTEXT_SIZE`](veil_crypto::chunked_aead::CHUNK_PLAINTEXT_SIZE)
//! steps and emits one [`EncryptedChunk`] per call. Callers feed those
//! into the tus client (or any other transport) without needing to
//! buffer the whole file.
//!
//! Decryption is the symmetric inverse: stream ciphertext chunks in
//! and write plaintext to a destination file.

use std::path::Path;

use rand::RngCore;
use thiserror::Error;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use zeroize::Zeroizing;

use veil_crypto::chunked_aead::{
    open_chunk, random_nonce_prefix, seal_chunk, ChunkedAeadError, CHUNK_PLAINTEXT_SIZE,
    NONCE_PREFIX_LEN,
};

/// The current public API returns all ciphertext chunks in a Vec and downloads
/// blobs in one shot. Bound it until a true streaming consumer is exposed.
const MAX_ONE_SHOT_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Per-chunk envelope for upload. The ciphertext is ready to be
/// `PATCH`ed to a tus offset; the index is exposed so callers can
/// implement their own retry/parallelism if they want.
#[derive(Debug, Clone)]
pub struct EncryptedChunk {
    pub index: u64,
    pub is_final: bool,
    pub ciphertext: Vec<u8>,
}

/// Metadata produced by [`encrypt_file_to_chunks`]. The receiver needs
/// the same `nonce_prefix`, `chunk_count` and `plaintext_size` to
/// decrypt; the server treats it as opaque ciphertext metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedFileMeta {
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub chunk_count: u64,
    pub plaintext_size: u64,
    pub ciphertext_size: u64,
}

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("aead: {0}")]
    Aead(#[from] ChunkedAeadError),
    #[error("chunk count mismatch: expected {expected}, got {actual}")]
    ChunkCount { expected: u64, actual: u64 },
    #[error("invalid encrypted file metadata: {0}")]
    InvalidMetadata(String),
    #[error("file exceeds the current {0}-byte one-shot limit")]
    FileTooLarge(u64),
    #[error("destination already exists")]
    DestinationExists,
}

/// Encrypt `src` into a Vec of chunks plus the metadata the receiver
/// needs to decrypt. The function reads the file into memory chunk by
/// chunk; for very large files prefer the streaming variant
/// (`encrypt_file_streaming`, exposed once the upload pipeline can
/// consume an async stream — Phase 3 v1 ships this simpler API first).
pub async fn encrypt_file_to_chunks(
    key: &[u8; 32],
    src: &Path,
) -> Result<(Vec<EncryptedChunk>, EncryptedFileMeta), StreamError> {
    let nonce_prefix = random_nonce_prefix();
    let file = File::open(src).await?;
    let plaintext_size = file.metadata().await?.len();
    if plaintext_size > MAX_ONE_SHOT_FILE_BYTES {
        return Err(StreamError::FileTooLarge(MAX_ONE_SHOT_FILE_BYTES));
    }
    let mut reader = BufReader::with_capacity(CHUNK_PLAINTEXT_SIZE, file);

    let mut chunks = Vec::new();
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_PLAINTEXT_SIZE]);
    let mut idx: u64 = 0;
    let mut bytes_consumed: u64 = 0;
    let mut ciphertext_size: u64 = 0;

    loop {
        let mut filled = 0usize;
        // BufReader::read returns short reads; loop until full buffer
        // or EOF so we know whether this is the final chunk.
        while filled < buf.len() {
            let n = reader.read(&mut buf[filled..]).await?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            // Empty file — emit one zero-length final chunk so the
            // receiver still authenticates the truncation flag.
            if idx == 0 {
                let ct = seal_chunk(key, &nonce_prefix, 0, true, &[])?;
                ciphertext_size += ct.len() as u64;
                chunks.push(EncryptedChunk {
                    index: 0,
                    is_final: true,
                    ciphertext: ct,
                });
                idx = 1;
            }
            break;
        }
        bytes_consumed += filled as u64;
        let is_final = bytes_consumed >= plaintext_size;
        let ct = seal_chunk(key, &nonce_prefix, idx, is_final, &buf[..filled])?;
        ciphertext_size += ct.len() as u64;
        chunks.push(EncryptedChunk {
            index: idx,
            is_final,
            ciphertext: ct,
        });
        idx += 1;
        if is_final {
            break;
        }
    }

    let meta = EncryptedFileMeta {
        nonce_prefix,
        chunk_count: idx,
        plaintext_size,
        ciphertext_size,
    };
    Ok((chunks, meta))
}

/// Decrypt an already-fetched ciphertext blob (concatenation of every
/// chunk's `ciphertext` field, in order) into `dst`. The encoder above
/// emits chunks at predictable boundaries: every chunk except the
/// last is `CHUNK_PLAINTEXT_SIZE + TAG_LEN` bytes; the tail chunk is
/// shorter. We exploit that to slice the blob without needing a
/// per-chunk length prefix.
pub async fn decrypt_stream_to_file(
    key: &[u8; 32],
    meta: &EncryptedFileMeta,
    ciphertext: &[u8],
    dst: &Path,
) -> Result<(), StreamError> {
    use veil_crypto::chunked_aead::{FULL_CHUNK_CIPHERTEXT_SIZE, TAG_LEN};

    validate_encrypted_file(meta, ciphertext.len(), TAG_LEN)?;
    if tokio::fs::try_exists(dst).await? {
        return Err(StreamError::DestinationExists);
    }

    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    let mut random = rand::rngs::OsRng;
    let (temporary_path, file) = {
        let mut created = None;
        for _ in 0..8 {
            let suffix = random.next_u64();
            let candidate = parent.join(format!(".veil-decrypt-{suffix:016x}.tmp"));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
                .await
            {
                Ok(file) => {
                    created = Some((candidate, file));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(StreamError::Io(error)),
            }
        }
        created.ok_or_else(|| {
            StreamError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "could not allocate a unique temporary decrypt file",
            ))
        })?
    };
    let mut writer = BufWriter::new(file);

    let operation: Result<(), StreamError> = async {
        let mut cursor = 0usize;
        let mut decoded_chunks: u64 = 0;
        let total = meta.chunk_count;

        while decoded_chunks < total {
            let is_final = decoded_chunks + 1 == total;
            let take = if is_final {
                ciphertext.len().checked_sub(cursor).ok_or_else(|| {
                    StreamError::InvalidMetadata("ciphertext cursor overflow".to_string())
                })?
            } else {
                FULL_CHUNK_CIPHERTEXT_SIZE
            };
            let end = cursor.checked_add(take).ok_or_else(|| {
                StreamError::InvalidMetadata("ciphertext length overflow".to_string())
            })?;
            if take < TAG_LEN || end > ciphertext.len() {
                return Err(StreamError::ChunkCount {
                    expected: total,
                    actual: decoded_chunks,
                });
            }
            let slice = &ciphertext[cursor..end];
            let mut plaintext = Zeroizing::new(open_chunk(
                key,
                &meta.nonce_prefix,
                decoded_chunks,
                is_final,
                slice,
            )?);
            writer.write_all(&plaintext).await?;
            plaintext.fill(0);
            cursor = end;
            decoded_chunks += 1;
        }
        if cursor != ciphertext.len() {
            return Err(StreamError::ChunkCount {
                expected: total,
                actual: decoded_chunks,
            });
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
    if tokio::fs::try_exists(dst).await? {
        let _ = tokio::fs::remove_file(&temporary_path).await;
        return Err(StreamError::DestinationExists);
    }
    if let Err(error) = tokio::fs::rename(&temporary_path, dst).await {
        let _ = tokio::fs::remove_file(&temporary_path).await;
        return Err(StreamError::Io(error));
    }
    Ok(())
}

fn validate_encrypted_file(
    meta: &EncryptedFileMeta,
    actual_ciphertext_len: usize,
    tag_len: usize,
) -> Result<(), StreamError> {
    if meta.plaintext_size > MAX_ONE_SHOT_FILE_BYTES {
        return Err(StreamError::FileTooLarge(MAX_ONE_SHOT_FILE_BYTES));
    }
    let chunk_size = u64::try_from(CHUNK_PLAINTEXT_SIZE)
        .map_err(|_| StreamError::InvalidMetadata("chunk size overflow".to_string()))?;
    let expected_chunks = if meta.plaintext_size == 0 {
        1
    } else {
        meta.plaintext_size.div_ceil(chunk_size)
    };
    if meta.chunk_count != expected_chunks {
        return Err(StreamError::ChunkCount {
            expected: expected_chunks,
            actual: meta.chunk_count,
        });
    }
    let authentication_overhead = meta
        .chunk_count
        .checked_mul(u64::try_from(tag_len).unwrap_or(u64::MAX))
        .ok_or_else(|| StreamError::InvalidMetadata("tag overhead overflow".to_string()))?;
    let expected_ciphertext_size = meta
        .plaintext_size
        .checked_add(authentication_overhead)
        .ok_or_else(|| StreamError::InvalidMetadata("ciphertext size overflow".to_string()))?;
    if meta.ciphertext_size != expected_ciphertext_size
        || u64::try_from(actual_ciphertext_len).unwrap_or(u64::MAX) != expected_ciphertext_size
    {
        return Err(StreamError::InvalidMetadata(
            "ciphertext size does not match authenticated chunk geometry".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;

    fn key() -> [u8; 32] {
        [42u8; 32]
    }

    async fn write_tmp(content: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("plaintext.bin");
        let mut f = tokio::fs::File::create(&path).await.unwrap();
        f.write_all(content).await.unwrap();
        f.flush().await.unwrap();
        (dir, path)
    }

    #[tokio::test]
    async fn roundtrip_small_file() {
        let (_d, src) = write_tmp(b"hello veil uploads").await;
        let (chunks, meta) = encrypt_file_to_chunks(&key(), &src).await.unwrap();
        assert_eq!(meta.chunk_count, 1);
        assert!(chunks[0].is_final);
        let blob: Vec<u8> = chunks.iter().flat_map(|c| c.ciphertext.clone()).collect();
        let dst = src.with_extension("dec");
        decrypt_stream_to_file(&key(), &meta, &blob, &dst)
            .await
            .unwrap();
        let got = tokio::fs::read(&dst).await.unwrap();
        assert_eq!(got, b"hello veil uploads");
    }

    #[tokio::test]
    async fn roundtrip_multi_chunk_file() {
        // 2.5 chunks worth of pseudo-random data.
        let plaintext: Vec<u8> = (0..(2 * CHUNK_PLAINTEXT_SIZE + 12345))
            .map(|i| (i & 0xff) as u8)
            .collect();
        let (_d, src) = write_tmp(&plaintext).await;
        let (chunks, meta) = encrypt_file_to_chunks(&key(), &src).await.unwrap();
        assert_eq!(meta.chunk_count, 3);
        assert!(chunks[2].is_final);
        assert!(!chunks[0].is_final);
        let blob: Vec<u8> = chunks.iter().flat_map(|c| c.ciphertext.clone()).collect();
        let dst = src.with_extension("dec");
        decrypt_stream_to_file(&key(), &meta, &blob, &dst)
            .await
            .unwrap();
        let got = tokio::fs::read(&dst).await.unwrap();
        assert_eq!(got, plaintext);
    }

    #[tokio::test]
    async fn roundtrip_empty_file() {
        let (_d, src) = write_tmp(b"").await;
        let (chunks, meta) = encrypt_file_to_chunks(&key(), &src).await.unwrap();
        assert_eq!(meta.chunk_count, 1);
        let blob: Vec<u8> = chunks.iter().flat_map(|c| c.ciphertext.clone()).collect();
        let dst = src.with_extension("dec");
        decrypt_stream_to_file(&key(), &meta, &blob, &dst)
            .await
            .unwrap();
        assert_eq!(tokio::fs::read(&dst).await.unwrap(), Vec::<u8>::new());
    }

    #[tokio::test]
    async fn tampered_tail_never_publishes_partial_plaintext() {
        let plaintext = vec![7u8; CHUNK_PLAINTEXT_SIZE + 123];
        let (_d, src) = write_tmp(&plaintext).await;
        let (chunks, meta) = encrypt_file_to_chunks(&key(), &src).await.unwrap();
        let mut blob: Vec<u8> = chunks
            .iter()
            .flat_map(|chunk| chunk.ciphertext.clone())
            .collect();
        *blob.last_mut().unwrap() ^= 1;
        let dst = src.with_extension("tampered-dec");

        assert!(decrypt_stream_to_file(&key(), &meta, &blob, &dst)
            .await
            .is_err());
        assert!(!tokio::fs::try_exists(&dst).await.unwrap());
        let leftovers: Vec<_> = std::fs::read_dir(dst.parent().unwrap())
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

    #[tokio::test]
    async fn malformed_metadata_is_rejected_before_touching_destination() {
        let (_d, src) = write_tmp(b"small").await;
        let (chunks, mut meta) = encrypt_file_to_chunks(&key(), &src).await.unwrap();
        let blob: Vec<u8> = chunks
            .iter()
            .flat_map(|chunk| chunk.ciphertext.clone())
            .collect();
        meta.chunk_count = u64::MAX;
        let dst = src.with_extension("invalid-dec");

        assert!(decrypt_stream_to_file(&key(), &meta, &blob, &dst)
            .await
            .is_err());
        assert!(!tokio::fs::try_exists(&dst).await.unwrap());
    }
}
