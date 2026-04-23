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

use thiserror::Error;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};

use veil_crypto::chunked_aead::{
    open_chunk, random_nonce_prefix, seal_chunk, ChunkedAeadError, CHUNK_PLAINTEXT_SIZE,
    NONCE_PREFIX_LEN,
};

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
    let mut reader = BufReader::with_capacity(CHUNK_PLAINTEXT_SIZE, file);

    let mut chunks = Vec::new();
    let mut buf = vec![0u8; CHUNK_PLAINTEXT_SIZE];
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

    let file = File::create(dst).await?;
    let mut writer = BufWriter::new(file);

    let mut cursor = 0usize;
    let mut decoded_chunks: u64 = 0;
    let total = meta.chunk_count;

    while decoded_chunks < total {
        let is_final = decoded_chunks + 1 == total;
        let take = if is_final {
            ciphertext.len() - cursor
        } else {
            FULL_CHUNK_CIPHERTEXT_SIZE
        };
        if take == 0 || cursor + take > ciphertext.len() || take < TAG_LEN {
            return Err(StreamError::ChunkCount {
                expected: total,
                actual: decoded_chunks,
            });
        }
        let slice = &ciphertext[cursor..cursor + take];
        let pt = open_chunk(key, &meta.nonce_prefix, decoded_chunks, is_final, slice)?;
        writer.write_all(&pt).await?;
        cursor += take;
        decoded_chunks += 1;
    }
    if cursor != ciphertext.len() {
        return Err(StreamError::ChunkCount {
            expected: total,
            actual: decoded_chunks,
        });
    }
    writer.flush().await?;
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
        decrypt_stream_to_file(&key(), &meta, &blob, &dst).await.unwrap();
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
        decrypt_stream_to_file(&key(), &meta, &blob, &dst).await.unwrap();
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
        decrypt_stream_to_file(&key(), &meta, &blob, &dst).await.unwrap();
        assert_eq!(tokio::fs::read(&dst).await.unwrap(), Vec::<u8>::new());
    }
}
