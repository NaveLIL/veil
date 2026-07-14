//! Chunked authenticated encryption for streaming uploads/downloads.
//!
//! ## Why
//!
//! Phase 3 wants resumable file uploads where neither the server nor a
//! network attacker learns the plaintext. Encrypting the whole file as
//! a single AEAD frame would:
//!
//!   * force clients to keep the entire file (and its plaintext) in
//!     memory before computing one giant tag;
//!   * make resumes impossible because tampering with any byte
//!     anywhere in the file would invalidate the single tag — but the
//!     receiver only learns this after streaming the full ciphertext
//!     down again.
//!
//! Both problems vanish when the file is split into fixed-size chunks
//! that each carry their own AEAD tag.
//!
//! ## Construction
//!
//! * Plaintext is split into chunks of [`CHUNK_PLAINTEXT_SIZE`] bytes
//!   (the tail chunk is shorter).
//! * The whole stream uses **one** symmetric content key `K` and one
//!   16-byte random `nonce_prefix` chosen at upload time.
//! * Format v2 packs the index and final bit into one injective 64-bit
//!   counter: `counter = (chunk_index << 1) | final_flag`.
//! * Per-chunk nonce = `nonce_prefix (16) || u64_be(counter)`.
//! * `aad = b"veil/file/v2" || nonce_prefix || u64_be(chunk_index) || final_flag`.
//!   Binding the prefix and index into AAD as well prevents reordering
//!   or copy-paste of chunks across uploads sharing the same `K`.
//! * Each chunk on the wire = `ciphertext || tag` (the AEAD library
//!   already appends the 16-byte tag).
//!
//! `chunk_index` is limited to [`MAX_CHUNK_INDEX`] so the checked shift
//! cannot overflow. This still permits [`MAX_CHUNKS`] chunks per stream,
//! far beyond any file representable by the surrounding `u64` byte-size
//! metadata at the current 1 MiB chunk size.
//!
//! The receiver detects truncation: if the chunk advertised as final
//! is missing or out of order, decryption
//! fails. Bit-for-bit reuse of `(K, nonce_prefix)` between two files
//! is forbidden — the prefix is generated fresh per upload from a CSPRNG.
//!
//! ## Format compatibility
//!
//! The pre-release v1 XORed the final flag into the low index bit. That
//! mapping reused a nonce for `(0, non-final)` and `(1, final)` (and every
//! analogous adjacent pair), so it is deliberately unsupported. Callers
//! must persist and require `format_version = 2`; there is no automatic
//! legacy fallback because a resumable stream must never mix nonce schemes
//! under the same key and prefix.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};

/// Plaintext bytes per chunk. 1 MiB strikes the standard balance
/// between AEAD overhead (16 B tag per chunk → 0.0015 % expansion)
/// and resume granularity / memory pressure on small devices.
pub const CHUNK_PLAINTEXT_SIZE: usize = 1 << 20;

/// Size of the random per-stream nonce prefix.
pub const NONCE_PREFIX_LEN: usize = 16;

/// Per-chunk AEAD overhead (Poly1305 tag).
pub const TAG_LEN: usize = 16;

/// Ciphertext size when the chunk is fully populated.
pub const FULL_CHUNK_CIPHERTEXT_SIZE: usize = CHUNK_PLAINTEXT_SIZE + TAG_LEN;

/// Only supported chunked-AEAD format version.
pub const CHUNK_FORMAT_VERSION: u8 = 2;

/// Largest zero-based chunk index encodable by the v2 packed counter.
pub const MAX_CHUNK_INDEX: u64 = u64::MAX >> 1;

/// Number of distinct chunk indices supported by one v2 stream.
pub const MAX_CHUNKS: u64 = 1u64 << 63;

/// Domain-separation tag woven into AAD so a chunk encrypted under the
/// same key in a different protocol cannot be replayed here.
const AAD_PREFIX: &[u8] = b"veil/file/v2";

/// Errors returned by chunked AEAD operations.
#[derive(Debug, thiserror::Error)]
pub enum ChunkedAeadError {
    #[error("plaintext chunk too large (max {} bytes)", CHUNK_PLAINTEXT_SIZE)]
    PlaintextTooLarge,
    #[error("ciphertext chunk too short (must be at least the tag length)")]
    CiphertextTooShort,
    #[error("chunk index {index} exceeds v2 maximum {max}")]
    ChunkIndexOutOfRange { index: u64, max: u64 },
    #[error("aead error: {0}")]
    Aead(String),
}

/// Generate a fresh per-stream 16-byte nonce prefix from the OS CSPRNG.
pub fn random_nonce_prefix() -> [u8; NONCE_PREFIX_LEN] {
    let mut p = [0u8; NONCE_PREFIX_LEN];
    OsRng.fill_bytes(&mut p);
    p
}

/// Encrypt one chunk.
///
/// `chunk_index` is zero-based. `is_final` must be `true` for the last
/// chunk and `false` for every other chunk; the receiver enforces the
/// same flag during decryption so truncation is detectable.
pub fn seal_chunk(
    key: &[u8; 32],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    chunk_index: u64,
    is_final: bool,
    plaintext: &[u8],
) -> Result<Vec<u8>, ChunkedAeadError> {
    if plaintext.len() > CHUNK_PLAINTEXT_SIZE {
        return Err(ChunkedAeadError::PlaintextTooLarge);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| ChunkedAeadError::Aead(format!("init: {e}")))?;
    let nonce_bytes = build_nonce(nonce_prefix, chunk_index, is_final)?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad = build_aad(nonce_prefix, chunk_index, is_final);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| ChunkedAeadError::Aead(format!("seal: {e}")))
}

/// Decrypt one chunk. The caller must pass the same `chunk_index` and
/// `is_final` flag the sender used; AAD/nonce binding ensures any
/// mismatch (reordered, mislabeled-final, swapped between streams)
/// surfaces as an authentication failure.
pub fn open_chunk(
    key: &[u8; 32],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    chunk_index: u64,
    is_final: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ChunkedAeadError> {
    let nonce_bytes = build_nonce(nonce_prefix, chunk_index, is_final)?;
    if ciphertext.len() < TAG_LEN {
        return Err(ChunkedAeadError::CiphertextTooShort);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| ChunkedAeadError::Aead(format!("init: {e}")))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad = build_aad(nonce_prefix, chunk_index, is_final);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| ChunkedAeadError::Aead(format!("open: {e}")))
}

fn build_nonce(
    prefix: &[u8; NONCE_PREFIX_LEN],
    idx: u64,
    is_final: bool,
) -> Result<[u8; 24], ChunkedAeadError> {
    let final_flag = u64::from(u8::from(is_final));
    let counter = idx
        .checked_mul(2)
        .and_then(|value| value.checked_add(final_flag))
        .ok_or(ChunkedAeadError::ChunkIndexOutOfRange {
            index: idx,
            max: MAX_CHUNK_INDEX,
        })?;
    let mut n = [0u8; 24];
    n[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    n[NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
    Ok(n)
}

fn build_aad(prefix: &[u8; NONCE_PREFIX_LEN], idx: u64, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + NONCE_PREFIX_LEN + 8 + 1);
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(&idx.to_be_bytes());
    aad.push(if is_final { 1 } else { 0 });
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(&[7u8; 32]);
        k
    }

    fn legacy_v1_nonce(prefix: &[u8; NONCE_PREFIX_LEN], idx: u64, is_final: bool) -> [u8; 24] {
        let mut nonce = [0u8; 24];
        nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
        nonce[NONCE_PREFIX_LEN..].copy_from_slice(&idx.to_be_bytes());
        if is_final {
            nonce[23] ^= 1;
        }
        nonce
    }

    fn legacy_v1_aad(prefix: &[u8; NONCE_PREFIX_LEN], idx: u64, is_final: bool) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"veil/file/v1");
        aad.extend_from_slice(prefix);
        aad.extend_from_slice(&idx.to_be_bytes());
        aad.push(u8::from(is_final));
        aad
    }

    #[test]
    fn legacy_v1_xor_mapping_reuses_nonce_and_aad_does_not_save_confidentiality() {
        let prefix = [3u8; NONCE_PREFIX_LEN];
        let previous = legacy_v1_nonce(&prefix, 0, false);
        let final_chunk = legacy_v1_nonce(&prefix, 1, true);
        assert_eq!(previous, final_chunk);
        assert_eq!(
            legacy_v1_nonce(&prefix, 1, false),
            legacy_v1_nonce(&prefix, 0, true)
        );

        let previous_aad = legacy_v1_aad(&prefix, 0, false);
        let final_aad = legacy_v1_aad(&prefix, 1, true);
        assert_ne!(previous_aad, final_aad);

        // AEAD nonce uniqueness is required independently of AAD. With the
        // repeated XChaCha20 nonce, the ciphertext bodies reuse a keystream,
        // so their XOR exposes the XOR of the plaintexts even though the AADs
        // and authentication tags differ.
        let cipher = XChaCha20Poly1305::new_from_slice(&key()).unwrap();
        let first_plaintext = [0x11u8; 32];
        let second_plaintext = [0x42u8; 32];
        let first = cipher
            .encrypt(
                XNonce::from_slice(&previous),
                Payload {
                    msg: &first_plaintext,
                    aad: &previous_aad,
                },
            )
            .unwrap();
        let second = cipher
            .encrypt(
                XNonce::from_slice(&final_chunk),
                Payload {
                    msg: &second_plaintext,
                    aad: &final_aad,
                },
            )
            .unwrap();
        let exposed_xor: Vec<u8> = first[..first_plaintext.len()]
            .iter()
            .zip(&second[..second_plaintext.len()])
            .map(|(left, right)| left ^ right)
            .collect();
        let plaintext_xor: Vec<u8> = first_plaintext
            .iter()
            .zip(second_plaintext)
            .map(|(left, right)| left ^ right)
            .collect();
        assert_eq!(exposed_xor, plaintext_xor);
    }

    #[test]
    fn v2_packed_nonce_is_injective_for_sampled_space_and_boundaries() {
        let prefix = [9u8; NONCE_PREFIX_LEN];
        let mut seen = HashSet::new();
        for idx in 0..=65_535 {
            assert!(seen.insert(build_nonce(&prefix, idx, false).unwrap()));
            assert!(seen.insert(build_nonce(&prefix, idx, true).unwrap()));
        }
        for idx in [MAX_CHUNK_INDEX - 1, MAX_CHUNK_INDEX] {
            assert!(seen.insert(build_nonce(&prefix, idx, false).unwrap()));
            assert!(seen.insert(build_nonce(&prefix, idx, true).unwrap()));
        }

        assert_ne!(
            build_nonce(&prefix, 0, false).unwrap(),
            build_nonce(&prefix, 1, true).unwrap()
        );
        assert_eq!(
            &build_nonce(&prefix, MAX_CHUNK_INDEX, true).unwrap()[NONCE_PREFIX_LEN..],
            &u64::MAX.to_be_bytes()
        );
    }

    #[test]
    fn v2_rejects_chunk_index_that_would_overflow_packed_counter() {
        let prefix = [4u8; NONCE_PREFIX_LEN];
        let overflow = MAX_CHUNK_INDEX + 1;
        assert!(matches!(
            seal_chunk(&key(), &prefix, overflow, false, b"never encrypted"),
            Err(ChunkedAeadError::ChunkIndexOutOfRange { index, max })
                if index == overflow && max == MAX_CHUNK_INDEX
        ));
        assert!(matches!(
            open_chunk(&key(), &prefix, overflow, false, &[0u8; TAG_LEN]),
            Err(ChunkedAeadError::ChunkIndexOutOfRange { index, max })
                if index == overflow && max == MAX_CHUNK_INDEX
        ));
    }

    #[test]
    fn v2_open_rejects_legacy_v1_ciphertext_without_fallback() {
        let prefix = [5u8; NONCE_PREFIX_LEN];
        let legacy_nonce = legacy_v1_nonce(&prefix, 2, true);
        let legacy_aad = legacy_v1_aad(&prefix, 2, true);
        let cipher = XChaCha20Poly1305::new_from_slice(&key()).unwrap();
        let legacy_ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&legacy_nonce),
                Payload {
                    msg: b"pre-release v1",
                    aad: &legacy_aad,
                },
            )
            .unwrap();

        assert!(open_chunk(&key(), &prefix, 2, true, &legacy_ciphertext).is_err());
    }

    #[test]
    fn roundtrip_single_chunk() {
        let prefix = random_nonce_prefix();
        let pt = b"the quick brown fox jumps over the lazy dog".to_vec();
        let ct = seal_chunk(&key(), &prefix, 0, true, &pt).unwrap();
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
        let dec = open_chunk(&key(), &prefix, 0, true, &ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn roundtrip_multi_chunk_stream() {
        let prefix = random_nonce_prefix();
        let chunks: Vec<Vec<u8>> = (0..3)
            .map(|i| vec![i as u8; CHUNK_PLAINTEXT_SIZE / 4])
            .collect();
        let last_idx = (chunks.len() - 1) as u64;
        let cipher: Vec<Vec<u8>> = chunks
            .iter()
            .enumerate()
            .map(|(i, c)| seal_chunk(&key(), &prefix, i as u64, i as u64 == last_idx, c).unwrap())
            .collect();
        for (i, c) in cipher.iter().enumerate() {
            let pt = open_chunk(&key(), &prefix, i as u64, i as u64 == last_idx, c).unwrap();
            assert_eq!(pt, chunks[i]);
        }
    }

    #[test]
    fn detects_chunk_swap() {
        // Reordering ciphertext chunks must fail authentication.
        let prefix = random_nonce_prefix();
        let c0 = seal_chunk(&key(), &prefix, 0, false, b"zero").unwrap();
        let c1 = seal_chunk(&key(), &prefix, 1, true, b"one!").unwrap();
        assert!(open_chunk(&key(), &prefix, 0, false, &c1).is_err());
        assert!(open_chunk(&key(), &prefix, 1, true, &c0).is_err());
    }

    #[test]
    fn detects_truncation_via_final_flag() {
        // If a non-final chunk is replayed claiming to be the last,
        // AAD/nonce mismatch must reject it (so an attacker cannot
        // chop off the tail and pretend the file was already shorter).
        let prefix = random_nonce_prefix();
        let pt = b"middle".to_vec();
        let c = seal_chunk(&key(), &prefix, 5, false, &pt).unwrap();
        assert!(open_chunk(&key(), &prefix, 5, true, &c).is_err());
    }

    #[test]
    fn detects_tampering() {
        let prefix = random_nonce_prefix();
        let mut c = seal_chunk(&key(), &prefix, 0, true, b"hello").unwrap();
        c[0] ^= 1;
        assert!(open_chunk(&key(), &prefix, 0, true, &c).is_err());
    }

    #[test]
    fn rejects_oversize_chunk() {
        let prefix = random_nonce_prefix();
        let huge = vec![0u8; CHUNK_PLAINTEXT_SIZE + 1];
        assert!(matches!(
            seal_chunk(&key(), &prefix, 0, true, &huge),
            Err(ChunkedAeadError::PlaintextTooLarge)
        ));
    }
}
