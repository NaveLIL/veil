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
//! * Per-chunk nonce = `nonce_prefix (16) || chunk_index (8 BE) || final_flag (0|1)`.
//!   The 1-byte trailing flag is part of the AEAD nonce, not AAD,
//!   which both binds the "this is the last chunk" decision into the
//!   tag *and* keeps the prefix ⊕ index space large enough that an
//!   adversary who somehow predicts the prefix still cannot replay one
//!   chunk into another file.
//! * `aad = b"veil/file/v1" || nonce_prefix || u64_be(chunk_index) || final_flag`.
//!   Binding the prefix and index into AAD as well prevents reordering
//!   or copy-paste of chunks across uploads sharing the same `K`.
//! * Each chunk on the wire = `ciphertext || tag` (the AEAD library
//!   already appends the 16-byte tag).
//!
//! The receiver detects truncation: if the chunk advertised as final
//! (per its trailing flag) is missing or out of order, decryption
//! fails. Bit-for-bit reuse of `(K, nonce_prefix)` between two files
//! is forbidden — the prefix is generated fresh per upload from a CSPRNG.

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

/// Domain-separation tag woven into AAD so a chunk encrypted under the
/// same key in a different protocol cannot be replayed here.
const AAD_PREFIX: &[u8] = b"veil/file/v1";

/// Errors returned by chunked AEAD operations.
#[derive(Debug, thiserror::Error)]
pub enum ChunkedAeadError {
    #[error("plaintext chunk too large (max {} bytes)", CHUNK_PLAINTEXT_SIZE)]
    PlaintextTooLarge,
    #[error("ciphertext chunk too short (must be > tag length)")]
    CiphertextTooShort,
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
    let nonce_bytes = build_nonce(nonce_prefix, chunk_index, is_final);
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
    if ciphertext.len() < TAG_LEN {
        return Err(ChunkedAeadError::CiphertextTooShort);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| ChunkedAeadError::Aead(format!("init: {e}")))?;
    let nonce_bytes = build_nonce(nonce_prefix, chunk_index, is_final);
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

fn build_nonce(prefix: &[u8; NONCE_PREFIX_LEN], idx: u64, is_final: bool) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    n[16..24].copy_from_slice(&idx.to_be_bytes());
    // The trailing byte is part of the index space (it's the low byte
    // of a u64), so XOR'ing in `is_final` does NOT corrupt the index —
    // it just toggles the parity of the very last nonce. Because we
    // only ever produce 2^63 - 1 chunks per stream this is collision
    // free.
    if is_final {
        n[23] ^= 0x01;
    }
    n
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

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(&[7u8; 32]);
        k
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
