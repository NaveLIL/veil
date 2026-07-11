//! # veil-uploads
//!
//! Resumable end-to-end encrypted file uploads for Veil. The crate
//! combines two concerns the desktop / mobile clients otherwise have
//! to glue together themselves:
//!
//!   1. **Streaming encryption** — wraps a plaintext file as a chunked
//!      AEAD stream (see [`veil_crypto::chunked_aead`]). The resumable API uses
//!      bounded chunk buffers for files up to 2 GiB; the legacy one-shot
//!      adapter remains capped at 64 MiB.
//!   2. **tus.io client** — talks the
//!      [tus 1.0.0 protocol](https://tus.io/protocols/resumable-upload.html)
//!      so partial uploads survive flaky links: the client HEADs the
//!      resource to learn the server-side offset and resumes from
//!      there. The veil-server gateway authenticates these requests
//!      with a single bearer token (issued by `/v1/uploads/token`),
//!      not per-chunk Ed25519 signatures, so PATCH bodies can stream
//!      without buffering.
//!
//! ## Threat model
//!
//! * The server only ever sees ciphertext plus optional metadata already
//!   encrypted by the caller. Plaintext filenames and MIME types are never
//!   placed in tus headers. The content key never leaves the client.
//! * Chunked AEAD detects truncation, reordering and per-chunk
//!   tampering (see [`veil_crypto::chunked_aead`]).
//! * The bearer token is bound to a single user via HMAC-SHA256;
//!   guessing or reusing one across users is computationally
//!   infeasible.
//!
//! ## What this crate intentionally does NOT do
//!
//! * EXIF stripping — the client UI is responsible for sanitising the
//!   plaintext before it hits this crate (the encrypted blob is
//!   opaque to anything downstream).
//! * Conversation-key wrapping — the caller passes a 32-byte content
//!   key that they derived (or got out-of-band). Phase 6 (MLS) will
//!   change how that key reaches recipients.
//! * Cross-protocol HTTP fallback — TLS only.

pub mod client;
pub mod stream;
pub mod streaming;

pub use client::{TusClient, TusClientError, TusUploadHandle, TusUploadInit, TusUploadState};
pub use stream::{
    decrypt_stream_to_file, encrypt_file_to_chunks, EncryptedChunk, EncryptedFileMeta, StreamError,
};
pub use streaming::{
    ciphertext_resume_position, decrypt_file_streaming, decrypt_reader_to_file,
    geometry_for_plaintext, prepare_streaming_upload, prepare_streaming_upload_with_control,
    validate_streaming_metadata, ResumePosition, StreamingError, StreamingGeometry,
    StreamingUploadPlan, StreamingUploadResult, TransferControl, TransferProgress, TransferStage,
    MAX_STREAM_PLAINTEXT_BYTES,
};
