//! # veil-crypto
//!
//! Cryptographic core for the Veil encrypted messenger.
//!
//! All cryptographic operations happen exclusively within this crate.
//! Keys never leave Rust memory boundary. UI layers interact only
//! through opaque handles and plaintext results.
//!
//! ## Modules
//!
//! - [`keys`] — Identity generation (BIP39, Argon2id, X25519, Ed25519)
//! - [`aead`] — Authenticated encryption (XChaCha20-Poly1305 + padding)
//! - [`kdf`] — Key derivation (HKDF-SHA256, Argon2id)
//! - [`signature`] — Ed25519 signing and verification
//! - [`x3dh`] — Extended Triple Diffie-Hellman key agreement
//! - [`ratchet`] — Double Ratchet protocol (forward secrecy)
//! - [`share`] — Secure share encryption/decryption
//! - [`fingerprint`] — Visual fingerprint generation (emoji + hex)

pub mod aead;
pub mod fingerprint;
pub mod kdf;
pub mod keys;
pub mod ratchet;
pub mod share;
pub mod signature;
pub mod x3dh;

pub use keys::{IdentityKeyPair, KeyBundle};
pub use ratchet::RatchetSession;
pub use x3dh::{PreKeyBundle, X3DHResult};
