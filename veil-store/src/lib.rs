//! # veil-store
//!
//! Encrypted local storage for Veil messenger.
//!
//! - SQLCipher (encrypted SQLite) for messages, conversations, ratchet state
//! - OS Keychain (via `keyring` crate) for seed/master key storage
//! - All data encrypted at rest, key derived from user's identity

pub mod db;
pub mod keychain;
pub mod models;
