//! # veil-client
//!
//! Protocol engine for Veil messenger.
//!
//! Handles WebSocket connection, Protobuf encoding/decoding,
//! ratchet session management, and offline message queue.
//! All cryptographic operations are delegated to `veil-crypto`.
//! All storage operations are delegated to `veil-store`.
//!
//! This crate provides the public API that UI layers (Tauri/RN) call.

pub mod api;
pub mod connection;
pub mod protocol;
