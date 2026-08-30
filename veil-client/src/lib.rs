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
pub mod attachments;
pub mod auth_contract;
pub mod connection;
mod device_identity;
#[cfg(feature = "test-utils")]
pub use device_identity::DeviceIdentityV1;
pub mod direct;
pub mod direct_history;
mod direct_v2;
pub mod prekeys;
pub mod protocol;
mod rest_auth_v2;
pub mod transparency;
mod ws_auth_v3;
pub mod ws_events_v3;

#[cfg(test)]
mod auth_contract_fixture_tests;
#[cfg(test)]
mod origin_contract_fixture_tests;
