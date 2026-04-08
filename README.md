# Veil — Next-Generation Encrypted Messenger

**Native-only** end-to-end encrypted messenger. Keys never leave Rust memory.

## Architecture

| Module | Language | Purpose |
|--------|----------|---------|
| `veil-crypto` | Rust | Cryptographic engine (X3DH, Double Ratchet, AEAD, BIP39) |
| `veil-store` | Rust | Encrypted local storage (SQLCipher + OS Keychain) |
| `veil-client` | Rust | Protocol engine (WebSocket, Protobuf, offline queue) |
| `veil-ffi` | Rust | UniFFI bindings for Kotlin/Swift |
| `veil-proto` | Protobuf | Wire protocol definitions |
| `veil-server` | Go | WebSocket gateway + microservices |
| `veil-desktop` | Rust + SolidJS | Tauri v2 desktop app |
| `veil-mobile` | TypeScript | React Native (Expo) mobile app |
| `veil-share-viewer` | Rust (WASM) | Browser decryptor for secure shares |

## Build

```bash
# Rust (all crates)
cargo build --workspace
cargo test --workspace

# Server (Go)
cd veil-server && go build ./cmd/gateway/

# Desktop
cd veil-desktop && npm install && npm run tauri dev

# Mobile
cd veil-mobile && npm install && npx expo start
```

## Security

- XChaCha20-Poly1305 + HKDF-SHA256 + Argon2id
- X3DH key agreement with SPK signature verification
- Double Ratchet with forward secrecy
- `zeroize` on drop for all key material
- SQLCipher with `cipher_memory_security = ON`
- OS Keychain for seed storage

## License

MIT
