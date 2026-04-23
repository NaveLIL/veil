# Veil — Next-Generation Encrypted Messenger

**Native-only** end-to-end encrypted messenger. Keys never leave Rust memory.

## Architecture

| Module | Language | Purpose |
|--------|----------|---------|
| `veil-crypto` | Rust | Cryptographic engine (X3DH, Double Ratchet, AEAD, chunked AEAD, sender keys, BIP39) |
| `veil-store` | Rust | Encrypted local storage (SQLCipher + OS Keychain) |
| `veil-client` | Rust | Protocol engine (WebSocket, Protobuf, offline queue, optional FTS hook) |
| `veil-search` | Rust | Local-only Tantivy full-text index over decrypted messages |
| `veil-uploads` | Rust | tus.io resumable client + streaming chunked-AEAD encrypt/decrypt |
| `veil-ffi` | Rust | UniFFI bindings for Kotlin/Swift |
| `veil-proto` | Protobuf | Wire protocol definitions |
| `veil-server` | Go | WebSocket gateway, auth, chat, servers/channels, push, uploads |
| `veil-desktop` | Rust + SolidJS | Tauri v2 desktop app (Cmd-K palette, Island UI) |
| `veil-mobile` | TypeScript | React Native (Expo) mobile app |
| `veil-share-viewer` | Rust (WASM) | Browser decryptor for secure shares |

### Server packages (`veil-server/internal/`)

| Package | Purpose |
|---------|---------|
| `auth` | Identity registration + signed-REST authentication |
| `authmw` | Ed25519 request signature middleware + per-user rate limit |
| `chat` | Conversations, messages, members, reactions, edits/deletes |
| `servers` | Discord-like servers, channels, roles, invites |
| `gateway` | WebSocket hub, fan-out, offline-push routing |
| `push` | UnifiedPush / ntfy dispatcher (XChaCha20 envelopes, jitter, dead-endpoint pruning) |
| `uploads` | tusd v2 wrapper, HMAC bearer tokens, per-user quota, sweeper |
| `metrics` | Prometheus metrics on a dedicated internal listener |
| `integration` | testcontainers harness for end-to-end Go suite |

## Build

```bash
# Rust workspace (all crates)
cargo build --workspace
cargo test  --workspace

# Server (Go)
cd veil-server && go build ./cmd/gateway/
go test ./...

# Desktop
cd veil-desktop && pnpm install && pnpm tauri dev

# Mobile
cd veil-mobile && pnpm install && npx expo start
```

## Run the stack

```bash
# Postgres + gateway + ntfy distributor
docker compose up -d
```

Generate transport keys before enabling phase 3/4 services:

```bash
# Phase 3 — uploads bearer-token HMAC key
export VEIL_UPLOAD_TOKEN_KEY="$(openssl rand -base64 32)"

# Phase 4 — push transport AEAD key
export VEIL_PUSH_TRANSPORT_KEY="$(openssl rand -base64 32)"
export VEIL_PUSH_HASH_SALT="<unique per deployment>"
```

Leaving either env var empty boots the corresponding subsystem in
**disabled** mode (endpoints reachable, traffic refused) so the
gateway always starts.

## Security

- XChaCha20-Poly1305 + HKDF-SHA256 + Argon2id
- X3DH key agreement with SPK signature verification
- Double Ratchet with forward secrecy + post-compromise security
- Sender keys for encrypted groups/channels (Signal-style)
- Chunked AEAD for streaming uploads — nonce + AAD bind chunk index
  and final-flag, so reorder, truncation and per-chunk tampering are
  all detectable
- `zeroize` on drop for all key material
- SQLCipher with `cipher_memory_security = ON`
- OS Keychain (Linux: secret-service via `keyring` v3 with
  `sync-secret-service` + `crypto-rust` features) for seed storage
- Server is E2EE-blind: only ciphertext + opaque size/timing metadata
  for files; only constant-size padded envelopes for push
- Push key (`K_push`) is HKDF-derived from the ratchet root with
  domain separation — leak of `K_push` reveals previews only, never
  live ratchet state

## Phase status

- ✅ Phase 1 — identity, X3DH, ratchet, store
- ✅ Phase 2 — gateway, signed REST, hub, offline queue
- ✅ Phase 3 — resumable encrypted uploads (tus.io + chunked AEAD)
- ✅ Phase 4 — UnifiedPush + ntfy offline notifications
- ✅ Phase 4A — groups, sender keys, Discord-like servers/channels/roles
- ✅ Local-only Tantivy full-text search (Cmd-K palette)
- 🔜 Phase 5 — calls (WebRTC + DTLS-SRTP)
- 🔜 Phase 6 — MLS migration

See [`INTEGRATION_ROADMAP.md`](INTEGRATION_ROADMAP.md) for the detailed
plan and [`VEIL_DESIGN.md`](VEIL_DESIGN.md) for the cryptographic
design.

## License

MIT
