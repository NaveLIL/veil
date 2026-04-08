# veil-proto

Protocol Buffer definitions for the Veil encrypted messenger.

All Veil components (clients, server, bots) depend on this repository as the single source of truth for the wire protocol.

## Structure

```
veil/v1/
├── envelope.proto   # Root message (WebSocket frame wrapper)
├── auth.proto       # Authentication (Ed25519 challenge-response)
├── chat.proto       # Messages, key exchange, sender keys
├── presence.proto   # Online status, typing indicators
├── share.proto      # Secure share links
├── server.proto     # Servers, channels, roles, multi-device sync
├── media.proto      # File upload/download
└── voice.proto      # Voice/video (LiveKit tokens)
```

## Usage

### Rust (prost)
```toml
# In your build.rs
prost_build::compile_protos(&["path/to/veil/v1/envelope.proto"], &["path/to/"])?;
```

### Go
```bash
protoc --go_out=. --go_opt=paths=source_relative veil/v1/*.proto
```

## Versioning

- `v1` — current stable version
- Breaking changes → `v2` (new directory)
- Additive changes (new fields, new oneof variants) are backwards compatible
