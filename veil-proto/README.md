# veil-proto

Protocol Buffer definitions for the Veil encrypted messenger.

All Veil components (clients, server, bots) depend on this repository as the single source of truth for the wire protocol.

Normative byte encodings for cryptographic device identity and conversation
device rosters are documented in [DEVICE_BINDING_V1.md](DEVICE_BINDING_V1.md).

The append-only public presentation/recovery registry is documented in
[PUBLIC_FAILURE_CODE_V1.md](PUBLIC_FAILURE_CODE_V1.md). It intentionally does
not add or repurpose a protobuf field.

## Structure

```
veil/v1/
├── envelope.proto   # Root message (WebSocket frame wrapper)
├── auth.proto       # Authentication (Ed25519 challenge-response)
├── chat.proto       # Messages, key exchange, sender keys
├── presence.proto   # Online status, typing indicators
├── share.proto      # Secure share links
├── server.proto     # Servers, channels, roles, multi-device sync
├── profile.proto    # Presentation-only profile invalidation
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
# Run from the monorepo root. protoc-gen-go v1.36.11 is the reviewed version.
protoc --proto_path=veil-proto \
  --go_out=. \
  --go_opt=module=github.com/NaveLIL/veil \
  veil-proto/veil/v1/*.proto
```

This writes the checked-in bindings to `veil-server/pkg/proto/v1`. Review both
the `.proto` source and regenerated Go diff in the same change.

## Versioning

- `v1` — current Preview wire namespace; compatibility may still change before
  the first stable release
- Breaking changes → `v2` (new directory)
- Additive changes (new fields, new oneof variants) are backwards compatible
