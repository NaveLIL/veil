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

### WebSocket authentication versions

`AuthChallengeV3`, `AuthResponseV3`, and `AuthResultV3` are the active native
authentication exchange on exact `/v3/events`. Their Envelope tags are 14, 15,
and 16. The frozen legacy tags 10, 11, and 12 remain decodable only so a
post-handshake downgrade attempt can be identified, its bearer cleared, and
the socket closed; no v2 verifier or compatibility endpoint exists. `/ws`
permanently returns HTTP 410. WS v3 binds canonical Node origin, account,
device, client metadata, registration intent, challenge, and optional Node
Access Pass into one signed attempt. Commands, ACKs, and events then share the
same authenticated socket and sequence epoch.

Signed HTTP routes use REST authentication v2. Its transcript binds canonical
origin, account, method, raw request target, timestamp, nonce, and body digest;
replay state is durable in PostgreSQL. REST v1 parse failures never fall back
from a route configured as v2-only.

### Direct cryptographic profiles

Direct v2 is an additive profile inside the `veil.v1` namespace. A v2
`SendMessage` carries `crypto_profile = "direct_v2"`, era `1`, the exact target
device and binding version, and the Direct transcript commitment. The gateway
derives the sender device from the authenticated WS v3 principal and persists
the full routing context. `MessageEvent` returns that context so the receiver
can reconstruct the same origin/account/device/session transcript before
decrypting. Once a conversation has a durable v2 commitment, missing or legacy
profile fields are a rejected downgrade, never inferred compatibility.
