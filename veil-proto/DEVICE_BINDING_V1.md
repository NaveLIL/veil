# Veil cryptographic device binding v1

This document is normative for the v1 byte encodings shared by desktop,
mobile, and server implementations. A device binding does not replace the
account identity. It adds a separately generated X25519 encryption key and
Ed25519 signing key for one stable 16-byte device identifier.

All integers are unsigned, fixed-width, and big-endian. Binding versions are
limited to `1..2^63-1`; capability bit 63 is reserved and MUST be zero, so the
mask is limited to `0..2^63-1`. Domain strings end in one NUL byte (`00`). No
text, UUID formatting, protobuf serialization, or JSON serialization is
signed.

## Capabilities and status

Capabilities are a `u64` bit mask:

- `SENDER_KEY_V5 = 0x0000000000000001`
- `SEALED_SKDM_V3 = 0x0000000000000002`
- the v1 channel-ready mask is `0x0000000000000003`

Signed status is one byte:

- `01 ACTIVE`
- `02 EXCLUDED`
- `03 REVOKED`

`04 LEGACY_UNBOUND` is response-only and MUST NOT be accepted in a signed
binding. `REVOKED` is terminal. `EXCLUDED` can return to `ACTIVE` only through
the next account-signed version.

## Account-authorized binding

The account Ed25519 key signs exactly:

```text
"veil-device-binding-v1" || 00
|| account_x25519_public[32]
|| account_ed25519_public[32]
|| device_id[16]
|| binding_version_u64be[8]
|| device_x25519_public[32]
|| device_ed25519_public[32]
|| capabilities_u64be[8]
|| status_u8[1]
```

Version starts at 1 and advances by exactly one. The two device public keys
are immutable for a device ID; key replacement requires a new device ID. An
identical retry of the current version is idempotent. Any other reuse or
rollback of a committed version is rejected.

## Device proof during WebSocket authentication

The device Ed25519 key signs exactly:

```text
"veil-device-auth-v1" || 00
|| server_ephemeral_x25519_public[32]
|| account_x25519_public[32]
|| account_ed25519_public[32]
|| device_id[16]
|| binding_version_u64be[8]
|| device_x25519_public[32]
|| device_ed25519_public[32]
|| capabilities_u64be[8]
|| status_u8[1]
|| account_binding_signature[64]
|| X25519(device_private, server_ephemeral_public)[32]
```

The server independently derives the final secret with its ephemeral private
key. This proves possession of both device private keys. Once a device ID has
a binding, omitting this proof is a downgrade error. A revoked device cannot
authenticate.

## Conversation device roster commitment

The SHA-256 input is:

```text
"veil-conversation-device-roster-v1" || 00
|| conversation_uuid_bytes[16]
|| required_capabilities_u64be[8]
|| member_count_u32be[4]
|| each member, sorted by raw UUID bytes:
     user_uuid_bytes[16]
     device_count_u32be[4]
     each device, sorted by signed device_id bytes:
       device_id[16]
       status_u8[1]
       binding_version_u64be[8]
       capabilities_u64be[8]
       device_x25519_public[32]
       device_ed25519_public[32]
       account_binding_signature[64]
```

A legacy device is deliberately included with status `04` and zeroes for all
remaining binding fields. Duplicate user or device identifiers are invalid.
Every authorized active device must satisfy the required capability mask;
legacy and insufficient active devices make the directory not ready. An
explicitly excluded or revoked device is never eligible.

The server persists a monotonic `roster_version` and increments it only when
this commitment changes. The REST response itself is not server-signed in v1:
clients authenticate the HTTPS connection and signed request, verify every
account binding signature, recompute the commitment, and reject a roster
version below the highest locally accepted version.

## REST representation

- `GET|PUT /v1/device-bindings/{device_id_hex}` is account request-signed and
  owner-only. Public keys and signatures are standard padded Base64. `version`
  and `capabilities` are canonical unsigned decimal strings (never JSON
  numbers, which lose `u64` precision in JavaScript); status is a JSON number.
- `GET /v1/conversations/{conversation_uuid}/device-directory` is request-
  signed and member-only. It returns the conversation ID, monotonic version,
  lowercase hex commitment, readiness plus reason, required mask, account
  keys, and the exact binding for every device. `roster_version`,
  `required_capabilities`, and nested binding integers use the same canonical
  decimal-string representation.

## Deterministic vector

The executable vectors live in
`veil-server/internal/auth/device_binding_test.go` and
`veil-server/internal/db/device_roster_test.go`. The device-binding vector
uses these inputs:

```text
account X25519 public = 11 * 32
account Ed25519 seed  = 22 * 32
device id             = 33 * 16
binding version       = 1
device X25519 private = 44 * 32
device Ed25519 seed   = 55 * 32
capabilities          = 3
status                = ACTIVE (1)
server X25519 private = 66 * 32
```

Expected outputs:

```text
account Ed25519 public:
a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0

device X25519 public:
ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b

device Ed25519 public:
c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242

server X25519 public:
219e4d800da968d2a5fcb009c784f4746c7138edb9ee4844b739e830b05cf424

account binding signature:
30c502700162d164a178a1fd624b3876c084f327f5e1a822fca2c9be977f7092928ff337559313ae0d11f7cc2447ae33f66f1f369dc9b2f32af3ee6fede29a00

device/server shared secret:
bef8ae582f817bd7eb1b104a83343a15770c1cf2dbc4b4207b70897b7a532209

device proof signature:
c17d2519f57119fc9415472aef77b212233c586365f10db7b5011dc3f45f7bd883eedbb6bbfcabe0291fedcc83685ec17790901ce252a3683937b3659f448303
```
