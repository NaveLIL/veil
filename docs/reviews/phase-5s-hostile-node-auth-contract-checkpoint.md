EVIDENCE CHECKPOINT ONLY — the hostile-Node P1 and Phase 5S remain open.

# Phase 5S exact-origin transport-auth contract checkpoint

Date: 2026-07-20

This host-only checkpoint freezes a shared Rust/Go byte contract for future
WebSocket authentication v3 and signed REST authentication v2. It is a
prerequisite for closing the known cross-Node credential-relay boundary; it is
not runtime mitigation by itself and is not a production-readiness claim.

## Scope

The checkpoint adds pure, deterministic code only:

- `veil-client::auth_contract` owns native exact-origin, UUID, HTTP method and
  request-target validation; the origin-scoped Node Access Pass commitment;
  REST v2 bytes; and crate-private WS v3 context/proof bytes;
- `veil-server/internal/auth` owns the same Pass and WS v3 byte builders;
- `veil-server/internal/authmw` owns the same exact-origin validator, REST v2
  byte builder, body digest, and canonical future header parsers;
- `test-vectors/transport-auth/v1.json` is one cross-language, synthetic-only
  fixture whose exact bytes are pinned by SHA-256;
- ADR-0003 records the version, fields, validation, downgrade policy, and
  activation requirements.

The frozen fixture SHA-256 is:

```text
c90f7aac7619d178e06c0ac0d7aab6084511ceffb505b8fcf7058ba6812ad9bc
```

`.gitattributes` forces LF for the JSON and checksum. Rust and both Go packages
load the same file, require one final LF with no CR, bound it to 64 KiB, compare
the reviewed digest and exact `SHA256SUMS` line, reject unknown fields through
typed decoders, and require canonical lowercase fixed-width hex. The reviewed
whole-file digest is the exact-byte guard across both languages.

## Exact contract

All domains include their final NUL byte. Variable byte strings use a four-byte
unsigned big-endian length. Fixed-width values are appended raw and integers are
unsigned big-endian. No protobuf, JSON, HTTP serialization, implicit delimiter,
or platform normalization enters a signing message.

### Origin-scoped Pass commitment

```text
SHA-256(
  "veil-node-access-pass-commitment-v1\0"
  || u32be(origin_length) || canonical_origin
  || raw_pass_32
)
```

The raw bearer is borrowed only for hashing, is not retained in a contract
structure, and is absent from the signed WS context. The commitment does not
replace the server's private lookup digest or transactional one-time Pass
consumption.

### WS v3

```text
context =
  "veil-ws-auth-v3/context\0"
  || u32be(origin_length) || canonical_origin
  || server_ephemeral_x25519_32
  || account_x25519_public_32
  || account_ed25519_public_32
  || device_id_16
  || verified_device_binding_commitment_32
  || registration_intent_u8
  || pass_commitment_32

account_proof_message =
  "veil-ws-auth-v3/account-proof\0"
  || u32be(context_length) || context
  || contributory_account_dh_32

device_proof_message =
  "veil-ws-auth-v3/device-proof\0"
  || u32be(context_length) || context
  || contributory_device_dh_32
  || account_proof_signature_64
```

Intent is exactly 1 existing, 2 explicitly open registration, or 3 Pass
registration. Existing/open require an all-zero Pass slot; Pass registration
requires a non-zero origin-scoped commitment. For an absent identity the future
server must never infer or fall back between those creation modes. An exact
identity already committed on the same origin authenticates without rechecking
or consuming a registration capability, preserving idempotent process-death
recovery and ADR-0002. The account signature is chained into the device message.

The commitment supplied to the builder is a typed boundary assumption, not a
client assertion: future runtime must first verify the complete account-signed
device binding and compute its commitment itself. The synthetic fixture uses a
fixed stand-in commitment and fixed non-zero DH result bytes; it proves transcript
and signature agreement, not X25519 derivation or binding verification.

### REST v2

```text
"veil-rest-auth-v2\0"
|| u32be(origin_length) || canonical_origin
|| canonical_user_uuid_bytes_16
|| u32be(method_length) || uppercase_http_method
|| u32be(target_length) || canonical_origin_form_target
|| timestamp_ms_u64be
|| nonce_32
|| sha256(exact_body_bytes)_32
```

The user is a canonical non-nil lowercase UUID and is encoded in RFC network
byte order. Timestamp is in `1..MaxInt64`; the future header parser rejects
signs, leading zeros, zero, and range overflow. Nonce is a non-zero 32-byte value
whose future header form is strict, unpadded base64url with decode/re-encode
equality. Replay state is not implemented in this checkpoint.

Method is an uppercase bounded HTTP token. The bounded exact request target
keeps query order and duplicate query keys but rejects absolute form, fragments,
controls/non-ASCII, backslashes, duplicate path slashes, dot segments, a bare
trailing `?`, lowercase/malformed percent escapes, encoded unreserved bytes, and
encoded path separators. Future middleware must take the exact request target
from an unambiguous raw server boundary and hash the exact body before parsing.

## Cross-language evidence

The fixture contains deliberately public synthetic Ed25519 seeds, keys, Pass,
nonce, DH-result stand-ins, body, and expected outputs. Rust and Go independently
reproduce and compare:

- account and device public keys derived from the synthetic seeds;
- origin-scoped Pass commitment;
- WS context and its SHA-256;
- WS account and device proof messages and deterministic signatures;
- REST body SHA-256, signing message, message SHA-256, and deterministic
  signature.

Mutation tests show that origin, challenge, account keys, device ID, verified
binding commitment, intent/Pass commitment, both DH results, chained account
signature, REST user/method/target/timestamp/nonce/body, and proof domains cannot
be changed while retaining signature validity. Other-origin vectors model the
cryptographic core of Node-A-to-Node-B forwarding. Legacy WS v2 and REST v1
domains are not accepted as the new proof messages.

Validation matrices cover explicit/implicit/default/leading-zero ports,
uppercase and Unicode hosts, userinfo/path/query/fragment, DNS trailing dots,
canonical IPv4/IPv6, mapped/zone-scoped IPv6, non-loopback cleartext, UUID
aliases, method aliases, request-target escapes and routing aliases, timestamp
aliases/range, nonce length/encoding/zero, and fixed-field bounds.

## Deliberately not activated

No existing connection, gateway handler, protobuf message, REST middleware,
FFI/Kotlin surface, server configuration, deployment file, compatibility flag,
or running Node uses these builders. WS v2 and REST v1 behavior is unchanged.
No phone, ADB, APK, Pass, recovery, or live-server operation was performed.

This preserves Preview compatibility while the contract is attacked in
isolation, but it also means the known P1 remains open. In particular, this
checkpoint does not provide:

- a mandatory configured canonical public Node origin;
- client/server version negotiation or a fail-closed production cutover;
- raw request-target/body capture and REST v2 replay-cache semantics;
- runtime computation of the verified device-binding commitment;
- an opaque strictly verified account-proof type enforcing the device-proof
  builder's activation order (the pure builder accepts a non-zero 64-byte field);
- an actual two-Node relay harness covering existing-account, open-registration,
  and B-Pass prerequisites;
- Host/SNI/redirect enforcement, deployment migration, or removal of legacy
  credentials;
- first-contact key transparency, malicious roster consistency, multi-device
  session lifecycle, or an independent cryptographic audit.

The hostile-Node P1 closes only when those runtime and two-Node gates pass and a
production Node rejects origin-unbound WS v2 and ingress-dependent REST v1.

## Internal review disposition

A separate read-only internal review found no blocking, high-, or
medium-severity byte-layout, validator-parity, fixture, activation-scope, or
documentation finding. It recorded one low-severity activation hazard: the
pure device-proof builders can validate only that the chained account-signature
field is 64 bytes and non-zero. The client must supply its locally generated
signature; the server must supply only a strictly verified account proof.
ADR-0003 now requires that order and recommends an opaque verified-proof type
before live wiring. This review is not an independent external cryptographic
audit and does not close Phase 5S.

## Required host evidence

The checkpoint is accepted only when all of the following pass on the final
tree:

```text
cargo fmt --all -- --check
cargo clippy -p veil-client --all-targets -- -D warnings
cargo test -p veil-client
go test ./internal/auth ./internal/authmw
go vet ./internal/auth ./internal/authmw
git diff --check
```

Final-tree evidence for this checkpoint:

- focused Rust auth-contract tests: 8 passed;
- full `veil-client` unit suite: 185 passed, 11 explicitly ignored as
  superseded, followed by 4 passed integration tests and clean doc tests;
- full ordinary Go workspace: all packages passed `go test ./...` and
  `go vet ./...`;
- Rust format and `veil-client` all-target clippy with warnings denied passed;
- Go format diff and repository `git diff --check` passed.

The wider Rust and Go workspace gates remain required before release or runtime
activation. Focused green tests do not replace the Phase 5S exit gate or an
independent audit.
