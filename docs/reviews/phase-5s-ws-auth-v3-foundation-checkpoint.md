EVIDENCE CHECKPOINT ONLY — the hostile-Node P1 and Phase 5S remain open.

# Phase 5S WebSocket auth v3 foundation checkpoint

Date: 2026-07-20

## Scope

Checkpoint 5S.3B-2 adds a dedicated, non-activated WebSocket authentication v3
foundation without changing the current `/ws` handshake:

- `AuthChallengeV3`, `AuthResponseV3`, and `AuthResultV3` are separate protobuf
  messages rather than extensions to the legacy auth messages;
- their Envelope tags are fixed at 14, 15, and 16, while legacy auth and device
  registration retain tags 10 through 13; v3 declarations are appended after
  all legacy declarations so generated descriptor indexes also remain stable;
- registration intent is explicit (`EXISTING`, `OPEN`, or `PASS`) and v3 has a
  dedicated failure enum using Node Access Pass terminology;
- the Go server can create an origin-bound, version-marked, one-shot v3
  challenge, but no gateway route calls that constructor or verifies a v3
  response;
- the native Rust client can validate an exact `/ws` target, prepare the frozen
  account/device proof chain, and validate a future v3 result, but no connection,
  API, FFI, desktop, Kotlin, or Android entry point calls that code;
- every known v3 auth envelope received after the authenticated barrier is a
  terminal authentication-epoch anomaly instead of a silently ignored message.

The protobuf descriptors and Rust wire encodings independently freeze all v3
field, enum, and Envelope numbers. Generated Go bindings are reproducible with
the reviewed `protoc-gen-go` v1.36.11 toolchain.

## Security semantics established

The client accepts only an exact endpoint spelling derived from an already
canonical Node origin. It permits `wss://`, or `ws://` only because the shared
origin grammar has already restricted cleartext to exact loopback. The endpoint
is exactly `/ws`; credentials, query, fragment, path aliases, host aliases, and
non-default implicit ports are rejected. Explicit and implicit default
WebSocket ports map to the same explicit canonical transcript origin.

The v3 challenge must carry protocol version 3, the exact selected canonical
origin, and one 32-byte server X25519 public value. Both account and device DH
results must be contributory. The client revalidates the account-signed local
device binding, derives its commitment from the exact binding preimage, commits
the selected registration intent and origin-scoped Pass commitment, signs the
account proof, then chains that signature into the device proof. A raw Pass is
copied only after every fallible proof operation succeeds. Its prepared
protobuf copy and encoded envelope buffer have explicit zeroizing ownership.

A successful result requires version 3, the exact target origin, a canonical
non-nil lowercase user UUID, an active matching binding version/status,
per-device security, no failure reason, and no diagnostic error. Failure
classification comes only from the dedicated enum after version and origin
validation; peer diagnostic text is never interpreted or retained. The
preparer returns an opaque, non-cloneable result expectation beside the
zeroizing wire buffer, binding result validation to the exact origin, device
binding version/status, and registration intent used by that same signed
attempt instead of accepting caller-fabricated comparison values.

On the server, each connection has at most one pending challenge. Replacement,
disconnect, expiry, protocol mismatch, or verification consumes or clears the
stored private key. Legacy v2 input validation remains before challenge
consumption, preserving its existing behavior; a v3 challenge presented to the
v2 verifier is consumed once and rejected before cryptography or database I/O.

## Deliberately not activated

The current gateway still calls only `CreateChallenge`, emits only legacy
`AuthChallenge`, and routes only legacy `AuthResponse` to `VerifyResponseV2`.
An unauthenticated `AuthResponseV3` receives the same generic pre-authentication
401 path and does not increment legacy authentication state. Its now-known raw
Pass field is nevertheless cleared from the decoded Go message on every return
path instead of being left until garbage collection. The current Rust connection
still initiates only the legacy exchange. There is no v3-to-v2 fallback or
capability inference from generated protobuf support.

Therefore this checkpoint does **not** close the cross-Node credential-relay
P1, activate Node Access Pass v3 registration, or make a production-readiness
claim. Activation still requires a separately reviewed endpoint or subprotocol,
a complete server v3 verifier and atomic Pass/account transaction, explicit
Preview compatibility policy, live exact-origin enforcement, and a two-Node
relay matrix. The future transport boundary must also validate the raw v3
Envelope canonically and reject unknown or duplicate security fields before
prost/Go decoding can discard their representation; the pure helpers in this
checkpoint intentionally accept already-decoded structures and cannot enforce
that wire-boundary rule by themselves.

No phone, ADB, APK, recovery ceremony, Pass issuance/application, Compose
runtime, live Node, or deployment configuration was accessed or changed.
Physical Android testing remains deferred until it is explicitly resumed and a
newly displayed recovery phrase is confirmed recorded.

## Host-only gates

The final tree must pass:

```text
protoc regeneration with no generated diff
go test ./...
go vet ./...
go test -race -timeout 10m ./...
go list -mod=readonly -deps ./...
go mod verify
cargo fmt --all -- --check
cargo clippy -p veil-client --all-targets -- -D warnings
cargo test -p veil-client
git diff --check
```

These checks demonstrate local byte agreement, validation, state-machine
isolation, and regression coverage only. They are not a live transport,
hostile-Node, external cryptographic-audit, or release-signing result.

## Final-tree host evidence

- reviewed `protoc-gen-go` v1.36.11 / protoc 34.1 regeneration was byte-for-byte
  reproducible; Go and Rust tests freeze field numbers, enum values, Envelope
  tags, and append-only legacy descriptor indexes;
- `go test ./...`, `go vet ./...`, readonly dependency loading, and
  `go mod verify` passed across the server workspace;
- `go test -race -timeout 10m ./...` passed across every ordinary Go package,
  including simultaneous one-shot challenge consumers and decoded-Pass
  clearing on the unactivated gateway path;
- Rust formatting and all-target `veil-client` clippy with warnings denied
  passed;
- the full `veil-client` suite passed 196 tests with 11 explicitly superseded
  tests ignored, followed by 4 passing integration tests and clean doc tests;
- the focused native v3 suite passed all 8 proof/target/result tests, and the
  post-authentication anomaly and frozen protobuf wire-number tests passed;
- the existing transport-auth and origin fixtures remained byte-identical at
  SHA-256 `c90f7aac7619d178e06c0ac0d7aab6084511ceffb505b8fcf7058ba6812ad9bc`
  and `42b8fe154439b3dde57a1c3e9c3f845c7a9df04649e6fd85b28ec577fff0ef5c`;
- static call-site review confirmed that the gateway still calls only legacy
  `CreateChallenge`/`VerifyResponseV2`, while the live Rust connection still
  sends and accepts only the legacy pre-authentication messages;
- two independent final security reviews reported no remaining P0–P3 finding
  in the stated non-activated scope, and `git diff --check` passed.
