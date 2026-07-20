EVIDENCE CHECKPOINT ONLY — Phase 5S remains open.

# Phase 5S Direct-v1 key-validation checkpoint

Date: 2026-07-20

## Scope

This host-only checkpoint addresses findings 1 and 2 recorded by the frozen
Direct-v1 transcript review. It tightens two existing rejection boundaries; it
does not introduce a new Direct protocol, claim a cryptographic audit, or
change the Preview-only status.

The frozen `test-vectors/direct-v1/v1.json` and its `SHA256SUMS` entry were not
changed. The reviewed fixture SHA-256 remains
`DAD0A84E5D7366E5189B24C9FB230C4BDD4CC67245607C148B3E3003D9915C2E`.
Valid Direct-v1 wire bytes, associated data, session serialization, and the
SQLCipher schema remain on their existing versions; this checkpoint requires
no wire- or stored-state migration.

## Finding 1 — exact peer/bundle identity

The public `VeilClient::establish_session(peer_identity_key, bundle)` path now
rejects unless `peer_identity_key == bundle.identity_key`. The comparison is
the first classified session-establishment check, before X3DH initiation,
ratchet construction, SQLCipher publication, or in-memory session/header
publication. A mismatch is a definite peer-bundle rejection, not a storage-
uncertain result, and neither key is included in the diagnostic.

The file-backed client probe verifies that a mismatch leaves both candidate
peer keys without an in-memory or SQLCipher ratchet session and leaves the
pending INITIAL-header store empty. Reopening the same SQLCipher database must
observe the same absence. A separate matching-key probe verifies that the valid
path persists and reopens exactly one session and one pending INITIAL header
under the bundle identity.

## Finding 2 — contributory X25519 result before publication

X3DH and Double Ratchet now use one internal contributory-result check over the
actual `x25519-dalek` shared secret. The check is not a byte-level blacklist:
zero and non-zero low-order public encodings are rejected when their DH result
is non-contributory.

The received-ratchet-key transition validates both DH results before publishing
new counters, receiving/sending chains, root key, or DH keys. The normal decrypt
path still operates on a cloned candidate and installs it only after successful
authentication. Primitive tests compare serialized session bytes before and
after rejected zero and non-zero low-order keys, then decrypt the untouched
authentic packet. The production `veil-client` integration probe mutates the
INITIAL ratchet key to a non-zero low-order encoding and verifies that runtime
session, file-backed SQLCipher session, and one-time prekey state remain byte-
identical.

## Host evidence

The checkpoint passed these host-only gates:

```text
cargo fmt --all -- --check
cargo clippy -p veil-crypto -p veil-store -p veil-client --all-targets -- -D warnings
cargo test -p veil-crypto
cargo test -p veil-store
cargo test -p veil-client
```

- `veil-crypto`: 94 unit tests and 8 integration tests passed;
- `veil-store`: 91 unit tests passed;
- `veil-client`: 184 unit tests total — 173 passed and 11 explicitly ignored
  legacy tests — plus 4 integration tests passed.
- `git diff --check` passed;
- the frozen fixture SHA-256 was recomputed as
  `DAD0A84E5D7366E5189B24C9FB230C4BDD4CC67245607C148B3E3003D9915C2E`;
- a separate read-only review of the checkpoint diff reported no P0, P1,
  or P2 findings.

## Residual findings and non-claims

Findings 3–5 from the transcript checkpoint remain open:

1. the relationship between `X3DHResult.associated_data` and the larger
   versioned Direct AAD still requires exact protocol review;
2. Direct AAD still does not bind canonical Node origin, account IDs, or device
   IDs;
3. non-empty skipped-key serialization is not yet canonical, and malformed
   skipped-key entries, exhaustion, corruption, and rollback remain open.

This checkpoint does not close hostile-Node or cross-Node credential scope,
first-contact key transparency, Sesame-like session lifecycle, simultaneous
initiation, proper multi-device semantics, the isolated `libsignal` spike,
Android/desktop cross-runtime fixture consumption, Android FFI/UI behavior,
physical-device evidence, or an independent cryptographic/security audit.
Phase 5S and the Android Direct Preview exit matrix therefore remain open.
