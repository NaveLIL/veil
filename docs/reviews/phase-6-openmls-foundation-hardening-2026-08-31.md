# Phase 6 OpenMLS foundation hardening — 2026-08-31

## Outcome

The isolated MLS library is hardened but remains disabled in every product
runtime. This checkpoint removes the unsafe prototype persistence path; it does
not claim that Veil group messaging has migrated to MLS.

## Threat and invariant

The former prototype stored the MLS signer and provider map separately and
accepted an unversioned, unbounded, non-canonical snapshot. A malformed or
misbound snapshot could consume excessive memory, silently replace duplicate
keys, accept trailing bytes, or combine state from different leaves. Mutating
operations also returned protocol output before a caller proved the new secret
tree or epoch durable.

The new invariant is: one leaf has one complete checkpoint, generations advance
exactly by one through atomic compare-and-swap, restore rejects state older than
the caller's external anchor, and a mutating API releases output only after its
new checkpoint is durable. Any protocol, encoding, or persistence failure
restores the exact pre-operation provider state.

## Implemented

- Upgraded from the temporary OpenMLS 0.7/RustCrypto 0.4 line to upstream
  OpenMLS 0.9.0 and RustCrypto 0.6.0; removed the vendored provider fork.
- Added checkpoint format `VMLSCP01`: explicit version/flags/generation,
  SHA-256 leaf binding and body integrity, deterministic key ordering, exact
  length/trailing-byte checks, and hard total/entry/key/value/signer limits.
- Combined the TLS-encoded signature key and all OpenMLS provider entries in
  one zeroizing secret-bearing blob.
- Changed mutating client APIs to exclusive `&mut` access and added exact
  provider rollback around every operation.
- Added an atomic `MlsKeyStore` checkpoint contract and in-memory CAS
  implementation. Restore requires a minimum external generation.
- Replaced inactive SQLCipher `mls_signer` plus `mls_provider_snapshot` tables
  with `mls_checkpoints(leaf, generation, checkpoint)` and a one-statement CAS
  boundary. Old prototype rows are intentionally discarded: MLS was never an
  enabled user feature and the formats cannot be safely combined.
- Deleted unregistered Tauri commands and unused renderer wrappers that still
  modeled the old split persistence flow.

## Open-source decision

OpenMLS remains the protocol implementation; Veil does not implement MLS
cryptographic primitives. The official OpenMLS SQLite provider was inspected.
Its current crate owns a separate bundled SQLite connection, so adopting it now
would place MLS secrets outside Veil's SQLCipher database and would not provide
the required atomic transaction with Veil's durable network outbox. The next
adapter therefore implements the OpenMLS checkpoint contract over `VeilDb`;
this decision should be revisited if upstream supports the same encrypted
transaction boundary.

## Verification

Automated coverage includes:

- canonical checkpoint round-trip and leaf/generation binding;
- corrupt, truncated, trailing and oversized input rejection;
- consecutive in-memory compare-and-swap conflicts;
- exact rollback after an injected persistence failure;
- stale restore rejection against an external generation anchor;
- SQLCipher create/advance/stale-writer/skipped-generation CAS behavior;
- existing two-party, three-party async catch-up, KeyPackage pool and
  restart/epoch/message round trips;
- the RFC 9180 HPKE regression suite.

The final CI run and exact result are recorded in the pull request before merge.
The local Windows host can run formatting, metadata and diff checks but lacks
the MSVC linker/Windows SDK, so compiled Rust evidence comes from GitHub CI.

## Still blocking MLS runtime

- Derive credentials from exact canonical Node origin, account, device,
  binding version and accepted transparency state.
- Implement `MlsKeyStore` over `VeilDb` and keep the external monotonic anchor
  outside the replaceable SQLCipher file.
- Commit checkpoint plus ciphertext/commit/welcome outbox atomically so a crash
  after state advance cannot lose unpublished protocol output.
- Bound and authenticate KeyPackage lifecycle and Delivery Service operations.
- Prove obsolete-secret deletion, concurrent-commit handling, replay/reorder,
  removal, offline catch-up/rejoin and process/power-loss recovery.
- Complete desktop/Android interoperability, hostile-Node, fuzz and physical
  device gates before exposing an MLS badge or migration control.
