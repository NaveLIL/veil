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
the store-owned external anchor, and a mutating API releases output only after
its new checkpoint and exact durable output are committed. Any protocol,
encoding, or pre-commit persistence failure restores the exact pre-operation
provider state.

## Implemented

- Upgraded from the temporary OpenMLS 0.7/RustCrypto 0.4 line to upstream
  OpenMLS 0.9.0 and RustCrypto 0.6.0; removed the vendored provider fork.
- Added checkpoint format `VMLSCP01`: explicit version/flags/generation,
  SHA-256 leaf binding and body integrity, deterministic key ordering, exact
  length/trailing-byte checks, and hard total/entry/key/value/signer limits.
- Enforced exact 16-byte conversation UUIDs, exact 32-byte derived leaf IDs,
  and hard KeyPackage/handshake/application/exporter limits before parsing or
  allocation. The commit API rejects every processed content type except a
  staged MLS Commit and rolls the receive tree back on mismatch.
- Combined the TLS-encoded signature key and all OpenMLS provider entries in
  one zeroizing secret-bearing blob.
- Changed mutating client APIs to exclusive `&mut` access and added exact
  provider rollback around every operation.
- Added an atomic `MlsKeyStore` checkpoint contract and in-memory CAS
  implementation. Restore requires a minimum external generation.
- Replaced inactive SQLCipher `mls_signer` plus `mls_provider_snapshot` tables
  with the versioned `mls_checkpoints_v1` boundary. The follow-up durable-
  boundary checkpoint adds atomic `mls_outbox_v1`/`mls_inbox_v1` and the OS
  rollback anchor. Old prototype rows are intentionally discarded: MLS was
  never an enabled user feature and the formats cannot be safely combined.
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

## Superseded local-boundary items

The `VeilDb` adapter, external rollback anchor, atomic network outbox, and
receive recovery projection were completed later on 2026-08-31 and are
documented in
[`phase-6-openmls-durable-boundary-2026-08-31.md`](phase-6-openmls-durable-boundary-2026-08-31.md).

## Still blocking MLS runtime

- Derive credentials from exact canonical Node origin, account, device,
  binding version and accepted transparency state.
- Bound and authenticate KeyPackage lifecycle and Delivery Service operations.
- Prove obsolete-secret deletion, concurrent-commit handling, replay/reorder,
  removal, offline catch-up/rejoin and process/power-loss recovery.
- Complete desktop/Android interoperability, hostile-Node, fuzz and physical
  device gates before exposing an MLS badge or migration control.
