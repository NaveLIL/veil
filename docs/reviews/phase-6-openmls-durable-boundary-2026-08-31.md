# Phase 6 OpenMLS durable boundary — 2026-08-31

## Outcome

Fixed. The isolated OpenMLS engine now has a production-shaped persistence
adapter over Veil's existing SQLCipher database and OS keychain. This closes
the local checkpoint/rollback/output durability slice of Phase 6 without
enabling MLS in desktop, Android, or Node runtime.

The prior foundation could make an OpenMLS state transition durable, but a
caller still had to coordinate the returned Commit, Welcome, Ciphertext, or
KeyPackage with a separate network queue. A crash in that gap could consume a
secret-tree generation without retaining the exact bytes that must be retried.
On receive, a database commit followed by keychain failure could similarly
advance the receive tree while the caller lost the only plaintext result.

## Security path and invariant

The reviewed path is:

1. untrusted MLS wire input or a local group mutation enters `MlsClient`;
2. OpenMLS mutates its provider/secret-tree state in memory;
3. Veil serializes one leaf-bound checkpoint and derives exact output IDs;
4. `VeilDbMlsStore` commits the checkpoint plus network outbox or receive inbox
   in one SQLCipher `BEGIN IMMEDIATE` transaction;
5. only after commit does the store advance the independent OS-keychain
   generation anchor;
6. only after the store reports success does the ordinary API release output.

The invariant is: no state-advancing output can exist only in process memory.
Every exact network byte needed for retry, and every receive plaintext whose
secret-tree generation is already consumed, is durably recoverable beside the
matching checkpoint. An anchor ahead of SQLCipher is rollback evidence and
fails closed. SQLCipher ahead of the anchor is the single expected crash gap
and may heal only from the generation verified in the database.

## Implementation

- Added `VeilDbMlsStore` over the application's existing synchronized `VeilDb`;
  no second SQLite database or plaintext OpenMLS provider was introduced.
- Added `mls_checkpoints_v1`, `mls_outbox_v1`, and `mls_inbox_v1`. Rows use
  exact leaf/group/digest shapes, deterministic domain-separated IDs, hard
  payload/count/page limits, 64 MiB aggregate pending-byte budgets, consecutive
  checkpoint CAS, and foreign keys.
- Commit, Welcome, Ciphertext, and KeyPackage bytes are staged exactly, not
  regenerated. ACK checks the exact scoped digest and erases the payload;
  repeated matching ACK is idempotent.
- Typed Welcome/Commit receipts and decrypted application bytes are staged
  inside SQLCipher in the same transaction as receive state. They are not
  network output or a second public history. The caller ACKs a control receipt
  after transport projection, or erases application plaintext only after its
  normal message projection is durable.
- The store owns its rollback comparison. The previous caller-controlled
  minimum-generation argument was removed.
- Added a canonical leaf-bound OS-keychain generation record. Missing,
  malformed, unavailable, cross-leaf, decreasing, and database-behind-anchor
  states fail closed. Monotonic writes/deletion are serialized process-wide;
  a multi-process runtime remains outside the enabled product boundary and is
  part of the concurrency gate.
- A stale client may not advance the anchor from an unverified generation.
  The adapter heals a lagging anchor only after SQLCipher proves the matching
  generation already exists.
- Explicit leaf reset deletes SQLCipher state first and the keychain anchor
  last. A keychain deletion failure therefore leaves a visible fail-closed
  partial reset that is safe to retry; no reset is executed automatically by
  this checkpoint.
- The earlier raw checkpoint writer exists only under `cfg(test)`. Workspace
  consumers cannot select it as a persistence path that bypasses the rollback
  anchor and durable output contract.
- Secret-bearing checkpoint snapshots, outbox bytes, inbox plaintext, and
  intermediate provider copies are zeroized on drop where Rust ownership
  permits.
- Removed the inactive pre-v0.3 split MLS tables rather than preserving a
  misleading compatibility path.

## Legitimate behavior preserved

Ordinary create, KeyPackage generation, group creation, add/welcome, commit,
encrypt, decrypt, restore, offline outbox retry, and inbox projection remain
automatic APIs. No epoch, key, anchor, or retry ceremony is exposed to the
user. A pre-commit rejection restores the exact in-memory provider state. If
SQLCipher has committed and only the keychain update fails, the client keeps
the advanced generation and reports a distinct durable-commit-pending result;
restore heals it after secure storage becomes available.

## Verification

Automated tests cover:

- SQLCipher checkpoint CAS and atomic checkpoint+outbox/inbox rollback under
  injected insert failures;
- exact output recovery and bounded, digest-bound idempotent ACK;
- process-gap behavior where SQLCipher commits and the anchor update fails;
- receive-gap recovery of plaintext without decrypting the ciphertext twice;
- typed Welcome/Commit receipt recovery without applying control input twice;
- database rollback detection when the keychain anchor is newer;
- rejection of a stale/unverified client generation without poisoning the
  anchor;
- explicit reset failure, retry, and safe generation-zero recreation;
- checkpoint corruption/shape limits and existing 2/3-party OpenMLS round trips.

Formatting and patch-integrity checks pass locally. The Windows host lacks the
MSVC linker/SDK, so compiled workspace evidence is taken from the protected
GitHub CI attached to PR #60. Exact final run results are recorded in the PR
before merge.

## Remaining gates

This work does not make MLS a shipped user feature. Activation still requires:

- exact canonical Node-origin/account/device/transparency-bound MLS credentials;
- authenticated bounded KeyPackage publication/consumption and Delivery
  Service HTTP/WS transport;
- `veil-client`, Tauri, and UniFFI orchestration with deterministic group
  migration and no Sender-Key downgrade;
- concurrent commit, replay/reorder, removal, stale-device, offline rejoin,
  process/power-loss, and obsolete-secret deletion evidence;
- parser/fuzz, hostile-Node, desktop/Android interop, and physical-device gates;
- an independent audit before any strong public assurance claim.
