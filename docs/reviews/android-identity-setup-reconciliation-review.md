# Android identity setup reconciliation review

> **HOST-AUTOMATED EVIDENCE CHECKPOINT ONLY — NOT A TESTER RELEASE OR DEVICE RESULT.**
> A04/A05 and all connected or physical execution remain open.

Date: 2026-07-20

## Scope

This checkpoint adds durable, fail-closed reconciliation for native Android
identity setup after React-context loss or Android process replacement. It does
not change the recovery phrase ceremony, weaken the write-once vault, or make a
JavaScript route authoritative for identity state.

The application-owned native journal, coordinator, reconciler, recovery
Activity, runtime foreground epoch, React Native bridge, store, and bootstrap
gate now share one exact attempt/process correlation. A terminal receipt is
retained for at-least-once delivery; successful onboarding is accepted only
after the strict vault and a fresh runtime bootstrap agree.

## Fixed non-secret journal

The v1 record is exactly 80 bytes, big endian:

| Field | Size | Semantics |
| --- | ---: | --- |
| magic | 8 | Fixed format discriminator |
| version, flags | 2 | Version 1, no flags |
| mode, phase, outcome, revision | 4 | Closed enums and bounded transition revision |
| reserved | 2 | Must be zero |
| attempt UUID | 16 | Random UUIDv4 correlation only |
| process-incarnation UUID | 16 | Random UUIDv4 correlation only |
| SHA-256 | 32 | Digest of the preceding 48 bytes |

The schema has no variable-length payload and cannot carry a recovery phrase,
seed, key, identity/account/device identifier, Node origin, Access Pass, server
text, exception, or diagnostic. Attempt and process UUIDs must be distinct
IETF UUIDv4 values. `toString()` projections redact them.

The closed state machine is `PREPARED -> ACTIVE -> COMMITTING -> TERMINAL`,
with narrowly allowed cancellation/interruption edges and monotonically exact
revisions. A terminal record cannot transition again.

## Persistence and authority semantics

- The record lives below `noBackupFilesDir`; it is not cloud-backup or account
  data.
- Cross-thread/process access is locked. Reads require regular, non-symlinked
  files and exact encoded size/version/flags/reserved bytes/checksum/semantic
  shape. Newly created staging and lock inodes request owner-only permissions.
- Updates compare the complete expected record, create an exclusive staging
  inode, flush and fsync it, read it back, atomically rename it, and sync the
  directory.
- Crash recovery validates and re-fsyncs a surviving staging inode before
  promotion. Validation or fsync failures before rename preserve the prior base
  and pending stage. A post-rename sync/readback failure remains ambiguous and
  fails closed; a later reopen may observe the new record.
- The strict write-once native vault remains identity authority. A journal
  receipt is correlation and delivery state only; it cannot create, replace,
  or erase an identity.
- One application-owned coordinator serializes reconciliation with acquisition,
  listener settlement, completion, and abandonment using the full attempt UUID,
  process UUID, and lease. No timeout or uncorrelated Activity result decides
  success.

## Reconciliation truth table

| Durable/native observation | Result |
| --- | --- |
| No journal record | `NONE` |
| Same-process nonterminal record with the exact live coordinator owner | `IN_PROGRESS` |
| Same-process `COMMITTING` with the exact owner settled | Strict vault presence writes/returns `COMMITTED`; strict absence writes/returns `INTERRUPTED` |
| Same-process `PREPARED`/`ACTIVE` without the exact live owner, or any ownership conflict | `UNCONFIRMED` |
| Old-process nonterminal record and coordinator `ABSENT` | First persist an `INTERRUPTED` tombstone under the current process, then let strict vault presence decide |
| Terminal record with coordinator `ABSENT` or `SETTLED` | Strict vault presence is authoritative; otherwise only a matching cancellation/interruption receipt is returned |
| Malformed record/result, journal/vault I/O failure, coordinator exception, live/conflicting stale ownership, or invalid transition | `UNCONFIRMED` |

A reconciliation read never clears terminal receipts. Ambiguity cannot reopen
onboarding or synthesize success.

## React bootstrap and replay

The initial React tree remains opaque while the current foreground authority
epoch is being reconciled. `NONE` permits normal bootstrap. `IN_PROGRESS`
reattaches or parks the caller. `COMMITTED` requires fresh authoritative native
bootstrap confirmation before routing to the application. Cancellation and
interruption retain their distinct create/restore semantics, while
`UNCONFIRMED`, malformed bridge shapes, and hostile module/method/property
access block setup with the public `VEIL-SETUP-002` boundary. A stale-epoch
result is discarded; the route remains opaque while reconciliation is replayed
against the current epoch.

If authority changes again during confirmation, the retained terminal receipt
is replayed against the new current epoch. The App never requests Ready capture
while reconciliation is checking or blocked. Release-native policy cannot clear
protection; physical capture behavior remains deferred.

## Automated evidence

All commands were host-only. No ADB, device, emulator, install, uninstall,
connected test, server Pass operation, or APK assembly/signing was used.

- `pnpm exec jest --runInBand`: 27 suites, 213/213 tests passed.
- `pnpm exec eslint .`: passed.
- `pnpm exec tsc --noEmit`: passed.
- `gradlew.bat :app:testDebugUnitTest :app:testReleaseUnitTest :app:testInternalTesterUnitTest`:
  - Debug: 302 tests, 0 failures/errors, 1 skipped;
  - Release: 302 tests, 0 failures/errors, 12 skipped;
  - InternalTester: 302 tests, 0 failures/errors, 12 skipped.
- `gradlew.bat :app:lintDebug`: passed with 0 errors and 27 warnings.
- `git diff --check`: passed before checkpoint commit.

Two separate focused code-review passes finished with P0/P1/P2 findings at
zero after fixes. These were implementation reviews, not an external security
or cryptographic audit.

The combined Release/InternalTester lint attempt did not complete because the
third-party `expo-modules-core` CMake/Ninja configuration failed to create a
Windows/pnpm-path intermediate. This is not recorded as a green gate and is not
treated as evidence for those lint variants; their JVM unit-test variants did
complete successfully.

## Open boundaries

- A04 Activity recreation and A05 OS process-death recovery have not been run.
- Android filesystem, Keystore, SQLCipher, lifecycle, and protected-Activity
  timing have not been exercised for this checkpoint.
- No phone or emulator was touched; no existing local identity or recovery
  state was modified.
- No Node Access Pass was issued, applied, or consumed.
- No APK was produced by this checkpoint. There is still no stable tester key,
  signed standalone tester artifact, or tester-release claim.
- The broader recovery/vault/capture, Direct cross-client, airplane/background,
  hostile-Node, and Phase 5S matrices remain open.

The authoritative deferred manual cases remain in the
[Android Direct Preview physical test plan](android-direct-preview-physical-test-plan.md).
