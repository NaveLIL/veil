# Android Direct Preview physical test plan

> **PLAN ONLY — NOT EXECUTED.** Passing unit, JVM, Rust, emulator, or build
> checks does not satisfy this gate. Mobile CI now publishes a short-lived debug
> `veil-mobile-debug-ci` APK for diagnostic evidence; it is not the signed tester
> artifact required by this plan and does not establish production readiness.

Execution was explicitly deferred on 2026-07-20. Until the user resumes this
gate, no ADB/device command, install, uninstall, package-data clear, connected
test, Node Access Pass application, or recovery ceremony is authorized.

This is the final hands-on evidence matrix for the Android Direct Preview. It
is intentionally deferred until the implementation, release signing, and
non-destructive test packaging are ready.

## Safety boundary

- Never run Gradle `connected*AndroidTest`, Android Test Orchestrator, or any
  install/uninstall test task against an account-bearing personal phone. AGP
  may uninstall the target package and destroy package-scoped Keystore and
  SQLCipher state.
- Never use `pm clear`, uninstall, downgrade, signing-key replacement, restore,
  or a package-name collision without an explicit destructive-test approval
  naming the exact disposable package and identity.
- A recovery phrase must be recorded and confirmed locally before its identity
  receives a Node Access Pass. The phrase is never pasted into chat, logs,
  screenshots, test reports, shell history, or issue trackers.
- Use only synthetic messages and disposable accounts. Do not collect full
  `bugreport`, accessibility trees, database files, Keystore material, Pass
  bearers, raw enrollment URIs, or unfiltered logs.
- The user's Samsung S23 is manual black-box evidence only. Automated connected
  tests run on a freshly created, attested disposable emulator or dedicated
  wiped test device.

## Release prerequisites

Record all of the following before touching a physical device:

| Evidence | Required result |
|---|---|
| Source | exact commit, clean tree, reviewed diff |
| Artifact | release-like tester APK, byte size, SHA-256 |
| Signing | stable tester certificate fingerprint; no debug key |
| Package isolation | exact tester application ID `io.veil.mobile.tester` coexists with `io.veil.mobile`; no package replacement or migration |
| Runtime | bundled JS; Metro and developer menu unavailable |
| Native libraries | expected ABI set, recorded Rust library hashes, no stale generated UniFFI bindings |
| Policy | release `FLAG_SECURE` cannot be downgraded by JS/settings; APK evidence binds SDK, permissions, recovery activity, and complete backup/transfer exclusions |
| Supply chain | dependency lock, notices/licenses, secret scan, CI provenance |
| Verifier | sanitized JSON passes the independent tester APK contract and records the exact APK SHA-256 |
| Node | disposable exact HTTPS origin, pinned configuration snapshot, admin access for one-use Pass issuance/revocation |
| Desktop peer | exact desktop build/commit and a disposable peer identity |

A differently signed tester APK cannot replace an existing debug package in
place. The checked-in contract reserves `io.veil.mobile.tester`, `veil-tester`,
distinct visual branding, and a package-scoped Keystore/database for this
purpose. This is packaging code only: no signed artifact has yet been produced
or tested. Do not solve a failed preflight by uninstalling the user's current
package.

## Evidence record

For every case record: case ID, UTC time, device/OS, app version and commit,
APK hash/certificate fingerprint, Node version, desktop version, precondition,
actions, expected result, observed result, and a sanitized evidence reference.
Public failure codes and bounded stage enums are allowed. Secrets, account IDs,
message IDs, raw origins with paths, ciphertext, and native/server text are not.

## Matrix A — install, setup, and local authority

| ID | Scenario | Required result |
|---|---|---|
| A01 | Clean tester install | No debug/Metro dependency; onboarding appears only after authoritative native absence |
| A02 | Create identity | Native protected ceremony shows one phrase; app remains closed until commit and durable presence verification |
| A03 | Cancel before commit | No identity is published; shown phrase is explicitly marked for destruction |
| A04 | Activity recreation during ceremony | No second ceremony/lease; result correlates to the original attempt |
| A05 | Process death at each setup boundary | No duplicate identity, false absence, or unsafe restart; uncertain state is `VEIL-SETUP-002` |
| A06 | Restore with valid phrase | Same local identity opens; phrase never crosses React Native |
| A07 | Invalid restore input | Fixed public error only; no phrase fragment in logs/accessibility/crash data |
| A08 | Background/Recents during protected UI | Opaque surface, no screenshot/recording/Recents disclosure |
| A09 | Lock/unlock and process restart | Keystore/SQLCipher reopen the same identity; plaintext remains absent before explicit authority |
| A10 | Keystore/DB unavailable simulation on disposable target | Fail closed with LOCAL code; never offer a second onboarding flow from uncertainty |

A04/A05 now have a host-only automated precursor covering the fixed-schema
journal state machine, persistence/fault handling, exact coordinator/vault
reconciliation policy, malformed bridge results, retained terminal replay, and
the opaque App bootstrap gate. No Activity recreation, low-memory kill, Android
filesystem/Keystore timing, or physical OS process-death was exercised; A04 and
A05 remain open.

## Matrix B — Node Access Pass and exact origin

| ID | Scenario | Required result |
|---|---|---|
| B01 | Plain connect while registration is closed | Typed post-proof `VEIL-PASS-001`; repeated snapshot/React recreation preserves the same code |
| B02 | Stage valid Pass URI | Native owns bearer; UI shows only canonical origin, short token reference, and bounded TTL |
| B03 | Background while Pass is staged | Pass capability is revoked according to lifecycle contract; bearer never reaches JS/logs |
| B04 | Use valid Pass once | Exact-origin registration succeeds, Pass is cleared only after success, authenticated binding is exact |
| B05 | Replay consumed Pass | `VEIL-PASS-002`; no account-existence or bearer oracle beyond reviewed semantics |
| B06 | Expired/malformed/wrong-origin Pass | Fail closed with reviewed PASS/local code; no request to a substituted origin |
| B07 | `RegistrationClosed` after a Pass was supplied | Inconsistent hostile-Node outcome collapses to `VEIL-RUNTIME-999`, not another-Pass advice |
| B08 | `InviteInvalid` without a supplied Pass | Inconsistent hostile-Node outcome collapses to `VEIL-RUNTIME-999` |
| B09 | TLS/canonical-origin mismatch | No downgrade, redirect following, host/path inference, or authenticated binding |
| B10 | App/React recreation after failure | Exact native snapshot code survives within the process; code never grants retry authority |

## Matrix C — Direct E2EE interoperability

Run both Android-to-desktop and desktop-to-Android directions.

| ID | Scenario | Required result |
|---|---|---|
| C01 | First Direct text with OPK | X3DH INITIAL decrypts, exact conversation/identities/header are authenticated, OPK is consumed only on successful commit |
| C02 | Deleted first packet | Initiator repeats INITIAL metadata until authenticated peer possession; later packet decrypts |
| C03 | Wrong conversation/sender/header/ciphertext | Authentication fails without OPK/session/ratchet mutation |
| C04 | Empty, Unicode, boundary-size text | Identical supported semantics on desktop/mobile; invalid size fails before transport |
| C05 | Duplicate delivery/replay | One durable message; no double ratchet advance or duplicate UI row |
| C06 | Out-of-order within supported skip bound | Correct plaintext/order and bounded skipped-key state |
| C07 | Beyond skip/resource bounds | Deterministic fail-closed result with no unbounded memory/storage growth |
| C08 | Peer/session unavailable | Explicit native session action only; no automatic destructive prekey fetch from rendering/selection |
| C09 | Process restart after established session | SQLCipher state restores; no plaintext/raw ratchet state crosses JS |
| C10 | Cross-client transcript fixture | Desktop, Android bridge, and independent primitive oracle agree on immutable Direct-v1 semantics |

## Matrix D — durable outbox, ACK, and recovery

| ID | Fault point | Required result |
|---|---|---|
| D01 | Offline before send | One SQLCipher-owned intent marked sending; exact ciphertext/state committed atomically |
| D02 | Kill after enqueue, before transport | Restart replays the same durable intent/ciphertext, not a second ratchet encryption |
| D03 | Kill after server accept, before local ACK commit | Idempotent replay converges to one server/local message |
| D04 | ACK deadline | Typed retry policy only; no public-code-driven retry |
| D05 | Wi-Fi loss / airplane mode | Plaintext disappears behind privacy gate as required; bounded jittered reconnect resumes safely |
| D06 | Node restart during live receive | Cursor/history/live handoff has no gap or duplicate after reconnect |
| D07 | Background during connect/sync/send | Old callbacks cannot publish into a newer lifecycle epoch |
| D08 | OS process death with stored target | Same account/origin is re-derived and verified; no Pass persistence or origin guessing |
| D09 | Staged Pass races stored reconnect | New enrollment intent suppresses stale stored reconnect without bearer leakage |
| D10 | Storage failure at each transaction boundary | No false ACK, partial ratchet commit, orphan plaintext, or unsafe automatic retry |

D03 has a host-only automated precursor: a file-backed SQLCipher session is
fully dropped after a deterministic server ledger accepts the send and before
the ACK is delivered, then reopened and reconciled through the production
decoder/FIFO with exact ciphertext replay and one resulting delivery. That
bounded test oracle is not a real Node, Android OS process-death, or physical
device result, so D03 remains open in this matrix.

## Matrix E — public errors, privacy, and hostile inputs

| ID | Scenario | Required result |
|---|---|---|
| E01 | Every reviewed setup/runtime code | Exact registry code, local title/body/action; no native/server message rendered |
| E02 | Unknown/missing/conflicting code or snapshot fields | Restrictive revision-zero state and `VEIL-RUNTIME-999` |
| E03 | Equal-revision snapshot disagreement | Direct authority revoked; `VEIL-RUNTIME-999` |
| E04 | Hostile diagnostic text containing code-like strings/secrets | Text cannot select public code and is absent from UI/log/evidence |
| E05 | Screenshot/recording/Recents in setup, lock, Pass, sync | Always protected in release tester build |
| E06 | Screenshot preference on Ready chat | Release policy remains authoritative; JS cannot clear mandatory native protection |
| E07 | Rotation, split-screen, keyboard, accessibility navigation | No plaintext flash, hidden heavy screen, Pass bearer, or recovery phrase exposure |
| E08 | ANR/crash/low-memory kill | Sanitized exit evidence only; next launch follows authoritative recovery path |

## Completion rule

The Android Direct Preview physical gate passes only when every applicable case
has reproducible evidence on the declared matrix, all deviations are resolved
or explicitly scoped as release blockers, and the exact signed tester artifact
is the artifact that was tested. A debug APK, demo UI, emulator-only result, or
unchecked cryptographic round trip is not a substitute.
