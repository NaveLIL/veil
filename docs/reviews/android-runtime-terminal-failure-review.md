# Android runtime terminal failure review

> **EVIDENCE CHECKPOINT ONLY — NOT A TESTER RELEASE OR PRODUCTION CLAIM.**
> The physical-device matrix is deliberately deferred and was not executed for
> this checkpoint.

## Scope

This checkpoint closes the React-context liveness failure where a typed
`VEIL-PASS-001` operation rejection was immediately reduced to
`VEIL-RUNTIME-999` when JavaScript reread the still-running native runtime.

The native snapshot now contains a required nullable `publicFailureCodeV1`.
Only the reviewed terminal subset may be retained:

- `VEIL-LOCAL-002`, `VEIL-LOCAL-003`;
- `VEIL-NODE-002`, `VEIL-NODE-003`, `VEIL-NODE-004`;
- `VEIL-PASS-001`, `VEIL-PASS-002`;
- `VEIL-SYNC-001`, `VEIL-RUNTIME-999`.

Setup and operation-only outcomes are not snapshot state. Missing, unknown,
malformed, conflicting, or state-inconsistent values collapse to a restrictive
revision-zero `VEIL-RUNTIME-999` projection.

## Security semantics

- The retained code is process-local presentation state. It is not persisted,
  is never retry authority, and contains no exception or server diagnostic.
- `RegistrationClosed` maps to `VEIL-PASS-001` only for a plain connection.
  If a Pass was supplied, that hostile/inconsistent outcome becomes
  `VEIL-RUNTIME-999`.
- `InviteInvalid` maps to `VEIL-PASS-002` only when a Pass was actually used.
  The same outcome on a plain connection becomes `VEIL-RUNTIME-999`.
- Reads, listener reattachment, and Pass staging do not clear a terminal cause.
  A new owner transition may clear it only after all native error components
  have been superseded.
- Native public directory projection and the JavaScript chat gate both require
  the snapshot failure to be null. Store and snapshot failures independently
  deny rendering.
- Operation failure reconciliation compares the sanitized Promise result with
  a fresh native snapshot. Disagreement or an unavailable fresh read becomes
  `VEIL-RUNTIME-999` without inventing a local-unlock requirement.
- An active revalidation cannot temporarily clear a previously latched deny.
  A successful authoritative operation completion is required.

## Automated evidence

- TypeScript typecheck and ESLint pass.
- Jest passes 27 suites and 188 tests, including strict snapshot parsing,
  equal-revision disagreement, operation/snapshot reconciliation, React-tree
  recreation, staged-Pass liveness, and the full Pass-to-Ready UI transition.
- Android JVM tests pass 245 tests, including typed cause tables, repeated
  snapshot/listener reads, context-bound enrollment failures, reconnect causes,
  disconnect failure, and stale-owner rejection.
- Android `lintDebug` and `assembleDebug` pass without a connected-device task.
- The append-only public failure registry validator and `git diff --check` pass.

## Open boundaries

- This code has not yet been installed or exercised on the user's phone. The
  exact manual cases remain in the
  [Android Direct Preview physical test plan](android-direct-preview-physical-test-plan.md).
- A process restart starts with no retained presentation cause; authoritative
  session/reconnect recovery must derive the next state again.
- The assembled debug APK is not a signed standalone tester artifact.
- Direct send/delivery public outcomes, desktop/Go consumer parity, complete
  cross-client E2EE evidence, and the broader Phase 5S review remain open.
