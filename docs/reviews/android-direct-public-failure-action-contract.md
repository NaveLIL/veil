EVIDENCE CHECKPOINT ONLY — Android Direct Preview and app-wide rollout remain open.

# Android Direct public-failure action contract

Date: 2026-07-20

## Scope

This host-only checkpoint separates a definite Direct non-send from an
indeterminate delivery result without turning either presentation code into
retry authority. It extends the append-only `PublicFailureCodeV1` registry and
its Android/TypeScript consumers; it does not change the Rust Direct wire
protocol, SQLCipher schema, server API, or terminal runtime snapshot format.

The immutable initial registry history remains the exact 16-entry prefix. The
current registry appends two active entries:

| Code | Authoritative exposure gate | Safe presentation action |
| --- | --- | --- |
| `VEIL-DIRECT-001` | A bounded local text rejection, typed native `Rejected`, or durable `delivery = failed` | Keep or edit the text. A new send is a new explicit intent and is allowed only under a separately confirmed current Direct generation. |
| `VEIL-DIRECT-002` | Durable typed `delivery = unknown` only | The original may already have arrived. Keep it and wait for authenticated reconciliation; never resend it blindly. |

These codes describe presentation and recovery semantics only. They do not
authorize retransmission, reconnect, session replacement, trust downgrade, or
Access Pass replay.

## Exact fail-closed routing

- Only the exact native pair `E_VEIL_DIRECT_SEND_REJECTED` plus
  `VEIL-DIRECT-001` becomes a definite send rejection in JavaScript.
- Empty, malformed-Unicode, or over-limit local text is rejected before the
  native call and receives `VEIL-DIRECT-001` because no send was attempted.
- Invalid conversation/generation authority, Direct session failure,
  `E_VEIL_DIRECT_SEND_UNAVAILABLE`, malformed or conflicting metadata, hostile
  accessors, and revoked proxies collapse to `VEIL-RUNTIME-999`.
- `VEIL-DIRECT-002` is never accepted from an exception or callback failure. It
  is derived only from the validated durable delivery projection.
- `Accepted`, accepted-for-replay, and accepted-session-invalid native outcomes
  remain accepted intents. They are not rewritten as rejection.
- Both Direct codes are operation/projection-only and are rejected from the
  process-local terminal runtime snapshot.

Kotlin publishes one fixed failure message and a singleton
`userInfo.publicFailureCodeV1`; legacy exception/native/server text does not
cross the React Native boundary. TypeScript reads only own data properties and
requires the exact reviewed internal/public pair. The store retains only the
opaque reason and public code under the existing exact peer, binding,
generation, and request-revision guards.

## UI semantics

Direct send failure and durable delivery failure use the bundled reviewed
catalog (`title + description + next action + code`). Native/server detail is
not rendered or retained. A definite rejection preserves the current draft.
Durable `failed` and `unknown` rows have no Retry control; the persistent cards
also disable assertive live-region announcements. The public code remains
selectable for support.

## Host evidence

The checkpoint is gated by:

```text
node --test scripts/tests/validate-public-failure-code-v1.test.mjs
node scripts/validate-public-failure-code-v1.mjs --against-ref HEAD
pnpm test -- --runInBand
pnpm exec tsc --noEmit
pnpm lint
gradlew :app:testDebugUnitTest :app:testReleaseUnitTest :app:testInternalTesterUnitTest :app:lintDebug
git diff --check
```

The registry test passes 14/14 and the validator reports 18 registry, 18
TypeScript, and 18 Android codes while preserving the 16-entry history. The
mobile suite passes 27 Jest suites and 227 tests; TypeScript and ESLint pass.
Generated JUnit XML reports 305 tests in each Android variant with zero failures
or errors; Debug skips 1 reviewed test, while Release and InternalTester each
skip 12. `lintDebug` reports zero errors and 27 existing warnings.

## Residual work and non-claims

This is not a production-readiness or cryptographic-audit claim. Direct session
and mixed unavailable outcomes intentionally remain `VEIL-RUNTIME-999` until a
narrower typed gate exists. Desktop and Go consumers, non-English catalogs,
cross-client conformance, physical accessibility behavior, Android A04/A05,
the full device/reconnect matrix, signed tester APK, standalone signing, and
release publication remain open. No phone, ADB, APK installation, Node Access
Pass, recovery ceremony, or server mutation is evidence for this checkpoint.
