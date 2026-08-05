# Phase 5S live transport cutover checkpoint

- Date: 2026-08-04
- Scope: live WS v3 and signed REST v2 activation
- Status: implemented; disposable PostgreSQL two-Node relay/downgrade evidence
  is in CI; cross-client/physical evidence and independent audit remain open

## Activated boundary

- Desktop, Android, and native reconnect selection require exact
  `/v3/events`; arbitrary aliases, queries, fragments, credentials, and
  origin mismatches are rejected before authentication.
- The primary WS v3 connection carries commands, ACKs, retained state, and
  live events through one authenticated socket and one sequence epoch.
- The Android background supervisor cannot coexist with a primary transport.
  Native session state owns cancellation, verifies the authenticated account
  against the durable origin/account reconnect selection, and accepts events
  only inside that exact background epoch.
- Every signed gateway handler uses REST v2-only selection with exact route
  media policy and the durable PostgreSQL replay boundary. No missing-field or
  parse failure falls back to REST v1.
- `/ws` is fail-closed by default with HTTP 426. The server-only emergency flag
  `VEIL_ALLOW_LEGACY_WS_V2=true` may restore old Preview interoperability for a
  controlled rollback; no client performs an automatic downgrade.

## Evidence in this checkpoint

- Go gateway and package tests pass with the v2-only routes and default-disabled
  legacy endpoint.
- Rust workspace checks pass for client, FFI, and desktop after the unified v3
  connection refactor.
- Generated Kotlin types compile, and the Android Direct/runtime/origin unit
  tests pass against the v3 endpoint contract.
- Desktop and mobile JavaScript suites, type checks, production builds, and the
  remaining adversarial two-Node matrix are tracked as the final verification
  work for this cutover.

This checkpoint supersedes the activation status in earlier Phase 5S
foundation reviews. Those dated documents remain historical evidence of what
was not yet live at their respective checkpoints.
