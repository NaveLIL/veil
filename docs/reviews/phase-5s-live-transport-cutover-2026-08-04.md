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
- `/ws` is permanently retired with HTTP 410. The old server-only emergency
  switch is rejected during startup and cannot restore origin-unbound WS v2.
- Post-handshake v2 or v3 auth frames close an authenticated socket; the shared
  message pump cannot enter a second, weaker verifier.

## Evidence in this checkpoint

- Go gateway and package tests pass with the v2-only routes and default-disabled
  retired endpoint and no compiled legacy dispatch branch.
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

Update (2026-08-05): the temporary rollback allowance described in the
original checkpoint was removed before release. REST dispatch is now a thin
v2-only boundary with no `PreviewDual` mode or v1 middleware dependency.
