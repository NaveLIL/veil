# Veil Phase 5S end-of-day report — 2026-07-20

Status: host-only, non-activated checkpoint. No production-readiness claim.

## Outcome

The server side of the origin-bound transport-auth foundation advanced from
byte contracts and isolated helpers to two audited, still disconnected
verification boundaries:

- WebSocket auth v3 now has a transport-neutral verifier and atomic PostgreSQL
  account/device/binding/Node Access Pass admission transaction.
- REST auth v2 now has an exact raw-HTTP adapter and explicit v2-only/finite
  Preview-dual dispatcher around the durable replay store.

The live gateway was not switched. `/ws` remains WS auth v2 and signed REST
routes remain REST auth v1, so the cross-Node credential-scope P1 and Phase 5S
remain open.

## WebSocket auth v3 work completed

- one-shot v3 challenge consumption with exact configured origin;
- strict account-signed active device-binding validation;
- contributory account and device X25519 results with chained Ed25519 proofs;
- registration intent verified before policy or Pass lookup;
- account, device, immutable binding state, and Pass consumption in one
  transaction;
- existing identity resolved before Pass lookup, preserving unused Passes and
  making uncertain post-commit retry idempotent;
- opaque verified result carrying copied principal, protocol, origin, and
  signed intent without Pass/proof/DH material; and
- repository-wide no-live-callsite gate for v3 challenge, verifier, and
  admission entry points.

Exact evidence:
[WS auth v3 verifier/admission checkpoint](phase-5s-ws-auth-v3-verifier-admission-checkpoint.md).

## REST auth v2 work completed

- raw `RequestURI` and all-value case-insensitive proof-header capture;
- strict bodyless/fixed-media policies, bounded single body read, exact body
  restoration, and shared v1/v2 retained-body admission;
- two freshness decisions plus a 60-second monotonic staged-proof limit;
- exact signature before durable account+nonce replay claim and principal
  publication only for the winner;
- proof-header scrubbing before v2 downstream processing and after dispatcher
  return;
- explicit unknown-account 401 versus outage/timeout/cancel/malformed-key 503;
- mixed `not-found + outage` error trees remain operational 503 unless every
  leaf means absence;
- `V2Only` and finite `PreviewDual` selection with no fallback, explicit owner,
  maximum 30-day monotonic deadline, and sticky fail-closed expiry; and
- recursive AST nonactivation barrier covering constructor aliases,
  containers, `make/new`, conversions, generic instantiations, type assertions,
  function parameters/results, and zero-value paths.

Exact evidence:
[REST auth v2 HTTP boundary checkpoint](phase-5s-rest-auth-v2-http-boundary-checkpoint.md).

## Verification completed

- complete Go ordinary and race suites;
- complete Go vet, read-only dependency resolution, and module verification;
- focused auth/authmw/chat/servers/db ordinary and race suites;
- disposable-PostgreSQL WS v3 lifecycle, rollback, cancellation, Pass race,
  same-identity retry, and intent-policy tests, including race execution;
- disposable-PostgreSQL REST replay lifecycle/cross-process test and migration
  030 upgrade/fresh-chain test;
- Rust formatting and clippy with warnings denied;
- `veil-client`: 203 unit tests passed, 11 explicitly ignored superseded cases,
  and 4 integration tests passed;
- unchanged shared Rust↔Go transport-auth fixture SHA-256:
  `c90f7aac7619d178e06c0ac0d7aab6084511ceffb505b8fcf7058ba6812ad9bc`;
  and
- final internal read-only hostile review: no current P0-P3, fail-open path, or
  authentication-success bypass. This was not an external audit.

## Honest open gates

Before any REST v2 live cutover:

1. impose a short absolute network body deadline that also covers early
   metadata/auth rejection and automatic Go server body draining;
2. bound signing-key lookup concurrency or add a dedicated preflight quota and
   settle the unknown-account 401 versus known-key 429 policy;
3. migrate every selected handler to verified principal context and add global
   proxy/middleware Header+Trailer redaction;
4. freeze the route-by-route media/body table and non-redirecting ServeMux
   registration; and
5. add deployment ownership, compatibility telemetry, client consumption, and
   real HTTP/1.1/HTTP/2 ingress evidence.

Before any WS v3 live cutover:

1. validate canonical raw protobuf before decoded security fields reach the
   verifier;
2. add strict subprotocol/gateway dispatch and result serialization;
3. connect desktop and Android request preparation with exact selected-origin
   comparison; and
4. pass a real A↔B two-Node relay/downgrade/Pass/restart matrix.

Phase 5S still also requires hostile-Node/key-transparency decisions, the
isolated libsignal spike, and independent external review. The wider product
goal still includes physical Android Direct validation, signed tester APK,
push, Circle, Space/Rooms/roles/Veil Links, attachments, and safe QR-based
multi-device.

## Android and operational boundary

No phone, ADB, APK, install/uninstall, signing key, recovery ceremony, Node
Access Pass issuance/application, live Node, Compose deployment, or production
configuration was touched. Physical Android work remains deferred until it is
explicitly resumed and a newly displayed recovery phrase is confirmed
recorded. The prior black-screen/001/999 device observations were not retested
or represented as fixed.

## Recommended continuation point

Resume host work with the two REST resource gates first: absolute network body
deadline/early-drain tests, then bounded preflight lookup admission. After that,
continue canonical WS v3 raw-protobuf/subprotocol wiring and the two-Node
harness. Keep all new paths non-activated until their route/client/relay gates
are complete.
