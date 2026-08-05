EVIDENCE CHECKPOINT ONLY — NON-ACTIVATED — the hostile-Node P1 and Phase 5S remain open.

# Phase 5S REST authentication v2 HTTP boundary checkpoint

Date: 2026-07-20

Status: checkpoint 5S.3B-5 is implemented and host-tested. Runtime activation
is prohibited by the open gates below.

## Scope

This checkpoint adds a deliberately non-activated Go HTTP adapter and
authentication-version dispatcher around the isolated REST authentication v2
verifier and durable PostgreSQL replay boundary from checkpoint 5S.3B-3. It
does not register or replace any live route.

For a selected v2 request the adapter now:

1. validates the exact method, server-observed `RequestURI`, authentication
   header cardinality, transfer representation, and route body/media policy,
   while deleting all five proof headers from the mutable request after taking
   its private cardinality-preserving snapshot;
2. performs an initial freshness check and resolves a strict copy of the
   candidate account signing key before reading an attacker-sized body;
3. obtains the existing middleware's shared per-client/global body admission,
   reads at most one bounded body, closes the inbound stream, and restores the
   exact captured bytes for the downstream handler;
4. verifies the exact body commitment and Ed25519 proof;
5. rechecks wall-clock freshness and a 60-second monotonic staged-proof age
   immediately before the durable replay claim; and
6. publishes the private verified principal and authoritative compatibility
   `X-User-ID` only after the replay winner is known.

When a body stream is admitted, its lease remains held while the authenticated
handler runs.
Any earlier attacker-supplied `X-User-ID`, including case variants, is removed
before verification and remains absent on every failure path. The nonce,
signature, timestamp, candidate user, and authentication-version headers never
reach the downstream handler; success carries only verified context and the
authoritative compatibility `X-User-ID`.

## Exact HTTP boundary

The adapter takes the transcript target only from `http.Request.RequestURI`.
It never reconstructs the signed bytes from `URL.Path`, parsed queries, `Host`,
forwarding headers, or a redirect target. Header collection is
case-insensitive over every map entry and retains every value; it does not use
`Header.Get` to collapse duplicates. Empty, duplicate, comma-combined,
non-canonical, unknown-version, and mixed-version inputs fail closed.

Each route supplies an opaque policy constructed as either bodyless or one
exact fixed media type with an explicit maximum no greater than the shared
signed-body ceiling. The boundary rejects unsupported transfer codings,
content encoding, trailers, invalid lengths, hidden body bytes on a bodyless
route, empty required bodies, and oversized declared or streamed bodies. It
still performs a bounded read for chunked/unknown-length bodies and for a
declared length of zero. Parsing remains downstream and occurs only after proof
and replay admission.

The two freshness samples prevent a proof from being accepted after it became
stale during key lookup, body admission, or body I/O. A staged continuation is
single-use, clears its copied signature, nonce, public key, identifiers, and
request metadata on every terminal path, and cannot outlive one 60-second
freshness window. This bound is shorter than the durable five-minute replay
marker retention. A zero clock, rollback-like negative elapsed interval,
timeout, cancellation, or replay-store uncertainty fails closed.

The final age check bounds acceptance, not a blocked network read. The current
gateway and managed ingress read timeouts are much longer than 60 seconds, so a
slow body can still retain one shared body-admission slot after its proof can no
longer succeed. A per-v2 absolute body-read deadline and real `net/http`
slow-reader evidence remain required before activation.
That evidence must also cover Go server automatic body draining after an early
metadata or authentication rejection, before shared body admission was ever
acquired.

## Key lookup and public failures

`ErrSigningKeyNotFound` is the only signing-key lookup result classified as an
unknown account and mapped to the generic unauthenticated response. Timeout,
cancellation, storage outage, an incoherent nil row, and a malformed stored
Ed25519 key are operational failures mapped to the generic unavailable
response. The three existing production signing-key providers translate only
`pgx.ErrNoRows` to the explicit not-found sentinel. Legacy REST v1 retains its
existing public behavior until its contract is versioned separately.

Every HTTP rejection uses an existing stable `publicerr` code and a fixed
non-secret message. Internal lookup, body-I/O, signature, and replay-store
causes are not serialized. Retryable key/replay dependency failures return
generic `503 unavailable`; authentication failures do not reveal whether the
candidate key, signature, or proof bytes were close to valid.

Removing proof headers at this adapter boundary limits downstream retention; it
does not prove that an outer proxy or middleware has a safe logging policy.
Global header redaction remains an activation review gate.

## Explicit version dispatch

`RESTAuthVersionDispatcher` has only two construction modes:

- `V2Only`, which rejects a missing or unknown selector; and
- `PreviewDual`, which selects legacy v1 only when the v2 selector and nonce
  are absent and an explicit compatibility owner and expiry are valid.

Preview compatibility is limited to at most 30 days from construction. Its
bounded duration is reattached to a monotonic deadline, and the legacy branch
is permanently latched closed after any request observes expiry or an invalid
clock. A request selected as v2 is never retried as v1. The dispatcher rejects
typed-nil or incomplete legacy dependencies and requires both versions to
share the same body-admission authority.

PreviewDual intentionally preserves the current v1 handler's representation
semantics. It does not make v1 obey a v2 route's body/media policy. A complete
route-by-route policy migration and reviewed telemetry are therefore blocking
activation gates, not properties inferred from this dispatcher.

## Executable evidence

Unit and race suites cover raw target preservation, case-variant and duplicate
headers, fixed representation policies, bounded read/restore, admission
retention, proof-header scrubbing, no early principal, downstream-failure
replay consumption, single-use continuation races, initial and final freshness
boundaries, monotonic maximum age, key-lookup classifications, dependency
timeouts, generic public failures, exact dispatcher selection, no fallback, finite
Preview expiry, sticky closure, and unsafe constructor inputs.

A repository-wide AST gate rejects production constructor use and constructor
aliases for the v2 verifier, HTTP boundary, and dispatcher. Its only allowed
construction sites are their own reviewed constructors. The live gateway has
no v2 HTTP or dispatcher call site.

The settled slice passed:

```text
# veil-server/
go test -count=1 ./internal/auth ./internal/authmw ./internal/chat ./internal/servers ./internal/db
go test -count=1 -race ./internal/auth ./internal/authmw ./internal/chat ./internal/servers ./internal/db
go test -count=1 ./...
go vet ./...
go test -race -timeout 10m ./...
go list -mod=readonly -deps ./...
go mod verify
go test -tags=integration -run '^TestRESTAuthV2ReplayStoreLifecycleAndCrossProcessClaim$' -count=1 ./internal/db
go test -tags=integration -run '^TestMigrationUpgradePreflights$/030' -count=1 ./internal/integration

# repository root
cargo fmt --all -- --check
cargo clippy -p veil-client --all-targets -- -D warnings
cargo test -p veil-client
git diff --check
```

The full Go ordinary/race/vet/dependency gates were green. The native client
run passed 203 unit tests with 11 explicitly ignored superseded cases and all 4
client integration tests. Both tagged REST replay/migration commands passed
against disposable synthetic PostgreSQL only; they did not contact a Veil
Node. These outcomes were recorded from the final settled tree rather than
inferred from source presence.

A separate internal read-only hostile review of the final bytes found no
current P0-P3 issue, authentication-success bypass, or fail-open path. It
specifically rechecked mixed lookup-error trees, late dependency success,
proof-header retention, replay publication order, typed-nil dependencies, and
constructor/zero-value activation bypasses. This is internal engineering
review, not the independent external security or cryptographic audit still
required by Phase 5S.

## Deliberately not activated

Current live signed REST routes still use REST auth v1, and `/ws` still uses WS
auth v2. This checkpoint adds no gateway constructor, route registration,
route-policy table, `ServeMux` raw-target/redirect guard, deployment flag,
client transport, or FFI/Kotlin/Android consumer. It adds no live telemetry and
does not prove HTTP/1.1 versus HTTP/2 ingress preservation.

The remaining activation gates include:

- an audited route-by-route parser/body/media policy table and exact
  non-redirecting route registration;
- migration of every selected v2 handler from raw `X-Veil-User` reads to the
  verified-principal context, plus global proxy/middleware proof Header and
  Trailer redaction;
- bounded signing-key lookup concurrency or a dedicated preflight quota: the
  existing outer pre-authentication rate limit is defense in depth but does
  not by itself bound database lookup concurrency for forged, syntactically
  valid proofs; its policy review must also decide whether unknown-account 401
  versus known-key 429 under exhausted body admission is acceptable account-
  existence exposure;
- a per-v2 absolute network body-read deadline no longer than the staged-proof
  lifetime, with connection/deadline restoration and slow-reader tests; the
  final freshness check alone does not release a slot blocked in `Read`, and
  early-reject tests must cover automatic `net/http` body draining;
- explicit deployment/config ownership and no-secret compatibility telemetry;
- desktop and Android request-bound v2 preparation, exact selected/TLS-origin
  comparison, durable version pinning, and fresh-proof retry semantics;
- the canonical WS v3 raw-protobuf/subprotocol/gateway boundary;
- real A↔B two-Node relay, Host/SNI/forwarded-header, downgrade, restart, and
  multi-process matrices; and
- independent security and cryptographic review.

This checkpoint does not close the cross-Node credential-relay P1, Phase 5S,
Android Direct Preview, key transparency, hostile-Node analysis, or the
isolated libsignal decision. It is not production readiness.

No phone, ADB, APK, signing key, recovery ceremony, Pass issuance/application,
live Node, Compose deployment, or production configuration was accessed.
Physical Android testing remains deferred until it is explicitly resumed and
a newly displayed recovery phrase is confirmed recorded.
