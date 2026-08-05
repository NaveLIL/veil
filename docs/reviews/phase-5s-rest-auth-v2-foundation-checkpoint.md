EVIDENCE CHECKPOINT ONLY — NON-ACTIVATED — the hostile-Node P1 and Phase 5S remain open.

# Phase 5S REST authentication v2 foundation checkpoint

Date: 2026-07-20

Status: isolated foundation and host-only evidence reviewed. Runtime activation
is prohibited by the open gates below.

## Scope

Checkpoint 5S.3B-3 freezes isolated server-side and private native-client
foundations around the already shared REST authentication v2 transcript. It is
limited to:

- the exact future HTTP header representation and single-claim v2 verifier
  input;
- configured-origin transcript construction over an already captured exact
  request target and already bounded exact message-content bytes;
- a private native preparer that can construct one v2 proof without exposing a
  live transport or public FFI entry point;
- strict Ed25519 verification and verified-principal publication order;
- a durable, cross-process account-and-nonce replay boundary; and
- host-only unit and integration evidence for those isolated components.

REST API path versions and authentication versions remain independent. This
checkpoint does not change any live route from REST auth v1 to v2, does not add
Android or desktop transport use, and does not close the hostile-Node P1.

## Frozen HTTP representation

An eventual REST v2 request has exactly one value for each logical field:

| Header | Required value |
|---|---|
| `X-Veil-REST-Auth-Version` | exact ASCII `2` |
| `X-Veil-User` | canonical lowercase, hyphenated, non-nil UUID |
| `X-Veil-Timestamp` | canonical unsigned decimal in `1..MaxInt64` |
| `X-Veil-Nonce` | strict raw unpadded base64url of 32 non-zero bytes: 43 ASCII characters |
| `X-Veil-Signature` | strict raw unpadded base64url of a 64-byte Ed25519 signature: 86 ASCII characters |

Header names have normal HTTP case-insensitive matching, but values have no
aliases. Empty, repeated, comma-combined, padded, non-canonical, mixed v1/v2,
and unknown-version forms fail closed; missing version also fails in the
v2-only profile. A separately reviewed Preview compatibility dispatcher may
select legacy v1 once from an absent selector before verification under its
explicit expiry policy. A failed v2 request is never retried as v1. Parsed
base64url values must re-encode byte-for-byte to their received representation.

The eventual HTTP boundary must capture the transcript target from the inbound
Go server `RequestURI`, validated directly as canonical origin-form. It must not
rebuild it from `URL.Path`, `EscapedPath`, parsed query values, route variables,
`Host`, forwarding headers, redirects, DNS, or TLS routing metadata. The
isolated verifier accepts that exact target as an already captured value. Its
transcript origin is the mandatory configured canonical public Node origin.

The eventual HTTP boundary must read and restore the exact bounded
message-content bytes from `r.Body`, after hop-by-hop transfer framing and
before application parsing or content decoding. The isolated verifier accepts
those bytes only after that boundary has captured them. Every activated route
must also have one fixed reviewed media policy because media type is not signed
in v2: bodyless routes reject a body, JSON routes accept one exact JSON media
type, and alternate content types, parameters, or content encodings are
rejected unless a future contract signs that choice.

## Isolated native preparer

The private `veil-client` preparer validates an already selected canonical
origin, canonical account UUID, uppercase method, exact canonical request
target, timestamp range, and non-zero nonce before signing. Its runtime-only
freshness sources are the native system clock in Unix milliseconds and the OS
CSPRNG; clock failure, randomness failure, an all-zero nonce, or any invalid
canonical input fails closed. It hashes the caller's exact supplied body,
signs with the native account identity, and emits the five frozen header values
using canonical decimal and raw unpadded base64url encodings.

The preparation wrapper permits one consuming extraction and intentionally
implements neither `Clone` nor `Debug`. That is not replay enforcement: the
returned encoded wire strings remain copyable, and only the durable server
store enforces one accepted account-and-nonce claim. The transient binary
transcript, raw signature, and raw nonce are zeroized after use; no body or
signing key is retained in the header value object. The encoded nonce and
signature remain authentication material and must not be logged. This module
has no transport, API, FFI, desktop, Kotlin, or Android call site. It does not
choose a URL, compare the selected TLS origin, set an HTTP header, retry a
request, or define a downgrade policy; all of those remain activation work.
Activation requires an opaque request-bound transport operation that consumes
the proof with its exact origin, method, target, and body, without automatic
redirect, retry, or downgrade. A new attempt must prepare a new proof.

## Verification and replay semantics

The future live verifier order is fixed as follows:

1. require the configured origin and exact header/version cardinality;
2. validate canonical scalars, method, raw target, and an inclusive
   `now_ms +/- 60,000` freshness window using one clock sample converted once
   to Unix milliseconds;
3. resolve and strictly validate the candidate account's pinned Ed25519 public
   key before admitting a large attacker-controlled body;
4. enforce the bounded body and route media policy and construct the transcript
   with the configured origin;
5. verify the signature without publishing a principal; and
6. atomically consume replay state keyed only by the verified canonical account
   and exact 32-byte nonce, then publish the principal only for the winner.

Signature failure occurs before replay insertion, preventing unauthenticated
nonce poisoning. Replay state must be shared by all gateway processes and
survive restart. A live marker remains strictly beyond the last moment at which
the signed timestamp could pass freshness, with a positive precision and clock
safety margin. Cleanup deletes only expired state; saturation, timeout,
transaction failure, or uncertain storage fails closed and cannot evict a live
marker or fall back to an in-process cache. The marker stays consumed when any
later rate limit, parser, handler, database, response, or network operation
fails.

The isolated Go verifier represents every future header as a value slice so a
later HTTP adapter can preserve cardinality rather than call `Header.Get`. It
requires an opaque configured canonical origin, a key lookup, and a replay
store at construction. Canonical metadata and its bounded body input are
rejected before account lookup; the isolated input currently shares the
existing 4 MiB signed-body ceiling. A strict pinned account key and signature
are then required before the replay store is called. The verifier returns a
principal only after the atomic claim, and its account field is private to the
package. Typed failure classifications expose fixed non-secret messages, but
they are not yet public HTTP errors.

The isolated PostgreSQL store uses `(user_id, nonce)` as its primary key and
`ON CONFLICT DO NOTHING` as the atomic one-winner operation. The normal claim
sets expiry from PostgreSQL time at five minutes, exceeding the complete
two-sided 60-second freshness interval. Schema constraints require a non-zero
32-byte nonce and positive expiry bounded to ten minutes. Cleanup is explicit,
batch-bounded, uses expired-only locked selection, and never selects a live
marker. No cleanup scheduler, capacity policy, or operational deployment of
this migration is activated by the checkpoint.

## Node Access Pass isolation

REST authentication v2 never carries, verifies, consumes, refunds, or rotates a
Node Access Pass. Mobile-only first-account registration remains a future WS v3
operation whose proof must verify before the Pass is touched and whose account
creation and one-time Pass consumption must commit atomically. Existing
digest-only Pass storage is supporting legacy evidence, not permission to mix a
Pass into this REST verifier.

## Deliberately not activated

This checkpoint is an isolated foundation. Current live gateway routes continue
to use REST authentication v1. The native v2 preparer remains crate-private and
unreferenced by live connection/API code. The v2 HTTP adapter and dispatcher,
route media-policy table, production legacy rejection, desktop/FFI/Android
signing transport, Preview compatibility expiry, and real two-Node relay tests
remain absent or outside this checkpoint. No source file or migration by itself
constitutes an activation claim.

Follow-on checkpoint 5S.3B-5 now supplies the still non-activated HTTP adapter
and version dispatcher; its evidence and remaining route/client/two-Node gates
are recorded in
[the REST auth v2 HTTP boundary checkpoint](phase-5s-rest-auth-v2-http-boundary-checkpoint.md).

No Compose service is started, stopped, recreated, or contacted for this
checkpoint. A host-only integration gate may create and destroy a disposable
PostgreSQL testcontainer populated only with synthetic accounts; that is not a
Node or deployment test. No running Node or live `.env` is read or changed.
Phone testing is still deferred: no phone, ADB, APK, installation, Node Access
Pass, recovery ceremony, or release-signing operation is part of this work.
Physical testing may resume only after explicit authorization and after a new
recovery phrase has been displayed and confirmed recorded.

## Required verification matrix

The isolated foundation must prove at least:

- the frozen shared REST v2 success vector and every malformed canonical field;
- exact-one verifier-input cardinality, including empty, repeated,
  comma-combined, padded, malformed, missing-version, and unknown-version
  values, plus rejection of a legacy-domain signature;
- altered method, origin, raw target, body, timestamp, nonce, user, or signature;
- rejection at a different configured origin, with no `Host` or forwarding
  header accepted by the isolated verifier API as an origin input;
- exact raw query ordering/escaping and distinct exact body-byte commitments;
- the isolated verifier's bounded input rejection before key or replay success;
- unknown account, malformed stored key, wrong key, stale/future timestamp, and
  signature failure without replay insertion;
- one winner for concurrent reuse of `(account, nonce)`, reuse rejection after
  restart or by another gateway process, and independence between accounts;
- durable-store error before principal publication, bounded expired-only
  cleanup, schema constraints, and no deletion of a live marker; and
- native system freshness, canonical header emission, exact fixture signature,
  field mutation, origin separation, fail-closed invalid inputs, and the absence
  of a live native call site.

The later activation matrix must additionally prove HTTP case-variant and
duplicate/comma header collection, legacy-only and mixed-version negotiation,
raw `RequestURI` capture, exact bounded body restoration, bodyless/fixed-media
policies, replay-store timeout/capacity behavior, and marker retention for every
downstream failure class.

A later real two-Node relay matrix must seed the same synthetic account UUID and
signing key on Nodes A and B so rejection proves origin binding rather than an
unknown account. It must cover A-to-B and B-to-A relays, `Host` and forwarded
header variants, a valid B request, downgrade cases, and same-origin concurrent
and restart replay. Cryptographic fixtures alone do not satisfy that gate.

## Gates still open

- runtime WS v3 and REST v2 dispatch with strict, non-fallback negotiation;
- audited raw `RequestURI` capture, one bounded `r.Body` read and exact
  restoration, plus shared client/server size limits and exact route-by-route
  REST media policies;
- desktop/FFI/Android v2 transport, exact selected/TLS-origin comparison,
  HTTP/1.1 and HTTP/2 observed-target evidence, durable auth-version pinning,
  and retry/reconnect/process-death no-downgrade behavior;
- reviewed stable public error/action mappings at the eventual transport and
  mobile boundaries;
- durable replay migration operational review, cleanup ownership, retention,
  capacity, and multi-process/restart evidence in the actual deployment shape;
- Preview compatibility owner and expiry, followed by production rejection of
  WS v2 and REST v1;
- strict live Host/SNI/redirect behavior and the real two-Node relay matrix;
- hostile selected-Node behavior, malicious device rosters, key transparency,
  metadata/availability limits, and isolated libsignal evaluation; and
- independent security and cryptographic review.

## Host-only evidence

The settled tree passed:

```text
# repository root
cargo test -p veil-client rest_auth_v2
cargo test -p veil-client
cargo clippy -p veil-client --all-targets -- -D warnings
cargo fmt --all -- --check

# veil-server/
go test ./...
go test -race ./internal/authmw ./internal/db
go test -race -timeout 10m ./...
go vet ./...
go test -tags=integration -run '^TestRESTAuthV2ReplayStoreLifecycleAndCrossProcessClaim$' -count=1 ./internal/db
go test -tags=integration -run '^TestMigrationUpgradePreflights$/030' -count=1 ./internal/integration

# repository root
git diff --check
```

The focused native preparer suite passed all 7 tests. The complete
`veil-client` library run passed 203 tests with 11 explicitly ignored, followed
by 4 passing client integration tests. The focused verifier/database race run,
complete Go race and ordinary suites, vet, Rust clippy with warnings denied,
Rust format, Go format diff, and repository whitespace check were clean.

The two tagged tests used disposable synthetic PostgreSQL containers. They
proved one winner across separate pools, persistence across close/reconnect,
account scoping, expired-only bounded cleanup, live-marker retention, schema
constraints, migration 030 preflight, and the fresh 001-through-030 migration
chain. They did not start or contact a Veil Node.

The immutable shared transport-auth fixture remained byte-identical at SHA-256
`c90f7aac7619d178e06c0ac0d7aab6084511ceffb505b8fcf7058ba6812ad9bc`.
The static unit test recursively scans every other Rust source file in
`veil-client`; repo-wide call-site review additionally confirmed that the
preparer remains private and that the gateway has no v2 verifier constructor,
HTTP adapter, dispatcher, or route call site. This evidence is not a live
transport, two-Node relay, phone,
release-signing, external audit, or production-readiness result.

Independent read-only in-repository reviews found no P0 or P1 client issue and
no P0-P3 server, replay-store, migration, or non-activation issue. The client
review found that the earlier phrase "one-shot output" overstated the type-state
guarantee: consuming extraction does not prevent copying wire strings. The code,
source-policy test, and this evidence now state the narrower guarantee and keep
request-bound consuming send semantics as an activation gate. This internal
review is not the independent external security or cryptographic review still
required by Phase 5S.
