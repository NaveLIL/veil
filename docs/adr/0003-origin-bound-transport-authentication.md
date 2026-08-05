# ADR-0003: Origin-bound transport authentication

- Status: Accepted and activated on live client/server paths
- Date: 2026-07-20
- Scope: WebSocket authentication v3 and signed REST authentication v2
- Owners: Veil client, server, desktop, Android, protocol, and operations maintainers

## Context

> Activation update (2026-08-04): desktop and Android select exact
> `/v3/events`; the gateway's signed handlers select REST v2 only; `/ws` is
> fail-closed by default and may be restored solely by the explicit emergency
> `VEIL_ALLOW_LEGACY_WS_V2=true` operator flag. Clients never auto-downgrade.
> A disposable PostgreSQL two-Node relay/downgrade matrix is now in CI;
> cross-client/physical evidence and independent audit remain release gates.

The deployed Preview authentication paths are versioned, but their signed
transcripts do not cryptographically identify the exact Veil Node origin.
WebSocket auth v2 binds a server challenge and X25519 result. REST auth v1
derives authority from the incoming HTTP `Host` and does not sign the account
UUID or a fresh explicit nonce. Consequently, an ingress allowlist can reduce
exposure on one deployment but cannot prove that credentials obtained through
Node A are unusable at Node B.

This is a cross-Node credential-scope P1. It does not show that a Node can read a
properly established Direct E2EE session, but it can expose authenticated
control and metadata operations on another Node. A common byte contract is
required before desktop, Android, and server runtime integration can proceed
without implementation-specific normalization.

## Decision

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

### Common encoding and origin

1. Every transcript has a unique ASCII domain ending in one NUL byte. Fixed-size
   values are appended raw, integers are unsigned big-endian, and every variable
   byte string is encoded as `u32be(length) || bytes`. JSON, protobuf, HTTP
   header serialization, platform strings, and implicit separators are never
   signed directly.
2. The canonical origin is ASCII and at most 512 bytes. It is exactly
   `https://host:port`, or `http://host:port` only for `localhost`, `127.0.0.1`,
   and `[::1]`. The port is explicit decimal in `1..65535`. Scheme and DNS host
   are lowercase; DNS labels use canonical LDH/punycode form; IPv4 and bracketed
   IPv6 use their canonical textual forms. Userinfo, path, trailing slash, query,
   fragment, trailing DNS dot, zone identifier, implicit/zero/leading-zero port,
   raw Unicode, and parser-normalized aliases are rejected. An ACE hostname
   MUST survive non-transitional WHATWG/UTS #46 domain-to-ASCII processing
   byte-for-byte, and a DNS spelling whose final label triggers WHATWG's legacy
   IPv4-number path is rejected. Implementations reconstruct the origin and
   require byte-for-byte equality.
3. Runtime activation MUST compare the signed origin with a mandatory configured
   public Node origin and the client-selected TLS origin. It MUST NOT derive the
   security scope from `Host`, forwarded headers, DNS resolution, or redirects.

### Node Access Pass commitment

The raw 32-byte bearer is represented in the WebSocket transcript only by:

```text
SHA-256(
  "veil-node-access-pass-commitment-v1\0"
  || u32be(origin_length) || canonical_origin
  || raw_pass_32
)
```

This commitment is origin-scoped and domain-separated. It does not replace the
server's private lookup digest or the existing atomic one-time consumption
transaction. The raw Pass MUST NOT be logged, persisted in client state, placed
in an error, or copied into the signed transcript.

### WebSocket auth v3

The canonical context is:

```text
"veil-ws-auth-v3/context\0"
|| u32be(origin_length) || canonical_origin
|| server_ephemeral_x25519_32
|| account_x25519_public_32
|| account_ed25519_public_32
|| device_id_16
|| verified_device_binding_commitment_32
|| registration_intent_u8
|| pass_commitment_32
```

Registration intent is exactly `1 = authenticate existing`, `2 = register under
explicit open-registration policy`, or `3 = register with Pass`. Intents 1 and
2 require an all-zero Pass commitment. Intent 3 requires a non-zero commitment.
There is no fallback or inference between creation modes. After both proofs,
the server first checks the exact account identity: if it already exists on this
origin, authentication succeeds without looking up or consuming a presented
registration capability. This makes an uncertain post-commit retry idempotent
and preserves ADR-0002. Only an absent identity enters the signed intent branch:
intent 1 fails, intent 2 requires explicit open policy, and intent 3 requires the
raw Pass to match the signed commitment and be consumed atomically with account
creation.

The account and device proof messages are:

```text
"veil-ws-auth-v3/account-proof\0"
|| u32be(context_length) || context
|| contributory_account_dh_32

"veil-ws-auth-v3/device-proof\0"
|| u32be(context_length) || context
|| contributory_device_dh_32
|| account_proof_signature_64
```

The binding commitment is accepted only after the Node has strictly verified
the account-signed device binding. For the current binding v1 it is SHA-256 of
the exact `veil-device-binding-v1` signing message; an arbitrary digest supplied
by a client is not a verified commitment. The device proof's inclusion of the
account signature prevents moving it to another account proof under the same
challenge. X25519 results MUST be contributory, Ed25519 public keys and
signatures MUST pass strict verification (including canonical encoding), and
fixed identifiers/commitments that represent present objects MUST not be all
zero. The pure device-message builder can validate only the chained signature's
fixed non-zero shape; client code supplies its freshly generated signature and
server code MUST verify the account proof strictly before constructing or
accepting the device proof. Runtime integration SHOULD make that ordering
type-safe with an opaque verified-proof value.

The v3 result is also fail-closed. Every result repeats protocol version 3 and
the exact canonical origin. Success requires a canonical non-nil user UUID, an
active matching positive binding version/status, `per_device_secure = true`,
an unspecified failure reason, and no diagnostic error. Failure has no user
UUID or binding state and uses one known non-zero reason. `REGISTRATION_CLOSED`
is coherent only with the signed `OPEN` intent, while
`NODE_ACCESS_PASS_INVALID` is coherent only with the signed `PASS` intent;
unknown, unspecified, or contradictory outcomes are protocol-invalid rather
than aliases for a generic rejection. Diagnostic text never selects client
behavior. The expected origin, binding version/status, and intent used to
validate a result MUST be carried from the same prepared proof attempt rather
than reconstructed from caller-supplied comparison values.

### Signed REST auth v2

The exact request signing message is:

```text
"veil-rest-auth-v2\0"
|| u32be(origin_length) || canonical_origin
|| canonical_user_uuid_bytes_16
|| u32be(method_length) || uppercase_http_method
|| u32be(target_length) || canonical_origin_form_request_target
|| timestamp_ms_u64be
|| nonce_32
|| sha256(exact_body_bytes)_32
```

The user UUID is the non-nil, lowercase hyphenated textual UUID decoded to RFC
network-order bytes. Method is a non-empty uppercase HTTP token of at most 32
bytes. Target is at most 16 KiB, printable ASCII origin-form beginning with one
slash, and is signed byte-for-byte. It rejects fragments, backslashes, absolute
form, duplicate-slash and dot-segment aliases, a trailing bare `?`, malformed or
lowercase percent escapes, percent-encoded unreserved characters, and encoded
path separators. Query order and duplicate query keys are not normalized.

Timestamp is in `1..MaxInt64` milliseconds and has one canonical decimal header
representation at the future HTTP boundary. Nonce is 32 non-zero random bytes
with one canonical header encoding. Runtime replay state will be keyed by the
authenticated account and nonce after signature verification. The exact body is
hashed before parsing. Endpoints MUST enforce one fixed media type when media
type changes parser semantics; supporting multiple security-relevant media
types requires adding a bounded field in a new contract version.

#### REST v2 HTTP header profile

The REST API path version and the authentication version are independent. A
request to a path such as `/v1/prekeys` can use REST authentication v2; the path
MUST NOT select or imply the authentication verifier. The v2 verifier is
selected only by this exact logical header set:

| Header | Canonical value |
|---|---|
| `X-Veil-REST-Auth-Version` | the single ASCII byte `2` |
| `X-Veil-User` | one canonical lowercase, hyphenated, non-nil UUID |
| `X-Veil-Timestamp` | one unsigned decimal value in `1..MaxInt64`, with no sign or leading zero |
| `X-Veil-Nonce` | strict unpadded base64url of exactly 32 non-zero bytes; therefore exactly 43 ASCII characters |
| `X-Veil-Signature` | strict unpadded base64url of exactly one 64-byte Ed25519 signature; therefore exactly 86 ASCII characters |

Header names follow HTTP's case-insensitive field-name rules; their values do
not have aliases. Each logical field MUST occur exactly once. Empty, repeated,
comma-combined, padded, non-canonical, or differently encoded values are
rejected, even when decoding them could produce otherwise valid bytes. A parser
MUST decode and re-encode nonce and signature values and require byte-for-byte
equality with the received value. Authentication values and raw request bodies
MUST NOT be logged, reflected in an error, or used as telemetry labels.

`X-Veil-REST-Auth-Version` is a fail-closed verifier selector, not an unsigned
substitute for transcript versioning. The selected verifier always uses the
`veil-rest-auth-v2\0` domain, so deleting or changing the selector cannot make a
v2 signature valid as REST v1. A request carrying mixed legacy and v2
authentication material is rejected; verification failure never triggers a
second verifier. In the v2-only activation profile, a missing selector is also
rejected. A separately reviewed Preview compatibility dispatcher MAY select
legacy v1 directly from an absent selector before verification, but only under
the explicit flag, owner, telemetry, and expiry rules below; unknown or mixed
selectors are never a legacy alias.

#### Raw HTTP boundary and media types

On the Go server, the signed target comes from the inbound server-only
`RequestURI`: the unmodified HTTP/1 request-target or HTTP/2 `:path` made
available by `net/http`. It MUST NOT be reconstructed from `URL.Path`,
`EscapedPath`, parsed query values, route variables, `Host`, forwarded headers,
or a redirect target. The exact `RequestURI` is validated against the bounded
canonical target grammar before it enters the transcript. Reverse proxies MUST
preserve accepted target and message-content bytes; an ingress rewrite is a
signature failure, not a normalization opportunity.

The body commitment covers the exact HTTP message-content bytes read from
`r.Body` after hop-by-hop transfer framing has been removed and before JSON,
form, image, compression, or other application decoding. The verifier performs
one bounded read, hashes those bytes, and restores exactly those bytes for the
handler. Declared length never replaces the bounded read, including for a
chunked request or a request whose declared length is zero.

Because media type is not a v2 transcript field, every activated endpoint MUST
declare one fixed parser policy outside attacker control. A JSON endpoint uses
one exact reviewed JSON media type; a bodyless endpoint rejects a body; a binary
endpoint uses its own exact reviewed type. Parameters, alternate content types,
content encodings, or other headers that could change parser semantics are
rejected unless a later authentication-contract version signs a bounded
representation of that choice. Body parsing happens only after authentication
and replay admission.

#### Verification and durable replay order

The live verifier MUST execute the following order without publishing an
authenticated principal early:

1. Require a configured non-zero canonical public origin and select exactly
   REST v2 from the single version header. Reject unknown, missing, duplicate,
   combined, or mixed authentication fields without trying REST v1.
2. Parse the canonical user, timestamp, nonce, signature, uppercase method, and
   raw canonical request target. Perform the initial freshness decision with
   one server-clock sample converted once to Unix milliseconds and the
   inclusive interval `now_ms +/- 60,000`; sub-millisecond precision MUST NOT
   silently narrow either boundary.
3. Resolve and strictly validate the account's pinned Ed25519 public key before
   admitting an attacker-sized body. A header UUID is only a lookup candidate;
   it becomes the authenticated account only when the v2 signature verifies.
4. Apply bounded body admission, read the exact body once, enforce the route's
   fixed media policy, and build the v2 transcript with the configured origin.
   The incoming `Host`, forwarded headers, DNS result, and TLS routing metadata
   never provide the transcript origin.
5. Strictly verify the Ed25519 signature. Failed signatures MUST NOT create a
   replay marker, so an unauthenticated party cannot poison another account's
   nonce space.
6. Immediately before the durable replay claim, take one new server-clock
   sample, convert it once to Unix milliseconds, and revalidate the same
   inclusive freshness interval. A proof that became stale while its bounded
   body was admitted or read fails without a replay claim. The staged
   continuation also MUST NOT remain usable for more than one 60-second
   freshness window measured with monotonic elapsed time when available;
   negative elapsed time, an invalid clock sample, or a longer delay fails
   closed without a replay claim. Activated HTTP transport MUST also impose an
   absolute body-read deadline no later than that continuation expiry; a
   post-read age check alone is not a bound on a connection blocked in `Read`.
   The bound MUST also cover any automatic `net/http` body drain after an early
   rejection, or that rejection MUST close the connection safely; restoring a
   longer listener deadline MUST NOT reopen that resource window.
   Then atomically
   consume replay state keyed by the verified canonical account and exact
   32-byte nonce in a store shared by every gateway process for that Node. Only
   the winner may publish the verified-principal context and invoke the
   handler.

Replay authority MUST be durable across process death and simultaneous gateway
instances; a process-local map or signature-text cache is not sufficient. The
marker remains live strictly beyond the last instant at which the signed
timestamp can pass the freshness window, including a positive clock/precision
safety margin. Cleanup removes only expired markers. Capacity handling never
evicts a live marker: per-account or global saturation, storage uncertainty,
transaction failure, and timeout all fail closed before the handler, with no
fallback to a local cache or REST v1. Once a verified request wins replay
admission, its marker remains consumed even if rate limiting, application
validation, database work, response writing, or the network later fails.

The replay key is account plus nonce, not timestamp, signature text, request
target, or body digest. Consequently the same nonce cannot authorize a second
request for that account merely by changing and re-signing another field, while
independent accounts do not share a nonce namespace.

### Version and downgrade policy

WebSocket v2 bytes are not valid v3 proof bytes, and REST v1 bytes are not valid
v2 proof bytes. Unknown fields or semantic changes require a new version; no
implementation silently appends, omits, or normalizes them.

The pure transcript and isolated foundation checkpoints led to the active
runtime: dedicated transport dispatch, mandatory configured public origin,
exact client comparison, a shared durable replay store, route media policies,
fail-closed negotiation, and a two-Node relay harness are implemented. Missing
or unknown version never means "try the other version".
A Preview-only compatibility dispatcher, if required, MUST select v1 or v2 once
before verification under an explicit flag with no-secret telemetry, an owner,
and a finite expiry no more than 30 days after process start. The process MUST
reattach that bounded interval to a monotonic deadline when available and MUST
keep legacy selection disabled after any request observes expiry or an invalid
clock; a later wall-clock rollback cannot re-enable it. Production MUST reject
origin-unbound WS v2 and ingress-dependent REST v1.

## Executable evidence

Rust and Go load one immutable, synthetic-only fixture from
`test-vectors/transport-auth/v1.json` and pin its SHA-256. Both implementations
must reproduce the Pass commitment, WS context and proof messages, REST message,
and deterministic Ed25519 signatures. Mutation tests cover every security field,
origin aliases, registration-intent substitution, cross-domain substitution,
other-origin relay, v1/v2 downgrade bytes, bounds, and malformed encodings.

This evidence is now paired with configured-origin runtime integration,
production downgrade removal, durable replay tests, and a disposable
PostgreSQL two-Node relay matrix. Independent review and cross-client/physical
evidence remain separate release gates.

## Consequences

- A credential signed for one exact origin has a versioned representation that
  cannot be reinterpreted as authorization for another origin.
- Registration policy and Pass presence become explicit authenticated intent.
- REST identity, target, freshness, and body commitment share one bounded binary
  grammar across native clients and the server.
- The deliberate Preview cutover is active. Legacy WS compatibility is an
  explicit, server-only emergency rollback switch; it is never negotiated or
  selected by a client after a v3 endpoint has been configured.
- Any future field with authorization or parser semantics requires explicit
  contract review instead of relying on an unsigned header or protobuf field.

## Rejected alternatives

- **Rely on Host/SNI or an ingress allowlist:** useful defense in depth, but not
  an end-to-end credential scope and not portable to arbitrary self-hosted Nodes.
- **Sign a serialized protobuf or HTTP request:** admits library/version-specific
  ordering and normalization into the security boundary.
- **Put the raw Pass in the transcript:** expands sensitive bearer exposure and
  is unnecessary once intent and an origin-scoped commitment are signed.
- **Reuse WS v2/REST v1 domains with more fields:** creates ambiguous downgrade
  behavior and makes old and new verifiers difficult to distinguish safely.
- **Activate the builders immediately:** byte agreement is necessary but does
  not provide configured-origin enforcement, replay handling, negotiation, or
  two-Node evidence.
