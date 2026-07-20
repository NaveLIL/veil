# ADR-0003: Origin-bound transport authentication

- Status: Accepted contract; runtime activation pending
- Date: 2026-07-20
- Scope: WebSocket authentication v3 and signed REST authentication v2
- Owners: Veil client, server, desktop, Android, protocol, and operations maintainers

## Context

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
   raw Unicode, and parser-normalized aliases are rejected. Implementations
   reconstruct the origin and require byte-for-byte equality.
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

### Version and downgrade policy

WebSocket v2 bytes are not valid v3 proof bytes, and REST v1 bytes are not valid
v2 proof bytes. Unknown fields or semantic changes require a new version; no
implementation silently appends, omits, or normalizes them.

The first implementation checkpoint is deliberately pure and non-activated. A
later runtime checkpoint must add dedicated protocol messages/headers, mandatory
configured public origin, exact client comparison, replay-cache semantics,
fail-closed negotiation, and a two-Node relay harness. Production MUST reject
origin-unbound WS v2 and ingress-dependent REST v1. A Preview-only compatibility
period, if required, needs an explicit flag, telemetry that contains no secrets,
an owner, and an expiry.

## Executable evidence

Rust and Go load one immutable, synthetic-only fixture from
`test-vectors/transport-auth/v1.json` and pin its SHA-256. Both implementations
must reproduce the Pass commitment, WS context and proof messages, REST message,
and deterministic Ed25519 signatures. Mutation tests cover every security field,
origin aliases, registration-intent substitution, cross-domain substitution,
other-origin relay, v1/v2 downgrade bytes, bounds, and malformed encodings.

This evidence proves agreement on bytes and local validation only. It does not
close the hostile-Node P1 until configured-origin runtime integration,
production downgrade removal, and the two-Node relay matrix pass.

## Consequences

- A credential signed for one exact origin has a versioned representation that
  cannot be reinterpreted as authorization for another origin.
- Registration policy and Pass presence become explicit authenticated intent.
- REST identity, target, freshness, and body commitment share one bounded binary
  grammar across native clients and the server.
- Existing Preview runtime remains compatible until a deliberate cutover; the
  pure checkpoint alone is not a production security claim.
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
