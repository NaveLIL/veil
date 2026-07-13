# Phase 4D versioned text profile: schema, privacy and security review

Date: 2026-07-13

Status: approved for the text-only server checkpoint and the presentation-only
`ProfileUpdated` invalidation contract described below. This review does not
approve avatar upload, remote image URLs, profile-based trust, or changes to the
message/cryptographic protocols.

## Scope

The first network profile contains only mutable presentation metadata owned by
one account on one Veil server origin:

- `display_name`: optional plain text;
- `about`: optional plain text represented as an empty string when absent;
- `profile_version`: server-controlled monotonic revision;
- `profile_updated_at`: server-controlled timestamp;
- `avatar_asset_id`: reserved nullable schema field, never accepted from or
  returned to clients until the separate avatar review is complete.

The immutable technical `username`, account UUID, X25519 identity key and
Ed25519 signing key remain outside the editable profile. A profile is scoped by
the authenticated server origin: the same UUID on another self-hosted origin is
a different account.

## API and authorization

- `GET /v1/users/{user_id}/profile` requires an authenticated, signed request.
  It returns public-on-that-instance presentation metadata and the technical
  username fallback. It never returns device, recovery, network or secret data.
- `PUT /v1/users/me/profile` requires an authenticated, signed request. The
  verified principal from middleware is the only owner selector; a client
  cannot supply another account ID.
- Updates require `expected_version`. PostgreSQL increments the version in the
  same statement that stores the text. A stale version returns a bounded `409`
  response without exposing database details.
- Existing signed-request replay protection and verified-principal rate limits
  are mandatory outer middleware. No unsigned compatibility route exists.

## Profile update invalidation

`ProfileUpdated { user_id, profile_version }` is an additive protobuf event.
It contains no display name, about text, identity/signing key, relationship,
presence or device data. The signed REST response remains authoritative; the
event only tells a client to refetch the exact origin-scoped profile.

- Fanout is limited to the updated account and accounts which already have a
  durable relationship with it on that origin: accepted friends, a shared
  conversation or a shared server. It is never broadcast instance-wide and is
  not forwarded through offline push.
- PostgreSQL computes the indexed, deduplicated relationship union after the
  committed CAS update. A fanout/audience failure is logged only as a bounded
  error class and cannot rewrite the already committed REST success into a
  misleading client error.
- The native client accepts only a canonical UUID and a positive revision no
  larger than PostgreSQL `BIGINT`, tags the renderer event with the exact
  authenticated origin and binding generation, and exposes the revision as a
  decimal string so JavaScript cannot lose precision.
- The renderer ignores retired origins/generations and only refreshes an open
  profile whose origin and user ID match. The existing exact identity key is
  still required by native profile loading before SQLCipher publication.
- Missing events are harmless: reconnect or reopening the Identity Island uses
  signed REST and the monotonic SQLCipher cache rules. The event is not a
  durable synchronization or authorization channel.

This event is not a roster/member event. It never invokes membership refresh,
conversation quarantine, ACL changes, Sender-Key rotation or identity proof
changes.

## Local message search identity hydration

Message search remains a process-memory-only Tantivy index. The index stores
the decrypted body, message/conversation IDs and a technical sender key needed
for indexing; it is never persisted or treated as an identity directory.

Before native code returns a search hit to the renderer, it reloads the current
message from SQLCipher under the exact authenticated server origin and requires
an exact match of message ID, conversation ID, sender key and plaintext. Stale,
deleted, cross-origin or otherwise mismatched hits are omitted. Author metadata
is emitted only from the immutable SQLCipher message-author snapshot and only
when that snapshot's origin and identity key match the message binding.

The renderer validates origin, UUID, identity/signing keys and profile origin a
second time. A hit without a complete locator can still open its conversation
but cannot open an Identity Island. The selected exact author is exposed as a
separate accessible action outside the message-search listbox; `Alt+Enter`
provides the keyboard path. Search presentation never grants trust, changes an
ACL or triggers Sender-Key rotation.

## Text contract

Version 1 accepts UTF-8 JSON strings and stores Unicode NFC. It renders only as
text content, never HTML or Markdown.

- `display_name`: empty/whitespace-only becomes `null`; at most 64 extended
  grapheme clusters and 512 UTF-8 bytes; no line breaks.
- `about`: empty is allowed; at most 280 extended grapheme clusters and 2048
  UTF-8 bytes; LF is allowed, CR and other control characters are rejected.
- Leading/trailing Unicode whitespace is removed. Internal text is not
  rewritten beyond NFC normalization so the server does not silently change a
  user's statement.
- C0/C1 controls, DEL, bidi marks/embedding/override/isolate controls and
  deprecated directional controls are rejected. ZWJ remains allowed for valid
  emoji grapheme sequences.

Database byte constraints are a second boundary; application validation is the
authoritative grapheme/security policy.

## Trust boundary

Profile text, profile version and the future avatar are presentation metadata.
They never:

- select or replace an identity/signing key;
- grant `Verified` or local verification state;
- affect ACL, roles, device binding, conversation membership or privacy policy;
- rotate Sender Keys or alter Double Ratchet/Sender-Key payloads;
- substitute for signed HTTP authorization.

Service-mediated TOFU remains explicitly `Not compared`. Local verification is
stored separately in SQLCipher against `(origin, user_id, identity_key)` and is
reset/displayed as `Identity changed` when the observed key changes.

## Privacy and abuse considerations

The server operator can read profile text; it is not E2EE. The UI must disclose
this before editing. Authenticated users on the same origin may fetch a profile
when they know its UUID. Enumeration resistance relies on UUID entropy, signed
request rate limits and pseudonymized access logs; profile responses contain no
presence history, email, IP address, devices or relationship graph.

The client must retain the technical username as a safe fallback and must not
treat a mutable display name as a globally unique locator. Logs and metrics may
record only route templates and bounded error classes, never profile text or raw
account identifiers.

## Separately reviewed avatar scope

Avatar upload/fetch/decoding and `avatar_asset_id` mutation are implemented
under the independent decoder/privacy boundary documented in
[`phase-4d-avatar-security-review.md`](phase-4d-avatar-security-review.md). They
do not weaken or extend this text contract.

## Explicitly deferred

- remote image URLs or renderer network access;
- client-signed profile manifests and rollback semantics beyond server version;
- profile discovery outside the authenticated origin;
- presence, roles, server nicknames or privacy preferences in this endpoint.
