# Phase 4D versioned text profile: schema, privacy and security review

Date: 2026-07-13

Status: approved for the text-only server checkpoint described below. This
review does not approve avatar upload, remote image URLs, profile-based trust,
or changes to the message/cryptographic protocols.

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

`ProfileUpdated` fanout is deliberately excluded from this first checkpoint.
It must be added as a presentation-only event in the next checkpoint and must
not reuse roster/member events or trigger Sender-Key rotation.

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

## Explicitly deferred

- avatar upload/fetch/decoding and `avatar_asset_id` mutation;
- remote image URLs or renderer network access;
- client-signed profile manifests and rollback semantics beyond server version;
- profile discovery outside the authenticated origin;
- presence, roles, server nicknames or privacy preferences in this endpoint.
