# Phase 4E Veil Link v1 — schema, API, privacy and security review

Status: approved for the pre-release v1 implementation described below.

Date: 2026-07-14

Scope: one `space` capability with bounded immediate membership after an
explicit authenticated native confirmation. This review does not authorize a
browser messenger, account enrollment, Circle links, role-bearing links,
Restricted Room access, history grants or unlimited links.

## Threat boundary

A Veil Link is an admission capability, not identity proof. Possession of its
secret can authorize only the ordinary default Space membership that the link
creator configured. It cannot establish `Verified`, select an account, switch a
Veil Node, bypass TLS, grant roles, bypass Room ACL, disclose past Sender Keys or
change the separately enforced history policy.

The public browser sees only an invitation ceremony. Identity keys, account
sessions, recovery material, member lists, owner identifiers, messages and IPC
are outside this boundary.

## Canonical wire format

The canonical share URL is:

```text
https://<exact-origin>/join/v1/<selector>#s=<secret>
```

- `<exact-origin>` is the canonical Veil Node origin: scheme, host and effective
  port. Production links require HTTPS. Loopback HTTP is allowed only by the
  existing explicit development-origin policy.
- `<selector>` is 32 CSPRNG bytes encoded as unpadded base64url (43 characters).
- `<secret>` is an independent 32 CSPRNG bytes encoded in the same form.
- The secret is in the URL fragment. Browsers do not send it in the HTTP request,
  access log path or `Referer` header.
- Query parameters, userinfo, redirects, non-canonical ports, alternate path
  forms and unknown fragment fields are rejected by the native parser.
- The portal may hand the native app the exact custom transport
  `veil://join/v1/<selector>?origin=<encoded-origin>#s=<secret>`. Native Rust
  parses it as an untrusted claim, never as proof of origin. Veil must already
  have an authenticated account binding for that exact TLS origin before
  preview or join; the URI cannot switch Node or account.

The public selector is deliberately independent from the management UUID. A
database row identifier is never a selector.

## Stored schema

`server_invites` is replaced before release. No compatibility reader remains.
Each row contains:

- opaque UUID `id` used only by authenticated management APIs;
- `public_selector` (43-character base64url, unique);
- `secret_hash = SHA-256("veil-link-v1\0" || raw_secret)`;
- fixed `version = 1` and `link_type = 'space'`;
- Space ID and creator ID;
- bounded `max_uses`, current `uses`, mandatory `expires_at`;
- `created_at` and nullable `revoked_at`.

Raw secret bytes and the complete share URL are returned exactly once by the
create response and are never stored. Cryptographic hashing is appropriate here
because the secret has 256 bits of uniformly random entropy; a password KDF
would not add meaningful resistance.

V1 limits are `1..100` uses and `5 minutes..7 days` lifetime. The UI defaults to
one use and 24 hours. `0 = unlimited`, `NULL = never` and one-year development
links are removed.

## API surface

All JSON endpoints reject unknown/trailing fields through the existing strict
decoder. Authenticated endpoints remain request-signed and origin-bound.

```text
POST   /v1/servers/{space_id}/veil-links
GET    /v1/servers/{space_id}/veil-links
DELETE /v1/servers/{space_id}/veil-links/{link_id}
DELETE /v1/servers/{space_id}/veil-links

GET    /v1/veil-links/{selector}
POST   /v1/veil-links/{selector}/preview
POST   /v1/veil-links/{selector}/join

GET    /join/v1/{selector}
```

Create accepts `max_uses` and `expires_in_secs`. Its response alone includes
`secret` and `share_url`. List responses include management UUID, public
selector, counters, timestamps and state, never the secret/hash/share URL.
Revoke and revoke-all address UUID rows, not raw capability material.

The public GET uses only the selector and returns a versioned allowlist:
Space name, owner-approved description, deterministic Space-mark seed input,
exact origin, expiry and the fixed immediate-membership policy. It never returns
owner UUID, creator UUID, members, roles, Rooms, created-at, image URLs or invite
counters. Invalid, expired, exhausted and revoked selectors are
indistinguishable.

Authenticated preview and join additionally require the raw secret in a JSON
request body. The secret is hashed and compared in constant time. Preview is
fresh and bound to the currently authenticated exact origin. Join requires a
separate explicit user action; preview never consumes a use.

## Atomic admission and moderation

Join runs in one PostgreSQL transaction and locks the link row. It checks the
active Space, version/type, revocation, expiry, secret and authoritative ban,
then resolves existing membership. The remaining-use check applies before any
new membership, while an already-admitted member may repeat the same exhausted
link idempotently. A banned account receives the same
public join failure class, consumes no use, creates no membership or
conversation roster row and emits no member-joined/rotation trigger.

For a new allowed member, Space membership, eligible Space-wide text Room roster
rows and use-count increment commit atomically. The client remains send-
quarantined until fresh authoritative roster hydration and Sender-Key
distribution succeed. The link never supplies historical keys.

Ban persistence is `(space_id, user_id)` with actor, bounded reason and
timestamps. Ban/remove is not delayed for batching. Unban does not restore
membership or keys; a later explicit link join is required.

## Browser portal and response privacy

The portal is same-origin, script-minimal and contains no third-party resources.
It renders only the public DTO as escaped text and a deterministic Space mark.
It sets:

```text
Cache-Control: no-store
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-<per-response>'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
```

OpenGraph metadata is generic. The fragment secret is read only by an audited
same-origin helper when native handoff is available; it is never sent by fetch,
analytics or a third-party request. Without native handoff the portal can tell
the user to open the original link in Veil, but cannot join in the browser.

## Logging, rate limits and lifecycle

- Raw selector/secret/share URL must not be logged. Operational access logging
  records no request path and uses short-lived HMAC references for user/IP
  fields. The narrow lifecycle journal stores only Space UUID, management link
  UUID (or null for revoke-all), actor UUID, event type and timestamp; it has no
  selector, secret or arbitrary metadata columns, is retained for at most 90
  days and is capped at 10,000 rows per Space.
- Public preview, authenticated preview and join have independent bounded rate
  limits. Responses do not reveal whether selector, secret, expiry, revocation,
  exhaustion or ban caused rejection.
- Native code may retain at most one pending link in volatile memory for five
  minutes. Replacement, cancel, timeout, lock, account/origin generation change,
  successful consumption and process exit clear it. Renderer state and
  plaintext config never persist it.

## Required evidence

- entropy failure is fail-closed; selector and secret are independent and at
  least 256 bits;
- DB never contains raw secret and list/revoke never return it;
- expiry/max-use races, revoke/revoke-all and already-member idempotence are
  transactionally tested;
- ban/rejoin/unban proves rejected joins have no roster/use side effects;
- generic public errors and mandatory privacy headers are integration-tested;
- native parser rejects origin confusion, redirects, malformed base64url,
  query/userinfo/path variants and stale binding/account transitions;
- logs and browser requests contain no raw secret.

Any change to capability type, limits, URL grammar, disclosed preview fields,
browser behavior, role/history semantics or secret persistence reopens this
review.
