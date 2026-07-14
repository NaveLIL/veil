# Phase 4D avatar pipeline security review

Date: 2026-07-13
Scope: migration 022, signed avatar mutation/fetch routes, desktop native fetch,
renderer local blob registry, mobile Phaseprint/Identity sheet adaptation.
Status: implementation checkpoint accepted; final Phase 4D completion gate is
explicitly deferred.

## Boundary and non-goals

Profile avatars are mutable, server-visible presentation metadata. They are not
E2EE and never select identity/signing keys, grant verification, change ACLs or
roles, rotate Sender Keys, or alter message encryption/storage. The attachment
tus pipeline is not reused. Remote URLs, SVG, GIF/APNG, WebP and renderer network
fetches remain prohibited.

## Server ingest

- Only signed self `PUT`/`DELETE` requests for the current authenticated account
  may mutate an avatar; the exact `expected_version` query and raw body digest
  are covered by the request signature.
- Input is bounded to 2 MiB, 4096 pixels per dimension and 16 megapixels. The
  decoder semaphore admits at most two concurrent normalizations per process.
- Declared MIME, signature and strict file ending must agree. PNG animation and
  trailing polyglot bytes are rejected.
- The server applies decoded orientation, center-crops/resizes to 512×512,
  flattens transparency and re-encodes JPEG. EXIF/GPS/XMP/IPTC/ICC, filename and
  original container bytes are therefore not retained.
- Output is at most 256 KiB. PostgreSQL stores a random UUID, SHA-256 digest,
  fixed dimensions/content type and normalized bytes. Replacement is atomic
  with profile-version advancement; the old row is orphaned and removed after
  a 24-hour grace period.

## Native and renderer boundary

Desktop fetches only from the currently published authenticated REST origin and
binding generation. It checks response size, MIME, JPEG magic/end marker,
server-advertised digest, SHA-256 in constant time, successful JPEG decoding and
exact 512×512 dimensions. Integrity failure produces no image and does not
replace Phaseprint.

The renderer receives normalized base64 bytes, never an asset URL. It performs
a second size/magic check and creates an `image/jpeg` Blob URL. The exact
`(origin, user_id, identity_key)` registry has 128-entry/16-MiB budgets and
revokes URLs on replacement, LRU eviction, decode error, lock, logout and origin
transition. `UserAvatar` keeps Phaseprint rendered underneath, so decode failure
has no broken-image state. CSP is not widened to arbitrary HTTPS images.

## Privacy and trust

The editor discloses that the avatar is visible to the selected server and is
not end-to-end encrypted. An avatar, display name, nickname, role or presence
never changes trust language. Service-mediated TOFU remains `Not compared`;
only explicit out-of-band comparison may become `Verified on this device`.

## Evidence and deferred final work

Checkpoint evidence includes strict-format/size/dimension normalization tests,
signed route tests, SQLCipher profile rollback/equivocation tests, desktop Rust
tests, renderer tests/build and mobile TypeScript compilation. The later final
completion gate still owns the full workspace matrix, Docker integration,
visual matrix, Windows smoke, independent review and expanded decoder corpus or
fuzz evidence. This document does not claim that gate has run.
