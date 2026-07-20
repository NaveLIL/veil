# Veil server

## Required database configuration

Every server binary requires an explicit PostgreSQL connection string:

```text
DATABASE_URL=postgres://user:password@database-host:5432/veil?sslmode=require
```

Startup fails when `DATABASE_URL` is absent or malformed. For an isolated
local development database only, the historical localhost configuration can
be enabled deliberately:

```text
VEIL_ALLOW_INSECURE_DEV_DATABASE=1
```

That opt-in uses `postgres://veil:veil@localhost:5432/veil?sslmode=disable` and
must not be enabled in production. Docker Compose supplies its own explicit
`DATABASE_URL` and requires `VEIL_DB_PASSWORD`, so it does not use this escape
hatch.

## Required canonical public origin

Every gateway process requires one explicit client-visible Node origin:

```text
VEIL_PUBLIC_ORIGIN=https://veil.example:443
```

The value is already canonical: `https://host:port`, or `http://host:port` only
for exact local loopback development. Scheme and DNS host are lowercase, the
port is explicit canonical decimal, and credentials, path, query, fragment,
trailing DNS dot, Unicode host aliases, and parser-normalized spellings are
rejected. Startup fails closed when the value is absent or invalid. It is never
derived from `Host`, forwarded headers, redirects, or DNS.

This began as the Phase 5S.3B-1 configuration foundation. Isolated,
non-activated WS v3 protocol/challenge helpers and a transport-neutral REST v2
verifier plus PostgreSQL replay migration now also exist, but no gateway route
calls them. The current `/ws` and signed REST paths remain legacy Preview WS
auth v2 and REST auth v1 until the raw transport boundaries, v3 verifier,
route media policy, replay operations, downgrade cutover, and two-Node relay
evidence are complete.

## Account registration

First-time account creation is disabled by default. Existing accounts can
still authenticate. Enable registration only for an intentional development
or public onboarding window:

```text
VEIL_ALLOW_REGISTRATION=true
```

Production Compose keeps this flag `false` unless the operator explicitly
changes it. Invalid values fail startup instead of silently enabling access.

## Current multi-device limitation

The X3DH prekey-bundle endpoints currently return a bundle for only the most
recently seen device. A safe multi-device implementation needs a versioned
response containing distinct device identities, prekey IDs and independent
ratchet sessions. Until that protocol exists, the server intentionally does
not merge or iterate device bundles. Sender-key distributions are durably
queued for every already-registered target device, but that does not by itself
provide complete multi-device X3DH session establishment.

## Corresponding Source

Official gateway images embed the exact 40-character Git revision used by the
build. The running service exposes:

- `/source` — a downloadable archive of that revision;
- `/source/browse` — a human-readable source tree;
- `/.well-known/veil-source.json` — machine-readable license, revision, archive,
  and browse URLs.

This is the network source offer for `AGPL-3.0-or-later`. If you operate a
modified build, set `VEIL_SOURCE_REVISION`, `VEIL_SOURCE_ARCHIVE_URL`, and
`VEIL_SOURCE_BROWSE_URL` together. The revision must be a full Git commit and
both URLs must be durable public HTTPS locations for the exact source you run.
The gateway refuses partial, credentialed, mutable-query, or non-HTTPS
overrides.

## Third-party notices

The release container generates its Go dependency inventory from `go.sum` and
the packages actually linked into `cmd/gateway`. Veil's license files and the
generated upstream notices are available inside the image at
`/usr/share/licenses/veil/`. `ALPINE_PACKAGES.txt` records the exact runtime
base packages, upstream pages, and declared SPDX expressions as well. Notice
generation is strict: a dependency without
an upstream LICENSE/NOTICE file, or a linked module not reviewed in
`third_party/go-modules.allow`, fails the image build.
