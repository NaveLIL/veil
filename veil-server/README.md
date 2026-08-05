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

This began as the Phase 5S.3B-1 configuration foundation. The live authenticated
transport is now `/v3/events`: desktop and Android use the same WS v3 barrier
for commands and events, and all signed REST handlers use the REST v2 profile
with the durable PostgreSQL replay store. Missing, legacy, mixed, duplicate, or
unknown REST authentication fields fail closed.

The legacy `/ws` route is disabled by default and returns HTTP 426 without
upgrading. An operator may temporarily restore it only through the explicit
emergency compatibility flag:

```text
VEIL_ALLOW_LEGACY_WS_V2=true
```

That flag re-enables origin-unbound WS v2 and therefore must not be used for a
normal or production deployment. It exists for controlled rollback while old
Preview clients are retired; clients never downgrade automatically. Hostile
two-Node and independent-review evidence are still release gates, so this
runtime cutover is not by itself a production-readiness claim.

## Identity transparency rollout

Identity Transparency v1 is an explicit, one-way per-origin rollout. It is
disabled by default so an existing Node is never silently relabelled as having
transparent identity history. A new empty Node can enable it with:

```text
VEIL_IDENTITY_TRANSPARENCY_ENABLED=true
VEIL_IDENTITY_TRANSPARENCY_SIGNING_SEED=<canonical-unpadded-base64url-32-byte-seed>
```

The seed is a dedicated Ed25519 seed for transparency tree heads; it is not an
account key, transport key, or TLS key. Store it in the deployment secret
manager, keep recoverable offline backup material, and never rotate or replace
it as an ordinary configuration change. The canonical public origin and the
derived transparency public key permanently determine the log id.

Startup performs a complete audit of the log head, every account registration,
every device-binding version, every immutable leaf, and the compact Merkle
nodes. It fails closed if the configured origin/key differs, if an event is
missing or changed, or if a non-empty legacy Node has no existing audited log.
There is intentionally no automatic legacy backfill. Such a deployment needs a
separately specified and reviewed bootstrap ceremony before this flag may be
enabled.

When active, account creation and device-binding publication append their exact
events in the same PostgreSQL transaction as the product mutation. Authenticated
clients can request bounded inclusion/consistency proofs from:

```text
GET /v1/transparency/accounts/{account_uuid}?from_size={pinned_size}
GET /v1/transparency/devices/{device_id}/bindings/{version}?from_size={pinned_size}
```

`GET /v1/prekeys/{identity_key}?transparency_from_size={pinned_size}` embeds the
account and exact device-binding proof under one identical signed tree head.
Desktop and Android verify these proofs and atomically advance a SQLCipher pin.
After a pin exists, omission of the proofs is a sticky downgrade error. A Node
that has never enabled transparency remains usable on first contact to preserve
existing deployments, but it receives no transparency/verified security claim.

External witness quorum and public client-checkpoint gossip are implemented.
Configure `VEIL_IDENTITY_TRANSPARENCY_WITNESSES` as comma-separated
`canonical-https-url|lowercase-32-byte-public-key-hex` entries together with
`VEIL_IDENTITY_TRANSPARENCY_WITNESS_QUORUM`. The Node requests signatures
concurrently, rejects redirects and malformed responses, locally verifies every
signature, and can retry a lagging witness with an exact consistency proof.
The repository does not ship an independently operated witness service; see
[`docs/operations/transparency-witness-rollout.md`](../docs/operations/transparency-witness-rollout.md).
Until such witnesses or gossip are actually operated, fingerprint/QR comparison
remains the immediate out-of-band verification path.

## Account registration

First-time account creation is disabled by default. Existing accounts can
still authenticate. Enable registration only for an intentional development
or public onboarding window:

```text
VEIL_ALLOW_REGISTRATION=true
```

Production Compose keeps this flag `false` unless the operator explicitly
changes it. Invalid values fail startup instead of silently enabling access.

## Current Direct multi-device limitation

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
