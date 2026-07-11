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

## Current multi-device limitation

The X3DH prekey-bundle endpoints currently return a bundle for only the most
recently seen device. A safe multi-device implementation needs a versioned
response containing distinct device identities, prekey IDs and independent
ratchet sessions. Until that protocol exists, the server intentionally does
not merge or iterate device bundles. Sender-key distributions are durably
queued for every already-registered target device, but that does not by itself
provide complete multi-device X3DH session establishment.
