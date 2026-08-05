EVIDENCE CHECKPOINT ONLY — the hostile-Node P1 and Phase 5S remain open.

# Phase 5S configured-origin foundation checkpoint

Date: 2026-07-20

## Scope

Checkpoint 5S.3B-1 establishes one mandatory, explicit canonical public Node
origin at configuration and deployment-template boundaries:

- root development Compose requires `VEIL_PUBLIC_ORIGIN` and its checked-in
  template uses the exact client-visible loopback endpoint
  `http://127.0.0.1:9080`;
- production Compose requires the same variable with no fallback, while the
  managed template fixes `https://veil.erez.pro:443`;
- `internal/nodeorigin` owns the shared canonical grammar and returns an opaque
  validated value, so later consumers cannot manufacture an arbitrary origin
  through a `config.Config` literal; the zero value remains an explicit
  non-gateway/unconfigured state;
- gateway configuration rejects a missing or non-canonical value instead of
  deriving trust scope from `Host`, forwarded headers, redirects, or DNS;
- local CI resolves both Compose files and independently proves that missing
  and explicitly empty `VEIL_PUBLIC_ORIGIN` values are rejected before any
  container can start.

The explicit port is security-relevant. The development value names host port
9080, not container-only port 8080, because desktop and other host clients
select `http://127.0.0.1:9080` as their Node origin.

Rust and Go consume the same strict `origin-v1.json` accept/reject corpus. Its
reviewed SHA-256 is
`42b8fe154439b3dde57a1c3e9c3f845c7a9df04649e6fd85b28ec577fff0ef5c`.
It covers canonical IDNA/ACE labels and rejects WHATWG numeric-final host
aliases so configured origin parsing cannot diverge from the native client.
The Go validator uses the pinned `golang.org/x/net/idna` v0.54.0 package; its
upstream BSD-style license was reviewed and the exact linked module was added
to the gateway notices allowlist.

## Deliberately not activated

This is configuration foundation, not transport-auth activation. The frozen
Rust/Go WS v3 and REST v2 builders are still not wired into the live gateway,
protocol, desktop, FFI, Kotlin, or replay cache. Current `/ws` and signed REST
therefore remain legacy Preview WS auth v2 and REST auth v1. Merely setting
`VEIL_PUBLIC_ORIGIN` neither closes the cross-Node credential-relay P1 nor
creates a production cryptographic or release-readiness claim.

No Compose service was started, stopped, recreated, or contacted. No running
Node or live `.env` was read or changed. Phone testing remains deferred: no
phone, ADB, APK, Node Access Pass, recovery ceremony, or signing operation was
performed. Physical testing can resume only after explicit authorization and a
new recovery phrase has been displayed and confirmed recorded.

## Gates still open

- WS auth v3 and REST auth v2 runtime messages/headers and strict negotiation;
- exact raw REST target/body capture and cross-process replay-nonce semantics;
- desktop and Android consumption of the configured origin contract;
- Preview compatibility expiry and production downgrade removal;
- strict live Host/SNI behavior and a real two-Node credential-relay matrix;
- independent security and cryptographic review.

## Host-only evidence

This checkpoint requires:

```text
go test ./internal/nodeorigin ./internal/config ./internal/auth ./internal/authmw
go vet ./internal/nodeorigin ./internal/config ./internal/auth ./internal/authmw
cargo fmt --all -- --check
cargo clippy -p veil-client --all-targets -- -D warnings
cargo test -p veil-client
node scripts/generate-third-party-notices.mjs --component gateway --output <temporary-path>
docker compose --env-file .env.example config --quiet
docker compose -f deploy/compose.prod.yml --env-file deploy/.env.example config --quiet
missing and explicitly empty VEIL_PUBLIC_ORIGIN rejected for both Compose files
git diff --check
```

The Go/Rust tests include a separately pinned shared accepted/rejected origin
corpus; the Compose checks validate static configuration resolution only. None
of these gates runs a container, mutates a deployment, contacts the managed
Node, or proves WS v3/REST v2 security.

Final-tree host evidence:

- ordinary `go test ./...`, `go vet ./...`, and module-readonly package loading
  passed across the server workspace;
- `go test -race -timeout 10m ./...` passed across all ordinary Go packages;
- Rust format and all-target `veil-client` clippy with warnings denied passed;
- the full `veil-client` suite passed 186 tests with 11 explicitly superseded
  tests ignored, followed by 4 passing integration tests and clean doc tests;
- the gateway notices generator passed with 28 linked component entries and
  included `golang.org/x/net`;
- both development and production Compose files resolved successfully, while
  their missing and explicitly empty origin variants failed before startup;
- workflow YAML parsing, the pinned corpus digest, Go format, and
  `git diff --check` passed.
