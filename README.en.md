# Veil

<img src="assets/brand/phase-shift-mark.svg" width="88" alt="Veil Phase Shift logo">

[Русский](README.md) · [English](README.en.md)

[![Rust CI](https://github.com/NaveLIL/veil/actions/workflows/rust.yml/badge.svg)](https://github.com/NaveLIL/veil/actions/workflows/rust.yml)
[![Go CI](https://github.com/NaveLIL/veil/actions/workflows/go.yml/badge.svg)](https://github.com/NaveLIL/veil/actions/workflows/go.yml)
[![Desktop UI CI](https://github.com/NaveLIL/veil/actions/workflows/desktop-ui.yml/badge.svg)](https://github.com/NaveLIL/veil/actions/workflows/desktop-ui.yml)
[![Mobile CI](https://github.com/NaveLIL/veil/actions/workflows/mobile.yml/badge.svg)](https://github.com/NaveLIL/veil/actions/workflows/mobile.yml)
[![Security Audit](https://github.com/NaveLIL/veil/actions/workflows/security.yml/badge.svg)](https://github.com/NaveLIL/veil/actions/workflows/security.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-663399.svg)](LICENSE)

Veil is a native-first system for encrypted direct conversations and shared
spaces, backed by a self-hostable Veil Node.

> **Preview status:** Veil has not reached a stable release and has not
> completed an independent cryptographic or comprehensive security audit.
> APIs, storage formats, protocol details, and Preview data may still change.
> Do not present a development build as a stable, audited, or officially
> supported release.

[Project site](https://veil.erez.pro/) ·
[Downloads](https://veil.erez.pro/#download) ·
[Documentation](docs/README.md) ·
[Security](SECURITY.md) ·
[Contributing](CONTRIBUTING.md)

Registration on the managed Preview Node is invite-only. A one-time **Node
Access Pass** authorizes creation of one account identity; that registered
identity can reconnect without another pass. A **Veil Link** is separate and
only invites an existing account into a Space.

## What exists today

Substantial Preview implementations exist for:

- native Rust identity, X3DH, Double Ratchet, membership-bound Sender Keys v6
  with explicit v5 history compatibility,
  encrypted attachment primitives, and recovery foundations;
- origin-scoped SQLCipher storage and a process-memory-only local search index;
- origin/account/device-bound REST v2 and WebSocket v3 transport with durable
  replay protection and Protobuf contracts. `/v3/events` is the live client
  endpoint; the removed `/ws` endpoint is no longer registered and clients
  never auto-downgrade;
- Direct, Circle, and structured Space/Room product surfaces and ACLs;
- a Tauri v2 desktop client with a SolidJS interface;
- a Go Veil Node gateway with PostgreSQL, uploads, push wake-ups, profiles,
  invitations, and release/download pages;
- a closed Android Direct Preview through React Native, Kotlin, and UniFFI:
  Node Access Pass registration, Keystore/SQLCipher runtime, receive/read,
  one-shot peer-prekey, idempotent send/outbox, guarded reconnect, atomic vault,
  native recovery, whole-app lifecycle authority, and host-tested durable
  non-secret identity-setup reconciliation are implemented. Android Activity
  recreation and OS process-death cases A04/A05 remain unexecuted.

Implemented code is not the same as release evidence. The authoritative phase
status and remaining physical/device matrices are tracked in
[INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md) and the
[completion reviews](docs/README.md#reviews-и-completion-gates).
The exact 2026-08-04 beta handoff, current red checks, and local unsigned macOS
x86_64 build evidence are recorded in the
[beta integration and macOS checkpoint](docs/reviews/beta-integration-macos-2026-08-04.md).

## What is not complete

- There is no stable, independently audited release.
- Android still lacks the full Desktop ↔ Android send/outbox/reconnect/airplane/
  process-death device matrix, connected recovery/capture instrumentation,
  app-wide public failure codes, and signed standalone tester distribution.
  Its native Direct runtime reliably opens and services only the authenticated
  existing Direct directory. Baseline `f6dbf5a` adds screens and FFI/Kotlin/
  request scaffolding for user search, friend requests, and Direct creation,
  but the generated Kotlin bindings and route/header/transport contracts do not
  yet match the gateway. This is not a completed mobile contact flow.
  `PublicFailureCodeV1` currently covers Android identity setup and the secure
  runtime gate; Direct session/send/delivery and desktop/Go consumers remain
  open. Calls and the MLS runtime are not enabled as complete user features.
- Identity Transparency v1 verifies Node-signed Merkle inclusion/consistency,
  pins accepted history, and supports independent witness quorum and public
  checkpoint gossip. The repository does not operate the independent witness
  service; explicit local fingerprint/QR verification remains authoritative.
- Platform signing, multi-device, attachment, and distributor matrices still
  require release evidence.
- There is no full browser client. Web surfaces are deliberately limited to
  the project site and origin-hosted Node Access and Space invitation pages.
  A narrow Secure Share Viewer is planned, but the current WASM module is an
  unwired prototype rather than a working public service.
- Node-wide administration, an in-product report queue, and the production
  guest Secure Share flow are planned contracts, not completed Preview features.

## Security boundary

Private-key operations, E2EE state, and decrypted long-term storage remain
inside the native Rust boundary. Sending fails closed when the required
session, roster proof, or Sender Key is unavailable; there is no plaintext
fallback.

On Android, recovery material is displayed only inside a screenshot-protected
native Activity and is excluded from React Native, clipboard, autofill,
accessibility, content capture, and the system IME. An interrupted result remains
unknown until a strict native durable-vault check; a recovery phrase is never
discarded based on a failed or unsettled check.

The Veil Node stores and routes ciphertext, but it still sees unavoidable
routing metadata such as network addresses, timing, sizes, account and
conversation membership, and delivery state. E2EE does not hide that metadata.
The canonical HTTPS origin is part of the account model. Desktop and Android
use exact REST v2 and `/v3/events` WS v3 contracts through the Rust/FFI/native
boundaries. Production rejects missing/legacy proofs without fallback. A
disposable PostgreSQL hostile two-Node relay/downgrade matrix and parser fuzz
smoke are in CI. Cross-client/physical evidence, independently operated
witnesses, signed release candidates, and independent review remain release
gates.

Files are encrypted before upload. Push payloads are restricted to generic
wake-up signals without sender, message, conversation, or plaintext preview.
Local full-text search uses a bounded in-memory index rebuilt from the
authenticated origin's SQLCipher store.

Read the [architecture overview](docs/architecture.md) and
[Security Policy](SECURITY.md) before testing security-sensitive behavior.
Never post recovery phrases, private keys, tokens, real messages, production
databases, or unsanitized logs in a public Issue.

## Repository map

| Path | Purpose |
|---|---|
| **veil-crypto**, **veil-store**, **veil-client** | Native crypto, encrypted storage, and protocol engine |
| **veil-search**, **veil-uploads** | In-memory search and encrypted transfer primitives |
| **veil-ffi**, **veil-mls** | Mobile native boundary and OpenMLS 0.9 foundation with bounded atomic checkpoints; MLS runtime remains disabled |
| **veil-desktop** | Tauri/SolidJS desktop application |
| **veil-mobile** | Closed Android Direct Preview using React Native, Kotlin, and Rust/UniFFI |
| **veil-server** | Go Veil Node gateway and hosted web surfaces |
| **veil-proto** | Protobuf wire contracts |
| **veil-share-viewer** | Experimental viewer prototype; production Secure Share is not wired |
| **deploy** | Production Compose, Nginx, backup, rollback, and smoke procedures |

## Build and run pointers

Development requires Rust/Cargo, Go, Node.js with pnpm, Docker Compose, and the
platform prerequisites for the selected desktop or mobile target.

Core checks:

~~~powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets

Push-Location veil-server
go test ./...
go vet ./...
Pop-Location

Push-Location veil-desktop
pnpm install --frozen-lockfile
pnpm test:run
pnpm build
Pop-Location
~~~

For the local development Node, copy **.env.example** to a local **.env**,
replace every placeholder secret, and run **docker compose up -d --build**.
The development gateway binds to loopback by default. Do not expose it
publicly without the canonical HTTPS origin, TLS, origin allowlist, backups,
and the production gates documented in
[deploy/README.md](deploy/README.md).

Contributor workflow, integration tests, and platform-specific checks are in
[CONTRIBUTING.md](CONTRIBUTING.md). The Russian
[README.md](README.md) contains the longer local build and release notes.

## Releases and support

The [download page](https://veil.erez.pro/#download) is populated only after
the release gate publishes and atomically installs a verified manifest. If no
verified Preview is available, the site should not offer a stale manual
artifact. Historical Linux branches and locally built installers are not the
release source.

Every desktop release must contain Linux `.deb` and AppImage packages plus
Windows `.exe` and `.msi` installers. Windows artifacts are Authenticode-signed
when both signing secrets are configured; otherwise they are explicitly marked
as an unsigned Preview and may trigger SmartScreen or Smart App Control. The
site exposes the signing state and SHA-256 checksums. A partial or invalid
signing configuration fails closed instead of silently downgrading.

Preview support is best effort and has no SLA. See [SUPPORT.md](SUPPORT.md).
Report suspected vulnerabilities privately to **security@erez.pro** according
to [SECURITY.md](SECURITY.md), never through a public Issue.

## License

Copyright © 2026 NaveLIL.

Original Veil material is licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE)
(**AGPL-3.0-or-later**). Network-modified versions must offer their users the
corresponding source as required by the license. Third-party components retain
their own notices; the reproducible inventory and release packaging are
documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The Veil name
and Phase Shift logo are governed separately
by [TRADEMARKS.md](TRADEMARKS.md).
