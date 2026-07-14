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

## What exists today

Substantial Preview implementations exist for:

- native Rust identity, X3DH, Double Ratchet, authenticated Sender Keys v5,
  encrypted attachment primitives, and recovery foundations;
- origin-scoped SQLCipher storage and a process-memory-only local search index;
- signed REST/WebSocket transport with Protobuf contracts;
- Direct, Circle, and structured Space/Room product surfaces and ACLs;
- a Tauri v2 desktop client with a SolidJS interface;
- a Go Veil Node gateway with PostgreSQL, uploads, push wake-ups, profiles,
  invitations, and release/download pages;
- an Android/mobile foundation through React Native and UniFFI.

Implemented code is not the same as release evidence. The authoritative phase
status and remaining physical/device matrices are tracked in
[INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md) and the
[completion reviews](docs/README.md#reviews-и-completion-gates).

## What is not complete

- There is no stable, independently audited release.
- Mobile production messaging, calls, and the MLS runtime are not enabled as
  complete user features.
- Key transparency is not implemented; the current model is service-mediated
  TOFU with explicit local fingerprint verification.
- Platform signing, multi-device, attachment, and distributor matrices still
  require release evidence.
- There is no full browser client. Web surfaces are deliberately limited to
  the project site, origin-hosted invitation preview, and a narrow one-time
  Share Viewer.

## Security boundary

Private-key operations, E2EE state, and decrypted long-term storage remain
inside the native Rust boundary. Sending fails closed when the required
session, roster proof, or Sender Key is unavailable; there is no plaintext
fallback.

The Veil Node stores and routes ciphertext, but it still sees unavoidable
routing metadata such as network addresses, timing, sizes, account and
conversation membership, and delivery state. E2EE does not hide that metadata.
The canonical HTTPS origin is part of account identity.

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
| **veil-ffi**, **veil-mls** | Mobile native boundary and experimental MLS foundation |
| **veil-desktop** | Tauri/SolidJS desktop application |
| **veil-mobile** | React Native/Expo mobile foundation |
| **veil-server** | Go Veil Node gateway and hosted web surfaces |
| **veil-proto** | Protobuf wire contracts |
| **veil-share-viewer** | Isolated one-time share viewer |
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
