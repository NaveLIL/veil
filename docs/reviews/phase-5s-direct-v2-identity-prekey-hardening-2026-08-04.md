# Phase 5S Direct v2, identity, and prekey hardening checkpoint

- Date: 2026-08-04
- Scope: Direct cryptographic binding, first-contact verification, mobile FFI,
  and X3DH local-key lifecycle
- Status: implemented and host/CI-tested; independent audit, physical-device,
  cross-client, and independently deployed witness gates remain open

## Security properties implemented

### Direct v2 and downgrade resistance

- The Direct v2 transcript commits to canonical Node origin, conversation,
  both account UUIDs and account keys, both exact device bindings, and the X3DH
  coordinates. HKDF-derived session material is profile-separated from Direct
  v1.
- The sender includes the exact target device/binding and session commitment.
  The WS v3 gateway supplies the authenticated source device, validates the
  target, persists the complete context, and relays it to the receiver.
- SQLCipher retains a sticky per-conversation profile/session commitment.
  Missing, legacy, cross-origin, cross-account, cross-device, or conflicting
  context after v2 installation fails closed. There is no automatic v2-to-v1
  downgrade and no plaintext fallback.
- Schema migration `031_direct_v2_message_context.sql` preserves legacy history
  as explicitly legacy/unknown rather than manufacturing v2 claims.

### Human identity verification

- The account-v2 fingerprint includes canonical origin, both canonical account
  UUIDs, and both X25519/Ed25519 account public keys in deterministic order.
- Mobile asks the native Ready session for the exact Direct conversation and
  lifecycle generation. Kotlin rechecks lifecycle, generation, account, and
  conversation both before and after the native call.
- React Native receives only origin/user/version/emoji/hex/state. It never
  receives the peer's raw key bytes through this verification API.
- `Verified on this device` is written only when the caller confirms the exact
  lowercase 32-byte digest currently displayed. A mismatch, stale generation,
  changed identity, malformed result, or wrong account returns no verified
  claim. Verification is local and is not inherited by a replacement identity.
- The displayed QR is a canonical, versioned 89-byte ASCII payload:
  `veil-identity:account-v2:<64 lowercase hex>`. Rust alone derives and parses
  it. A scan triggers a fresh exact-route derivation and constant-time digest
  comparison before SQLCipher can record verification; JavaScript has no API
  that can directly write a verified state.
- The camera is mounted only after an explicit user action and permission
  result, accepts QR frames only, closes after the first frame, and is
  unmounted when the app leaves the foreground. A rejected, malformed, stale,
  cross-account, or cross-origin result leaves the prior local trust state
  unchanged and presents no verification claim.

### Production FFI boundary and zeroization

- Production UniFFI omits raw ratchet, AEAD, X3DH, arbitrary signing, KDF,
  recovery-string, Secure Share primitive, generic signature-verification, and
  caller-assembled fingerprint exports.
- Required mobile operations remain high-level and stateful through
  `VeilMobileSession`. A checked-in script fails CI if a forbidden symbol
  reappears or a required high-level operation disappears.
- Mnemonic and temporary private-key buffers use zeroizing owners or are
  explicitly erased after ownership transfer. Runtime revocation clears
  prekeys, ratchets, pending plaintext, directory routes, and authenticated
  binding state.

### Signed-prekey retention and OPK refill

- Initial publication reserves one SPK id and twenty OPK ids before generation;
  committed reservations may leave safe gaps but cannot reuse an id.
- Low inventory now reuses the exact acknowledged SPK and reserves only twenty
  new monotonic OPK ids. SQLCipher checks the retained SPK secret, public key,
  signature, id, authenticated origin/account, local device, and absence of a
  pending outbox before committing new OPKs and the replacement exact-byte
  outbox in one immediate transaction.
- Runtime OPK state is published only after the SQLCipher commit. Lost ACKs
  resend byte-identical bodies. Local initialization derives every persisted
  X25519 public key from its secret, verifies every SPK signature against the
  account signer, and rejects unexpected OPK signatures before publishing the
  runtime epoch.
- Historical local SPKs are deliberately retained. Deleting them without a
  receiver acknowledgement/grace protocol could make delayed initial messages
  permanently undecryptable.

### Identity Transparency v1 foundation

- A per-origin append-only Merkle log now commits every new account and every
  immutable device-binding version in the same PostgreSQL transaction as the
  product mutation. Startup audits the complete log and refuses silent legacy
  backfill, log-key replacement, origin drift, missing leaves, and altered
  account/device material.
- Go and Rust share frozen account/device event, tree, inclusion, consistency,
  log-id, and signed-head fixtures. Proof coordinates and binary/decimal JSON
  encodings are canonical and bounded.
- Authenticated proof endpoints and the Direct prekey endpoint return exact
  account and device-binding inclusion/consistency proofs. The bundled pair is
  generated from one snapshot and reuses one exact signed tree head; a
  clock-tick regression test prevents timestamp/signature drift between the two
  proofs.
- SQLCipher atomically pins each origin/log/key/head, verifies Node signatures,
  inclusion and append-only consistency, and records immutable signed alarm
  evidence for replacement, rollback, same-size split view, or inconsistent
  advance. An optimistic single-row check prevents a head advance from being
  reported after unexpected concurrent or corrupted state.
- Desktop and Android request proofs from their exact pinned size before Direct
  session establishment. Once an origin has a pin, proof omission is a sticky
  downgrade failure. A never-pinned legacy/disabled Node remains usable without
  receiving a transparency or verified claim, preserving existing deployments.
- External witness quorum, public checkpoint gossip, and the desktop OS-backed
  whole-file rollback anchor are implemented. Android still lacks a separate
  OS-backed anchor; compiled mandatory witness policy is its available
  whole-file rollback mitigation.

## Host evidence in this checkpoint

- `cargo test --workspace --exclude veil-desktop` passes. The security-heavy
  suites include 230 collected `veil-client` unit tests (219 passed and 11
  explicitly superseded fixtures ignored) plus 4 client end-to-end tests,
  100 `veil-crypto` unit tests plus 8 crypto end-to-end tests, 112
  `veil-store` tests, 86 `veil-ffi` tests, 5 MLS tests, 2 HPKE regression
  vectors, 16 passing search tests, and 20 uploads tests. One manual
  release-profile search benchmark remains intentionally ignored.
- `cargo check -p veil-desktop` passes. Linking the desktop test `cdylib` under
  the local MinGW GNU toolchain is blocked by its export-ordinal limit; the
  frontend production build and 169 desktop tests pass independently.
- Strict Clippy for `veil-store`, `veil-client`, and `veil-ffi`, including all
  targets and `-D warnings`, passes. `cargo fmt --check` passes.
- Targeted client/store tests cover exact retry, OPK-only monotonic allocation,
  immutable-SPK matching, transaction rollback, cross-origin publication,
  corrupt keypair/signature rejection, and runtime publication only after
  durable commit.
- Mobile identity-verification Rust, Kotlin, TypeScript, and UI tests pass.
- The complete mobile Jest run passes 28 suites and 233 tests; TypeScript and
  ESLint pass. Android JVM compilation/tests complete successfully across 228
  Gradle tasks when the unavailable local native `.so` artifact verification
  is excluded. Generated Kotlin compiles, and the production UniFFI symbol gate
  passes.
- Go `test ./...` and `vet ./...` pass. The desktop production Vite build,
  TypeScript check, and 31-file/169-test Vitest run pass.
- Full `pnpm audit --audit-level=low` passes for both mobile and desktop. The
  lockfiles were advanced from vulnerable transitive `postcss`, `tar`,
  `undici`, and `brace-expansion` releases to patched overrides; all 231 mobile
  tests, all 169 desktop tests, both TypeScript checks, mobile ESLint, and the
  desktop production build pass after the lock updates. Adding the QR renderer
  and explicit camera module retains a zero-finding full mobile audit.
- Both JavaScript workspaces also accept a pnpm 10.29.2 frozen install, matching
  the pinned build-job package-manager version; focused Direct/identity and
  origin-transition tests pass on the recreated dependency trees.
- `govulncheck` reports no reachable Go vulnerabilities. RustSec reports no
  known Rust vulnerability; `event-listener` was advanced from the unsound
  5.4.1 release to 5.4.2. CI now denies any new unsound Rust advisory and has
  one documented exception for Tauri's Linux-only `glib` 0.18.5 chain.
- Go already contains integration coverage for current-SPK replenishment,
  conflicting material, replay receipts, pruning bounds, and concurrent
  account/device publication limits.

The final workspace matrix and exact command output belong in the release gate,
not in this implementation checkpoint.

## Explicitly open release/security gates

1. **Independent witness deployment.** The strict quorum client/protocol and
   gossip comparison are implemented, but this repository does not ship or
   operate an independent persistent witness service. Manual fingerprint/QR
   comparison remains the immediate out-of-band defense without one.
2. **Android whole-file rollback anchor.** Desktop compares SQLCipher state
   with a crash-safe OS credential-store anchor. Android currently relies on a
   compiled mandatory witness policy and still needs a separately reviewed
   Keystore-backed monotonic protocol.
3. **Full Direct multi-device fanout.** Direct v2 authenticates one exact target
   device. Sending one user intent to every active peer device and keying every
   ratchet by account plus device require a versioned fanout/receipt migration.
4. **Physical QR interoperability evidence.** QR display, exact native scan
   confirmation, permission handling, single-frame consumption, and camera
   lifecycle shutdown are active and host-tested. A signed release build still
   needs a two-device Android/iOS cross-scan matrix covering rotation,
   permission denial, process backgrounding, identity replacement, and stale
   Direct generations.
5. **Protocol feature parity.** Direct v2 text is fail-closed. Secure encrypted
   Direct edit/delete semantics are rejected rather than silently emitted with
   an incomplete profile and need a separate versioned design.
6. **External evidence.** The Docker/PostgreSQL two-Node relay matrix and four
   Go fuzz targets are now in CI. Android device process-death/airplane/recovery
   tests, cross-client Direct v2 vectors, signed artifacts, and independent
   cryptographic review are still mandatory before a stable security claim.
7. **Tauri Linux GTK lineage.** Current Tauri/WebKitGTK dependencies retain the
   unmaintained GTK3 bindings and `glib` 0.18.5. RustSec's unsound method family
   is not called by Veil, and the exact advisory is the only explicit CI
   exception. Removing it requires an upstream-compatible Tauri Linux runtime
   migration; every new unsound advisory still fails CI.

None of these open gates authorizes plaintext, a weaker cryptographic profile,
automatic transport downgrade, deletion of delayed-message key material, or a
verified-identity claim based only on server data.
