# Veil beta integration and macOS checkpoint — 2026-08-04

Status: development beta handoff. This checkpoint is not a stable release,
security audit, signed distribution, or production-readiness claim.

## Scope and source state

The checkpoint was prepared on branch `ds/beta-all-2026-07-21` from source
baseline `f6dbf5a` (`feat: complete MobileWsEvents controller and v3 server
endpoint`). It records both that integration slice and the previously uncommitted
Veil UI/build work needed to continue on another workstation.

## Changes preserved in the beta branch

### Integration baseline `f6dbf5a`

- the gateway registers a separate experimental `/v3/events` WebSocket endpoint;
- the Rust client contains the v3 event supervisor and mobile controller;
- the FFI/Kotlin/React Native layers contain the first mobile event and contact
  flow integration slice; and
- Android Preview screens contain contact search and Direct initiation
  scaffolding.

This does not replace the legacy `/ws` production path or close Phase 5S. The
new endpoint and mobile flow still have the contract and generated-binding
problems listed below.

### Local UI and generated-source changes

- Android `RootDock` hides unfinished Spaces/Updates destinations in release
  builds, omits a misleading one-item dock, respects horizontal/bottom safe
  areas, and uses the updated island/icon/label layout in development Preview.
- Android Preview Home shows a short authenticated user ID in its subtitle.
- Desktop onboarding uses a fixed 320 px action column for predictable layout.
- The desktop pnpm lockfile was refreshed by pnpm 11, deduplicating Babel helper
  entries and resolving `nanoid` 3.3.17 and `postcss` 8.5.25.
- Tauri's generated `macOS-schema.json` is tracked alongside the existing Linux,
  Windows, desktop, capabilities, and ACL schemas.

## macOS build evidence

The desktop app was built locally on an Intel Mac with macOS 15.7.8 (24G824),
Rust 1.97.1, Node 26.6.0, pnpm 11.20.0, and Tauri app version 0.1.4.

The first attempt stopped because the required `cargo-about` executable was
missing. After installing the exact tool version, the build completed:

```sh
cargo install cargo-about --version 0.9.1 --locked --features cli
cd veil-desktop
pnpm install --frozen-lockfile
pnpm tauri build --bundles app,dmg
```

Local outputs, intentionally ignored by Git:

| Artifact | Evidence |
|---|---|
| `target/release/bundle/macos/Veil.app` | x86_64 app; main binary 35,953,388 bytes; SHA-256 `102a31c6129d6713f29b31268f6e6310bdd3fae77fb02bae3159a049c1851a5f` |
| `target/release/bundle/dmg/Veil_0.1.4_x64.dmg` | 12,612,473 bytes; SHA-256 `7113a47583ff7851100a3662059d15e3ec7c6ea1aa8d71c59d021459d08cf043`; `hdiutil verify` passed |

The app and DMG are x86_64-only development artifacts. The app has no Apple
code signature, is not notarized, and is rejected by Gatekeeper assessment.
There is no universal/arm64 artifact. Therefore the successful local build does
not make macOS a public release target and the binaries are not committed.

The frontend build processed 2,146 modules and completed with a warning that the
main JavaScript chunk is 665.21 kB, above the configured 500 kB advisory limit.
Third-party notices were generated with 619 component entries.

## Verification snapshot

These results describe the exact source state being handed off; failures are
recorded as open integration work rather than hidden.

| Check | Result |
|---|---|
| `veil-crypto` | 100 unit + 8 E2E tests passed |
| `veil-store` | 109 tests passed |
| `veil-client` | 213 unit + 4 integration tests passed; 11 superseded tests ignored; 4 dead-code warnings remain in the new v3 path |
| `cargo test --workspace --all-targets` | failed while compiling `veil-ffi`; details below |
| `veil-desktop: pnpm test:run` | 29/31 files and 164/168 tests passed; 4 failures remain |
| `veil-mobile: pnpm exec jest --runInBand` | 22/27 suites and 220/223 tests passed; 5 suites remain red |
| targeted mobile `RootDock` suite | 3/3 tests passed after the final dock changes |
| `pnpm tauri build --bundles app,dmg` | passed and produced the local app/DMG above |
| Go server tests | not run because Go is not installed on this Mac |

Desktop failures: two event-listener timeout cases, one assertion where a newer
pending Veil Link is overwritten, and one app-shell component timeout. The
timeouts were observed under concurrent workspace load; the Veil Link assertion
is deterministic and must not be dismissed as load-related.

Mobile failures: runtime-gate and onboarding-restore timeout/failure cases,
`ChannelsIsland` used without a `NavigationContainer`, and two Design Preview
suites that import Reanimated ESM without the required Jest transform/mock.

## Known integration blockers

1. `veil-ffi/src/lib.rs` does not compile in the full workspace:
   `mobile_test_authenticated_session` is missing near line 4376, and the v3
   controller setup near line 4895 passes `Mutex<VeilClient>` where
   `Arc<Mutex<VeilClient>>` is required.
2. The new UniFFI records and methods are absent from the checked-in generated
   Kotlin bindings. Kotlin calls contact/runtime methods that are not present in
   `VeilMobileRuntime.kt`, and it expects `createdAt` although the Rust create
   result currently exposes only `conversation_id`.
3. The mobile Direct creator prepares `/v1/dms`, while the Go gateway route is
   `/v1/conversations/dm`.
4. The mobile UI sends `X-Veil-User-Id`, while the server contract requires
   `X-Veil-User`.
5. The mobile friend-request flow prepares `/v1/users/{id}/friends`, but current
   friend requests use the protobuf/WebSocket path and that REST route does not
   exist.
6. The new v3 code still contains verification markers and warning-producing
   dead code. Endpoint-level, generated-binding, two-Node, downgrade, and
   cross-client evidence is missing.
7. The desktop package keeps pnpm overrides in `package.json`, while pnpm 11
   warns that project-level `pnpm` configuration should move to the workspace
   root. The refreshed lockfile reflects pnpm 11 resolution.

Until these are resolved, `/v3/events` is an experimental side endpoint and the
contact UI is scaffolding, not a functioning Android parity claim. REST v2 is
still not connected to live routes, and Phase 5S remains open.

## Continue on another workstation

```sh
git clone https://github.com/NaveLIL/veil.git
cd veil
git switch ds/beta-all-2026-07-21
git pull --ff-only
```

Install the repository toolchains, including Go for server validation. For a
matching macOS development build:

```sh
cargo install cargo-about --version 0.9.1 --locked --features cli
cd veil-desktop
pnpm install --frozen-lockfile
pnpm tauri build --bundles app,dmg
```

Start integration repair with the two `veil-ffi` compile failures, regenerate
and review UniFFI Kotlin bindings, then align the contact Direct route, identity
header, and friend-request transport with the server contracts. After that, run
the full Rust, Go, desktop, mobile, and physical-device matrices from the
canonical roadmap.
