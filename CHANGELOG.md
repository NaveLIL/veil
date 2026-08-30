# Veil changelog

All notable release checkpoints are recorded here. Veil remains pre-1.0:
minor releases may intentionally remove obsolete protocol paths when keeping
them would weaken security or complicate the product without serving deployed
users.

## Unreleased - v0.3.0 Clean Slate

### In progress

- Accepted ADR-0004: maintained open-source implementations of open security
  standards are preferred over new Veil-specific protocol generations when
  their application boundaries, licensing, persistence, and platform behavior
  pass Veil's gates.
- Removed desktop support for 4-5 digit legacy PIN unlock; the single supported
  PIN policy is now 6-12 ASCII digits.
- Removed the Android SharedPreferences identity-vault migration adapter. The
  current durable no-backup-file format remains write-once and fail-closed.
- Removed the retired `/ws` route and compatibility response completely;
  `/v3/events` is the only registered WebSocket transport.
- Patched the actionable desktop/mobile `nanoid` and `js-yaml` dependency
  advisories with narrow version overrides and reproducible lockfile updates.
- Upgraded the pinned Go toolchain and server build image from 1.26.5 to
  1.26.6 after `govulncheck` found reachable standard-library advisories.
- Kept only two exact, time-bounded mobile `image-size` build-tool audit
  exceptions; their reachability, controls, expiry, and removal gate are
  documented in `docs/reviews/mobile-image-size-audit-exception-2026-08-30.md`.

This is an intentionally breaking pre-release line. Message/ratchet/Sender-Key
history cutover and the OpenMLS runtime remain pending and are tracked in
ADR-0004 and `INTEGRATION_ROADMAP.md`.

## 0.2.0 Preview — 2026-08-05

This release promotes the integrated beta line to the default development
baseline. It is a GitHub prerelease and engineering preview, not an independent
security certification or a production-readiness claim.

### Security

- Bound production WebSocket v3 and REST v2 authentication to the exact Node
  origin, account, device, request target/body, freshness window, and nonce.
- Removed live legacy `/ws`, REST v1, dual-dispatch, and rollback paths instead
  of silently downgrading security.
- Added Direct v2 session commitments, Identity Transparency, optional witness
  quorum and gossip, membership epochs, and Sender-Key v6 roster binding.
- Added frozen cross-language vectors, hostile two-Node integration coverage,
  parser fuzz smoke, database invariants, and rollback/split-view regression
  gates.
- Narrowed the production mobile FFI boundary so callers cannot assemble raw
  cryptographic trust claims or extract private key material.

### Product and UX

- Preserved automatic reconnect, offline replay, outbox delivery, typed ACKs,
  and historical encrypted-data reads across the security cutover.
- Advanced the Android Direct Preview through Rust/UniFFI/Kotlin builds for
  `arm64-v8a` and `x86_64`; Mobile CI publishes a short-lived debug APK and its
  SHA-256 sidecar.
- Integrated the current desktop, Spaces, Secure Share foundation, Node,
  operations, accessibility, appearance, and roadmap workstreams.
- Trust warnings remain reserved for real key/policy changes or fail-closed
  conditions; normal secure messaging requires no new ceremony.

### Compatibility

- Clients using legacy `/ws`, REST v1, retired standalone auth/chat services,
  or originless credentials must update. There is intentionally no network
  downgrade path.
- Historical Direct v1 and Sender-Key v5 ciphertext/storage rows remain
  readable; new secure-era traffic uses the current authenticated contracts.

### Known preview limitations

- Android is distributed only as short-lived debug CI evidence; no signed
  tester or public APK is included in this release.
- Physical Desktop ↔ Android process-death, airplane-mode, recovery, and QR
  interoperability matrices remain open.
- Independent security review and independently operated transparency witnesses
  remain release gates for stronger public security claims.
- Windows installers may be explicitly unsigned when signing credentials are
  unavailable; the release manifest records the actual signing mode.
- macOS, Android, calls, MLS runtime, and secure multi-device linking are not
  shipped as completed production features.

For exact implementation evidence and the next work items, see
[`INTEGRATION_ROADMAP.md`](INTEGRATION_ROADMAP.md) and
[`docs/reviews/security-hardening-audit-handoff-2026-08-05.md`](docs/reviews/security-hardening-audit-handoff-2026-08-05.md).

## 0.1.4 Preview — 2026-07-18

- Introduced secure closed-preview Node Access Passes.
- This checkpoint is preserved by tag `v0.1.4`; later security and product work
  is documented in the 0.2.0 section above.
