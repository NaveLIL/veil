# Security hardening audit handoff — 2026-08-05

- Branch: `ds/beta-all-2026-07-21`
- Implementation range: `b8ed439..HEAD` on the named beta branch
- Current status: internal implementation and regression hardening complete;
  final CI evidence for the current head is being collected
- Security claim: pre-release engineering evidence, not an independent audit

## What changed

| Commit | Boundary closed |
| --- | --- |
| `b8ed439` | Origin/account/device-bound WS v3 and REST v2, Direct v2, transparency, witnesses/gossip, membership epochs, Sender-Key v6, rollback anchors, and narrowed FFI |
| `e5a8d1f` | Deterministic static analysis, zeroization gate, and corrected downgrade regression fixture |
| `786eb2b` | PostgreSQL membership-epoch and Sender-Key v6 invariants plus migrations `033`–`035` upgrade coverage |
| `2913342` | Direct-message directory compatibility without weakening group membership scope; explicit migration test casts |
| `17108c3` | Go fuzz smoke for Node-origin, REST v2, membership-epoch, and transparency parsers |
| `bc987d0` | Integration harness moved from legacy REST v1 to production v2-only; hostile two-Node relay/downgrade matrix added |
| `155ecd1` | Superseded push/PR workflow runs cancel by source branch instead of consuming the CI queue |
| `1a46787` | Permanently retired WS v2 and standalone REST v1 binaries; removed the WS rollback switch, post-auth re-verification, and REST `PreviewDual` dispatch; corrected the SQLCipher restart fixture |
| current follow-up commit | Preserved optional no-reason moderation requests under REST v2 while keeping their signed-body boundary unambiguous; closed nullable PostgreSQL security-context checks for both fresh and already-upgraded databases; made Android foreground-service registration unambiguous to variant-aware lint |
| current CI reliability commit | Verifies the exported multi-architecture OCI layout directly with runner-provided `tar` and `jq`; no post-build `apt` or mutable third-party runner repository can invalidate an already successful image build |

Schema migrations introduced by this security range are:

- `031_direct_v2_message_context.sql`;
- `032_identity_transparency_log.sql`;
- `033_membership_epochs_v1.sql`;
- `034_sender_key_v6_membership_binding.sql`;
- `035_membership_epoch_database_invariants.sql`;
- `036_close_nullable_security_context_checks.sql`.

The fresh `001`–`036` chain and upgrades through `032`–`036` are exercised by
the Docker/PostgreSQL integration suite. Historical Direct v1 and Sender-Key v5
rows remain readable; only newly activated secure-era traffic is fail-closed.
Migration `036` replaces checks whose nullable expressions could evaluate to
PostgreSQL `UNKNOWN`, which a `CHECK` accepts, with explicit all-present or
all-absent predicates. This covers transparency events, membership bootstrap
owners, message contexts, Sender-Key membership coordinates, and idempotent
send acknowledgements. A database containing a partial security context fails
validation instead of silently relabelling or deleting the row.

## Security properties to review

1. Transport credentials bind the exact canonical Node origin, account,
   device, method/target/body, freshness, and nonce. Production is v2/v3 only.
   WS v2 has no handler or verifier, `/ws` returns 410, the removed rollback
   variable blocks startup, and post-handshake auth frames close the socket.
2. Direct v2 binds both account identities, both device bindings, X3DH
   coordinates, canonical origin, and a durable session commitment. Once
   installed, missing or conflicting v2 context cannot fall back to v1.
3. Identity Transparency v1 appends account/device events transactionally to a
   Node-signed Merkle log. Clients verify inclusion and consistency, pin the
   highest accepted head, and detect omission, rollback, replacement, and
   same-size split views.
4. Optional external witnesses sign the exact Node checkpoint. A configured or
   previously pinned witness policy is sticky and quorum failure blocks the
   trust advance. Public checkpoint gossip distinguishes lag from conclusive
   equal-size equivocation.
5. Membership epochs are owner/policy-authorized predecessor chains over the
   exact account/device roster. PostgreSQL enforces head topology and new
   Sender-Key v6 rows must bind the exact active epoch.
6. Production UniFFI exposes high-level account/session operations, not raw
   private keys, arbitrary signing/KDF/AEAD, or caller-assembled trust claims.

## UX and compatibility contract

- Normal messaging, reconnect, offline replay, and historical ciphertext need
  no additional user action.
- Pre-release clients that still use `/ws`, REST v1, or the retired standalone
  auth/chat services must update; there is intentionally no network downgrade
  path. This does not affect ciphertext history stored by current clients.
- Direct-message directory responses intentionally omit group-only membership
  bootstrap fields. Complete group scope is still mandatory; partial scope is
  rejected.
- Fingerprint/QR comparison remains optional and is the only path to the human
  label `Verified on this device`.
- A never-pinned legacy self-hosted Node remains usable but receives no
  transparency/witnessed label. After a transparency or witness policy is
  pinned, removing it is a security error rather than a confusing silent
  downgrade.
- Roster changes rotate and distribute group keys automatically. A user is
  blocked only when the authorized new epoch or exact key distribution is not
  yet available.
- Moderators may still remove a member without entering a reason. The absent
  body and an exact `application/json` body are both supported, but ambiguous,
  mislabeled, or oversized bodies are rejected before signature verification.

## Reproducible local evidence

From `veil-server`:

```text
go test ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...
go test -tags=integration ./internal/integration ./internal/db -run '^$'
```

All pass on the 2026-08-05 Windows host after live legacy authentication was
removed and the optional-body/database constraints were hardened. The last
command compiles the Docker suite; the actual disposable PostgreSQL run belongs
to GitHub Actions because Docker is unavailable on this host.

Fuzz smoke completed locally without a finding for all four targets. Approximate
two-second execution counts were 68,549 Node-origin, 14,143 REST-auth, 42,976
membership, and 34,321 transparency inputs. CI runs each target for five
seconds in `Security fuzz smoke`.

Additional local evidence:

- desktop TypeScript and 31 Vitest files / 169 tests pass;
- mobile focused identity tests pass after allowing 15 seconds for cold Jest
  startup; GitHub runs the complete JS and native Android suites;
- `cargo fmt --all -- --check`, desktop `cargo check`, and strict desktop
  Clippy pass;
- before the local GNU cache was invalidated, the full Rust workspace compiled
  and ran 225 passing tests with 11 explicitly ignored tests; its sole failure
  was the capability-bit restart fixture corrected in this range, and the
  corrected focused SQLCipher restart test passes;
- the post-cutover full-workspace retry is blocked before Veil code is linked by
  the local Windows GNU vendored-OpenSSL build (`ar.exe` truncates long archive
  member paths). This is recorded as a host-toolchain limitation, not a passing
  project result; the current-head Rust CI matrix is authoritative;
- linked Tauri tests cannot be produced by the local MinGW linker because its
  export ordinal exceeds the toolchain limit. Linux/macOS/Windows CI and
  packaging jobs are the authoritative linked-build evidence.

## CI and artifact evidence

The authoritative target is the commit containing this handoff; evidence from
an earlier checkpoint must not be substituted for a current-head result.
The final handoff must record successful current-head runs for:

- Go CI, including Docker integration and security fuzz smoke;
- Rust CI on Linux, macOS, Windows, WASM, and benchmark/build guards;
- Security Audit, Protocol Contracts, Coverage, Desktop UI, and Mobile CI;
- Beta Artifacts: Linux `.deb`/AppImage, Windows NSIS/MSI, Android APK, share
  viewer WASM, and the multi-architecture gateway OCI build.

An earlier security checkpoint already produced all Beta Artifacts and passed
the complete dependency audit. That evidence is useful diagnostically but is
not substituted for a green current-head run.

## Residual release blockers

- No independent cryptographic/security audit has reviewed this range. An
  internal handoff cannot certify its own independence.
- Android does not yet have a separate OS-backed transparency rollback anchor;
  its compiled mandatory witness policy is the available whole-file rollback
  mitigation. Desktop uses the OS credential store.
- The repository contains the witness client/protocol but not a deployable,
  independently operated witness service. Operators must deploy persistent
  independent witnesses before claiming witnessed first-contact security.
- Signed release APK/desktop artifacts and physical two-device process-death,
  airplane-mode, recovery, and QR interoperability matrices remain release
  evidence gates.
- Direct multi-device user-intent fanout, encrypted edit/delete, calls, and MLS
  are separate product work. Their absence must not be represented as a
  cryptographic downgrade of the implemented text path.
- No tag or stable release is created by this hardening range.

## External reviewer starting points

- Transport: `veil-server/internal/auth`, `veil-server/internal/authmw`,
  `veil-client/src/api.rs`, and `test-vectors/transport-auth/`.
- Direct and key lifecycle: `veil-client/src/direct.rs`,
  `veil-client/src/api.rs`, `veil-store/src/db.rs`, and
  `veil-server/migrations/031_direct_v2_message_context.sql`.
- Transparency/witness/gossip: `veil-crypto/src/transparency.rs`,
  `veil-client/src/transparency.rs`, `veil-server/internal/transparency`, and
  migration `032`.
- Membership/Sender-Key: `veil-crypto/src/membership.rs`, client/store
  Sender-Key code, server membership/database code, and migrations `033`–`036`.
- Mobile boundary: `veil-ffi`, Android runtime/transport Kotlin, and the UniFFI
  symbol audit in `.github/workflows/security.yml`.

Reviewers should first reproduce the frozen vectors and migration suite, then
attack cross-origin relay, canonical parser differences, replay races, restored
database state, split views, membership concurrency, delayed ciphertext, and
partial/legacy downgrade inputs.
