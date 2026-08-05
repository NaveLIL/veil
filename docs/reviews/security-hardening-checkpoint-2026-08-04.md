# Security hardening checkpoint — 2026-08-04

- Branch: `ds/beta-all-2026-07-21`
- Status: implementation hardened; current-head CI, physical release evidence,
  independent witness deployment, and external review remain in progress
- Purpose: make the current security work available to every contributor before the final gate

## What is implemented at this checkpoint

- Live authentication is origin/account/device-bound through WS v3 and REST v2. Legacy transport activation is explicit and cannot silently satisfy the new contract.
- Direct v2 binds the canonical origin, both accounts, exact device bindings, X3DH coordinates, and a durable session commitment. Live and history parsing reject profile/context substitution and sticky downgrade.
- Account and device first-contact data is covered by an append-only Merkle transparency log. PostgreSQL append, product mutation, proof generation, and startup audit share one fail-closed lineage.
- SQLCipher verifies and pins Node signatures, inclusion proofs, and consistency proofs, retaining immutable local evidence for replacement, rollback, split-view, and non-append-only advances.
- Desktop persists the highest accepted transparency head outside SQLCipher through the OS credential store and recovers a restored database only through a valid consistency proof.
- External witness support verifies a configured quorum of independently signed checkpoints. Witness calls are bounded, concurrent, redirect-free, locally reverified, and can retry with an exact historical consistency proof held by the witness.
- Desktop witness policy is operator-configured; Android witness trust is compiled into the native library. Absence preserves legacy/self-hosted usability, while a configured or previously pinned policy cannot silently disappear.
- Optional client gossip exports only a Node-signed public checkpoint. It distinguishes ordinary device lag from conclusive same-size split-view evidence and never mutates trust from unverified peer input.
- Membership epochs form a strict predecessor-linked, owner-authorized chain over the exact account/device roster. Sender-Key v6 messages, SKDMs, and ACKs carry the exact epoch/hash and device route.
- Existing Sender-Key v5 and Direct v1 history remains readable. New secure-era live traffic cannot fall back after activation.
- Existing device identities upgrade their capability declaration through an account-authorized version without replacing private identity keys. Sender-key material prepared under the older roster/profile is rotated before v6 activation.
- The mobile UniFFI surface remains high-level; raw ratchet, arbitrary signing/KDF, private-key, and recovery primitives are excluded from the production surface. Temporary secret buffers are zeroized at ownership boundaries.

## User-experience contract

- Ordinary messaging, reconnect, offline history, and old encrypted history do not require a new manual step.
- QR/fingerprint comparison remains optional and is the explicit human-verification path; server data alone is not shown as human-verified.
- A transparency-disabled legacy Node remains usable for a never-pinned client, but receives no verified/witnessed claim.
- Fail-closed blocking is reserved for a configured/pinned-policy downgrade, authenticated key substitution, rollback, non-append-only advance, or confirmed split view.
- Roster changes rotate group keys automatically. Owners automatically authorize valid membership transitions; non-owners wait for the authorized epoch instead of sending under stale membership.

## Evidence already rerun

- Focused Rust tests cover Direct v2 binding/downgrade, membership activation and restart, Sender-Key v6 live/history interoperability, SQLCipher/OS-anchor recovery, witness quorum stickiness, and gossip split-view detection.
- Rust and Go verify the same frozen transparency fixture, including witness checkpoint messages, signatures, and policy hash.
- Focused Go packages cover transparency, witness consistency retry, authentication, database admission, membership, chat, gateway, and configuration boundaries.
- `veil-store` and `veil-client` compile with their test targets; `veil-ffi` and the desktop check are being rerun for this checkpoint.
- The local MinGW toolchain cannot link the oversized Tauri test `cdylib` (`export ordinal too large`). This is a toolchain/export-table limitation; desktop is instead gated by `cargo check`, frontend production build, TypeScript, and Vitest. It is not counted as a passing linked desktop test.

## Remaining release gates

1. Record a green current-head Rust, Go, desktop, mobile, Gradle, audit,
   protocol, coverage, and Beta Artifacts matrix in the audit handoff.
2. Independently deploy and exercise the persistent witness service described
   by the protocol; the repository contains the strict client but no witness
   daemon.
3. Produce signed candidates and complete the physical-device/process-death,
   recovery, airplane-mode, cross-client, and QR interoperability matrices.
4. Obtain an independent cryptographic review before making a stable-security
   claim. This repository can prepare evidence but cannot self-certify
   independence.

Database-backed upgrades through migration `035`, production REST v2-only
integration, hostile two-Node relay/downgrade, and four parser/state-machine
fuzz targets have been added since the initial checkpoint. The complete handoff
is [security-hardening-audit-handoff-2026-08-05.md](security-hardening-audit-handoff-2026-08-05.md).

No tag or stable release claim is attached to this checkpoint.
