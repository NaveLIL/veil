EVIDENCE CHECKPOINT ONLY — Phase 5S and the `libsignal` decision remain open.

# Phase 5S isolated `libsignal` spike — source/build checkpoint

Date: 2026-07-21

## Purpose and isolation

This is the first, deliberately narrow checkpoint of the Phase 5S.2 spike. It
answers whether the current official source can be fetched at a reproducible
revision and whether its protocol crate builds and runs its own unit suite on
the Windows host. It does **not** import `libsignal` into Veil, modify a Veil
wire/state format, build an Android artifact, touch a phone, Node, Node Access
Pass, recovery material, or release/signing workflow.

The upstream checkout is deliberately outside the Veil worktree:

```text
C:\veil-phase5s-libsignal-spike
```

There are no `Cargo.toml`, lockfile, Gradle, UniFFI, Kotlin, or JavaScript
changes which make Veil depend on it. The checked-out upstream tree is clean.

## Reproducible input and host result

| Item | Recorded value |
| --- | --- |
| Upstream | [`signalapp/libsignal`](https://github.com/signalapp/libsignal) |
| Selected annotated tag | `v0.94.1` |
| Resolved source commit | `7c8cb0c5fce1d01805199de992bf4323f4765f1f` |
| Upstream workspace minimum Rust | `1.88` |
| Local Rust used | `rustc`/`cargo 1.96.0` |
| Tested package | `libsignal-protocol 0.1.0`, edition 2024, MSRV 1.85 |
| Host command | `cargo test -p libsignal-protocol --lib --quiet` |
| Result | 63 passed, 0 failed, 0 ignored; 76.92 s |

The command was run only in the isolated checkout on Windows. One upstream
property test emitted its own over-60-second progress notice and then passed.
The result is evidence that this particular host build is viable; it is not a
benchmark, reproducibility proof, fuzz campaign, API guarantee, or security
audit.

## What the source review establishes

1. The upstream repository states that use outside Signal is unsupported and
   that its APIs, implementations, JNI, C, and Node bridges can change without
   notice. A pinned source revision therefore does not create a stable Veil
   dependency contract.
2. Its root license declaration and source headers are `AGPL-3.0-only`.
   Any future product dependency requires the normal legal, distribution,
   notice/source-offer, update, and supply-chain review; a successful local
   compile is not that approval.
3. The repository contains an Android JNI/Gradle path and documents four ABIs
   (`armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`). No Android SDK/NDK build,
   instrumentation test, APK packaging, device test, binary size measurement,
   or crash-recovery test was run in this checkpoint.
4. The current upstream protocol surface includes modern KEM/PQ material and
   its own session/store abstractions. It is not byte- or state-compatible by
   assertion with Veil Direct v1, whose frozen transcript fixes a distinct
   X3DH profile, `veil-x3dh-v1` derivation label, packet/AAD grammar, SQLCipher
   state, outbox, and Rust/UniFFI boundary.

The authoritative upstream statements above are in its
[README](https://github.com/signalapp/libsignal/blob/v0.94.1/README.md) and
[source manifest](https://github.com/signalapp/libsignal/blob/v0.94.1/Cargo.toml).
The protocol comparison is a Veil engineering inference based on the pinned
source and the current [Direct-v1 transcript checkpoint](phase-5s-direct-v1-transcript-checkpoint.md),
not a claim about Signal interoperability.

## Decision impact

The only justified conclusion is: a host-only, pinned-source exploration can
continue. It does not justify a dependency addition, a replacement of Veil
Direct v1, changing existing sessions, claiming Signal compatibility, or
switching an Android Preview feature on.

`libsignal` also cannot close Veil's independent exact-origin transport,
hostile-Node credential scoping, first-contact/key-transparency, membership
authorization, or multi-device lifecycle gates. Those boundaries remain
fail-closed requirements regardless of the final protocol decision.

## Required next evidence before any integration decision

1. Create a separate, non-production adapter experiment with a versioned
   test-only input/output contract; keep it out of the existing Direct v1
   encrypt/decrypt path and outbox.
2. Compare only synthetic fixtures: identity/prekey semantics, malformed and
   replayed inputs, session persistence/crash recovery, error taxonomy, and
   concurrency. Never copy a real account, recovery phrase, Pass, or session
   database into the spike.
3. Build the upstream Android path and an equivalent Windows/Linux path from
   pinned toolchains; record ABI outputs, size, latency, FFI ownership/zeroize
   behavior, and tests. A device is still unnecessary until the separate
   signed-APK/recovery gate authorizes it.
4. Produce a complete migration-impact inventory for Node prekeys/envelopes,
   identity and device addressing, SQLCipher records, desktop/mobile bridges,
   Sender Keys, Direct transcript fixtures, rollback, and no-downgrade rules.
5. Only then write an ADR selecting either retained/audited Veil Direct v1 or
   an explicitly capability-negotiated `direct_v2_libsignal`; neither option
   is selected by this checkpoint.

## Non-claims

No external cryptographic audit has occurred. This checkpoint does not show
that `libsignal` is safe for Veil, that Veil Direct v1 is safe, that the two
protocols interoperate, or that an Android tester APK is ready. It authorizes
no production rollout and no destructive or connected test action.
