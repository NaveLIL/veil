# Mobile Veil 12.1 — profile/settings motion correction

Scope: remove the unwanted last-conversation button and correct profile/settings modal entry and live blur. The owner reports that horizontal chat/deck navigation is already smooth; its gesture and spring implementation are unchanged. This is a Design 12 maintenance release, not Design 13 Spaces.

## Changes and ownership

- `FloatingProfile` no longer exposes a last-conversation button or resume-command props. Both account and preview use the same component. The retained conversation/draft still resumes through the existing deck gesture; its integration regression test exercises that command boundary.
- `useSheetMotion` initializes a moving sheet below the viewport before Android's first modal frame. `onShow` starts entry once rather than repositioning an already visible sheet. Initially hidden sheets do not run phantom exits. Ordinary dismissal, reverse/reopen and stale-callback rejection keep their existing lifetime contract.
- Modal ownership distinguishes a window that is still mounted during exit from one that still requests background blur. Blur clears during the panel's exit rather than abruptly after its disappearance. Nested ownership retains the lower window's blur until the upper window begins leaving; changing an existing owner does not reorder it above another window.
- The shared Android `VeilBlurView` animates real subtree `RenderEffect` radius through `ValueAnimator` on Android's frame clock. JS sends the target and duration, not per-frame modal blur updates. A reversed target starts from the current radius; a normal RN property transaction restores the current effect without restarting the transition. Detach/drop cancels listeners/animators. There is no screenshot capture, bitmap overlay, network request or synthetic dark scrim.
- Zero-duration and system-disabled animations settle immediately. Presentation Reduce Motion applies to both root and nested modal blur, including exit/interruption. Direct chat gesture blur still uses immediate per-frame radius, without a second interpolator.

The native animation mechanism follows the Android [ValueAnimator contract](https://developer.android.com/reference/android/animation/ValueAnimator): update listeners receive each animation frame, and cancellation stops rather than completing the old target. Native blur remains supported on API 31+; older Android and iOS keep the previously documented clear underlay fallback.

## Evidence boundaries

The first-frame reposition and 0-to-full-strength blur switch were found by source inspection. They explain possible discontinuities but are not a measured GPU performance diagnosis. No before/after frame-time improvement is claimed.

At this checkpoint, the authorized Tailscale ADB endpoint `100.116.192.6:34183` is unavailable (`device not found`, reconnect timeout). No lock bypass or account uninstall was attempted. Fresh physical visual, TalkBack, font-scale, profiling and desktop↔phone Direct checks remain pending. The earlier user-verified Direct exchange remains historical evidence, not validation of these new APKs.

Security/native account gates, transport, protocol, crypto, trust model, status semantics and production signing are outside this patch and unchanged. The existing mismatch between the connected phone's old account signer and the maintained tester signer still prevents an in-place account update on that installation.

## Host verification

- 377 Jest tests, 57 suites: pass (the previous 371-test baseline is retained; six meaningful regressions added).
- TypeScript and ESLint: pass, no warnings/errors.
- Presentation/dependency cycle guard, preview isolation and production FFI surface guard: pass.
- Tester APK verifier: 63 tests pass; readiness CLI: 2 tests pass.
- Design release and account internal tester: build pass, including compilation of the shared Android blur implementation. Both contain the embedded Hermes bundle. Rust native libraries are reused, not rebuilt.
- Strict APK checks: signatures, application identities, source metadata, offline/no-account design boundary and tester security boundaries pass.
- Production JS boundary verifier: pass across 3,241 sources, including shipped legal notices. This is independent of APK signature verification.

Build warnings remain visible in the retained build/verifier logs: the Gradle 9 deprecation notice, the existing NO_COLOR/FORCE_COLOR warning and keytool's recommendation concerning the separate debug JKS. No signer migration or dependency upgrade was performed.

Both candidates use version code `2026100513`; their names are `0.1.0-design.20261005.12.1` and `0.1.0-tester.20261005.12.1`. The embedded build base is `855c1d18b3942a3be82c7c0845b6860498eae043`, with exact source snapshot `227b1a57e11e6846b4b074e6d3b2a7f15fd93606888aeea715a81ffcbb254cc2`. The immutable source archive, rather than the later publication commit's metadata, identifies the exact inputs of these builds.

The source release commit is `cfa7495` on `ce/mobile-design12-20261005`. All 346 mobile source files were compared with the frozen build archive: 146 differ only in Git/Windows line-ending normalization, with no other differences. The frozen candidate is `target/mobile-design12-1-20261005/227b1a57e11e6846`.

| Artifact | SHA-256 |
| --- | --- |
| Veil-Design-12.1.apk | `b89369b246684a973550aa84c27fb2344f2d5e19bccfa5e62a78c0f40385a2e0` |
| Veil-Account-Tester-12.1.apk | `01116714f0d25ab12ae3e8a9a7345a29356867e4cc43c15f42983409a553a146` |
| source-snapshot.zip | `9b684b5cd5e2ac5b9b045802408ffc09c3bc3645f656a11770d4171a21b450a6` |

These are tester artifacts. `releaseReady:false` remains the account verifier's production-readiness result: the production certificate has not been provisioned and fresh device/runtime checks remain deferred. It does not negate the successful local tester APK verification.

## Published tester downloads

[Release 12.1](https://github.com/NaveLIL/veil/releases/tag/mobile-test-20261005-12-1) targets source commit `cfa7495b811e57612cf4f7449d6745e586bda6c1`. It is a prerelease, with independent tester signing; the previously published Design 12 release is untouched.

- [Offline design preview](https://github.com/NaveLIL/veil/releases/download/mobile-test-20261005-12-1/Veil-Design-12.1.apk)
- [Real account tester](https://github.com/NaveLIL/veil/releases/download/mobile-test-20261005-12-1/Veil-Account-Tester-12.1.apk)
- [Exact mobile source archive](https://github.com/NaveLIL/veil/releases/download/mobile-test-20261005-12-1/source-snapshot.zip)

All three public downloads were fetched without authentication and compared by size and SHA-256 with the frozen local artifacts. GitHub's asset digests, release target and prerelease flags were independently read back. The public metadata receipt is `docs/reviews/mobile-design12-1-publication-2026-10-05.json`.

The immutable `build-manifest.json` retains `published:false` from candidate creation. It is historical build metadata, not a claim that the now-published GitHub release is private or unavailable.

## Physical follow-up

Open profile → settings → appearance → Back, close/reopen quickly, then interrupt a downward drag and reverse it. Check normal motion and Reduce Motion independently. Confirm no entry flash, no abrupt background switch, no stale backdrop and unchanged horizontal chat gestures/draft retention. Fresh TalkBack/focus and account Direct checks are still pending; do not treat the automated lifetime tests as a device frame-time benchmark.
