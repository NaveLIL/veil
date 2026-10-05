# Mobile 11 test distribution

Following explicit user approval, these artifacts are prepared for GitHub test
distribution on branch `ce/mobile-account-11-20261005`, with prerelease tag
`mobile-test-20261005-11`. The default branch and production signing are unchanged.
APKs are release assets, rather than large binaries stored in Git history.

## Download targets

- [Design Preview 11](https://github.com/NaveLIL/veil/releases/download/mobile-test-20261005-11/Veil-Design-11.apk): isolated interface fixtures, no registration/Access Pass, screenshots enabled by the existing preview policy.
- [Account Tester 11](https://github.com/NaveLIL/veil/releases/download/mobile-test-20261005-11/Veil-Account-Tester-11.apk): real account shell and existing native text Direct adapter; enrollment, PIN, authentication, trust and capture gates retained.
- [Test release](https://github.com/NaveLIL/veil/releases/tag/mobile-test-20261005-11).
- [Frozen corresponding source companion](https://github.com/NaveLIL/veil/releases/download/mobile-test-20261005-11/source.zip).
- [SHA256SUMS](https://github.com/NaveLIL/veil/releases/download/mobile-test-20261005-11/SHA256SUMS.txt).

These URLs become downloadable once all assets pass checksum verification and
the draft is published as a prerelease. Publication verification is recorded
separately; this document does not establish device or authenticated E2E results.

| APK | Package | SHA-256 |
|---|---|---|
| Design Preview 11 | `io.veil.mobile.designpreview` | `45976d0ed6be6f23028fbf31c595829dda815b4007579ee38fb898e533c64a7c` |
| Account Tester 11 | `io.veil.mobile.tester` | `9763aeed4d4d24750231cd52d23d24138a93253ccb1136b3b6e629ce7175e19b` |

Both APKs are version code `2026100511`, carry bundled JS and use independent
tester certificate `f5df868d3f517c0853225840e2c4f67f2d7b20d05b183bf1ab396e530fc3f250`.
The embedded build base is `8bbdf3ff154d9b7182be6a1ce295550be9c93b53`; the exact
mobile source snapshot is
`03884ecdf168945815f66ff5b1793e27b5629f8c61a53b291e33fe19c9a6b6d5`.
The distribution commit adds documentation to that existing verified snapshot;
it does not imply that the APK was rebuilt against a different embedded base.
The frozen source companion retains the exact checkpoint files and provenance.

## What is verified

Host: 350 app tests, 63 verifier tests, TypeScript, ESLint, both Android
assemblies/APK verifiers, production bundle, isolation and dependency/cycle
checks passed. Existing build warnings are retained in the verification report.
The packaging `git diff --check` also reports an existing extra blank line at
the end of `DockItem.tsx`; the verified mobile snapshot was preserved unchanged.

Device: the preceding shared-presentation revision was exercised without Metro,
including TalkBack, font scaling, appearance cold-start persistence, gestures,
blur and stress checks. Final safe-area/viewport/waiting-state changes were made
after the phones were taken away and remain unverified on-device. Authenticated
Direct E2E is not claimed; usable official test inputs are still required.

Keep existing account data when installing. The first phone's older account
tester has a different signing identity and cannot accept this APK as an
in-place update; do not erase it to force installation. The second phone's
tester certificate matched and permits a normal data-preserving update.

See the [full verification report](mobile-account-11-verification-2026-10-05.md),
[complete-scope audit](mobile-account-11-completion-audit-2026-10-05.md),
[architecture](../design/mobile-account-client-2026-10-05.md) and
[real Direct test instructions](account-tester-readiness-2026-10-05.md).
