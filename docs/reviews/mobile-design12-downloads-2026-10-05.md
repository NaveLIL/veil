# Mobile Design 12 distribution handoff

The owner authorized a separate GitHub test prerelease for installation on another phone. The release is [mobile-test-20261005-12](https://github.com/NaveLIL/veil/releases/tag/mobile-test-20261005-12); the source branch is [ce/mobile-design12-20261005](https://github.com/NaveLIL/veil/tree/ce/mobile-design12-20261005). Both APKs and the source ZIP were downloaded without authentication after publication; bytes and SHA-256 matched the immutable candidate. Release target, asset digests and public-download checks are recorded in the [publication receipt](mobile-design12-publication-2026-10-05.json). The release tag points to source commit `bf90280c8f21a3af119d4ef5bf41d137e1424953`; subsequent documentation commits do not replace its APKs.

| APK | Purpose | Download |
|---|---|---|
| Veil-Account-Tester-12.apk | Actual native/Rust account client and text Direct; existing enrollment/Access Pass/trust/security gates | [Account Tester 12](https://github.com/NaveLIL/veil/releases/download/mobile-test-20261005-12/Veil-Account-Tester-12.apk) |
| Veil-Design-12.apk | Standalone design fixtures, no account/Node; screenshots permitted | [Design 12](https://github.com/NaveLIL/veil/releases/download/mobile-test-20261005-12/Veil-Design-12.apk) |

Both use version code `2026100512` and maintained tester certificate SHA-256 `f5df868d3f517c0853225840e2c4f67f2d7b20d05b183bf1ab396e530fc3f250`. An existing installation signed with another key cannot be updated in place. Do not erase an established account/history as an update workaround. The connected S23's older account signing mismatch remains unresolved.

```text
d918718a57a6d79d0cf3aca9189dc3ab40a025351ad0d07d5c34b7026e1dc7af  Veil-Design-12.apk
ebc40a8c9ea3508b2c5e93fac026711ecba7a77a4e6bb00ab33a58e8cc84ee15  Veil-Account-Tester-12.apk
```

The release also carries `source-snapshot.zip`, `build-manifest.json` and `SHA256SUMS.txt`. The exact mobile snapshot is `76c9d20f095c76448fccaf08f4c6bdc8ae9d7a24bb1ab1208b7d16a46eb47063`. The mobile source overlay corresponds to the packaged builds; unchanged Rust/server sources are at [base commit 81da3e1](https://github.com/NaveLIL/veil/tree/81da3e12539cdc503119ca61088d14a8ecdb041f). The embedded base commit alone does not contain the migration. A later distribution commit includes the migration and reports, without rebuilding or replacing the immutable APKs.

The archived manifest's `published: false` describes the build candidate at archive time. Public distribution is established by the release readback receipt, not by rewriting immutable build evidence.

Verification: 371 Jest tests / 57 suites, 63 APK-verifier tests, two readiness CLI tests, TypeScript, ESLint, isolation/cycle checks, production JS export and both Android builds passed. See the [full verification report](mobile-design12-verification-2026-10-05.md) for warnings and precise evidence categories.

The owner verified bidirectional real text Direct on the preceding client. Post-migration Direct, physical account UI, TalkBack, font scale and release performance remain unverified. This is a test prerelease, not production readiness. Production signing and all protocol/crypto/trust/server behavior remain unchanged. No Passes, signing keys or credentials are distributed.
