CONTRACT CHECKPOINT ONLY — no signed tester APK has been produced or tested.

# Android tester artifact contract

Date: 2026-07-20

Scope: isolated, release-like packaging and verification for the closed Android
Direct Preview.

This contract makes a future tester artifact distinguishable, provenance-bound,
and fail-closed. It does not establish bit-for-bit reproducibility,
physical-device behavior, Direct
interoperability, production readiness, or completion of Phase 5S.

## Isolated identity

The `internalTester` Android build type inherits release optimization and
protection semantics, but publishes the separate `tester` distribution channel
and identity:

| Property | Required tester value |
|---|---|
| Application ID | `io.veil.mobile.tester` |
| User-visible name | `Veil Tester` |
| Custom enrollment scheme | `veil-tester` |
| HTTPS manifest host | non-production `tester.invalid` |
| Build channel metadata | `tester` |
| Debuggable | `false` |
| SDK boundary | min SDK 24; target SDK 35 |
| Ready-screen capture | `false` |
| Cleartext traffic | disabled |
| Backup and device transfer | legacy flags disabled; all reviewed data domains excluded by packaged rules |
| Recovery activity | non-exported, excluded from Recents, state not restored by Android |
| Permissions | exact reviewed allowlist; package-scoped receiver permission is `signature` protected |
| Push surface | UnifiedPush connector activity/receiver/foreground service removed; app push service remains non-exported and dormant |
| Native ABI payload | exactly `arm64-v8a` and `x86_64` `libveil_ffi.so` |

The tester package can coexist with `io.veil.mobile`; its Android Keystore,
SQLCipher files, app-private storage, and URI handler do not overwrite the
existing package. The tester build has a distinct label and launcher/recovery
branding so evidence cannot silently confuse it with the regular client.

The requested-permission allowlist is exactly `INTERNET`,
`POST_NOTIFICATIONS`, `VIBRATE`, `HIDE_OVERLAY_WINDOWS`, `WAKE_LOCK`,
`USE_BIOMETRIC`, `USE_FINGERPRINT`, and the package-scoped
`io.veil.mobile.tester.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`. The latter is
also the sole declared permission and must have `signature` protection. Any
additional, duplicate, renamed, or differently protected permission fails
artifact verification.

Because push is outside the Direct Preview gate, the tester manifest removes
the dependency-provided UnifiedPush `LinkActivity`, exported messaging receiver,
and exported foreground service. The app-owned `VeilPushService` remains in the
reviewed inventory only as a non-exported dormant boundary. The verifier rejects
unknown, duplicate, aliased, or unexpectedly exported app components.

## Required packaging inputs

The tester packaging graph accepts only a complete, tester-specific input set:

| Environment variable | Meaning |
|---|---|
| `VEIL_ANDROID_TESTER_KEYSTORE` | decoded keystore path outside the repository |
| `VEIL_ANDROID_TESTER_KEYSTORE_PASSWORD` | tester keystore password |
| `VEIL_ANDROID_TESTER_KEY_ALIAS` | tester certificate alias |
| `VEIL_ANDROID_TESTER_KEY_PASSWORD` | tester private-key password |
| `VEIL_ANDROID_TESTER_VERSION_CODE` | positive Android version code |
| `VEIL_ANDROID_TESTER_VERSION_NAME` | bounded `x.y.z-tester[.suffix]` version name |
| `VEIL_SOURCE_COMMIT` | exact lowercase 40-hex source commit |

Missing, partial, malformed, or mixed production/tester credentials abort
packaging. The tester variant must never inherit the production release signer
and must never fall back to the debug key. Its signing configuration explicitly
enables only APK Signature Scheme v2; the independent verifier checks the exact
scheme matrix again on the finished artifact. No keystore or password is
checked into the repository. A stable tester certificate still has to be provisioned in
the protected build environment before an artifact can exist.

The protected environment separately supplies
`VEIL_ANDROID_TESTER_CERT_SHA256` and the known
`VEIL_ANDROID_PRODUCTION_CERT_SHA256` as exactly 64 lowercase hexadecimal
characters. They must differ. The tester value is an independent verification
expectation, not a value derived from the APK under test; the production value
is a protected provisioning baseline. Repository/environment reviewers and
allowed-ref rules must be configured in GitHub before the manual workflow is
authorized for use.

## Protected build path

The manual `Android Tester APK` workflow is the only documented CI path for this
artifact. It uses the protected `android-tester` environment with read-only
repository permissions, decodes the keystore into runner-temporary storage,
uses an Ubuntu 24.04 runner, pins action revisions and the declared Java, Node,
pnpm, Gradle distribution, protoc, Rust, cargo-ndk, Android build-tools, and NDK
versions, and performs only host-side build/test work. Ubuntu image packages
installed by `apt` remain image-managed, so this is not a bit-reproducible build
claim. The workflow never invokes ADB,
`connected*AndroidTest`, an install task, or a device.

Production-release and tester JVM policy tests, plus tester lint, run before
the protected keystore is decoded and without signing passwords in their
environment. The inline configuration
preflight and final assemble step are the only steps that receive the four
tester signing values; cleanup runs immediately after assembly.

Before upload, the workflow must:

1. build both supported Rust Android libraries and regenerate UniFFI bindings;
2. reject a dirty generated-binding diff;
3. verify the production JavaScript bundle boundary;
4. pass production-release and tester JVM policy tests plus tester Android lint;
5. assemble the non-debuggable tester variant with bundled JavaScript;
6. run the independent APK verifier against the expected certificate, version,
   source commit, manifest policy, bundle, and native payload;
7. upload only the APK and sanitized JSON verification evidence.

## Independent APK verification

`pnpm verify:android-tester-apk` treats the APK as untrusted input. It invokes
the pinned Android `apksigner`, `apkanalyzer`, and `aapt2` binaries without a shell and
requires all of the following before evidence is written:

- an exact v2-only APK signature matrix (`v1=false`, `v2=true`, `v3=false`,
  `v3.1=false`, `v4=false`) with exactly one signer and the expected lowercase
  SHA-256 certificate fingerprint, distinct from the protected production
  certificate fingerprint; v3/v3.1 proof-of-rotation is intentionally rejected
  so a production certificate cannot hide in tester signing history;
- exact package, version code, and version name;
- `debuggable=false`, exact min/target SDK 24/35, cleartext traffic disabled,
  legacy backup flags disabled, no custom network-security configuration, Expo
  updates disabled, no custom backup agent/restore override, and the expected
  manifest metadata for tester channel, source commit, capture policy, and
  enrollment scheme;
- a uniquely bound packaged `xml/data_extraction_rules` whose exact compiled
  policy excludes `root`, `file`, `database`, `sharedpref`, `external`,
  `device_root`, `device_file`, `device_database`, and `device_sharedpref` from
  both cloud backup and device transfer;
- the exact reviewed permission allowlist, the package-scoped dynamic-receiver
  permission with `signature` protection, and non-exported/Recents-excluded
  recovery activity semantics;
- the exact reviewed activity/service/receiver/provider inventory, including
  the absence of deferred UnifiedPush connector components and the sole
  non-app exported profile receiver protected by `android.permission.DUMP`;
- a bundled React Native JavaScript asset rather than a Metro dependency;
- exact `Veil Tester` launcher/recovery strings and the distinct
  `drawable/ic_veil_tester_launcher` icon binding;
- exactly the reviewed `arm64-v8a` and `x86_64` `libveil_ffi.so` entries.

The JSON record contains the APK SHA-256 and only bounded artifact metadata. It
must not contain passwords, keystore paths, enrollment bearers, account IDs,
origins, messages, or device logs. Verification failure produces no successful
evidence claim.

## Deferred physical handoff

This checkpoint intentionally stops before generating, installing, or testing
an APK because stable tester signing material has not been supplied and the
physical gate is deferred. When that gate is explicitly resumed, the exact APK
hash and certificate fingerprint must be recorded first. A new disposable
identity's recovery phrase must then be recorded and confirmed locally before
any Node Access Pass is issued or applied. The complete matrix remains in the
[Android Direct Preview physical test plan](android-direct-preview-physical-test-plan.md).
