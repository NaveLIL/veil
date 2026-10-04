ARTIFACT CONTRACT — see the dated execution evidence for any produced APK;
this document alone does not establish physical-device testing.

# Android tester artifact contract

Date: 2026-07-20

Manifest/component contract reviewed against the first assembled APK and its
manifest-merger provenance on 2026-10-04. The reviewed replacement must be
rebuilt from the new clean source checkpoint; the earlier APK requesting
`RECORD_AUDIO` is rejected and must not be distributed as verified.

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
`USE_BIOMETRIC`, `USE_FINGERPRINT`, `FOREGROUND_SERVICE`,
`FOREGROUND_SERVICE_DATA_SYNC`, `CAMERA`, `ACCESS_NETWORK_STATE`, and the package-scoped
`io.veil.mobile.tester.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`. The latter is
also the sole declared permission and must have `signature` protection. Any
additional, duplicate, renamed, or differently protected permission fails
artifact verification.

Because push is outside the Direct Preview gate, the tester manifest removes
the dependency-provided UnifiedPush `LinkActivity`, exported messaging receiver,
and exported foreground service. The app-owned `VeilPushService` remains in the
reviewed inventory only as a non-exported dormant boundary. The verifier rejects
unknown, duplicate, aliased, or unexpectedly exported app components.

The native `VeilEventsService` remains non-exported with only the `dataSync`
foreground-service type (compiled manifest value `0x1`). Its existing React
native entry point calls `ContextCompat.startForegroundService`; the service
calls `startForeground` with `FOREGROUND_SERVICE_TYPE_DATA_SYNC` on Android 14+
and the native runtime's `startBackgroundEvents`. The two foreground-service
permissions describe that existing native service. This packaging contract
does not establish background delivery or lifecycle reliability on a phone.

`CAMERA` is retained for the existing reachable Direct identity verification
sheet, which renders an account-v2 QR code and offers an optional camera scan.
The scan submits the QR value to the scoped native identity-verification API;
manual safety-number comparison remains available if camera access is denied.
The production GUI has no voice/video recording action or microphone permission
request. The tester overlay removes the transitive Expo Camera `RECORD_AUDIO`
permission; the independent verifier rejects its presence.

Expo Camera 16.1.11 already includes CameraX, ML Kit barcode scanning and Google
code-scanner dependencies. The exact eight private dependency components below
were present in the assembled APK; they are pinned individually rather than
allowing arbitrary SDK components. `ACCESS_NETWORK_STATE` originates from
Google DataTransport 2.3.3/2.2.6 in that dependency graph, not Veil sync or
WorkManager. The assembled manifest has no WorkManager component, and the
current Veil native source has no WorkManager scheduling path. Keeping these
existing QR dependencies does not establish their complete data-collection
behavior or physical scanner behavior; neither is inferred from host checks.

| Exact dependency component | Required security attributes in compiled manifest |
|---|---|
| `androidx.camera.core.impl.MetadataHolderService` | service; `enabled=false`, `exported=false` |
| `com.google.mlkit.vision.codescanner.internal.GmsBarcodeScanningDelegateActivity` | activity; `exported=false`, `screenOrientation=1` |
| `com.google.mlkit.common.internal.MlKitComponentDiscoveryService` | service; `exported=false`, `directBootAware=true` |
| `com.google.mlkit.common.internal.MlKitInitProvider` | provider; `exported=false`, package-scoped `io.veil.mobile.tester.mlkitinitprovider` authority, `initOrder=99` |
| `com.google.android.gms.common.api.GoogleApiActivity` | activity; `exported=false` |
| `com.google.android.datatransport.runtime.backends.TransportBackendDiscovery` | service; `exported=false` |
| `com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService` | service; `exported=false`, `permission=android.permission.BIND_JOB_SERVICE` |
| `com.google.android.datatransport.runtime.scheduling.jobscheduling.AlarmManagerSchedulerBroadcastReceiver` | receiver; `exported=false` |

Every other reviewed component-security attribute must remain absent unless
already explicitly required by its individual inventory entry. In particular,
the QR dependency components cannot acquire foreground-service types, broader
exported state, alternate process/permission/authority/grant policies, or
unreviewed enabled/direct-boot overrides. The complete inventory is exactly
15 components: the original six, native `VeilEventsService`, and these eight.

Evidence sources are the packaged manifest (`apkanalyzer manifest print` and
`aapt2 dump xmltree`), its `manifest-merger-internalTester-report.txt`,
`src/components/identity/IdentityIslandSheet.tsx`, the installed Expo Camera
`android/build.gradle` and `android/src/main/AndroidManifest.xml`, and native
`VeilMobileRuntimeModule.kt`/`VeilEventsService.kt`. No package upgrade, signing
change, blanket component allowlist, or artifact verification bypass is part
of this alignment.

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
checked into the repository. A stable tester certificate must be provisioned in
the build environment before an artifact can exist. On 2026-10-04 the user
authorized a permanent local tester key outside the repository; its independent
public certificate expectation is
`f5df868d3f517c0853225840e2c4f67f2d7b20d05b183bf1ab396e530fc3f250`.
This does not provision the protected GitHub environment or a production key.

The protected environment separately supplies
`VEIL_ANDROID_TESTER_CERT_SHA256` and the known
`VEIL_ANDROID_PRODUCTION_CERT_SHA256` as exactly 64 lowercase hexadecimal
characters. They must differ. The tester value is an independent verification
expectation, not a value derived from the APK under test; the production value
is a protected provisioning baseline. Repository/environment reviewers and
allowed-ref rules must be configured in GitHub before the manual workflow is
authorized for use.

### First tester bootstrap when no production certificate exists

On 2026-10-04 the user explicitly confirmed that no production certificate has
been provisioned. A local first tester artifact may therefore use the narrowly
scoped verifier mode `--production-certificate-state not-provisioned`. It is
not a release artifact or evidence that tester and production certificates
differ. The default verifier and protected CI workflow still require the known
production fingerprint exactly as above; no CI secret or guard is bypassed.

Bootstrap requires both `--expected-cert-sha256` from the independently
provisioned permanent tester key and `--forbidden-debug-cert-sha256` from the
actual debug signing certificate, exported independently with the installed
JDK's `keytool`. Do not derive either expectation from the APK under test.
The repository `android/app/debug.keystore` is absent in this checkout; find
the actual configured debug signer instead of inventing a debug fingerprint.
Do not use a debug fingerprint in `--forbidden-cert-sha256` and call it
production separation. Never substitute an arbitrary or all-zero production
fingerprint. If a production certificate is provisioned later, use strict mode.

The two modes are mutually exclusive: bootstrap rejects a production forbidden
fingerprint; strict mode rejects a debug-baseline argument without bootstrap.
Missing, malformed or tester-equal debug fingerprints fail closed. Bootstrap
uses the same verified single signer, v2-only/no-rotation policy, exact package,
version/source metadata, SDK, privacy/backup/transfer/recovery rules, permission
and component inventories, branding, bundled JS and exact native ABI checks.
It never falls back to accepting a debug build or another signer.

Successful bootstrap writes the distinct sanitized schema
`veil.android-first-tester-bootstrap-evidence.v1`, with
`verificationScope=first-tester-bootstrap`, `releaseReady=false`,
`productionCertificateState=not-provisioned`,
`productionSeparationVerified=false`, `expectedTesterCertificateMatched=true`
and `debugCertificateRejected=true`. Its deferred gates explicitly include
production separation, release readiness and physical-device testing. Strict
`veil.android-tester-apk-evidence.v1` is unchanged. A consumer must not treat
bootstrap evidence as successful strict evidence based on `verified` alone.
Neither record contains private credentials or tool/keystore paths.

Example, with public fingerprints and source/version values supplied from the
independent build record:

```powershell
pnpm verify:android-tester-apk -- --android-sdk $env:ANDROID_HOME --apk $apkPath --expected-cert-sha256 $testerCertificateSha256 --production-certificate-state not-provisioned --forbidden-debug-cert-sha256 $debugCertificateSha256 --expected-version-code $testerVersionCode --expected-version-name $testerVersionName --expected-source-commit $sourceCommit --evidence-out $evidencePath
```

The verifier still binds the exact packaged source-commit metadata. A local
dirty checkout cannot acquire clean-commit/CI provenance merely by passing its
HEAD as that metadata: retain the base commit and reviewed source/diff record
with the artifact, label the build accordingly, and keep the clean-source
release gate open. No physical test is inferred from a host-only APK check.

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

Resource-file lookup follows the exact manifest resource ID to the unique
reviewed `drawable/ic_veil_tester_launcher` or `xml/data_extraction_rules`
resource-table name, then to one default XML file actually present in the APK.
AAPT2 resource optimization may shorten `res/drawable/ic_veil_tester_launcher.xml`
and `res/xml/data_extraction_rules.xml` to flat bounded `res/*.xml` filenames.
The verifier resolves those mappings without disabling shrinking or hardcoding
a particular optimized filename. Reassigned IDs/names, alternate resource
types, multiple/configuration-specific mappings, unsafe paths, file aliases,
or missing archive members fail closed. The bound backup XML still undergoes
the same exact cloud/transfer exclusion checks. Resource-table identity and
distinct tester branding are packaging checks, not a rendered pixel comparison.

The JSON record contains the APK SHA-256 and only bounded artifact metadata. It
must not contain passwords, keystore paths, enrollment bearers, account IDs,
origins, messages, or device logs. Verification failure produces no successful
evidence claim.

## Deferred physical handoff

The initial 2026-07-20 checkpoint stopped before generating an APK. On 2026-10-04
the user resumed host-only artifact preparation and authorized the stable local
tester key above. Physical execution remains a separate recorded gate. Before
any authorized manual physical handoff, the exact APK
hash and certificate fingerprint must be recorded first. A new disposable
identity's recovery phrase must then be recorded and confirmed locally before
any Node Access Pass is issued or applied. The complete matrix remains in the
[Android Direct Preview physical test plan](android-direct-preview-physical-test-plan.md).
