# Veil Mobile

The mobile client is a native security boundary, not an Expo Go application.
The checked-in Android project links the Rust `veil-ffi` library through generated
UniFFI Kotlin bindings. If the native module is absent, identity operations fail
closed; there is no JavaScript cryptographic fallback.

## Android development build

Prerequisites:

- Android SDK 35 and NDK `27.1.12297006`;
- Rust targets `aarch64-linux-android` and `x86_64-linux-android`;
- `cargo-ndk`;
- a complete Unix-compatible Perl and `make` (MSYS2 on Windows) for vendored
  OpenSSL/SQLCipher;
- an ASCII-only Cargo target directory on Windows.

The full Windows Android build must run from an actual ASCII-only checkout or
copy (for example `D:\veil-build\veil-mobile`). A directory junction is not
enough because pnpm/Node resolves native dependency sources back to their real
path and the NDK/Prefab toolchain cannot encode the Cyrillic workspace path.

From that ASCII checkout's `veil-mobile` directory:

```powershell
pnpm install
pnpm native:android
$env:NODE_ENV='development'
cd android
.\gradlew.bat assembleDebug
```

`pnpm native:android` regenerates the Kotlin bindings and builds both supported
Android ABIs. Generated `.so` files and signing secrets are intentionally ignored.
Gradle refuses to build if the Rust libraries are absent.

The Android Gradle connected-test lifecycle may uninstall the target package
after instrumentation and therefore destroy its Keystore, SQLCipher database,
and app-private files. Generic `connected*AndroidTest` tasks are consequently
blocked unless the current invocation supplies the explicit acknowledgement
printed by Gradle, `ANDROID_SERIAL` names exactly the sole connected device, and
that device is a fresh single-user emulator with no installed or retained
`io.veil.mobile` or `io.veil.mobile.tester` package. The guard repeats those
checks immediately before the connected task action and rejects a task-level
`--serial` override unless it is the same verified emulator. Physical devices
are forbidden, and a work profile
on an account-bearing handset is not a disposable boundary. This guard does not
cover manual `adb` or future managed-device providers. Every app-project Gradle
`install*` and `uninstall*` task is separately blocked before execution; use
`assemble*` for host-only work. Any later device mutation belongs to the
explicitly resumed manual physical plan. For an explicitly authorized phone
smoke, `adb install -r` is only a non-uninstalling update path:
upgraded code and migrations can still mutate state. Check `firstInstallTime`
and verify the same local account/vault afterwards; neither check is
instrumentation proof.

## Release signing

Release tasks never use the debug key. Provide all four values:

```powershell
$env:VEIL_ANDROID_KEYSTORE='D:\secure\veil-release.jks'
$env:VEIL_ANDROID_KEYSTORE_PASSWORD='...'
$env:VEIL_ANDROID_KEY_ALIAS='veil'
$env:VEIL_ANDROID_KEY_PASSWORD='...'
```

Keep the keystore and passwords outside the repository. A release task fails if
any value is missing.

## Isolated tester artifact

The release-like `internalTester` build type is reserved for the closed Direct
Preview and emits the `tester` channel. It uses application ID
`io.veil.mobile.tester`, the `veil-tester` enrollment scheme, the user-visible
name `Veil Tester`, bundled JavaScript, release capture policy, and a signing
identity that is independent of both production release and debug signing. It
can coexist with `io.veil.mobile`; its package-scoped Keystore, SQLCipher
database, and app-private files are separate.

Tester packaging requires all four `VEIL_ANDROID_TESTER_*` keystore values,
`VEIL_ANDROID_TESTER_VERSION_CODE`, `VEIL_ANDROID_TESTER_VERSION_NAME`, and an
exact lowercase 40-hex `VEIL_SOURCE_COMMIT`. Missing, partial, or malformed
inputs fail closed; tester never inherits the release signer or debug key. The
manual protected workflow verifies the completed APK with:

```text
pnpm verify:android-tester-apk -- --apk <apk> \
  --expected-cert-sha256 <64-lowercase-hex> \
  --forbidden-cert-sha256 <production-64-lowercase-hex> \
  --expected-version-code <positive-decimal> \
  --expected-version-name <exact-name> \
  --expected-source-commit <40-lowercase-hex> \
  --evidence-out <json> --android-sdk <sdk-root>
```

The verifier requires an exact v2-only signature by exactly one expected
certificate distinct from the protected production fingerprint. With
v1/v3/v3.1/v4 disabled, no production-certificate signing history is accepted.
It also requires the isolated package and exact SDK/activity/permission
manifest policy, the reviewed component inventory with deferred exported
UnifiedPush connector components absent, complete packaged
cloud-backup/device-transfer exclusions (including device-protected domains),
exact tester launcher/recovery branding, a production JS bundle, and exactly
the two reviewed Rust ABIs. The checked-in
code is only the packaging/verifier contract: no stable
tester key has been provided, no signed tester APK has been produced, and no
physical-device result is claimed. See the
[artifact contract](../docs/reviews/android-tester-artifact-contract.md) and the
[deferred physical plan](../docs/reviews/android-direct-preview-physical-test-plan.md).

## Current security boundary

- The recovery phrase is encrypted with an AES-256-GCM key held by Android
  Keystore; application backup is disabled.
- Secret onboarding screens use `FLAG_SECURE`, clipboard export is unavailable,
  and several recovery words must be confirmed before identity creation.
- JavaScript receives the public identity key only. It does not receive the seed,
  private signing key, ratchet state, database key, or a raw signing/AEAD oracle.
- Node Access Pass registration, the authenticated WebSocket generation,
  per-device prekey publication, the origin-bound Direct directory, and
  immutable legacy Direct-text history are owned by Rust/Kotlin. Idempotent text
  send/outbox mutation and its delivery state also stay behind that boundary.
  JavaScript sees only bounded public projections and coarse sync progress.
- History uses one native-owned HTTP capability at a time, a deterministic UUID
  order, a 4 MiB response ceiling, and a single in-memory conversation state.
  Unsupported or incomplete history blocks only that Direct conversation;
  uncertain SQLCipher state aborts the complete authenticated generation.
- Authenticated live events retain the same shared 4096-event/32 MiB permits as
  they move from the socket queue to the deferred FIFO. The Android boundary
  pumps at every HTTP/lifecycle boundary, including immediately before durable
  install. A terminal epoch observed at that boundary aborts before install; a
  concurrent terminal event linearizes before or after the boundary, and any
  committed prefix remains duplicate-safe when reconnect restarts history.
- After the gap-free history handoff reaches `Ready`, Android continuously asks
  Rust for bounded 64-event replay turns. Full batches continue immediately;
  an idle authenticated generation polls every 250 ms. Only a native aggregate
  content revision can refresh the conversation the user explicitly selected;
  ordinary snapshot reads never trigger another plaintext projection.
- Only typed native `Transport` and `AckDeadline` failures may create one
  account/origin/session-scoped reconnect plan. It uses full-jitter exponential
  backoff capped at 60 seconds, never retains or replays a Node Access Pass, is
  cancelled by background/lock/manual lifecycle actions, and resets only after
  a new `Ready` plus durable outbox barrier. Protocol, authentication, storage,
  and accepted-session-invalid failures remain terminal.
- A successful mobile authentication atomically selects one credential-free
  reconnect target in SQLCipher: only the canonical server origin and exact
  authenticated user ID. On a fresh process the native loader revalidates that
  target against the immutable self binding and current mnemonic-derived keys;
  Android then starts one zero-delay plain reconnect through the same guarded
  runtime. Access Pass bytes, WebSocket URLs, and key material are never stored
  or replayed, and an older database without an explicit selection is never
  guessed from timestamps or existing bindings.
- Manual disconnect is intentionally process-local and non-destructive: it
  closes the current transport but preserves the verified target, so a later
  background reopen or process restart may recover it. A future explicit
  “Forget Node / remain offline” action requires a separate destructive
  contract; no hidden clear API exists in this preview.
- A host-only D03 precursor now drops the complete native session after a
  deterministic server ledger accepts a Direct send but before its ACK reaches
  the client. Reopening the same file-backed SQLCipher store replays the exact
  client ID, header, ciphertext, and encoded payload without a second ratchet
  advance; the production protobuf decoder/deferred FIFO then converges the
  outbox and local projection to one `Sent` message. This proves the native
  persistence/reconciliation path against a bounded test oracle, not Android OS
  process death, a physical device, or a real Veil Node.
- Foreground authority is process-wide and restricted to exact `MainActivity`
  and `RecoveryActivity` surfaces. Internal handoff/configuration recreation
  cannot impersonate app background, dependency Activities cannot keep the
  session open, and an enrollment Intent crosses the native foreground barrier
  before its Pass is staged. Background Pass/session revocation is linearized
  under the runtime lifecycle lock.
- Android WSS uses an explicit per-connection `ring` provider with TLS 1.2/1.3
  and public WebPKI roots. The managed legacy REST-v1 ingress accepts only the
  exact bare/canonical-`:443` authority forms; this compatibility bridge does
  not replace the Phase 5S WS v3/REST v2 origin-binding gate.
- The write-once identity vault publishes through fsync/readback plus atomic
  directory rename. Native recovery holds a coordinator barrier over strict
  presence checks: READY/COMMITTING is always ambiguous, never false, so an
  unsettled commit cannot cause the only recovery phrase to be destroyed.
- UnifiedPush still accepts only decrypted 2048-byte generic wake records.

This remains a closed Direct Preview, not a tester release or production-ready
mobile messenger. Authenticated Direct directory/history, bounded live receive,
native projection, per-conversation prekey establishment, guarded send/outbox,
typed transient reconnect, and canonical-origin process-death recovery are
present, and the ambiguous-ACK D03 path has the host-only precursor described
above. Same-account force-stop recovery without a new Pass or device has been
physically confirmed on a Samsung S23. `PublicFailureCodeV1` is implemented for
identity setup and the secure runtime gate. A reviewed terminal subset is now
retained by the native process across snapshot reads and React recreation, but
it is deliberately not persisted across OS process death and has not yet passed
the deferred physical matrix. Direct session/send/delivery and desktop/Go
consumer parity remain open. Cross-client E2EE text/airplane/background evidence,
connected recovery/vault/capture instrumentation, push publication,
Circle/Space/attachments, correct multi-device, signed standalone APK
distribution, durable setup-result reconciliation after React-context/process
death, and the broader physical-device matrix remain gated.
