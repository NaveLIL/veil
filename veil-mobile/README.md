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
- UnifiedPush still accepts only decrypted 2048-byte generic wake records.

This remains a closed Direct Preview, not a tester release or production-ready
mobile messenger. Authenticated Direct directory/history, bounded live receive,
native projection, per-conversation prekey establishment, guarded send/outbox,
typed transient reconnect, and automated canonical-origin process-death
recovery are present. Physical process-death/airplane evidence, push
publication, Circle/Space/attachments, correct multi-device, signed standalone
APK distribution, and the broader physical-device matrix remain gated.
