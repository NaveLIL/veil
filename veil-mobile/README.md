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
- UnifiedPush accepts only decrypted 2048-byte generic wake records. Endpoint
  publication and sync remain dormant until the account/origin-bound native
  authenticated runtime is implemented.

This is a Phase 5A foundation, not a production-ready mobile messenger. SQLCipher,
native session/network orchestration, lock/PIN/biometric policy and physical device
tests are still required.
