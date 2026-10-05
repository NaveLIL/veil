# Account tester: reproducible Direct check

Update for Design 12: the owner has confirmed real desktop/mobile text Direct on the preceding account client. The read-only `account-tester-readiness.mjs` check now reports E2E as NOT RUN by that script; it cannot infer credential availability or negate a prior exchange. The [Design 12 verification report](mobile-design12-verification-2026-10-05.md) records current APKs and installation blockers. The Account 11 artifact/check details below remain historical evidence.

The account package is `io.veil.mobile.tester`, not `io.veil.mobile.designpreview`. It retains the actual enrollment, identity, authentication, trust and capture gates. Use only test identities and synthetic messages.

## Build and readiness

Run `node veil-mobile/scripts/account-tester-readiness.mjs`. It checks public source/build surfaces only and never searches for credentials. Optional `--device` uses `VEIL_ADB_PATH` and `VEIL_ADB_PORT` if configured.

Build prerequisites: the project's existing Node dependencies, JDK 17, Android SDK 35/NDK 27.1, existing native libraries for both supported ABIs, and the independent tester signing key. Set the four `VEIL_ANDROID_TESTER_*` signing environment variables privately, plus explicit `VEIL_ANDROID_TESTER_VERSION_CODE`/`VEIL_ANDROID_TESTER_VERSION_NAME`. Do not put passwords or Passes into command logs, the repository or this report.

Run `node veil-mobile/scripts/build-local-account-tester.mjs`. It only assembles `:app:assembleInternalTester`, checks that the source snapshot stayed fixed and emits a companion source hash manifest. It does not install, erase data, publish or change production signing. The embedded base commit represents the existing commit; the separate SHA-256 snapshot represents local changes. Preserve both with the APK/source archive. This Windows host additionally uses the documented local native-tools environment and Java-agent workaround; those are local build tools, not app dependencies.

Verify the produced APK with `verify-android-tester-apk.mjs`: explicit expected package/version/source commit/tester certificate, real debug certificate forbidden hash, and `--production-certificate-state not-provisioned` while the production certificate is absent. That existing bootstrap contract does not qualify production release readiness. Run the production JS boundary verifier independently.

## PC and phone

1. Use the existing desktop tester, point it at `https://veil.erez.pro`, and create a fresh test identity through its normal protected setup. Do not overwrite a personal identity or reset previously pinned trust.
2. Obtain an official single-use Node Access Pass for each new identity from the existing Node administrator. No pass is generated or recovered by this frontend session. Do not open registration or bypass the gate.
3. Install the verified account APK with `adb install -r <absolute APK path>`. Preserve app data. If the existing tester certificate differs, stop: do not uninstall/clear storage to bypass the conflict.
4. Stop Metro and remove any development reverse mapping. Launch **Veil Tester** from the phone. The tester JS is bundled. Confirm startup reaches the honest native identity/enrollment/security gate.
5. Follow the normal native identity ceremony. Import the administrator's invitation by the explicit **Import invitation from clipboard** action. Check the shown HTTPS origin before applying it. JS must not receive the token. The regular site's `veil://` launch targets the main app; tester uses its isolated scheme.
6. Find the other test identity by its account ID on the same Node. Open its identity proof and establish trust using the existing explicit fingerprint/QR comparison with both devices. Names/avatars alone are not verification.
7. Open the real Direct conversation. Wait for verified native history and enabled composer. Unsupported reply/edit/delete/file actions must not appear as production commands. Copy is allowed; it is not a transport receipt.
8. Send `PHONE-01 test`, `PHONE-02 test`, `PHONE-03 test`; verify exact text and one copy each on PC. Send `PC-01 test`, `PC-02 test`, `PC-03 test`; verify on phone. Record only public state/status, never private message logs.
9. Move phone to background, send a synthetic test from PC, return and reopen through the existing security gate. Verify no duplicate rows/listeners and correct history. Background plaintext/drafts are intentionally cleared by existing privacy policy.
10. Restart the phone process, reopen the identity, reconnect and verify canonical message IDs/order/status through visible behavior. Sent does not mean Delivered/Read. Unknown must remain Unknown and must not trigger unsafe automatic retry.
11. Switch A → B → C → A → C → B with test contacts. Check draft/viewport ownership while active, pending sends and incoming messages. Locked/revoked scopes must not render old plaintext.
12. Test loss of connection before/during send and native reconnect. Restore connectivity. Record public error codes and whether an operation was accepted; do not repeatedly submit an Unknown operation.

## Status

**E2E BLOCKED BY TEST CREDENTIALS** until usable official test Passes and fresh test trust inputs are confirmed through the existing secure flow. A designated prior test-Pass file exists; it is not evidence of an unused valid invitation. APK installation/startup or fixture tests are not authenticated exchange. The latest session evidence records build/device checks independently.

The current physical Samsung account tester has a different existing signing certificate. Do not remove it or clear its storage. The new APK is ready for a clean tester installation; in-place physical account verification is separately blocked by this certificate mismatch. The preview package is isolated and can be updated safely.

The later USB phone's existing tester certificate was checked and matches the current key. It disconnected before the account update, so that phone can use an ordinary preserved-data update when available again. Design 11 was installed there. Both phones were subsequently taken away; the final safe-area/viewport/waiting-state APK is built but not device-tested.

Final local artifacts: `target/mobile-account-20261005/03884ecdf168-account11/Veil-Account-Tester-11.apk` and `Veil-Design-11.apk`. See the [verification report](mobile-account-11-verification-2026-10-05.md) for hashes and the exact tested-versus-final revisions.
