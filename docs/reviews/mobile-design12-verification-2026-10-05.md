# Design 12 verification — 2026-10-05

Design 12 is a release candidate, not a completed physical-device or authenticated regression pass. The approved Veil composition was retained. The owner confirmed bidirectional desktop/mobile text Direct on the preceding account client; the newly migrated APK has not yet repeated that exchange.

The owner subsequently requested GitHub APK distribution for another phone. The distribution branch is `ce/mobile-design12-20261005` and the separate test prerelease tag is `mobile-test-20261005-12`. Download locations and provenance are recorded in the [distribution handoff](mobile-design12-downloads-2026-10-05.md). Publishing does not complete the deferred device or production gates.

## Changes and ownership

The [route audit and architecture](../design/mobile-design12-2026-10-05.md) records every authenticated route, compatibility route and native ceremony. Contact Search, Settings and SettingsDetail now use shared Veil presentation. Settings definitions remain the source of real account/runtime facts; profile settings and full-screen settings render the same content. About and account/security have distinct destinations. No account path imports demo transport or fixtures.

Contacts pushes Direct over the search owner, retaining query/result context. Returning focus releases a navigation latch; repeated transition presses cannot push duplicate Direct screens. Focus restoration accepts only existing directory conversations under the current account generation. Listener cleanup and offscreen rejection are covered by tests.

Ordinary sheet dismissal retains the modal and live blur through the common exit. Nested Back first returns to its parent section or scanner panel. Reopen, stale animation completion, destroyed owners and reversed drags are tested. Reduce Motion cancels unfinished gestures without a decorative spring. Privacy/account teardown remains immediate.

Demo profile input is a draft. Save commits once; Cancel, leaving edit and external closure discard an unfinished draft. No public/server profile mutation API was invented.

Contact operation errors no longer promise that account state is unchanged: native create may have completed before a subsequent projection read failed. The UI honestly says that the result is unconfirmed, hides the raw exception and offers an explicit lookup retry. A test verifies that this retry does not automatically repeat create.

The read-only readiness script no longer invents a credential blocker. It reports E2E as NOT RUN by that script and does not assess credential availability or prior exchanges. CLI tests check this distinction and that signing-input values remain hidden.

## VERIFIED AUTOMATICALLY

| Check | Result | Evidence |
|---|---|---|
| Jest | 371 tests, 57 suites passed; no snapshots | `design12-tests-final4.log` |
| TypeScript | passed | `design12-typecheck-final4.log` |
| ESLint | passed, no warnings/errors | `design12-lint-final4.log` |
| Presentation boundaries/cycles | passed | `design12-boundaries-final4.log` |
| Isolated preview source | passed | `design12-isolation-final4.log` |
| Production FFI surface guard | passed | `design12-uniffi-final4.log` |
| Production JS export/verifier | passed | `design12-bundle-final4.log` |
| Tester APK verifier unit tests | 63 passed | `design12-verifier-01.log` |
| Read-only readiness CLI tests | 2 passed | `design12-readiness-tests-final4.log` |

Logs are under `D:/tmp/veil-reliability-testtools-20261004`. New meaningful scenarios include native create completion after generation replacement, mismatched origin/account/peer rejection, preserved lookup context, navigation latch cleanup, hidden-filter clearing, nested About/security navigation, external profile draft cancellation, dismiss parity and Reduce Motion gesture branches. Existing status tests preserve Sending/Sent/Failed/Unknown; Delivered/Read were not added.

Both frozen builds and their APK verifiers passed. A JS export or successful Kotlin compile is not authenticated E2E evidence.

| Artifact | Result | SHA-256 |
|---|---|---|
| Veil-Design-12.apk | release build and isolated APK verifier passed | `d918718a57a6d79d0cf3aca9189dc3ab40a025351ad0d07d5c34b7026e1dc7af` |
| Veil-Account-Tester-12.apk | internalTester build, Kotlin compile and strict tester APK verifier passed | `ebc40a8c9ea3508b2c5e93fac026711ecba7a77a4e6bb00ab33a58e8cc84ee15` |
| Source snapshot ZIP | archived with file hashes | `1f80a2c05750394ca2bea01c8e44bd6a5859090db6a309dc181528643623fde0` |

Both use version code `2026100512` and the maintained independent tester certificate. The exact mobile source snapshot is `76c9d20f095c76448fccaf08f4c6bdc8ae9d7a24bb1ab1208b7d16a46eb47063`, based on repository HEAD `81da3e12539cdc503119ca61088d14a8ecdb041f` plus the uncommitted Design 12 patch. HEAD alone does not contain this migration. The source guard compared the snapshot at the beginning and end of each build.

The immutable candidate is under `target/mobile-design12-20261005/76c9d20f095c7644/`, with APKs, source snapshot ZIP/tree, verifier evidence, check logs, manifest and checksums. The older `f01d36f2d3f58001` and `dda8b26421ce2258` candidates are superseded and were not overwritten. At completion of local verification, the patch was uncommitted and unpublished; later owner-authorized distribution is a separate operation. Existing native libraries were reused; this is not a full Rust rebuild. Production signing is unchanged and its certificate remains unprovisioned, so the account tester's successful local verification does not mark it production-release-ready.

The build still emits the existing Gradle future-version deprecation notice and the `NO_COLOR`/`FORCE_COLOR` formatting warning. Keytool also recommends migrating the separate debug certificate's JKS container; no key or keystore was modified. These warnings are retained in the local logs. Git's LF/CRLF notices concern Windows checkout normalization; `git diff --check` passed.

## VERIFIED ON DEVICE

Wireless ADB pairing and a connection through the owner's Tailscale address succeeded. The connected device reports SM-S911B (Samsung S23), Android 16. Its independently signed design-preview package accepted the final in-place release update (`adb install -r` returned Success); `dumpsys package` confirmed `2026100512` / `0.1.0-design.20261005.12`. Existing account app data was not read, cleared or uninstalled.

The earlier candidate's Android activity-launch measurement was 167 ms while the system keyguard still blocked the UI. This is only a launch measurement; it is not evidence of a usable cold start, frame smoothness or successful navigation.

The system lock screen requires the owner's normal unlock. The ordinary Android dismiss-keyguard command reached the credential prompt; no lock bypass, credential attempt or security setting change was performed. The owner chose to unlock later. Fixture instrumentation correctly refused to inspect a non-fixture foreground window and returned no completed UI evidence.

Host port 8081 was not listening at the previous installation check, and the device again had no ADB reverse mapping after the final update. Bundled JS is verified automatically, but functional no-Metro release launch still needs the unlocked fixture surface. Earlier Design 11 font/TalkBack measurements are not reused as Design 12 verification.

## VERIFIED BY SOURCE INSPECTION

App startup/security gates, enrollment, trust comparison, native error authority and account/generation scoping remain in their existing owners. Protected recovery/unlock/enrollment activities remain native security ceremonies. Fingerprints, account IDs and protocol diagnostic identifiers are not translated or replaced. Reviewed security-ceremony wording remains separate from ordinary Russian product copy.

The patch does not change Rust, crypto, Node, backend or production signing. Account and design share radius, palette, composer, rendering and motion primitives. Ordinary account screens no longer import Rocket ContactItem, Rocket theme or legacy MobileHeader; shipped legal/MIT attribution is retained. Live blur uses the existing Android RenderEffect backend, whose API/platform limits remain documented in the account architecture.

No message body, Access Pass, private key, private URL or raw native exception was added to logging or global feedback. No link metadata fetch, embedded WebView, pagination, delivery/read receipts, production attachment method or group permission semantics were introduced.

## DEMO ONLY

Profile editing, attachments, reply/edit/delete and space/group fixture flows remain explicit design capabilities where no native Direct contract exists. Account UI does not silently fall back to these fixtures on an error.

URL interaction, search in the available native history and Design 13 Spaces have not started: the requested ordering puts them after the completed Design 12 account/device gate.

## BLOCKED / NOT VERIFIED

| Remaining check | Exact limitation |
|---|---|
| Preview TalkBack and focus order | phone locked; no completed Design 12 device pass |
| 100/130/150/200% physical font matrix | phone locked; JSX/layout tests are not physical evidence |
| Release motion/live blur/performance | phone locked; no before/after claim |
| Post-migration account install | installed account APK has a different signing certificate |
| Account Contact Search/result/create/nested Settings | new account APK cannot update this installation in place |
| Post-migration real Direct/lifecycle regression | new account APK not installed; earlier owner exchange is separately recorded |
| Account screenshot baselines | capture policy retained; no bypass of FLAG_SECURE |
| Emulator alternative | SDK has no emulator/system image or configured AVD |

The installed account version is `0.1.0-tester.20260924.8` (`2026092408`), signer `a85ef3edcd837c3f71679ac50d02165fe4a60258e56b062057a278ba35fe792c`. The maintained tester signer is `f5df868d3f517c0853225840e2c4f67f2d7b20d05b183bf1ab396e530fc3f250`. Its APK cannot preserve this installation through an ordinary Android update. The compatible earlier private signing key has not been provided; no substitute credential or destructive uninstall was used. A compatible tester device or officially designated matching tester key is needed for that check.

Access Pass validity or consumption was not inferred or guessed. No new Pass was issued and no user identity secrets were extracted. Missing signing compatibility is the known current account installation blocker, rather than an unsupported blanket claim that all test credentials are absent.

## Resume checklist

1. Unlock normally, open the isolated Veil Design package, and confirm the frozen candidate version/source snapshot.
2. Preserve design appearance before fixture resets; preserve and restore font scale, accessibility service settings and screen timeout around testing.
3. Stop Metro/check port 8081 and ADB reverse mappings, force-stop only the design package, launch it and complete the actual cold-start/UI pass.
4. Capture deterministic app-content states for list, conversation, profile, appearance, actions, error and font scales. Do not treat the system status bar as a pixel assertion.
5. Run actual TalkBack focus/actions, nested Back, interrupted/reversed sheet gestures and Reduce Motion. Inspect screenshots for layout clipping at every requested scale.
6. Use a compatible account tester installation. Preserve its gates and established identity. Check Contact Search, Settings/About parent context, keyboard, background/foreground and process reopen.
7. Repeat desktop -> mobile and mobile -> desktop test messages on the migrated account client. Do not use private history as fixtures or claim E2E from build verification.
8. Once these gates pass, proceed in the requested order: explicit URL interaction, search in available local projection, then the bounded Design 13 Spaces demo flow.

No phone unlock, account data deletion or production publication is required for the completed host-side migration and build checks. Those checks do not substitute for the remaining device gates.
