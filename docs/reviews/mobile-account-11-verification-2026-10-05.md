# Mobile Account 11 — verification and remaining gates

The real account client now uses the approved shared Veil presentation. This is
a frontend integration and local tester build, not authenticated Direct E2E or
a production release. The core, protocol, cryptography, trust model and Node
were not changed in the integration session. At this verification checkpoint,
no APK had been published and no changes had been pushed. Subsequent explicitly
authorized test distribution is documented in
[the download handoff](mobile-account-11-downloads-2026-10-05.md).

## What changed

- `AccountFrame` composes the shared dock, directory, chat deck, wallpaper,
  floating profile and profile panel. `HomeScreen` and `DirectConversationScreen`
  no longer own a separate legacy chat presentation.
- The existing text Direct adapter supplies `ConversationSurface`, the composer,
  message renderer and action sheet. Enrollment, identity, PIN, authentication,
  trust and native capture gates remain authoritative.
- Five themes and public device-local appearance preferences are shared between
  shells. Account identity does not own theme/wallpaper state.
- Startup states are mapped from existing native facts. `VeilState` provides
  loading/empty/unavailable/error/capability/offline presentation. Slow bootstrap
  exposes manual retry; there is no fixture fallback or automatic retry loop.
- Pending sends, drafts and viewport state use origin/account/generation/chat
  ownership. One native send remains serialized. A send in another conversation
  is explained rather than displayed as this conversation's operation.
- A queued callback from an obsolete runtime epoch is rejected before it can
  reconcile or clear the replacement account's UI. Background/revocation retains
  the existing fail-closed clearing and reopen policy.
- Shared sheets use swipe-down grips, Android Back and accessible dismissal,
  without close crosses. Android API 31+ uses live RenderEffect blur, including
  nested modal ownership and the moving navigation underlay. The native manager
  reapplies its effect after React Native's layer-effect update.
- Physical cold-start testing found and fixed two appearance regressions:
  inherited bridge methods were not exported to JS, and canonical Android path
  aliases caused cleanup to delete the current wallpaper. Both shells use the
  corrected shared storage implementation.
- The first bounded history batch renders before tail placement. Decorative
  avatar initials fit their fixed slot without changing global font scaling.
- One final change adds top safe area to the common sheet frame so a full-height
  viewer's dismiss grip does not occupy the status-bar/cutout region. This
  change was built/tested after the phone was taken away; device verification is
  still required.

See [architecture and ownership](../design/mobile-account-client-2026-10-05.md)
and [tester installation/E2E instructions](account-tester-readiness-2026-10-05.md).

## Builds and immutable evidence

Both final builds use base commit `8bbdf3ff154d9b7182be6a1ce295550be9c93b53`
and mobile source snapshot
`03884ecdf168945815f66ff5b1793e27b5629f8c61a53b291e33fe19c9a6b6d5`.
The commit is the existing base; the snapshot represents uncommitted local work.
It must not be described as a clean committed release.

| Build | Package | SHA-256 |
|---|---|---|
| Final Design 11 release | `io.veil.mobile.designpreview` | `45976d0ed6be6f23028fbf31c595829dda815b4007579ee38fb898e533c64a7c` |
| Final account internal tester | `io.veil.mobile.tester` | `9763aeed4d4d24750231cd52d23d24138a93253ccb1136b3b6e629ce7175e19b` |

Both are version code `2026100511`, independently tester-signed and contain JS
bundles. Production signing was not used. Production certificate provisioning
remains deferred under the existing verifier's tester bootstrap contract.

The immutable archive is
`target/mobile-account-20261005/03884ecdf168-account11/`.
It includes APKs, the available source tree, hash manifests, source/APK verifier
evidence, host/device checks and app-content visual baselines. Native libraries
were reused from the earlier native build; this session compiled the JS/Kotlin
integration, not a fresh Rust/core build. Source companions do not establish
bit-for-bit reproducibility of the native toolchain.

## VERIFIED ON DEVICE

Physical shared-presentation checks used Samsung **SM-S911B / Android 16**.
The last fully exercised device APK had SHA-256
`a302d376d153da12a4b104efe5f06f0e75847cc19fb3f2e08a66dfc9522fc150`
and source snapshot `f23c518132d4d10f87856354e1790a22542cc3e9b8b56ee239313cfc73fba25f`.
It preceded the final sheet safe-area change.

- Release cold start with Metro stopped and no port 8081 listener.
- Directory, long history, empty conversation, composer/keyboard, reply/cancel,
  Copy feedback, action sheet, attachment demo and image viewer/Back.
- Real live blur with sharp foreground panels; no moving black scrim, duplicate
  inner sheet frame or panel close crosses. Profile/actions downward swipe and
  deck reveal/resume gestures worked.
- Font scales 100%, 130%, 150%, 200%; original Android font setting restored.
  Layout was not fixed by reducing global type size or disabling message scaling.
- TalkBack main-flow regression on the earlier shared-sheet revision, plus image
  viewer on the later appearance-fixed revision. The actual Samsung service was
  bound with touch exploration. Focus was retained by the modal and restored to
  the attachment trigger after Back. This does not cover authenticated account
  security gates or certify the final safe-area revision.
- Reduce Motion was actually enabled through the native switch, persisted as
  true and exercised through chat/actions/profile. The first harness attempt
  targeted the text label rather than the switch; that attempt was not counted.
- Seeded managed wallpaper survived cold start. UI changes to **Forest / 45%
  dim / 10 px blur / the same wallpaper** survived another full process stop.
  Corrupt JSON restored safe OLED/default values. Fixture preferences were then
  reset; user account storage was never cleared.
- A smaller `1080x1920` configuration at the existing density (approximately
  360x640 dp) exercised directory, chat, keyboard, actions and profile. Original
  display size was restored. This was a device configuration, not another emulator.
- A → B → C → A → C → B preserved `Draft Максим`, `Draft Анна`, `Draft София`
  with three incoming fixture messages added in each revisited scope. No rejected
  actions occurred in the corrected harness sequence. This is fixture switching,
  not authenticated native incoming-message stress.
- Forty repeated chat/scroll/profile cycles completed in one process. Android
  PSS in KiB at cycles 10/20/30/40: **288894 / 303447 / 294112 / 289216**;
  views: **508 / 455 / 452 / 461**; one activity throughout. No linear growth was
  observed in this sample. A retained JS heap profiler was not available.

The user's second USB phone reported **SM-S948B / Android 17**. Design 11 was
installed and cold-started successfully there before USB disconnected. Its
existing account tester certificate matches the current tester key, but the
account APK update did not run after disconnection. The final safe-area APK has
not subsequently been installed on either phone.

## Performance — method, before and after

`dumpsys gfxinfo` was reset separately for each deterministic transition path.
These are short instrumented samples on one device, not React profiler traces or
proof of universally smooth rendering. The before build was Design 10; the
controlled after build was the appearance-fixed Design 11 with ordinary motion.

| Path | Before frames / janky / p95 / p99 | After frames / janky / p95 / p99 |
|---|---|---|
| Chat open | 50 / 10.00% / 31 / 69 ms | 55 / 3.64% / 30 / 125 ms |
| Keyboard | 61 / 4.92% / 20 / 42 ms | 63 / 7.94% / 17 / 21 ms |
| Actions + reply | 56 / 14.29% / 40 / 61 ms | 73 / 13.70% / 29 / 77 ms |
| Attachment controls | 65 / 9.23% / 19 / 65 ms | 73 / 10.96% / 22 / 77 ms |
| Profile | 7 / 42.86% / 77 / 77 ms | 20 / 10.00% / 77 / 77 ms |
| Chat switching | 213 / 6.10% / 17 / 57 ms | 210 / 3.33% / 13 / 89 ms |

The profile sample is especially small. Before/after results are mixed: fewer
janky chat-switch frames do not eliminate its tail. An intermediate migrated
profile sample reached p99 200 ms; the duplicate frame/native blur application
path was corrected and repeated samples reached 57–77 ms. No unsupported claim
about a specific JS bottleneck or a universal improvement is made.

Additional isolated after samples measured action-sheet open p99 **93 ms**, reply
appearance **77 ms**, reply cancel **10 ms**, viewer open **73 ms**, viewer close
**85 ms**. Normal release scrolling used ordinary ADB input without instrumentation
or accessibility-tree captures during the sample: **2710 frames, 1 janky frame
(0.04%), p95 20 ms, p99 21 ms**. Metro port listeners: zero. Local Reduce Motion
was enabled for this normal-scroll sample; it is not an uncontrolled before/after
transition comparison. The final safe-area revision was not reprofiled on-device.

## Capability matrix

| Presentation capability | Native Direct | Design adapter |
|---|---|---|
| Text/history/incoming | existing runtime, gated by readiness | fixtures |
| Copy | yes, explicit write-only command | yes |
| Reply/edit/delete | no existing contract | demo |
| Message attachments/retry | no existing contract | demo |
| Delivered/read | unavailable; never simulated | unavailable |
| Load older | unavailable; current projection ≤100 | fixture pages |
| Groups/spaces/unread/pin/mute | not fabricated in account directory | explicit fixtures |

Unknown remains Unknown and cannot trigger automatic resubmission. Native failed
send is not advertised as safely retryable without an idempotent contract.
The loaded native-history boundary states that this is the available history;
there is no fake pagination spinner or promise of older data.

## VERIFIED AUTOMATICALLY

- **350/350 app tests, 56 suites**. The initial 323-test base was retained.
- **63/63 tester APK verifier tests**, no skipped tests.
- TypeScript and ESLint: passed, zero current errors/warnings from those tools.
- Design release assembly; account internal tester JS bundle/Kotlin/assembly;
  both final APK verifiers: passed.
- Production JS boundary: 3236 sources checked; shared presentation and MIT
  notice included, design fixtures/native demo bridges excluded.
- Isolation, production high-level UniFFI surface and dependency/cycle checks:
  passed. No second UI kit or account-to-demo transport imports were introduced.
- Meaningful coverage includes startup facts, capability/status mapping, global
  send ownership, stale completion/callback rejection, foreground/background
  listener cleanup, scoped history/drafts, appearance fallback/late-owner results
  and sheet dismissal during Reduce Motion/unmount.

A first final test run exposed a test-only safe-area mock that exported the hook
but not `SafeAreaView`; all nine identity/trust interaction tests passed after
correcting that fixture. The full suite then passed again. An earlier restoration
test exceeded its existing 1-second wait under concurrent host load and passed
focused/full reruns. These failures were not hidden or skipped.

Build warnings remain: Gradle deprecation notices, inherited native/Kotlin
warnings and Metro's NO_COLOR/FORCE_COLOR warning. The local Windows native-tools
environment/Java-agent workaround is still required. No dependencies were upgraded.

## VERIFIED BY SOURCE INSPECTION

- Existing Rust → FFI → Kotlin → JS → store → Direct adapter → shared renderer
  path and its stable IDs, direction/timestamps/status mapping.
- Account/generation scoping, capability guards, 100-message boundary, absence
  of unsupported production mutation methods and no native-error fixture fallback.
- Native account capture/backup/signing/enrollment/trust boundaries retained.
  Blur is presentation, never a substitute for privacy clearing or authentication.
- New account presentation contains no message/Pass/key logging. Clipboard writes
  are explicit and sensitive; feedback contains no copied message text and does
  not read clipboard back. Private-message URLs are plain text; no preview fetch,
  hidden network metadata request or embedded WebView was added. Message URL tap
  navigation is not currently implemented.
- Managed local wallpaper paths, bounded/sanitized imports and canonical cleanup;
  appearance is public device presentation state, not account/server profile data.

Motion inventory: deck/dock use the shared Reanimated spring; all migrated panels
use the shared 220 ms native-driver transition; reply/attachment rows and new-
message indicators use ordinary layout/state updates; quote highlight is a static
temporary tint with 1800 ms lifetime; Copy notice has 3500 ms lifetime. Lifetimes
are feedback semantics, not competing transition easings. Reduce Motion bypasses
sheet/deck motion and animated quote scrolling while retaining useful feedback.

## BLOCKED / NOT VERIFIED

1. **Real text Direct E2E is not verified.** A designated prior test-Pass file
   exists, but unused validity and fresh controlled test identities/trust inputs
   are not confirmed. No personal identity secrets or messages were extracted.
2. The first Samsung's existing account tester uses a different signing key.
   Its data was preserved; no uninstall/storage clearing was performed.
   The second phone's key matches, but it disconnected before account update.
   Physical account startup/enrollment/ready composition, real bad-network
   exchange, reconnect/history and account TalkBack remain unverified.
3. The phones were taken away before final safe-area APK installation/retest.
   Its build/tests pass; full-height grip/cutout/modal focus needs device checking.
4. No emulator/system image was available. Three-button navigation, another
   hardware size, iOS and API 24–30 live blur are not verified. Older Android/iOS
   currently use a clear underlay, not an imitation dimming/blur fallback.
5. There is no full retained JS heap or React transition trace. Mixed-transition
   tails remain. Memory sampling is a limited shared-preview stress observation.
6. Visual baselines use app-content crops from the physical fixture revision,
   not the final untested revision. Dynamic test-send times remain diagnostic-only;
   empty native directory/startup errors are covered automatically, not by
   authenticated screenshots. The comparison tool is diagnostic, not a fake
   all-state visual pass.

## Next execution order

Install the final tester on a clean or compatible test installation, retaining
data. Verify full-height sheet safe areas/TalkBack first. Then use official fresh
test credentials and the existing enrollment/trust flow for synthetic PC/phone
Direct exchange, restart/background/reconnect and network failure checks. Profile
the remaining transition tails on that installed release. Unsupported native
reply/edit/delete/files and pagination require a separate real-contract stage;
they must not be invented in this frontend session.

## Host follow-up after phone withdrawal

A further audit found queued native-list measurements could address the replacement list ref. `useDirectViewportOwner` now scopes every content-size/viewability/scroll/index-failure callback to a mounted visit as well as the current account/origin/generation/conversation. A -> B -> A does not revive callbacks from the earlier A visit. Restoration reads the latest verified projection.

`useDirectHistoryWait` stops indefinite spinner presentation after ten seconds, replacing it with an honest waiting notice and the existing manual read action. It does not cancel native work, invent an error code, change Sending/Sent/Failed/Unknown or retry a send. The composer remains disabled until authoritative history arrives. Timers are scoped to the read revision and cleaned up on result, privacy clearing, scope replacement and unmount.

Eleven new ownership/deadline tests passed; the full suite is now 350 tests in 56 suites. TypeScript and ESLint passed after correcting two new test-only typing issues; no tests were skipped. Both APKs, production bundle, isolation/cycle checks and verifier checks were repeated. Neither follow-up nor the final safe-area change was exercised on a phone. The earlier immutable archive remains preserved; current hashes and source companion above identify the follow-up artifacts. See the [full-scope completion audit](mobile-account-11-completion-audit-2026-10-05.md).
