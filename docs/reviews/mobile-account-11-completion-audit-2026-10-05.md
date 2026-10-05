# Account integration completion audit

This audit preserves the full requested account-client scope. The session is
not fully verified: a built account shell and a fixture phone pass do not prove
authenticated account behavior. No device actions are authorized while the
user has the phones.

The [verification report](mobile-account-11-verification-2026-10-05.md) records
artifact hashes, measured results, warnings and exact device revisions.
`AUTOMATED` means host coverage of the named boundary, not native exchange.
`SOURCE` means implementation inspection, not a physical pass.

| Requested item | Current evidence | Remaining requirement |
|---|---|---|
| 1. Account shell migration | Shared AccountFrame/Directory/Profile/ConversationSurface; production boundary check | Authenticated device composition and parity |
| 2. Startup states | accountStartup tests, SecureRuntimeGate/native gate inspection; bounded history-wait presentation tests | Cold account startup and stalled-history UI on installed tester |
| 3. Account tester | Standalone tester assembly/signature/bundle verifier; readiness instructions | Install on compatible test phone |
| 4. Direct path and ownership | Existing Rust/FFI/Kotlin/JS mapping inspected; status/store tests | Authenticated event/send observations |
| 5. Network/runtime failures | Public error mapping, stale-result and unavailable tests | Actual disconnect before/during send and reconnect |
| 6. Lifecycle | Foreground/background epoch/subscription tests; privacy policy retained | Authenticated lifecycle, modal and pending-send behavior |
| 7. Production conversation list | Shared virtualized directory, empty/error primitives, accountDirectory tests | Real 0/1/many-dialog physical pass |
| 8. Switching stress | Fixture A/B/C device pass; scoped draft/store tests | Real incoming events and pending sends during switching |
| 9. History boundary | Native limit/false load-older capability inspected; stable-ID anchors; mounted-visit callback ownership tests | Real 100-message scroll boundary |
| 10. State primitives | Shared VeilState and sanitized PublicFailureCard | Account physical focus/layout pass |
| 11. Bars/IME/sizes | Fixture keyboard and small-device configuration pass | Final sheet cutout change, 3-button navigation, account checks |
| 12. Motion | Shared spring/sheet inventory; fixture Reduce Motion pass | Final account release motion verification |
| 13. Mixed transitions | Actual gfxinfo before/after and isolated fixture samples | Tail persists; account profiling and deeper trace unavailable |
| 14. Resource hygiene | 40 fixture cycles/PSS/views/activity samples; listener cleanup tests | Retained JS heap and authenticated extended session |
| 15. Accessibility regression | Real fixture TalkBack/focus checks | Account security gate -> ready and final sheet revision |
| 16. Visual baselines | 16 cropped fixture baselines and diagnostic comparator | Account empty/error/offline captures; final revision captures |
| 17. Presentation parity | Same primitives/tokens/composer/renderer; isolation graph | Physical account-versus-fixture comparison |
| 18. Module boundaries | Dependency/cycle/isolation checks; scoped feature controllers | No observed host blocker; continue as new features land |
| 19. Frontend misuse | Added paths inspected for logs/clipboard/URI/capture-policy misuse | Physical account capture-policy check |
| 20. Links | URLs remain plain text; no preview fetch/WebView | Tap navigation is absent, not claimed supported |
| 21. Copy feedback | Shared non-content notice/TalkBack announcement; native write-only clipboard | Native account physical Copy pass |
| 22. Quote navigation | Fixture target/highlight/bounded-seek tests and device checks | Native reply contract absent; unavailable capability retained |
| 23. Appearance | Shared provider/native storage, cold-start fixture persistence, corruption fallback | Account physical restore/picker/privacy interaction |
| 24. Capabilities | Typed flags, mapping/interface tests, unsupported commands absent | Device account action availability |
| 25. Unsupported features | No invented production reply/edit/delete/files/pagination methods | Requires a separately approved real native contract |
| 26. Test expansion | Existing suite retained plus targeted new regression coverage | Tests cannot replace physical/native exchange checks |
| 27. Physical regression | Shared design fixture pass on Android; second phone preview launch | Account regression and final revisions not installed |
| 28. Build matrix | Design/account APK, JS/Kotlin, verifiers, TS/lint/tests/boundaries | Native libraries reused; not a fresh core rebuild |
| 29. Architecture/handoff | Ownership/flow/capability docs and reproducible E2E instructions | Keep hashes/evidence aligned with next artifacts |
| 30. Credential-dependent E2E | No personal secrets extracted; prior designated Pass file not assumed valid | Official usable Passes, controlled identities/trust and phone |
| 31. Credential blocker isolation | Host work continued; shared UI, tests and builds completed independently | Only credential-dependent exchange remains blocked by credentials |
| 32. Strict limits | No protocol/crypto/trust/server/signing/publication/push changes | Preserve for follow-up work |
| 33. Stopping gate | Full completion is not established | Outstanding device/E2E/profiling gates above |
| 34. Final evidence categories | Report separates DEVICE/AUTOMATED/SOURCE/BLOCKED | Do not relabel prior fixture captures as final account verification |

The delayed-history presentation and queued viewport callbacks were hardened
without a phone. Their artifacts passed host verification. The next
required checks need a compatible device and, for
authenticated Direct, official test inputs. Unsupported native features are
contract blockers, not permission to invent a protocol.
