# Rocket.Chat React Native presentation source port

Upstream: [RocketChat/Rocket.Chat.ReactNative 4.77.0](https://github.com/RocketChat/Rocket.Chat.ReactNative/tree/0a7df3d82a2e9d20e37f9ec5651fd3c74b98ab36), commit `0a7df3d82a2e9d20e37f9ec5651fd3c74b98ab36`.
Adapted 2026-10-04. The selected CE presentation sources are covered by the upstream root MIT [LICENSE](LICENSE), retained verbatim. Adapted files identify the source and changes in their headers. Veil product branding is retained.

This is a modified source port of the concrete layout/styles below, not an unmodified upstream application or SDK. SHA-256 values identify the original UTF-8 bytes fetched from the pinned commit. Only the stated parts were brought into the Veil presentation layer.

| Veil file | Upstream source path(s) | Retained parts and deliberate changes |
|---|---|---|
| `src/presentation/rocketChat/theme.ts` | `app/lib/constants/colors.ts`, `app/views/Styles.ts` | Dark CE color tokens and base text attributes; system font weights replace Inter assets. |
| `src/presentation/rocketChat/RoomItem.tsx` | `app/containers/RoomItem/RoomItem.tsx`, `Wrapper.tsx`, `Title.tsx`, `styles.ts` | Avatar/title row, border/spacing/type sizes, title truncation; narrow DTO and callback replace subscriptions, swipe actions, unread/presence/last-message assumptions. |
| `src/presentation/rocketChat/ContactItem.tsx` | `app/views/NewMessageView/Item.tsx` | Contact row, avatar/name layout and typography; replace Rocket avatar with Veil Phaseprint slot, remove VoIP hooks. |
| `src/presentation/rocketChat/Message.tsx` | `app/containers/message/components/Message/FullMessage.tsx`, `components/User.tsx`, `components/Time.tsx`, `app/containers/message/styles.ts`, `app/containers/markdown/components/Plain.tsx`, `app/containers/markdown/styles.ts` | Full message avatar/content/header/plain text layout and typography; explicit DTO and identity/delivery slots replace model/context hooks. Timestamp is the native value or absent. No Rocket parser, links, preview loading, grouping/history inference or optimistic rows. |
| `src/presentation/rocketChat/Composer.tsx` | `app/containers/MessageComposer/components/MessageComposerContent.tsx`, `ComposerInput.tsx`, `Buttons/BaseButton.tsx`, `app/containers/MessageComposer/constants.ts` | Input/send row, border, padding, min/max heights, multiline input and button positioning; controlled presenter replaces draft autosave, uploads, commands, audio and thread logic. Existing Lucide icon and RN Pressable replace custom font/gesture control. |
| `src/screens/HomeScreen.tsx` | `app/views/RoomsListView/index.tsx` | FlatList/empty presentation and list sizing; native directory, explicit selection and Veil navigation replace search/subscription/settings providers. |
| `src/screens/ContactSearchScreen.tsx` | `app/views/NewMessageView/index.tsx`, `HeaderNewMessage.tsx`, `app/containers/SearchBox/index.tsx` | Search/list arrangement, margins, contact selection layout; explicit exact-username native command replaces local DB/spotlight/create pipeline. |
| `src/components/layout/ChatIsland.tsx` | `app/views/RoomView/List/components/List.tsx` | Virtualized list tuning (20 initial rows, 5/batch, window 10) and content padding; Veil controller provides a bounded native window and follows new rows only when already near the end. RN list avoids the Reanimated 4/worklets version dependency. |

No upstream fonts, images, icon fonts, `app/ee` files, Rocket SDK, WatermelonDB, crypto, Redux/auth pipeline, push, analytics or networking code is transferred. Existing Veil dependencies provide React/RN, React Navigation, Zustand, Lucide icons, SVG Phaseprints and safe areas. No dependency or platform upgrade is required by this subset. Source inventory is not evidence of an Android APK build or physical GUI qualification.

## Original source checksums

Paths below are relative to the pinned upstream repository.

```text
c27f5cd3efda920408e12e7d88b80c36ed7e32e8382cc2a72450e5f4b6c444ea LICENSE
bf4ead086b22d20e5fc3f66556055a670578cbc11908b4a7b20dd833bd25f55d app/lib/constants/colors.ts
1c5f5d08f81383e08e527ee710e17cf57b3d70694fe548f889effaab396202e2 app/views/Styles.ts
9139e7f4f32cb82fb36f69fdba2e58aa48903707f6e7079978d386e849902ddb app/containers/RoomItem/RoomItem.tsx
309ebbb1b7d63cd741f72ab7f9f753b344b64c7141fdbfa4a02726794e675b8f app/containers/RoomItem/Wrapper.tsx
b5756c604dcc38748c420689904f66b54fff670c04ea6670542075365b91ccca app/containers/RoomItem/Title.tsx
c5264773bdbc4b4111c31bba354095a0e1aead0671e683e5a875007ae47b30ca app/containers/RoomItem/styles.ts
b743966282aa8a397bade488811592653a4114eeccec1f3422ed15e9474a45e0 app/views/RoomsListView/index.tsx
8684b2579087e73eb181a9d0bf3722e9a6a55c543c505ab4810ba4b4bdeb14d5 app/views/NewMessageView/index.tsx
12b8f5635a544e9c62eae020f40c2223d6ed8b0a4666b30137b6b8262c3437d6 app/views/NewMessageView/HeaderNewMessage.tsx
c75548d054d1b13820e8a57a42a08ec8a78c17f3172c59421d2f7878a3c2e0dc app/views/NewMessageView/Item.tsx
50a7dcc5ef352f35ecdc15d88c5747dbdf6e7d1fa8466ace95bc19d6a2762f69 app/containers/SearchBox/index.tsx
a98cfa565bcd12a3c5798d6f7d78d8ce3f91d476e1c10862a5e1decb11f6941d app/containers/message/components/Message/FullMessage.tsx
dc172aae8378526a9cbdf051f6fa52018cc038b070d8964702af33d45d648e2e app/containers/message/components/User.tsx
f67dad837f7840f278a112a676202f1830e3fe9262f8dfda377eeb5bad652bf8 app/containers/message/components/Time.tsx
d7e7c8e5685bb87ecfe8efbc35b81045b9bc119ab1b94a8c0773c8a1178e8e1e app/containers/message/styles.ts
19e96816e2ce8fecf71e33d6aa16410a6f58f0e8e58cb1c1b23e5c39fea6f347 app/containers/markdown/components/Plain.tsx
bc3ce5812635072a58adaa55c5cd9be7006f5bb8dcb4865b552c04bf7bf49739 app/containers/markdown/styles.ts
6000246413e8ba23e514951b0357dc6cfdd46055c70c2e2c9076688009fc0a7d app/containers/MessageComposer/components/MessageComposerContent.tsx
65352854bc6b5eaaa52c8ee9ae99ae5df13da37633f97d4af5aaa2fda1fbdc7a app/containers/MessageComposer/components/ComposerInput.tsx
34255a5d5e065f9a0147369607eff4eb5f96b0f3deec46ada6ce682a44c19972 app/containers/MessageComposer/components/Buttons/BaseButton.tsx
b97dd865f9c7582b67f6324cf1266c90e217af697baf17bf88168cef8a872393 app/containers/MessageComposer/constants.ts
deb8d02b2979e95f1384590c100b063617e9402f4d8f1ec5dc7f1cc70bb98945 app/views/RoomView/List/components/List.tsx
```
