# Перенос мобильного интерфейса Rocket.Chat в Veil

Дата: 4 октября 2026 года. Статус: исследование исходников и предложение для M00–M05, не принятый ADR и не результат сборки. Пользователь предпочитает Rocket.Chat по устройству продукта и качеству интерфейса. Это меняет порядок проверки frontend кандидатов в [сравнении](mobile-frontend-candidates-2026-10-04.md) и [дорожной карте](../roadmaps/backend-and-mobile-reliability-2026-10-04.md).

Проверенный upstream: [Rocket.Chat.ReactNative 4.77.0](https://github.com/RocketChat/Rocket.Chat.ReactNative/releases/tag/4.77.0), опубликован 30 сентября 2026 года; commit `0a7df3d82a2e9d20e37f9ec5651fd3c74b98ab36`. Tag и commit подтверждены GitHub API. Зависимости не установлены, upstream не собирался; экономия времени пока не измерена.

## Вывод и граница работы

Перенос реален. Предлагаемый путь — взять исходные экраны и компоненты Rocket.Chat, сохранить их оформление и взаимодействия и подключить к native ядру Veil. Это адаптация зрелого frontend средней/высокой сложности. Простая замена URL не работает: кроме layout в экранах живут подписки, модели БД, identity, draft, send и crypto assumptions.

Первый результат — рабочий Android Direct-клиент с тремя экранами: список бесед, поиск/выбор собеседника, текстовая переписка. Существующие Veil onboarding, unlock, Node connection, runtime gate и settings окружают эти экраны. Полноценная мобильная версия развивается дальше по M05; первое Direct приложение ещё не означает поддержку всех функций Rocket.Chat.

## Способы адаптации

| Путь | Работа и последствия | Оценка |
|---|---|---|
| Перенести выбранный UI в Veil App | Сохранить Rocket компоненты, переписать узкие providers/hooks/actions поверх Veil projection | Предпочтительный путь; ограниченный объём и сохранение текущего native lifecycle |
| Fork всего мобильного приложения | В готовой оболочке заменить auth, БД, crypto, network, send/receive, push и множество screens/actions | Технически возможно; большой первоначальный объём и постоянное сопровождение общего fork |
| Имитировать Rocket.Chat server в Go | Реализовать REST, realtime subscriptions, users, rooms, permissions и ожидаемые события | Не устраняет замену клиентского E2EE; добавляет второй протокол и серверный слой совместимости |

В [SDK](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/lib/services/sdk.ts) есть room/user/typing/delete/read subscriptions. [sendMessage](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/lib/methods/sendMessage.ts) использует собственные DB и Encryption перед `chat.sendMessage`. Поэтому перевод URL/JSON на Go не создаёт Veil Direct v2 ciphertext и совместимость с desktop Veil. Небольшой локальный adapter с похожими presentation callbacks допустим; он не должен имитировать всю серверную платформу.

## Какие реальные части Rocket.Chat переносить

| Часть | Сохраняем | Заменяем или ограничиваем |
|---|---|---|
| Оформление | [ThemeContext](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/theme/index.tsx), цвета, типографику, spacing, поля, headers, touch targets | Локализацию, icon/font inventory и привязку preferences к Veil |
| Беседы | Layout [RoomsListView](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/views/RoomsListView/index.tsx), [RoomItem](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/containers/RoomItem/RoomItem.tsx), loading/empty и виртуализированный список | `useSubscriptions`, Redux server/settings и goRoom заменяем native directory/typed navigation. Last-message/unread/presence только при наличии native metadata |
| Новый Direct | Layout [NewMessageView](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/views/NewMessageView/index.tsx), поле поиска, presentation строки контакта | DB/spotlight search, VoIP hooks и create actions заменяем R13 native search/create. Начальный поиск — точный username |
| Переписка | Настоящий message renderer, header, разделители, long-press presentation и доступность | Room subscriptions, message models и providers получают bounded native DTO; action menu строится по реальным native capabilities |
| Composer | [MessageComposerContent](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/containers/MessageComposer/components/MessageComposerContent.tsx), внешний вид input/send, keyboard interaction | Send, drafts, autocomplete, quotes, uploads и slash commands. Начальный controller — controlled text input и async native acceptance |

Подходящая точка отделения есть в [MessageProvider](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/containers/message/stores/MessageStore.tsx#L108): DB subscription включается только при наличии `experimentalSubscribe`; provider допускает обычные объекты. Однако его типы и [MessageRoomProvider](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/containers/message/stores/MessageRoomStore.tsx#L65) всё ещё содержат Rocket model/settings/user/baseURL assumptions. Сузить типы и передавать Veil context явно, без fake Watermelon model и глобального Rocket Redux store.

Даже визуальный [Avatar](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/containers/Avatar/Avatar.tsx) связан с server/token/SDK. До native avatar projection использовать локальное presentation изображение/инициалы. Полный [InsideStack](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/stacks/InsideStack.tsx) не входит в перенос: он подключает многочисленные функции за пределами первого scope.

## Как связать с нашим кодом

```text
Veil App: onboarding / unlock / Node connection / runtime gate
    → Rocket presentation: Conversations / New Direct / Conversation
    → Veil presenters: directory / timeline / composer / actions / session
    → существующий Kotlin + UniFFI runtime
    → Rust / SQLCipher / Direct crypto / outbox / transport
```

Presentation сохраняет только краткоживущее состояние текущего экрана. Источник истории, status, IDs, retry и accepted send — native runtime. Подписки на native revisions обновляют проекцию. Хранение сообщений и черновиков в Rocket DB/AsyncStorage не появляется.

Точки интеграции:

- [App.tsx](../../veil-mobile/App.tsx): сохранить identity flow, `SecureRuntimeGate`, privacy curtain и lifecycle.
- [ChatListScreen.tsx](../../veil-mobile/src/screens/ChatListScreen.tsx): заменить production маршрут `DesignPreviewHomeScreen` реальным Rocket Direct Home. Preview сам по себе не является клиентом.
- [runtime.ts](../../veil-mobile/src/native/runtime.ts): использовать реальные directory/message/verification DTO и native commands.
- [chat.ts](../../veil-mobile/src/stores/chat.ts) и [useVeilRuntimeLifecycle.ts](../../veil-mobile/src/hooks/useVeilRuntimeLifecycle.ts): сохранить scoped projection/revision guards; адаптер renderer не создаёт вторую authority.
- [DirectConversationScreen.tsx](../../veil-mobile/src/screens/DirectConversationScreen.tsx): сохранить проверку существующей беседы и `selectedDmId`. После create принять snapshot текущего scope → найти conversation → `selectDm` → navigate.
- [ChatIsland.tsx](../../veil-mobile/src/components/layout/ChatIsland.tsx): текущая привязка send/projection служит основой controller, renderer заменяется выбранными Rocket компонентами.

## Контракты, которые придётся уточнить

1. **Scope и очистка.** Каждый presenter связан с origin/account/directGeneration и revision. Lock, disconnect или смена account/origin очищают plaintext и отменяют влияние запоздалых callbacks на новый экран.
2. **Отправка и draft.** [Rocket composer](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/containers/MessageComposer/MessageComposer.tsx) очищает input в своём send flow; [autosave hook](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/containers/MessageComposer/hooks/useAutoSaveDraft.ts) сохраняет draft в БД каждые три секунды и при unmount. Заменить controller: native acceptance → обновлённая projection → очистка неизменившегося draft того же scope. Rejection сохраняет разрешённый текущим scope текст. Durable offline draft вводится через R05.
3. **Стабильный UI ID.** В [Direct ACK transaction](../../veil-store/src/db.rs) `messages.id` меняется с local на server ID; [FFI projection](../../veil-ffi/src/lib.rs) сейчас публикует только текущий ID. Для устойчивой строки pending → sent добавить native `stableUiId`, отдельно client/server ID и typed acceptance correlation. Для outgoing использовать существующий outbox client ID и сохранённый ACK mapping, для incoming — server ID; origin/account/conversation участвуют в render key, generation ограничивает async публикацию. Mapping переживает restart в native storage; его retention согласовать с будущей очисткой outbox receipts. Для старых rows при необходимости мигрировать native alias; не связывать сообщения по тексту/времени и не создавать второй JS domain UUID. Первый renderer прототип может полностью заменять native snapshot без optimistic rows до расширения DTO.
4. **Время и автор.** Текущий message DTO содержит `timestampMs | null`, direction и delivery, но не отдельный author snapshot. Для Direct автора определяет текущая binding/directory. Pending timestamp не подменять текущим временем. Group author model потребует отдельного native контракта.
5. **Статусы и trust.** `sending/sent/failed/unknown` показываются по Veil semantics; Node ACK не означает прочтение. Rocket E2EE settings/markers заменить Veil verification projection и identity-change flow. Дополнительные статусы delivery и действия появляются вместе с R04/M05.
6. **Capability matrix.** Reply, attachments, edits, reactions, threads, channels, presence и calls не включать только потому, что у Rocket есть готовая кнопка. Сейчас mobile projection допускает immutable non-expiring text Direct, а неподдерживаемые payload shapes закрывает. У каждой будущей функции должны появиться native command/projection и GUI сценарий.
7. **Группы и права.** Для будущего M05 список допустимых действий отдаёт Veil controller. [Rocket permissions](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/lib/hooks/usePermissions.ts) основаны на его roles, а [Veil channel overwrites](../../veil-server/internal/db/channel_overwrites.go) имеют собственный порядок allow/deny; переименование роли не заменяет вычисление прав. Rocket workspace/team/room нельзя механически подставить вместо Veil Node/Space/Room: Node задаёт границу подключения, Space — продуктовую структуру внутри неё.

## Зависимости и сопровождение

[Rocket package.json](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/package.json) использует RN 0.81.5, Expo 54, React 19.1 и Reanimated 4.1.3; [Veil](../../veil-mobile/package.json) — RN 0.79.6, Expo 53, React 19.0 и Reanimated 3.17. React Navigation 7 и Zustand уже близки. Проверить конкретные worklets/keyboard APIs и Android build; перенос всех upstream dependencies не является решением version gap. При необходимости обновление native platform выделить в самостоятельное изменение с проверкой UniFFI/lifecycle.

Переносить только используемые UI helpers и зависимости. Rocket SDK, WatermelonDB persistence, mobile-crypto, auth/server Redux pipeline, uploads, VoIP/WebRTC, analytics и push adapters не входят в первый scope. Upstream [RoomItem stories](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/containers/RoomItem/RoomItem.stories.tsx) и [Message stories](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/containers/message/components/stories/Message.stories.tsx) полезны как визуальные эталоны; их mock store не переносится в production.

Хранить выбранный subset отдельно от наших presenters, фиксировать upstream commit и перечень локальных изменений. Обновления применяются к выбранным компонентам осмысленно; исправления upstream не попадут в extracted UI автоматически. Не обещать стоимость сопровождения как у обычной npm библиотеки.

Корневая [MIT license](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/LICENSE) разрешает такой перенос с сохранением notice. В `app/ee` существует [отдельная лицензия](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/ee/LICENSE) с client-side MIT исключением. Первый Direct subset не требует этих screens. Для выбранных files, third-party dependencies, fonts/icons и assets составить точный attribution inventory; логотипы и product branding заменить Veil.

## Порядок и предварительный объём

Это инженерные диапазоны для планирования, а не измеренный срок. Предполагаются один опытный React Native разработчик с пониманием native bridge, исправная Android/Rust toolchain и доступный тестовый Node. Настройка отсутствующего MSVC linker, большие platform upgrades и backend reliability R01–R24 не включены автоматически.

| Этап | Результат | Предварительный объём |
|---|---|---|
| M00 проверочный прототип | Зафиксированный UI subset, version/dependency решение, реальный список/разговор в Veil APK и проверенная native send граница | 3–5 рабочих дней как ограниченный бюджет проверки; при unresolved build/coupling — пересчитать план |
| M01–M04 Direct клиент | Вход/unlock/Node, реальные беседы, поиск/create после R13, text/send/history/errors, stable IDs, keyboard/back/lock и проверенный tester APK | Ориентир 4–8 недель включая M00; дополнительные core fixes и ожидание R13 учитываются отдельно |
| M05 расширенный клиент | Вложения/reply/offline/background/trust и затем полноценные Circle/Space/Room | Несколько месяцев; детализация по готовности native contracts, не только по числу экранов |
| Полный fork всего Rocket клиента | Переработанная platform оболочка и полный список выбранных функций | Отдельный крупный проект на месяцы; преимуществ по сроку пока не доказано |

Для M00 сначала достаточно перенести один настоящий `RoomItem`, одну native message projection и text composer в текущий Veil build. Затем довести остальные части трёх экранов. Не требуется заранее завершать весь backend roadmap, но готовый поиск и GUI tester остаются зависимостями M02/M04.

Прототип считается успешным, когда:

- Rocket компоненты показывают реальную native беседу и историю; выбранный экран достижим из штатного GUI.
- Native accepted send даёт одну строку из projection, rejection сохраняет draft; pending → ACK сохраняет устойчивое отображение.
- Входящая revision обновляет переписку, back/keyboard/insets работают на небольшом Android экране.
- Lock/account/origin change очищают providers и draft согласно scope; старый callback не воздействует на другую беседу.
- Dependency diff и source inventory подтверждают отсутствие второго durable message store и Rocket crypto/network authority.

Полная GUI готовность закрывается M04, а пользовательская связь ПК ↔ Android проверяется после неё в R24b. Скриншот, Storybook или library test не заменяют этот результат.
