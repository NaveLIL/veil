# Готовые основы мобильного интерфейса Veil

Дата: 4 октября 2026 года. Это исследование исходников и предложение для выбора frontend, а не результат сборки или интеграции кандидатов. Дополняет [дорожную карту](../roadmaps/backend-and-mobile-reliability-2026-10-04.md), задачи M00–M05.

Полноценного графического клиента Veil на телефоне сейчас нет. Цель — взять готовые экраны и компоненты и подключить их к существующему Veil runtime. Наш текущий стек: React Native 0.79.6, React 19.0, Expo 53, React Navigation 7, Reanimated 3.17 и Zustand 5: [package.json](../../veil-mobile/package.json).

## Рекомендация

После уточнения предпочтения пользователя **первым исследовать перенос настоящего интерфейса Rocket.Chat в существующее приложение Veil**. Его список бесед, экран переписки, оформление и взаимодействия лучше соответствуют желаемому продукту. Конкретная граница переноса и оценка сложности изложены в [плане адаптации Rocket.Chat](rocket-chat-frontend-adaptation-2026-10-04.md).

Предыдущая рекомендация проверить Ctere1 и `@kesha-antonov/react-native-chat` опиралась на меньшую связанность с чужим backend. Их оставить в сравнении как запасные варианты; небольшая стоимость адаптации не заменяет требуемое качество интерфейса. Первый build/adaptation spike теперь проверяет Rocket.Chat, а не сравнивает эти два шаблона.

Первый объём Rocket.Chat — три экрана: беседы, поиск/выбор собеседника, текстовая переписка. Сохраняем исходные presentation компоненты, заменяем providers и data actions на Veil. Полный fork, имитация Rocket.Chat server и окончательная frontend зависимость пока не выбраны; пригодность этого пути требует рабочего Android прототипа.

## Кандидаты, которые стоит сравнить

| Основа | Что действительно готово | Связь с чужим backend | Оценка для Veil |
|---|---|---|---|
| [Ctere1/react-native-chat](https://github.com/Ctere1/react-native-chat) | Приложение: Chats, Chat, Users, Group, Settings и account screens | Firebase auth, Firestore subscriptions, uploads, собственные pending messages | Запасной шаблон небольшой оболочки; взять presentation, заменить data layer |
| [@kesha-antonov/react-native-chat](https://github.com/kesha-antonov/react-native-chat) | UI одной переписки: список, composer, темы, reply/reactions и custom renderers | Сообщения и callbacks передаёт host приложение; чужой chat server не требуется | Запасной UI переписки; не заменяет оболочку приложения |
| [Rocket.Chat.ReactNative](https://github.com/RocketChat/Rocket.Chat.ReactNative) | Полный клиент с Direct, rooms, composer, вложениями и server/workspace navigation | Rocket.Chat SDK, REST/realtime, room stores, WatermelonDB, crypto/token pipeline | Предпочтительное направление пользователя; первый прототип проверяет перенос трёх Direct экранов |
| [OpenIM React Native demo](https://github.com/openimsdk/openim-reactnative-demo) | Контакты, список бесед, private/group chat, profile/settings | OpenIM native SDK, его message IDs, models, history и storage | Запасной полный шаблон; замена SDK потребует отдельного адаптера и удаления чужой state authority |

### Проверенные версии и лицензии

| Основа | Исследованный срез | Стек и лицензия |
|---|---|---|
| Ctere1 | [Commit 20.03.2026](https://github.com/Ctere1/react-native-chat/commit/e8b24b03a66c16c94574fbe4e82dfeaf47d7cc33) | [Expo 54, RN 0.81.5, Navigation 6, Reanimated 4, Gifted Chat 2.6.5](https://github.com/Ctere1/react-native-chat/blob/e8b24b03a66c16c94574fbe4e82dfeaf47d7cc33/package.json); [MIT](https://github.com/Ctere1/react-native-chat/blob/e8b24b03a66c16c94574fbe4e82dfeaf47d7cc33/LICENSE) |
| React Native Chat | [v5.0.1, 15.09.2026](https://github.com/kesha-antonov/react-native-chat/releases/tag/v5.0.1) | [Peer dependencies](https://github.com/kesha-antonov/react-native-chat/blob/v5.0.1/package.json) декларативно подходят нашим основным версиям; [MIT](https://github.com/kesha-antonov/react-native-chat/blob/v5.0.1/LICENSE); нужна отдельная проверка keyboard controller |
| Rocket.Chat | [4.77.0, 30.09.2026](https://github.com/RocketChat/Rocket.Chat.ReactNative/releases/tag/4.77.0), commit `0a7df3d82a2e9d20e37f9ec5651fd3c74b98ab36` | [RN 0.81.5, Expo 54, Navigation 7](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/package.json); корневая [MIT](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/LICENSE), отдельная [лицензия app/ee](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/ee/LICENSE) |
| OpenIM demo | [Commit 26.08.2026](https://github.com/openimsdk/openim-reactnative-demo/commit/140688ee7e9bedada5df822960e9d86d96d3352a) | [RN 0.73.6, React 18.2, Navigation 6, Zustand 4](https://github.com/openimsdk/openim-reactnative-demo/blob/140688ee7e9bedada5df822960e9d86d96d3352a/package.json); [AGPLv3](https://github.com/openimsdk/openim-reactnative-demo/blob/140688ee7e9bedada5df822960e9d86d96d3352a/LICENSE) |

Версия чужого package.json не переносится целиком. Сначала проверить выбранные компоненты на нашем native Android build. Для переносимых source files и assets сохранить upstream notices; итоговый dependency inventory проверяется отдельно от лицензии корневого репозитория.

## Что именно адаптировать

### Вариант A Небольшой готовый шаблон

У Ctere1 есть искомая оболочка и визуальные компоненты. Однако [Chats.js](https://github.com/Ctere1/react-native-chat/blob/e8b24b03a66c16c94574fbe4e82dfeaf47d7cc33/src/screens/Chats.js) напрямую подписывается на Firestore, а [Chat.js](https://github.com/Ctere1/react-native-chat/blob/e8b24b03a66c16c94574fbe4e82dfeaf47d7cc33/src/screens/Chat.js) связан с Firebase identity, pending messages и media upload. [chatMessageService.js](https://github.com/Ctere1/react-native-chat/blob/e8b24b03a66c16c94574fbe4e82dfeaf47d7cc33/src/services/chatMessageService.js) сохраняет pending messages в AsyncStorage.

Переносить layout списка, строки контакта, header/menu и presentation разговора. Авторизация остаётся в `App`/native Veil; email identity заменяется bounded Veil DTO. Firestore subscriptions заменяются native projections/revisions, send — native outbox, upload — encrypted Veil pipeline. Донорские pending storage и notifications не подключать к runtime Veil.

Это не замена одного Firebase URL: требуется переработка границ экранов. Размер шаблона делает такую проверку более ограниченной, чем fork большого клиента. Это инженерная оценка по исходникам, а не измеренный срок.

### Вариант B Готовый UI переписки в существующем приложении

Использовать `Chat` как renderer. Существующие `App`, identity setup, runtime gate, навигация и `useChatStore` сохраняют свои обязанности. Общий adapter преобразует native message projection в UI model и передаёт callbacks.

В [v5.0.1 `_onSend`](https://github.com/kesha-antonov/react-native-chat/blob/v5.0.1/src/Chat/index.tsx#L226) библиотека создаёт UI ID, меняет дату/автора и может очистить composer до callback; callback не ожидает native commit. Поэтому использовать [custom toolbar](https://github.com/kesha-antonov/react-native-chat/blob/v5.0.1/src/Chat/index.tsx#L295) или контролируемый ввод с явно проверенной семантикой acceptance. UI ID не становится domain message ID.

Новый обязательный peer — `react-native-keyboard-controller`, которого сейчас нет в Veil. [Официальная Fabric compatibility matrix](https://kirillzyusko.github.io/react-native-keyboard-controller/docs/guides/compatibility) связывает 1.18+ с RN 0.81+, а 1.16+ с RN 0.77+. Для RN 0.79.6 исследовать pinned совместимую ветку 1.16/1.17 и используемые API либо отдельный согласованный RN upgrade. Установка latest автоматически не является проверенным решением. Dev/test версия самого chat package новее нашей; Android build обязателен.

Оригинальный [Gifted Chat](https://github.com/FaridSafi/react-native-gifted-chat) объявил maintenance mode и направляет новые проекты в этот fork. Поэтому новая проверка начинается с fork, а не с предположения, что старый популярный пакет продолжает активную разработку.

### Вариант C Зрелый клиент каналов как донор

У Rocket.Chat доступны [RoomItem](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/containers/RoomItem/RoomItem.tsx) и [RoomsListView](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/views/RoomsListView/index.tsx). Их перенос теперь первый исследуемый путь для Home/списков.

Но [RoomView](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/views/RoomView/index.tsx), [MessageComposer](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/containers/MessageComposer/MessageComposer.tsx) и [database](https://github.com/RocketChat/Rocket.Chat.ReactNative/blob/4.77.0/app/lib/database/index.ts) содержат собственные stores, uploads, drafts и protocol assumptions. Извлечение presentation слоя нужно доказать маленьким прототипом по [детальному плану](rocket-chat-frontend-adaptation-2026-10-04.md). Полный fork с последующей заменой всех API не считается автоматически более быстрым.

## Остальные проверенные направления

| Клиент | Причина не ставить первым в текущем RN проекте |
|---|---|
| [Mattermost Mobile](https://github.com/mattermost/mattermost-mobile) | Полный поддерживаемый RN клиент, [Apache 2.0](https://github.com/mattermost/mattermost-mobile/blob/release-2.44/LICENSE.txt) и NOTICE. Но [Channel screen](https://github.com/mattermost/mattermost-mobile/blob/d295fa1c9e93d189b89f77dbe97c7b59fe60a1b7/app/screens/channel/index.tsx) и [PostList](https://github.com/mattermost/mattermost-mobile/blob/d295fa1c9e93d189b89f77dbe97c7b59fe60a1b7/app/components/post_list/post_list.tsx) связаны с WatermelonDB и Mattermost actions; дополнительная адаптация и другой navigation stack |
| [Element X Android](https://github.com/element-hq/element-x-android) | Kotlin/Compose и Rust/UniFFI близки к нашему native engine; возможен отдельный Android путь. Однако [MatrixClient](https://github.com/element-hq/element-x-android/blob/develop/libraries/matrix/api/src/main/kotlin/io/element/android/libraries/matrix/api/MatrixClient.kt) задаёт Matrix rooms/sync/verification, а не Veil DTO. AGPLv3/commercial dual license; смена UI стека и presenters — отдельное решение |
| [FluffyChat](https://github.com/krille-chan/fluffychat) | Полный Flutter клиент, AGPL-3.0-or-later. [Chat controller](https://github.com/krille-chan/fluffychat/blob/main/lib/pages/chat/chat.dart) использует Matrix Room/Timeline. Потребуются замена data layer и Dart/native bridge |
| [Zulip Flutter](https://github.com/zulip/zulip-flutter) | Нынешний mobile клиент на Flutter, [Apache 2.0](https://github.com/zulip/zulip-flutter/blob/main/LICENSE). [Store](https://github.com/zulip/zulip-flutter/blob/main/lib/model/store.dart) отражает Zulip realm/topics/event queue; это ещё одна крупная адаптация |
| [Flyer React Native Chat UI](https://github.com/flyerhq/react-native-chat-ui) | README прямо сообщает, что проект не поддерживается. Для нового выпуска modern RN сопровождение перейдёт к нам |

## Проверка выбора M00

1. Зафиксировать срез Rocket.Chat 4.77.0, нужные файлы, licenses/notices и минимальный dependency diff. Не менять серверный протокол ради UI.
2. В изолированном прототипе проверить настоящий Rocket renderer разговора и список/контакты; сопоставить их с существующими native DTO по [плану адаптации](rocket-chat-frontend-adaptation-2026-10-04.md). Этот spike проверяет возможность переноса, не заменяет готовность приложения M01–M04.
3. Собрать выбранные компоненты с текущим Android native project. Проверить keyboard/insets, навигацию, реальные IDs/статусы и отсутствие второго durable message store.
4. Измерить фактические правки, новые зависимости, оставшуюся работу по Home/Contacts/Settings и поддержку upstream. Если выбранные компоненты приходится глубоко форкать, это учитывается как наша будущая работа. К запасному варианту переходить по конкретному препятствию, а не только из-за меньшего числа файлов.
5. Зафиксировать одну выбранную основу и продолжить M01–M04; затем проверить ПК ↔ Android. До этого статуса пользовательская матрица остаётся закрытой отсутствием готового GUI.

Для всех вариантов источник messages — native projection; очистка draft следует native acceptance; неизвестный timestamp не заменяется выдуманным временем. Delivered/read не рисуются без соответствующих receipts. Reply/media/groups активируются вместе с их реальными контрактами M05. Ключи, plaintext durable storage, ratchet, retry и routing остаются в Rust/Kotlin/SQLCipher.

Итог исследования: готовые основы найдены, shortlist сформирован. Совместимость сборок и экономия интеграции требуют описанного spike; окончательная зависимость пока не принята.
