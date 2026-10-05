# Veil mobile design workbench

## После Live 09: общая граница и настоящий текстовый Direct

`ConversationSurface` — общий header/composer/body; `TimelineMessage` и `TimelineConversation` определены только в `conversationContract`. `messageGrouping` и `deliveryPresentation` работают с этим контрактом. `DesignConversation` управляет demo reply/actions/attachments; `NativeDesignTimeline`, подключённый вместо `ChatIsland`, использует существующий `useDirectTimelinePresenter` и `directDesignAdapter`. Ошибка native остаётся ошибкой, fixtures в этот путь не импортируются. Это подключённый код настоящего клиента, а не подключение account runtime к изолированному Design APK.

`DesignApp` собирает навигацию и feature-контроллеры; `useDesignAppearance` отвечает только за оформление. Детерминированные данные длинной истории выделены в `historyFixtures`. `verify-conversation-boundaries.mjs` проверяет runtime-циклы, отсутствие demo/native/store реализаций в общих компонентах и изоляцию native от fixtures.

Native drafts и scroll anchors хранятся раздельно по origin/account/generation/conversation, только в памяти; privacy clear их удаляет. Anchor — стабильный message ID, не только pixel offset. Нельзя восстанавливать текст под другой authority. Native projection ограничена существующим API (100 сообщений); older-history pagination не изобретена.

FFI намеренно объединяет внутренние delivered/read с sent. UI показывает только Sending/Sent/Failed/Unknown; Sent — не доказательство прочтения. Native capabilities reply/edit/delete/attachments/retry/read receipts отсутствуют. Demo attachments и остальные demo actions остаются в отдельном entrypoint.

`AccessibilityFocusBoundary` получает платформенный запрос через prop. Общая presentation не импортирует Android implementation. Для isolated design-host добавлен только UI helper `DesignAccessibilityModule`: существующее Android `View.performAccessibilityAction(ACTION_ACCESSIBILITY_FOCUS)` на прикреплённом React view, без разрешений, сети, аккаунта или новых методов Rust/Direct. Он нужен для проверки возврата фокуса после закрытия native Dialog на Samsung TalkBack; account runtime его не регистрирует. Остальной UI использует существующий React Native ref-based accessibility API. Timers отменяются при новом modal, смене навигации и unmount.

Android release `:designPreview:assembleRelease` содержит Hermes bundle и не требует Metro. Production signing и account capture policy не меняются. Проверки конкретного APK, холодного старта, TalkBack и font scale записываются в `docs/design/mobile-frontend-progress-2026-10-05.md`; исходники и артефакты фиксируются точным snapshot, без выдачи dirty tree за чистый commit.

Изолированный интерфейс на вымышленных данных. Настоящие аккаунты, транспорт и криптография здесь отсутствуют.

## Ответственность модулей

| Модуль                                                                | Ответственность                                                                                                      |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `DesignApp.tsx`                                                       | Собирает экраны, владеет demo-session и командами переходов; не рисует строки истории, списки каналов или настройки. |
| `NavigationPanel.tsx`                                                 | Док, личные/групповые чаты, поиск и каналы пространств; положение своего списка.                                     |
| `ChatDeck.tsx` / `navigation.ts`                                      | Удерживаемые слои, жест и анимация; чистые переходы выбрать/раскрыть/вернуться.                                      |
| `ConversationScreen.tsx`                                              | Заголовок, состояние разговора, композиция истории и поля ввода; узкие props и callbacks.                            |
| `ConversationHistory.tsx` / `history.ts`                              | Виртуализированная история, старые страницы, чтение и переход к последним; расчёты отделены от native списка.        |
| `Composer.tsx`                                                        | Управляемый многострочный ввод, ограниченная высота и отправка; не создаёт ID или сообщения.                         |
| `KeyboardFrame.tsx`                                                   | Единственный владелец изменения размеров при клавиатуре, вокруг полного viewport.                                    |
| `UserProfile.tsx`                                                     | Парящий профиль и его раскрытая панель.                                                                              |
| `AppearanceSettings.tsx` / `LockPreview.tsx` / `PreviewSheet.tsx`     | Отдельные панели оформления, блокировки и demo-сценариев.                                                            |
| `Primitives.tsx` / `appearance.ts`                                    | Повторно используемые кнопки/подписи и общие tokens оформления.                                                      |
| `model.ts`                                                            | Fixture DTO и чистые операции session/draft/send/retry/receive.                                                      |
| `appearanceBridge.ts` / `preferencesBridge.ts` / `clipboardBridge.ts` | Явные design-only native возможности: обработка подложки, сохранение оформления и запись clipboard.                  |

Поток данных: **session → props → presentation → callbacks → session**. Локальное состояние компонента — только его UI: высота ввода, вкладка профиля, позиция/загруженный диапазон истории. Черновик и сообщение не дублируются в нескольких компонентах. Поведение не зависит от цвета темы.

## Общие правила

1. Цвета берём из семантической `Palette`, без условных стилей под имя темы. Пять пресетов определены один раз в `appearance.ts`.
2. Прямоугольные поверхности используют `geometry.radius` (20dp). Внутренний clip концентричен рамке; круглые аватары/точки и уменьшенные образцы сохраняют свои формы. Интерактивные цели — минимум `geometry.touchTarget` (48dp).
3. Одинаковые роли текста используют `typography`. Размер системного шрифта не отключаем. Composer ограничивает число видимых строк с учётом fontScale.
4. Общие `motion` tokens и reduced motion применяются к переходам. Жест выполняется на UI-потоке. Не захватываем native объекты в worklets.
5. Стили находятся рядом со своим компонентом; общие значения — в tokens. Не создаём второй центральный файл со всеми стилями. Один компонент отвечает за экран, панель или самостоятельное поведение; не выносим каждый `View` в отдельный файл.
6. Новый функциональный блок подключаем через props/callbacks. Presentation не импортирует root controller, account runtime или transport. Новые runtime-файлы явно включаем в AST guard и проверяем фактический граф.
7. Стабильные message ID — ключи списка. Не вычисляем смещение по предполагаемой высоте текста. Для prepend сохраняем native видимый якорь, а при append сохраняем первый загруженный ID.
8. Удержание посещённых списков ограничено конечным набором fixture-чатов. Перед реальным directory нужен ограниченный cache и восстановление по message ID; нельзя масштабировать это до неограниченного числа смонтированных разговоров.
9. В `model.ts` остаются только демонстрационные операции. При подключении Veil источник команд, ID, статусов и разрешений — native/Rust adapter. `accepted` не изображает доставку или прочтение.
10. Единый формат TypeScript/TSX: 2 пробела, single quotes, trailing commas; Prettier 3.6.2. Не добавляем runtime-зависимости для форматирования.

## Проверки

Из `veil-mobile`:

```text
node node_modules/typescript/bin/tsc --noEmit
node node_modules/eslint/bin/eslint.js src/interfacePreview --ext .ts,.tsx
node scripts/verify-design-preview-source.mjs
node node_modules/jest/bin/jest.js --runInBand src/interfacePreview src/__tests__/App.runtimeGate.test.tsx
```

Тестируем пользовательские переходы и границы, а не снимок каждого style. Jest не подтверждает реальную клавиатуру, smooth scrolling, TalkBack или native сохранение якоря: эти проверки выполняются на телефоне. Release APK и Live APK проверяются отдельно; Live debug не служит замером release-производительности.

Сообщения и черновики остаются в памяти до перезапуска; оформление сохраняется отдельно. Позиция истории сохраняется при доке и переключении разговоров; demo-блокировка размонтирует рабочий экран. Ссылки в fixtures — обычный текст и не открываются. Design 08 реализует локальные действия, Design 09 — встроенные demo-вложения. Настоящие галерея/файлы/загрузка и подключение к backend не реализованы.

## Design 08: сообщения

messageActions.ts владеет правами и чистыми переходами: replies/edits по chat ID, edit-buffer отдельно от drafts, replyTo по message ID, удаление сохраняет tombstone без текста. Не хранить копию оригинального текста в цитате. useMessageInteractions владеет выбранным ID, командами и краткой обратной связью; presentation получает узкие callbacks. MessageActionsPanel, MessageQuote и MessageRow не меняют session напрямую. useQuoteNavigation подгружает ID и подтверждает видимость строки; timer ограничен и очищается при уходе/жесте/unmount. clipboardBridge предоставляет только явную запись через VeilDesignClipboard. Новые capability и runtime-файлы требуют точного обновления AST inventory, а native capability — пересборки Live APK.

Редактирование/удаление в fixtures не определяют серверные гарантии. Не переносить локальные разрешения в реальный клиент без native/Rust-контракта.

## Design 09 и граница Direct

`deliveryPresentation.ts` уменьшает только повтор одинакового обычного статуса в одной авторской серии. Attention остаётся у соответствующего сообщения (у вложения — внутри карточки). Отдельная accessibility label сохраняет факт каждой реплики. Mobile API не различает delivered/read: UI их не выдумывает.

`attachments.ts` — типы встроенных активов и чистые переходы choose/send/advance/cancel/retry. `useAttachmentTransfers.ts` — детерминированный adapter с ограниченными шагами, cleanup таймера и номером попытки. ID сохраняется при повторе, старые callbacks не оживляют отменённую операцию. `AttachmentCard`, `AttachmentVisual`, `AttachmentPanels` — presentation без транспорта. Подпись и reply остаются в своих chat-scoped drafts; отмена выбранного вложения сохраняет текст. Viewer удерживает историю смонтированной. SVG — встроенная иллюстрация; file metadata определяется фиксированным ASCII fixture body.

`useAppearancePreferences.ts` гидратирует оформление до показа экранов и объединяет записи через debounce/последовательный drain. `DesignPreferencesModule` принимает только allowlist оформления, использует atomic config и сохраняет одну обработанную подложку в приватном каталоге isolated app. Provider URI, исходные фото, сообщения, профиль, ключи и черновики не записываются. Ошибка хранения явно сообщается; настройки остаются в памяти. Фон при блокировке скрыт.

`conversationContract.ts` определяет presentation DTO. `presenters/directDesignAdapter.ts` читает существующий native text projection: stableUiId, direction, timestamp и sending/sent/failed/unknown. Не создаёт runtime или очередь. Unavailable не переключается на fixtures. Reply/edit/delete/attachments/retry/read receipts помечены unsupported в этой границе; адаптер пока не подключён к Design Live или account screen. UI ещё не является production Direct-клиентом.

Для APK из незакоммиченного рабочего дерева указывать базовый SOURCE_COMMIT вместе с SOURCE_PATCH_SHA256 (хеш manifest всех mobile-source файлов), сохранять исходный patch/new files и сравнивать manifest до/после сборки. Не подписывать рабочий diff как чистый Git commit. Live загружает JS динамически: snapshot подтверждает состояние сборки, дальнейшие Fast Refresh правки требуют новой фиксации при выдаче артефакта.
