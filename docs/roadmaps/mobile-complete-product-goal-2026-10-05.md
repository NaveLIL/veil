# Veil Mobile — общая цель полного product UI pass

## Цель и источник требований

Выполнить весь пользовательский промпт **«VEIL MOBILE — DESIGN 12 / COMPLETE PRODUCT UI PASS», разделы 1–31**, вместе с последующими уточнениями владельца. Результат — цельный настоящий мобильный Veil: ни одна обычная достижимая ветка не возвращает пользователя в визуально старое приложение, реальный Direct сохраняет работоспособность, а каждое заявление о готовности имеет проверяемое основание.

Это общая цель продукта, а не задача на один экран, набор ссылок или очередной APK. Checkpoint и публикация сборки не означают достижения цели. При недоступности телефона продолжаются независимые разрешённые задачи; физические проверки остаются незавершёнными до получения настоящего evidence.

Текущая ветка: `ce/mobile-design12-20261005`. Последний опубликованный checkpoint: **12.1**, source release commit `cfa7495`, документационный follow-up `85413ea`. База автоматических проверок: **377 Jest tests / 57 suites**, TypeScript, ESLint, архитектурные и isolation guards, обе Android сборки и строгие APK verifiers. Нельзя повторно выполнять завершённую миграцию только ради обновления номера Design.

Владелец подтвердил реальный desktop ↔ mobile text Direct на устройстве ранее и одобрил визуальный результат 12.1. Это не заменяет отдельный свежий Direct regression, TalkBack, проверки масштабов шрифта и измерение frame times на новой сборке.

## Общие ограничения

- Сохранить утверждённые острова, dock, ChatDeck, WallpaperSurface, floating profile, ConversationSurface, composer, message renderer, ProfilePanelFrame, VeilSheet, пять тем, радиусы, spacing, typography, плотность сообщений, reply UI и motion language. Redesign не выполнять.
- Не изменять Rust/core, protocol, crypto, trust model, Node/server или production signing. Не обходить Access Pass, PIN, security gates, account scoping или установленную capture policy. Не удалять существующий аккаунт ради установки tester APK.
- Не симулировать Delivered/Read, native reply/edit/delete/attachments, pagination, group permissions/roles/encryption. Не подменять native error демо-данными.
- Не добавлять reactions, stickers, stories, calls, voice, threads, bots и новый протокол вложений. Не проводить массовый dependency upgrade.
- Сохранить legal notices и attribution. Не логировать message content, private URLs, credentials, secrets, raw keys и чувствительные native errors. Не добавлять скрытые preview/metadata fetch или embedded WebView.
- Не объявлять проверку на устройстве по JSX, Jest, source inspection, APK verifier или наличию JS bundle.

## Milestones и критерии готовности

### M1. Цельность настоящего account client

Покрывает разделы **1–6, 18–19, 23–24**.

- [x] Утверждённый shared Veil design сохранён; обычные account screens используют общую presentation систему.
- [x] Reachable route audit записан в `docs/design/mobile-design12-2026-10-05.md`: Home, Direct, Contacts, profile, Settings/SettingsDetail, Appearance, About/diagnostics, account/recovery facts, devices, notifications, Node, storage, privacy, identity/trust, onboarding и runtime errors.
- [x] Contact Search presentation мигрирована без замены exact lookup, presenter, native authority и create Direct business logic.
- [x] Settings и профиль используют единые реальные settings definitions; About и account/security имеют разные назначения.
- [x] Shared Veil empty/loading/error/capability presentation и согласованная русская пользовательская copy внедрены в мигрированные маршруты.
- [x] Native protected recovery/unlock/enrollment ceremonies классифицированы отдельно и сохранены.
- [x] Reachable legacy presentation imports устранены, legal attribution сохранена, cycle/isolation guards проходят.
- [ ] На настоящем account APK физически пройти весь route audit, включая contact empty/result/not found/error/unavailable, keyboard и create/open Direct. Проверить, что обычная пользовательская ветка действительно не попадает в legacy UI.

### M2. Навигация и сохранение пользовательского контекста

Покрывает разделы **4, 7–8, 11–12, 16–17**.

- [x] Закрытие directory search очищает невидимый фильтр; contact query/result сохраняются при Direct → Back.
- [x] Nested settings stack и единая смысловая модель видимого/system Back реализованы и покрыты meaningful tests.
- [x] Demo profile editing имеет отдельный draft; Save применяет, Cancel/выход отменяет; server profile update не имитируется.
- [x] Группировка и Sent на релевантной границе группы сохранены; Sending/Failed/Unknown остаются при конкретном сообщении.
- [x] Ненужная кнопка возврата к последнему чату удалена; существующий возврат свайпом и владение draft сохранены.
- [ ] Пройти на устройстве Profile → Settings → Appearance/About → Back и Chat → peer profile → identity verification → Back → тот же chat/viewport.
- [ ] Физический daily-driver сценарий: Home → Contacts → Direct → profile/settings/appearance → Back → chat switching → link → Back, без потери draft, focus, navigation и viewport ownership.

### M3. Sheets, motion, live blur и Reduce Motion

Покрывает разделы **9–10, 20, 22** и последующие замечания владельца.

- [x] Обычные dismiss paths, stale completion rejection, reopen/reversal, nested Back и Reduce Motion gesture cancel покрыты автоматическими тестами.
- [x] Panels имеют accessible swipe-down/grip dismissal без крестиков закрытия.
- [x] Реальный Android RenderEffect blur используется на поддерживаемой платформе, без bitmap/scrim подмены.
- [x] 12.1 устраняет путь first-frame entry jump и переключение blur сразу на полную силу; native blur плавно меняется на Android frame clock, закрытие/последний Reduce Motion owner обработаны.
- [x] Владелец одобрил результат 12.1; это user visual feedback, не инструментальный benchmark.
- [ ] На устройстве проверить short/half swipe cancel, reverse, rapid close/reopen, Back during transition, nested ownership и Reduce Motion branches. Проверить отсутствие невидимого modal/backdrop и двойных callbacks.
- [ ] На standalone release с остановленным Metro точечно измерить Contact Search/Settings/nested panel/profile/sheet/chat switching/keyboard/live blur. Записать метод, before/after только при реально измеренном bottleneck.

### M4. URL interaction — текущий следующий этап

Покрывает разделы **13, 30**.

- [ ] Shared renderer распознаёт явные http/https URL и сохраняет текущую плотность/группировку сообщений.
- [ ] Нажатие пользователя передаёт URL через presentation command boundary в existing safe platform flow; UI не импортирует transport/native implementation.
- [ ] Автоматические preview/metadata fetch и WebView отсутствуют; private URL/raw exception не попадают в logs или global toast.
- [ ] Проверены punctuation, очень длинные URL, несколько ссылок, long press actions и accessible equivalent для TalkBack.
- [ ] Ошибка/отмена открытия показана честно и без утечки данных; stale result другого conversation/account scope не меняет текущий UI.
- [ ] Возврат из platform browser сохраняет draft, выбранный chat и viewport. На устройстве проверены http, https и Back.
- [ ] Design preview остаётся явно offline: никаких обходов его no-network isolation ради демонстрации ссылок.

### M5. Поиск по доступной истории Direct

Покрывает разделы **14, 30**.

- [ ] Поиск работает по текущей доступной native/local projection и обозначен именно так, без обещания поиска по всей истории.
- [ ] Query/result selection принадлежит chat scope; переход к результату, краткая highlight, Back/close и восстановление viewport предсказуемы.
- [ ] Проверены empty/no matches, длинный текст/URL, target visible/outside viewport/at boundary/unavailable, incoming message и переключение чатов.
- [ ] Будущая native pagination/search capability отделена; не придумываются native методы или фиктивные loading states.
- [ ] Meaningful tests и физический проход закончены, Reduce Motion и TalkBack работают.

### M6. Финальная валидация Design 12 и real Direct regression

Покрывает разделы **15, 20–22, 27–29, 31**.

- [ ] Account APK: real directory/contact create, mobile → desktop, desktop → mobile, несколько сообщений, conversation switch, background/foreground и cold reopen пройдены после крупных UI изменений.
- [ ] 48dp targets, keyboard, safe areas, gesture navigation и 100/130/150/200% font scale проверены без отключения scaling.
- [ ] TalkBack: labels/roles/states/actions, порядок focus, modal containment/return, доступные альтернативы gesture-only функциям проверены на Android.
- [ ] Deterministic app-content baselines: Home/list/Direct/profile/Settings/Appearance/About/Contact Search empty/result/error/large font/runtime unavailable.
- [ ] После новых изменений проходят tests, TS, ESLint, isolation/cycles, production JS verifier, Android builds/APK checks. Существующая тестовая база не потеряна.
- [ ] Документация отражает настоящий код и полный Design 12 DoD (все 15 условий раздела 29), а не только последнюю публикацию APK.
- [ ] Остаточные blockers точно названы и подтверждены. Разрешённые environment blockers документируются отдельно от выполненных device gates; они не превращают непроверенную функцию в VERIFIED.

### M7. Design 13 — Spaces

Покрывает разделы **25–26, 30**, после завершения Design 12.

- [ ] Один цельный flow: dock → space → categories → channel → read → channel info → members → Back → тот же channel.
- [ ] Много/пустые/collapsed categories, много каналов/участников, длинные названия и context restoration проверены.
- [ ] Если готового real native contract нет, flow явно DESIGN/DEMO; production capabilities, group permissions/roles/encryption не выдумываются.
- [ ] Общие UI primitives, themes и motion остаются едиными, без второго UI kit.

## Coverage всего исходного промпта

| Разделы | Где закрываются |
| --- | --- |
| 1–3 | M1: approved design, полный reachable audit и Contact Search |
| 4 | M1/M2: видимый search state |
| 5–6 | M1: реальные единые Settings и отдельный About |
| 7–8 | M2: nested navigation и согласованный Back |
| 9–10 | M3: sheet dismiss semantics и Reduce Motion |
| 11–12 | M2: profile draft Save/Cancel и contact context |
| 13 | M4: явное безопасное URL interaction |
| 14 | M5: честный поиск по доступной истории |
| 15–17 | M2/M6: работающий Direct, message UI и daily-driver sequences |
| 18–19 | M1: общие states и copy consistency |
| 20–22 | M3/M6: touch/font/accessibility, baselines, release profiling |
| 23–24 | M1: архитектура и removal legacy presentation |
| 25–26 | M7 и ограничения: Spaces после Design 12, без feature sprawl |
| 27–29 | M6: device pass, tests и все условия Design 12 DoD |
| 30 | M4 → M5 → M7: обязательный порядок дальнейших задач |
| 31 | Итоговый отчёт и evidence categories ниже |

## Текущие environment blockers

- Авторизованный Tailscale ADB endpoint последнего телефона `100.116.192.6:34183` недоступен, последний reconnect завершился timeout. Новый physical pass не состоялся.
- На ранее подключённом SM-S911B установлен старый account APK с другим signer. In-place update новым tester key несовместим; действующий аккаунт не удаляется. Другой совместимый tester device или официально предназначенный matching tester key позволяет продолжить этот device pass.
- Production certificate не provisioned; production signing не меняется. Это ограничение production readiness, не ошибка успешно собранного internal tester.
- Наличие/валидность Access Pass не проверяется по случайным файлам и не выдумывается. Credential blocker допустимо объявить только после конкретной readiness проверки, отдельно от connectivity/signing blocker.

## Definition of done общей цели

Окончательное закрытие охватывает весь исходный промпт, а не ближайший milestone. Отчёт содержит найденные/migrated/native security routes; Contacts/Settings/About; Back/context; sheets/motion/profile edits; links/search/Spaces; real Direct regression; device/accessibility/font/Reduce Motion/performance evidence; tests/TS/ESLint/builds; все остающиеся blockers.

Обязательные категории: **VERIFIED ON DEVICE**, **VERIFIED AUTOMATICALLY**, **VERIFIED BY SOURCE INSPECTION**, **DEMO ONLY**, **BLOCKED / NOT VERIFIED**. Пользовательское подтверждение учитывается отдельно как **USER VERIFIED**, с указанием проверенного объёма.

В этом чате инструмент целей пока содержит старую незавершённую цель account integration со статусом `blocked`. Попытка создать новую общую карточку отклонена инструментом: unfinished goal exists. Старая цель не объявляется complete ради замены; этот документ фиксирует полный актуальный объём, пока нет возможности заменить карточку. Это ограничение трекера, а не причина приостановить независимую безопасную разработку.
