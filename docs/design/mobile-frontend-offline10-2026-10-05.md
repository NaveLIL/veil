# Veil Mobile: автономная сессия после Live 09

Дата: 2026-10-05. Утверждённые острова, dock, парящий профиль, пять тем, радиус 20dp, targets 48dp, плотность сообщений, composer, самостоятельные фиолетовые цитаты и жесты сохранены. Redesign не выполнялся.

## 1. Сделано после Live 09

Разделены coordinator, demo controller, история, drafts/replies/attachments, transfers и appearance. `DesignApp.tsx` — 285 строк по isolation check; детали rendering/transport/persistence/timers вынесены в отдельные модули, огромный общий hook не создан. Demo и native используют canonical contract и общий `ConversationSurface`, `Composer`, `MessageRow`, `MessageQuote`, grouping/delivery. Runtime DAG проверен: cycles отсутствуют; 12 shared sources, 42 demo, 22 native. Общий UI не импортирует реализации транспорта, fixtures или native bridges; модели и design tokens не дублируются.

Исправлены labels/roles/state/actions, декоративные элементы, modal focus containment/return, увеличенные шрифты, appearance hydration и durable wallpaper. Для возврата TalkBack focus на Samsung добавлен только isolated design-host helper: существующий Android focus action на прикреплённом видимом React view. Новый Rust/Direct метод не добавлялся. Исправлены stale async results, scoped drafts/viewport anchors; добавлены regression fixtures и тесты. Настоящий текстовый Direct подключён в исходниках аккаунтного клиента через существующий API.

Сервер, Rust/core, криптография, протокол, trust model и production signing не менялись; публикации и Git-коммита нет.

## 2. Непосредственно на Android

ADB определил Samsung **SM-S911B**, Android **16**, 1080×2340, density 3. Проверки только в изолированном `io.veil.mobile.designpreview`, с вымышленными данными и собственными fixture images; реальные сообщения/аккаунты/галерея не читались.

Пройдены список/открытие чатов, длинная история, scrolling, keyboard/composer, reply/cancel, Copy, action sheet, attachments/cancel/retry, image viewer/Back, профиль/appearance, быстрые повторные действия. Проверены входящие при чтении старой истории, A → B → A, отдельные drafts и сохранение старого участка истории, reply/composer state, modal return.

Font/regression и часть TalkBack проходов выполнялись на release 05, APK SHA `b1f019cdb132d0fd2372009e9ddb9f8c84228550202c1c5d636aa0af1a0c74b5`. Final release 07 содержит **тот же побайтовый UI/Hermes bundle**, SHA `d6b7d24e0879afb70deace3fe52837034ef075e6730eec30d7c770ff6ba40dcd`; отличаются проверочные scripts и source manifest metadata. На самом final APK повторены TalkBack actions, appearance cold start/corruption, Reduce Motion и normal performance. Точная привязка проходов и снимков — в `PHYSICAL-CHECKS.json`.

## 3. Какая сборка работает без Metro

Комплект: `target/design-preview-20261005/a7d27f96989b-offline10/Veil-Design-10.apk`, версия `0.1.0-design.20261005.10`, package `io.veil.mobile.designpreview`, release/debuggable=false. Embedded JS/Hermes bundle внутри APK. Metro остановлен; финальный cold start подтверждён при **нуле listeners на 8081**. APK установлен и запускается самостоятельно. Это design/test клиент без регистрации, Access Pass, account DEX/libs/enrollment и network permission, с доступными скриншотами; для настоящей переписки не предназначен.

APK SHA `aa1c062291c7c246e8dc252f1633eba1f5d12b0ec04610a284fefd62d0018ae9`, 39 496 874 bytes. Отдельный tester certificate SHA `f5df868d3f517c0853225840e2c4f67f2d7b20d05b183bf1ab396e530fc3f250`; production signing не использован. Windows AGP/Prefab host adapter отражён в build log — это локальная сборка, не CI.

База Git `8bbdf3ff154d9b7182be6a1ce295550be9c93b53`. SHA manifest **290 mobile-файлов**: `a7d27f96989ba3d475024f57f65ccaa4c576567df8e3bf5506d46613ac97e9b9`. Комплект содержит полный source snapshot, tracked binary diff, проверки/снимки и SHA256SUMS; credentials не включены. Предыдущий `61c74ab43140-live09` сохранён.

## 4. TalkBack / font scale / Reduce Motion

TalkBackService реально включался на телефоне, `touchExplorationEnabled=true`. Android nodes/actions/focus проверены инструментально: 18-step focus pass, 31-step peer/media/retry/viewer и 28-step final composer/reply/copy/profile/settings, целевые действия приняты. Modal не выставляет фоновые chat/composer nodes; закрытие возвращает focus к инициатору (сообщение, attachment button, image card, профиль). Декоративные avatar/иконки исключены, message labels содержат направление/текст/время/реальное состояние; long-press имеет accessibility action. Для жестовой навигации есть явные Back/return buttons. Это не только JSX inspection. Spoken audio не записывался; экспертный ручной аудит произношения/всех TalkBack-жестов остаётся отдельной проверкой.

**100/130/150/200%**: cold start и список, chat/header/messages/time/badges, action sheet, reply + image preview + caption + keyboard, profile/appearance. Основной font scaling сохранён; глобального уменьшения шрифта нет. На 200% keyboard оставляет мало истории, но send и обе отмены доступны; настройки scrollable. Полное имя остаётся в a11y label при ellipsis. Исходный font_scale **1.0** возвращён.

Reduce Motion включён/выключен через настоящий Android Switch; проверены persisted true/false, навигация/swipe/reply/cancel/actions. Первый harness выбирал соседний TextView с таким же label, поэтому этот проход не засчитан; повтор выбирает Switch по class и фиксирует реальные boolean. Системные animations не менялись. Исходные accessibility services, включая Norton, восстановлены; TalkBack возвращён в исходное выключенное состояние.

## 5. Appearance persistence

Wallpaper теперь копируется из cache в собственный durable files directory; JSON пишется атомарно, validated allowlist и serial saves исключают stale overwrite. Hydration gate показывает нейтральный чёрный фон до восстановления, а не default theme.

На final APK существующим native save/load сохранены **Ocean + собственный JPEG + dim 35 + blur 8**. После нового процесса вернулись те же managed URI и значения, изображение реально отрисовано (`design10-final-wallpaper-cold.png`). Truncated JSON `{truncated` дал безопасный OLED/20/4/null wallpaper. Missing/invalid/oversize image и устаревшие поля имеют fallback; hydration/сериализация/ошибки/unmount покрыты тестами. После проверки возвращены OLED/стандартный фон/Reduce Motion false. Пользовательская галерея не открывалась; picker проверен fixture-путём. Покадровый высокоскоростной аудит возможной вспышки не проводился.

## 6. Реальный Direct

`DirectConversationScreen` → `ChatIsland` → `NativeDesignTimeline` → общий UI. Existing presenter/store/directory/runtime events используются для списка, истории, отправки и входящих; `directDesignAdapter` отображает canonical DTO. Native failures/loading/unavailable остаются честными ошибками, скрытого demo fallback нет. Scoped drafts очищаются после принятия неизменённой версии и совпадения account/origin/generation; pending/inflight guards препятствуют дубликатам. Viewport хранит stable message ID + following state, не только pixels; privacy/authority changes очищают transient state.

Контракт: `veil-ffi/src/lib.rs:513–520,676–681`; `veil-mobile/src/native/runtime.ts:76,834,908`. Внутренние `1..=3` намеренно объединены FFI в **Sent**. Mobile UI знает только Sending/Sent/Failed/Unknown, не симулирует Delivered/Read и не считает Unknown безопасным для retry. Повтор ordinary sent скрывается только внутри одинаковой валидной группы; attention остаётся у конкретного сообщения, индивидуальные a11y labels сохраняют все состояния.

Аккаунтные JS bundle и Kotlin успешно собраны: `:app:createBundleInternalTesterJsAndAssets`, `:app:compileInternalTesterKotlin`. Production bundle проверен по **3205 source entries**, разрешает общий presentation и запрещает demo реализации. Реальный обмен ПК ↔ телефон с authentication/PIN/trust **не проверен**: установлен design host, Access Pass/test identity для account E2E не подготовлены. Source integration не выдаётся за успешный E2E.

## 7. Что demo и почему

Attachments/upload/retry, reply, edit/delete, image viewer — изолированный demo. Готового native/Rust контракта encrypted attachment metadata/key/transport и этих операций нет; capabilities настоящего Direct выключены. Новый протокол, криптографический API или JS outbox не добавлялись. Native history ограничена текущей проекцией (100 сообщений), вымышленной pagination нет.

Пять тем/полные dock/profile/appearance пока в design shell. Реальному клиенту подключены общие message renderer/composer с сохранением существующих account navigation/identity/security gates; весь account shell ещё не мигрирован.

## 8. Regression / state / races / tests

720-message deterministic dataset: A A A A B B A, 20 коротких подряд, emoji/символ, длинные имя/URL/текст/reply, attachment + reply, даты, mixed sending/failed/unknown/sent. Grouping требует одинаковых author/direction/day и известного неотрицательного интервала ≤5 минут; неизвестные facts не заменяются вымышленными. Reply/media не ломают author grouping.

49-step physical regression: incoming при чтении старой истории оставляет позицию и счётчик 3; A/B drafts отдельные; быстрые Reply → Cancel → Reply, attachment → cancel, повтор Send, viewer/Back не дали дублей или зависшего backdrop. Единственный rejected action — третья прокрутка уже достигшего конца settings списка. Attempt IDs, same-message retry, stale scope/callback rejection, unmount timers/listeners, reply lifecycle и stable anchors проверены тестами. Состояние сообщений/drafts/reply/scroll transient между экранами внутри процесса; нового durable account format нет.

**323 tests / 47 suites проходят**, прежние 79 сохранены без отключений. Добавлены meaningful tests grouping/status, drafts/viewports, reply, retry без дубликатов, stale async, wallpaper restore, focus cleanup, native mapping/capabilities/errors. Initial probes с ошибочными selectors, transient window gap или Binder size исправлены и не названы успешными проверками приложения.

## 9. TypeScript / ESLint / build

TypeScript passes; полный ESLint **0 errors / 0 warnings**; source/isolation/APK verifiers passes; isolated release и account Kotlin/JS checks passes. Команды из `veil-mobile`:

```text
node node_modules/jest/bin/jest.js --runInBand
node node_modules/typescript/bin/tsc --noEmit
node node_modules/eslint/bin/eslint.js . --ext .js,.mjs,.ts,.tsx
node scripts/verify-design-preview-source.mjs
node scripts/verify-conversation-boundaries.mjs
node scripts/verify-android-production-bundle.mjs
```

Существующие warnings сохранены в логах: Gradle deprecated features incompatible with future Gradle 9; bundle workers NO_COLOR ignored because FORCE_COLOR. Старое production-bundle правило требовало legacy RocketMessage/Composer после их замены; обновлено под реальный общий renderer и дополнено запретом demo deps. Прочие security/license guards сохранены. Package manager/lockfile не менялись.

## 10. Release performance и ограничения

Final APK, Metro off, обычные ADB inputs без instrumentation/tree capture внутри frame sample: 20 прокруток длинной истории, **2678 frames / 3 janky (0,11%)**, p50 19ms / p90 20ms / p95 20ms / p99 23ms (Android gfxinfo). `am start -W`: COLD/TotalTime 192ms — activity launch, не полная JS-ready latency.

Instrumented mixed regression с accessibility trees/keyboard/modals/bitmap uploads: 841 frames / 106 janky (12,60%), p50 9ms / p90 13ms / p95 23ms / p99 65ms. Это дополнительная нагрузка harness; обещания стабильных 60/120 FPS нет. Keyboard/reply/actions/viewer/navigation проверены функционально на release; mixed-transition tail требует отдельного точечного profiling pass. Большой premature optimization не выполнялся.

## 11. Blockers и следующий этап

- Реальный account E2E: требуется тестовый Access Pass/identities/public trust configuration и отдельная account tester сборка. Source text Direct подключён; дальше фактический обмен с ПК/cold start/ошибки через существующие security gates.
- Native media/reply/edit/delete/retry: отсутствует контракт; core/protocol/trust расширение — отдельный согласованный этап, без незаметного demo fallback.
- Полная миграция account shell (dock/profile/appearance) ещё впереди; общая UI boundary готова.
- iOS не проверен на Windows; TalkBack spoken/manual audit и mixed-transition profiling остаются дополнительными проверками.

Следующий разумный этап — account tester text Direct E2E и затем постепенный перенос account shell в утверждённый frontend. Design release уже автономен, оставлен доступным на телефоне. Checkpoint не подменяет реальную backend/device проверку.
