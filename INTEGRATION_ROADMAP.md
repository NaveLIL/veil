# Дорожная карта Veil

> Актуально на 2026-07-12. Это основной продуктовый и интеграционный план.
> [`ROADMAP.md`](ROADMAP.md) сохранён как исторический security/infra backlog;
> при расхождении приоритетов главным считается этот документ.

Базовый принцип Veil: интерфейс обязан правдиво показывать фактически
используемый режим защиты. Нельзя молча откатываться на plaintext или более
слабую криптосхему при ошибке распределения ключей. Если защищённая отправка
невозможна, она блокируется с понятным состоянием для пользователя.

Veil ещё не выпускался, поэтому runtime backward compatibility не является
продуктовым требованием. Устаревшие форматы, originless caches и UI-ветки нужно
удалять либо переводить явным cutover на текущую модель, а не поддерживать
параллельно. История миграций сохраняется только для воспроизводимой установки
схемы и проверяемого обновления development БД; она не оправдывает live fallback
или ослабление современных security/UX invariants.

Ближайший порядок работ:

1. Completion gate фаз 1–4C пройден и опубликован в
   [`docs/reviews/phase-1-4c-completion-gate.md`](docs/reviews/phase-1-4c-completion-gate.md).
2. Закрепить completion evidence для local-data Identity Island. Затем провести
   отдельный schema/privacy/security review versioned text profile и локальной
   verification/identity-change flow; network avatar ingest остаётся за своим
   decoder/privacy gate.
3. Довести вынесенные продуктовые scopes: Phase 3B (attachment UX), Phase 4P
   (device push clients) и Phase 4E (server experience), не смешивая их с
   завершёнными protocol/runtime baselines.
4. На стабильном desktop/profile фундаменте начать Android foundation (5A),
   после per-device модели подключить боевые сообщения Android (5B).
5. Затем довести MLS runtime, звонки и release polish.

## Статус по фазам

| # | Фаза | |
|---|------|--|
| 1 | Kobalte — headless UI | закрыто: composite controls/focus/keyboard/ARIA унифицированы |
| 2 | Tantivy — локальный поиск | готово, индекс теперь только в RAM |
| 3 | tus.io — загрузка файлов | core закрыт; desktop/2 GiB streaming UX вынесен в 3B |
| 4 | UnifiedPush / ntfy | transport core закрыт; device clients вынесены в 4P |
| 4A | Группы, серверы, роли | access/crypto core закрыт; product IA/settings вынесены в 4E |
| 4B | Desktop UX & Appearance | закрыто: visual/a11y/scale/wallpaper/Windows bundle зелёные |
| 4C | Server Channel Crypto Decision | baseline закрыт: exact-device/offline/ACK/atomic recovery реализованы |
| 4D | Identity Island & Profiles | product scope реализован, включая isolated avatar и mobile Identity sheet; финальный gate отложен |
| 4E | Server Experience | запланировано: group/server IA, settings и manual device matrix |
| 5A | Android foundation | визуальный прототип есть, runtime не подключён |
| 5B | Android messaging | не начато |
| 6 | OpenMLS | фундамент готов, runtime-ветвление выключено |
| 7 | LiveKit звонки | не начато |
| 8 | Полировка, релиз | частично: CI и Windows release workflow готовы |

---

## Phase 1 — Kobalte

**Статус 2026-07-12: закрыто.** Composite controls используют Kobalte
Dialog/Popover/Tabs/Portal, управляемые диалоги возвращают focus, emoji search и
keyboard navigation тестируются. Простые нативные `<button>`/`input` остаются
семантическими HTML controls: переносить их в headless primitive без composite
поведения не является требованием фазы.

Заменил self-rolled Dialog/Select/ContextMenu/Tooltip на Kobalte primitives. Смысл: a11y (focus trap, ARIA, клавиатурная навигация) бесплатно, не меняя визуал. Только `@kobalte/core` (unstyled) — не `@kobalte/elements`.

Что сделал:
- `IslandDialog`, `IslandSelect`, `tooltip`, `context-menu` переписаны на Kobalte
- Добавил Toast (вместо красных полос), Switch (настройки), Sheet (slide-in панели), базовый Combobox
- Portal монтируется в `#island-portal` — иначе blur/backdrop рвётся в Tauri frameless режиме
- z-index вынес в `src/lib/zIndex.ts` (Z_DIALOG=50, Z_DROPDOWN=60, Z_TOAST=70, Z_DRAG=80). Больше никаких `z-50` напрямую в классах

Что поймал в процессе:
- Для controlled dialog без `Dialog.Trigger` previous focus сохраняется перед
  открытием и восстанавливается после закрытия; это покрыто regression-тестом.
- Drag-handle внутри диалога + focus trap: Kobalte поглощает pointerdown на тайтлбаре. Решение — `data-kb-focus-trap-exception` на ручку
- Tooltip имеет long-press fallback для touch без изменения desktop hover/focus.

Критерий закрытия: один набор Dialog/Select/Tabs/Button, единый focus-management
и отсутствие необоснованных raw z-index/overlay-дубликатов. Размер bundle не
фиксируем в roadmap — его контролирует CI, а не быстро устаревающая цифра в
документе.

---

## Phase 2 — Tantivy локальный поиск

Полнотекстовый поиск по расшифрованным сообщениям. Индекс живёт только на
устройстве, на сервер ничего не уходит. Поисковый трафик сервер не видит.

**Актуальная модель:** Tantivy использует `RamDirectory`. После unlock индекс
перестраивается из SQLCipher, при lock исчезает вместе с процессной памятью;
старый постоянный индекс удаляется. Отдельного plaintext-индекса, marker-файла,
Windows ACL для search-директории и `search/v1`/`search/v2` больше нет.

Схема индекса: `id (STORED)`, `conversation_id (STORED + INDEXED)`, `sender_id (STORED + INDEXED)`, `body (TEXT)`, `timestamp (STORED + FAST для сортировки)`. Токенайзер — стандартный с lowercaser. Для кириллицы в v1 достаточно; multi-language остаётся отдельным улучшением.

Tauri команды: `search_messages`, `rebuild_search_index`, `clear_search_index`, `ensure_search_backfill`. Backfill запускается после unlock, не блокирует UI и может быть безопасно повторён.

Что надо помнить:
- Ротация ratchet ключей не требует реиндексации — plaintext не меняется, это важно задокументировать
- При удалении сообщения надо вызывать `Indexer::delete(id)` — сделано
- Индекс расходует RAM пропорционально истории. До большой публичной beta нужны лимит памяти, отменяемый rebuild и измерение на крупных профилях.
- Смена схемы означает полный rebuild из SQLCipher; миграция отдельного search-файла не требуется.

Что сделано: crate `veil-search`, подключён в `veil-client::api` в шести местах (outgoing + incoming: insert, edit, delete). UI: `CommandPalette` на Kobalte Dialog + Cmd/Ctrl+K, debounce, inline `<mark>` highlight, клавиатурная навигация.

---

## Phase 3 — tus.io загрузка файлов

Цель: файлы до 2 ГБ, resumable, клиент шифрует до отправки. Сервер хранит только ciphertext-блобы.

**Статус core 2026-07-12: закрыто.** Server ACL, tus resume, chunked AEAD v2,
atomic publish и bounded offset/format проверки готовы. Не реализованный
продуктовый клиентский scope выделен в **Phase 3B — Attachment Experience** и
не считается частью закрытого protocol core.

**Как отличается от изначальных планов:**

tusd внутри gateway, не в отдельном бинарнике `cmd/uploads/`. Одна точка входа, один auth surface, проще в ops. Разнести можно потом без изменений протокола.

Auth через bearer-token, не через X-Veil подпись на каждый PATCH. Причина: X-Veil подписывает `sha256(body)`, а для стриминговой загрузки хешировать весь чанк тела убивает смысл tus. Клиент делает `POST /v1/uploads/token` (X-Veil подпись), получает HMAC-SHA256 bearer (`v1.<user>.<expires>.<mac>`), по умолчанию TTL 24 ч (`UPLOAD_TOKEN_TTL`). При долгом resume — минтим новый токен и продолжаем.

Quota gate в `pre-create` через `db.SumTusBytesInWindow` за скользящие 24 ч. HTTP 413 до того как что-то легло на диск — нельзя сжечь квоту незавершёнными загрузками.

Crate `veil-uploads` поверх `veil_crypto::chunked_aead`. Обязательный pre-release format v2: nonce = `nonce_prefix || u64_be((chunk_index << 1) | is_final)`, AAD = `veil/file/v2 || nonce_prefix || chunk_index || is_final`, `chunk_index <= 2^63 - 1`. Версия хранится в metadata; старый v1 без версии отвергается без fallback. Детектирует переставку чанков, обрезание, замену. Каждый чанк аутентифицирован отдельно.

Sweeper: горутина раз в `UPLOAD_SWEEP_INTERVAL` (1 ч по умолчанию) убивает просроченные блобы через tusd's Terminater + дропает строки. Abort TTL = `UPLOAD_ABORT_TTL` (24 ч), retention завершённых = `UPLOAD_RETENTION` (30 дней).

Download: `GET /v1/uploads/blob/{file_id}` — отдельный эндпоинт с auth-проверкой.
Attachment теперь привязан к сообщению/разговору; скачать может текущий участник,
которому разрешена история этого разговора. Сервер всё равно хранит только
ciphertext и не получает ключ файла.

**Phase 3B — Attachment Experience (отложено):**
- Tauri команды + drag-drop UI + file bubble компонент
- EXIF strip (клиентская сторона, до шифрования; `kamadak-exif` или ре-энкод через `image`)
- `veilfile://` custom protocol для range-decrypt видео в `<video>` теге
- безопасный K-wrapping для больших roster; он не должен блокировать базовые
  вложения в DM/маленьких группах, но обязан следовать принятой Phase 4C модели
- Streaming uploader API (сейчас `encrypt_file_to_chunks` материализует весь список чанков в памяти; нужен async stream когда начнём пушить 2 ГБ видео)

Важные грабли, которые надо помнить:
- MIME spoofing: не доверять client-declared MIME. Ре-деривить на стороне получателя через `infer` crate перед рендером
- Resume после долгого оффлайна с другим IP: bearer-токен привязан к пользователю, не IP. Достаточно заминтить новый токен
- Disk fill от прерванных загрузок: `unfinished-upload-expiration` в tusd = 24 ч (UPLOAD_ABORT_TTL)
- Per-recipient K в группах: не шифровать файл заново для каждого участника.
  Шифруется один blob; ключ оборачивается по правилам текущего crypto roster.
  MLS exporter можно использовать только после реального включения MLS runtime.

---

## Phase 4 — UnifiedPush / ntfy push-уведомления

**Статус transport core 2026-07-12: закрыто.** Server transport и encrypted envelope готовы. Полноценного
desktop/mobile `K_push` workflow ещё нет, поэтому UI не должен обещать
расшифрованные preview. До готовности показывается только нейтральное
«Новое сообщение» и выполняется sync после unlock.

Фоновые push без FCM/APNS в data path. Сервер отправляет только зашифрованный blob; устройство расшифровывает в notification extension.

Флоу: gateway видит что получатель оффлайн → fanout через dispatcher → ntfy endpoint получателя → UnifiedPush distributor → приложение расшифровывает с `K_push`.

`K_push` деривируется через HKDF-SHA256 из ratchet root с domain separator. Смысл: если push subsystem взломан — видны только превью, живой ratchet не затрагивается.

Envelope: JSON с короткими именами полей, padding до ровно 2 КБ (XChaCha20-Poly1305 AEAD). Одинаковый размер всех пакетов чтобы ntfy-оператор не мог делать выводы по размеру.

**Что сделано на серверной стороне:**
- Migration `006_push.sql` — таблица `push_subscriptions`
- `internal/push/`: `envelope.go` (padding до 2 КБ, AEAD), `dispatcher.go` (jitter [0, VEIL_PUSH_JITTER_MS), fan-out по всем подпискам пользователя, автопруниг при 410/404), `handler.go` (REST: POST/GET/DELETE subscriptions)
- Gateway: `Hub.SetPushNotifier()` + `fanoutMessageEvent()`. Отправляет push только для новых сообщений, только если у получателя ноль живых WS-сессий. Редакты/удаления/реакции — без push, чтобы не спамить
- ntfy в docker-compose на `9081:80`, deny-all ACL по умолчанию
- `veil-crypto::kdf::derive_push_key(root_key, conversation_id)` — HKDF, domain-separated, детерминирован

**Как отличается от изначальных планов:**
- Нет WebPush ECDH (`p256dh`/`auth_secret`) — UnifiedPush передаёт raw bytes, WebPush envelope layer тут лишний
- Только `KindMessage`. `KindCall` / `KindMention` зарезервированы, реализую в Phase 7 и когда дойдём до @-mentions
- Inner preview ciphertext пока не заполняется сервером — клиент получает wakeup и синкит по `/v1/messages`. K_push cache на стороне sender device откладывается на мобильный клиент

**Phase 4P — Device Push Clients (отложено):**
- Android: `react-native-unifiedpush-connector` в `veil-mobile/`, distributor picker, notification listener с K_push из keychain
- iOS: ntfy iOS app как APNS bridge, App Group для shared keychain между extension и основным приложением
- Desktop: settings panel с list/add/delete subscriptions (Tauri команды + Kobalte Dialog)
- Продуктовое решение для Android: UnifiedPush-only либо опциональный FCM wake-up
  с полностью зашифрованным/нейтральным payload. Транспорт не должен получать
  текст сообщения, имя отправителя или ключи.

Грабли:
- iOS App Group keychain: main app + extension обязаны использовать один access group. Без этого extension не расшифрует и будет вечно показывать "New message"
- Stale endpoints: ntfy может вернуть 410. Dispatcher ловит и прунит строку — это сделано
- Replay: в envelope есть `msg_id` + monotonic counter per-subscription для дедупликации
- Mute/DND должны проверяться на сервере (не отправлять push) — пока не реализовано

---

## Phase 4A — Группы, серверы и роли

**Статус access/crypto core 2026-07-12: закрыто.** REST/DB/ACL, роли, инвайты,
участники, authoritative channel access, roster revisions и desktop-потоки
работают. Продуктовая информационная архитектура и зрелые server/channel
settings не выданы за готовый core: они выделены в **Phase 4E — Server
Experience**.

Текущий runtime:

- DM: X3DH + Double Ratchet.
- Приватные группы: authenticated Sender Keys v5.
- Сервер — контейнер метаданных, ролей и каналов, а не одна криптогруппа.
- Каждый text channel привязан к отдельной conversation и сейчас шифруется
  Sender Keys. При незавершённой раздаче/ротации отправка блокируется.
- Канальные `channel_epochs`/`channel_key_envelopes` присутствуют в старой SQL
  миграции, но runtime их не использует. Поддерживать две модели нельзя.

Закрыто 2026-07-11 в части channel access:

- Crypto roster, conversation discovery/sync, message actions, typing, uploads и
  retained SKDM теперь используют фактический доступ к каналу.
- `channel_overwrites` применяются в runtime ACL в порядке `@everyone` →
  агрегированные роли → участник; owner/Administrator обходят overwrite. Маски,
  принадлежность target серверу, единственная default-роль и cleanup при
  удалении role/member защищены миграциями и integration-тестом.

Phase 4E обязана закрыть:

- Явно развести в UI «групповой чат» и «сервер».
- Определить private/public channel, историю для нового участника и поведение
  при role/access change.
- Завершить server settings, channel settings и правдивые crypto indicators.
- Добавить ручную desktop/mobile matrix для create/join/leave/kick, нескольких
  физических устройств и offline reconnect поверх уже существующих automated
  exact-device/integration/race tests.

---

## Phase 4B — Desktop UX & Appearance

**Цель:** сделать Windows desktop эталонным клиентом и получить один
переиспользуемый визуальный фундамент для Android.

**Статус 2026-07-12: закрыто.** Введены semantic tokens и пять палитр,
нативно валидируемые локальные обои, единая PIN-модель, keyboard focus/reduced
motion, согласованные Lucide-иконки, in-app decision dialogs и безопасное
сохранение черновика при ошибке отправки. Удалены параллельные desktop layout/
dialog paths. Visual regression проверяет 800×600, 1200×800, 1440×900 и
125%-equivalent LockScreen; wallpaper send regression запрещает прокрутку всего
WebView. Contrast tokens всех пяти тем имеют минимум 4.5:1 на рабочих
поверхностях. Unsigned Windows NSIS bundle собран и native release запущен.

### 4B.1 — UI foundation

1. Выбрать один активный AppShell/component path и убрать параллельный
   монолит/неиспользуемый layout после миграции.
2. Перевести цвета, поверхности, типографику, radii, elevation и motion на
   semantic tokens. Статусы success/warning/error/online не зависят от accent.
3. Сохранить фирменные цветные window controls, но добавить понятные символы,
   полноценные hit-target, tooltip и accessible labels.
4. Сохранить полноэкранную подачу Settings как часть дизайна. Внутри неё должны
   оставаться доступными перенос окна и window actions; красный `Back to Chat`
   заменить нейтральным и не дублировать одинаковые способы выхода.
5. Ввести единое navigation state:
   `friends | conversation(id) | serverChannel(serverId, channelId)`.
   При переключении All/DMs/Groups закрывать несовместимые create-панели.
6. Привести PIN к одной модели: новые PIN 6–12 цифр, legacy 4–5 принимаются
   только для миграции; динамический progress, hidden numeric input,
   физическая клавиатура/Backspace/Enter и native throttling.
7. Унифицировать Lucide/собственные vector icons вместо случайных emoji.
8. Убрать временные костыли Settings: повторное копирование, пустой раздел
   Notifications, обрезанный About, GitHub action с неверной семантикой.
9. Обеспечить стабильное масштабирование. Зафиксировать честный minimum window;
   если композиция не помещается, поднимать minimum или убирать вторичную
   панель осознанно, а не сжимать чат до нерабочей ширины.
10. Добавить видимый keyboard focus, reduced motion и достаточный контраст,
    сохранив текущий тёмный визуальный характер.

### 4B.2 — Appearance

- Раздел `Appearance` в Settings.
- 4–5 проверенных тёмных палитр и отдельный accent.
- Фон: solid / gradient / локальное PNG, JPEG или WebP.
- Для картинки: `cover`, focal point, dim, blur, preview, replace/remove/reset.
- Копирование валидированного изображения в app-data; без remote URL,
  произвольного CSS, SVG и синхронизации на сервер.
- `Show on lock screen` выключен по умолчанию.
- Прозрачность/glass островов — только после contrast/performance QA.
- Reduced-motion setting реализован; UI scale добавляется после breakpoint QA,
  чтобы увеличение не ломало честный minimum window.

### Критерии готовности 4B

- Нет hardcoded theme colors в основном active UI за исключением иллюстраций.
- PIN и основные сценарии работают мышью и клавиатурой.
- Проверены Windows размеры 800×600, 1200×800 и 1440×900; для неподдерживаемого
  размера приложение не допускает сломанную геометрию.
- Theme/wallpaper переживают restart, не покидают устройство и по умолчанию не
  видны до unlock.
- Есть visual-regression screenshots и accessibility smoke tests.
- `pnpm build`, Rust/Go tests и unsigned Windows bundle зелёные.

---

## Phase 4C — Server Channel Crypto Decision

Это сначала ADR + threat model, а не третья параллельная реализация.

**Статус baseline 2026-07-12: закрыто.** Принят
[`ADR-0001`](docs/adr/0001-authenticated-sender-keys-v5-for-server-channels.md):
каждый text channel — отдельный Sender Keys v5 security domain, silent downgrade
запрещён, история по умолчанию future-only. Exact-device binding/version history,
authoritative roster revision/commitment, immutable retry envelopes, несколько
retained incoming generations и exact durable device receipts реализованы на
server/client/SQLCipher слоях. Retained recovery атомарен внутри conversation и
изолирует повреждённый conversation от здоровых DM/groups. Join/leave/kick/
role/overwrite/device change инвалидирует roster proof; новое поколение не
выпускает ciphertext до завершения distribution. Desktop карантин блокирует
только затронутый conversation, сохраняет draft и не объявляет receipt
подтверждением полной истории.

Оставшиеся security hardening задачи не переопределяют baseline: service-
mediated TOFU/key transparency относится к Identity/Phase 4D, глобальный
storage budget/compaction — к Phase 8, а ручная физическая multi-device matrix —
к Phase 4E/release gate.

### Безопасный baseline ближайшего релиза

- Сервер остаётся контейнером; каждый text channel — отдельный security domain.
- Зашифрованные каналы продолжают использовать authenticated Sender Keys v5.
- MLS не включается автоматически в server channels до готовой multi-device
  orchestration и измерений churn/размера roster.
- Plaintext/public channel не входит в baseline первого server-релиза. Если он
  когда-либо появится, это будет отдельный явно выбранный профиль с заметной
  маркировкой; silent downgrade в него запрещён.
- Получатели ключей выводятся из channel ACL и устройств, а не из renderer cache.
- Join/leave/kick/access change требует ротации; защищённая отправка блокируется
  до подтверждённой раздачи нового ключа.
- Persisted roster head/version/commitment и device binding history не допускают
  rollback/equivocation; cold restore и lost-ACK retry используют ровно
  сохранённое поколение/envelope до подтверждённой смены roster.
- Новый участник не получает старые ключи автоматически, пока отдельно не
  спроектирован history-sharing protocol и UX согласия.

### Зафиксированный ADR contract

- Sender Keys, MLS или гибрид и точные границы режимов.
- Per-device identity, device add/revoke и восстановление после офлайна.
- Public/private channels, role overrides и одинаковые membership-set.
- Историю при join, сроки хранения distributions/commits и recovery flow.
- Wire version, capability negotiation, миграцию старых conversation.
- Выбор одной модели: удалить неиспользуемые epoch tables либо реализовать их;
  одновременно с Sender Keys они не остаются.
- Автоматизированную матрицу: join, leave, kick, role/overwrite/device change,
  offline reconnect, несколько устройств, retained generations и незавершённая
  ротация. Ручная физическая device matrix остаётся release evidence.

Критерий безопасности: исключённое устройство не расшифровывает новые
сообщения, а UI всегда различает encrypted, rotation pending и plaintext.

---

## Phase 4D — Identity Island & Profiles

**Статус 2026-07-13:** Phase 4D в активной реализации. Entry gate и формальное решение
опубликованы в
[`docs/reviews/phase-1-4c-completion-gate.md`](docs/reviews/phase-1-4c-completion-gate.md).
Реализованы canonical local identity foundation с authenticated origin/binding
fence, детерминированный Phaseprint и единый `UserAvatar`, Identity Island,
versioned text profile/cache/editor, локальная verification/identity-change flow,
relationship-scoped `ProfileUpdated`, identity-bearing local search DTO,
изолированный avatar pipeline и mobile Identity sheet. По решению владельца
финальный completion gate выполняется отдельно, поэтому Phase 4D ещё не объявлена
завершённой.

Цель — дать одному человеку единое и узнаваемое представление во всех местах
Veil: собственный footer, друзья, DM, группы, сообщения, server members и
settings. Профиль называется **Identity Island** и продолжает язык Phase Shift,
а не копирует banner/popover Discord.

Phase 4D отслеживается как пять прямых продуктовых deliverables без вложенных
«фаз внутри фаз»:

1. Identity foundation: durable origin binding, hard namespace cutover и
   удаление originless runtime legacy.
2. Детерминированный Phaseprint и единый `UserAvatar`.
3. Identity Island, все точки открытия, плавная навигация и переходы в DM.
4. Versioned text profile, Identity Proof и privacy/security review.
5. Изолированный безопасный avatar pipeline и финальный completion gate.

Малые migration/security commits внутри deliverable являются только
проверяемыми Git-checkpoint'ами, а не новыми уровнями roadmap.

### Entry gate 4D

Gate-review выполнен 2026-07-12 со ссылками на тесты, bundle и local migration
smoke:

| Предыдущая фаза | Gate | Scope disposition |
|---|---|---|
| 1 | пройден | composite controls/focus/keyboard закрыты; простые semantic HTML controls допустимы |
| 2 | пройден | RAM-only поиск и rebuild из SQLCipher работают; memory budget остаётся release hardening |
| 3 | пройден | encrypted upload core закрыт; attachment UX/2 GiB streaming — Phase 3B |
| 4 | пройден | encrypted transport core закрыт; device `K_push` clients — Phase 4P |
| 4A | пройден | authoritative access/roster core закрыт; product server IA/settings — Phase 4E |
| 4B | пройден | AppShell cleanup, scale/contrast/a11y/visual matrix и NSIS bundle зелёные |
| 4C | пройден | exact-device roster, multi-generation retention, receipts и atomic recovery реализованы |

Незавершённые client/product куски не исчезли: Phase 3B, 4P и 4E являются
явными владельцами. Открытый gate разрешает Phase 4D foundation, но не разрешает
называть будущий network profile/avatar pipeline безопасным до его собственных
критериев готовности.

Отдельные обязательные prerequisites непосредственно для профилей:

- исправить смешение `conversation_id` и peer `user_id` в DM;
- сохранять авторитетные `user_id`, identity/signing key и отображаемое имя
  автора вместе с локальной историей, чтобы после restart автор не менялся на
  префикс ключа;
- не выбрасывать identity/member metadata при построении group/server rows;
- ввести canonical account locator как минимум
  `(canonical_server_origin, user_id, identity_key)`; UUID пользователя не
  считается глобальным между self-hosted инстансами;
- использовать реализованный exact account/device binding и явно отличать TOFU
  от локально проверенного identity state.
- W9 закрыт до rollout profile API: access/error logs используют HMAC refs и
  bounded error classes, client responses проходят через `publicerr` boundary.

### Граница доверия

Публичный профиль и криптографическая identity — разные сущности:

- `display_name`, `about`, avatar и server nickname — изменяемые presentation
  metadata конкретного server instance; оператор сервера их видит, они не E2EE;
- `user_id`, X25519 identity, Ed25519 signing key, device bindings и fingerprint
  относятся к security identity и не меняются через редактор профиля;
- имя, avatar, роль или profile signature никогда не дают статус `Verified` и
  не участвуют в выборе ключа, ACL либо crypto mode;
- UI обязан прямо объяснять, что означает `Verified on this device`, и отдельно
  показывать `Identity changed`; смена ключа сбрасывает локальную verification;
- подпись HTTP-запроса владельцем обязательна. Дополнительный client-signed
  profile manifest с monotonic revision допустим позже, но не заменяет
  авторизацию REST и требует отдельной threat-model проверки replay/rollback.

### Реализовано в Identity foundation: canonical local identity snapshots

- `ProfileLocator` фиксирует `(canonical_server_origin, user_id, identity_key)`;
  UUID пользователя не считается глобальным между self-hosted origins.
- SQLCipher хранит origin-scoped account directory и отдельную неизменяемую
  author snapshot для сообщения: user ID, identity/signing keys, username/
  display name, profile version/origin, источник и время наблюдения.
- Conversation metadata хранит server origin и отдельный DM `peer_user_id`;
  account/friend actions больше не используют `conversation_id` как user ID.
- Directory и author metadata принимаются только из уже существующих
  authenticated directory/history flows. Author snapshot прикрепляется только
  при точном совпадении identity key с `messages.sender_key` и origin с
  conversation scope; конфликт, неизвестный live-author и cross-origin
  collision обрабатываются fail closed.
- После restart renderer использует сохранённое имя автора; при отсутствии
  авторитетной snapshot показывает `Unknown author`, а не префикс ключа.
- Схема `messages`, ciphertext, Double Ratchet, Sender Keys, ACL и rotation
  contract не изменены. Presentation metadata нигде не участвует в crypto trust.

Checkpoint не завершает полный multi-origin runtime. Conversation/ratchet/
roster/pending/server-cache namespaces ещё не полностью origin-scoped:
совпадающие conversation ID или peer identity на разных origins сейчас
отвергаются, а не поддерживаются одновременно. Legacy unscoped conversation
rows не получают активный origin по догадке и требуют отдельного authenticated
migration/cutover. Также остаются открыты полная нормализация friend/request/
group/server contexts и семантика `Former member`.

### Реализовано в Identity foundation: authenticated transition fence

- Native публикует renderer не отдельный UUID, а точный authenticated scope:
  canonical server origin, user ID и монотонную binding generation. Generation
  передаётся строкой без потери точности JavaScript и повторно подтверждается
  native после обязательной публикации prekeys, непосредственно перед UI.
- Любой reconnect, включая same-origin, снимает старый scope и закрывает live
  actions/events до подтверждения новой generation. На том же origin user ID не
  может молча измениться, generation обязана возрасти; очередь endpoint A→B→C
  работает latest-wins и не публикует уже отменённый B.
- Все authenticated native events несут exact origin/generation захваченного
  binding. Renderer принимает только точное совпадение; delayed event и старый
  disconnect не могут мутировать replacement namespace. Matching disconnect
  снимает readiness/binding fail closed и запускает реальный reconnect даже во
  время renderer hydration.
- Полный native listener set устанавливается до первого connect и откатывается
  целиком при частичной ошибке. User-initiated message/friend/Sender-Key actions
  разрешены только после renderer confirmation точного binding; action,
  захвативший generation N и дождавшийся mutex уже при N+1, отклоняется до
  local/network mutation. Изменения role authorization проходят тот же gate и
  сверяют REST origin до локального quarantine channel rosters.
- Cross-origin transition синхронно очищает store, component-local plaintext,
  deferred drafts, overlays, command/friend search state и очередь decision
  dialogs. Same-origin transition сохраняет безопасный navigation/draft state,
  но отменяет in-flight UI operations старой generation.
- Legacy UUID-only `veil://add/{user_id}` заблокирован: locator без origin и
  identity key неоднозначен между self-hosted instances.
- Originless server/channel/member/role cache удалён из renderer IPC surface.
  До отдельной origin-scoped cache schema эти данные загружаются только свежим
  authenticated REST; cache-first/offline server navigation намеренно выключена.

Этот checkpoint не меняет schema сообщений, ciphertext, ratchets, Sender Keys,
ACL либо rotation contract и не является завершением 4D.1. Открыты friend/
request/group/server consumer normalization, origin-scoped server cache v2,
`Former member`, одновременное хранение colliding namespaces и generation-bound
проверка каждого identity-mutating REST результата.

### Identity foundation: pre-release origin namespace cutover

До Phaseprint нужен один явно описанный storage cutover. Поскольку публичного
релиза не было, сохранять runtime-совместимость с originless development rows
не требуется:

- conversation/message/pending/roster/reaction keys переходят с bare UUID на
  обязательный origin namespace; новые unscoped writes удаляются;
- self account binding `(origin, user_id, identity_key, signing_key)` становится
  durable и проверяется до offline sync также после process restart;
- author snapshot обязательна для каждого нового incoming/outgoing message и
  сохраняется атомарно с message row; отсутствие authoritative metadata ведёт
  в quarantine/`Unknown author`, а не в UUID/key-prefix presentation fallback;
- originless contacts/group members/server cache models и их production CRUD
  удаляются либо заменяются одним typed account/context DTO;
- development rows без доказуемого origin не «усыновляются» текущим сервером:
  cutover их явно отвергает или удаляет после backup. Crypto payload formats,
  Double Ratchet и Sender-Key protocol при этом не меняются.

Durable self binding уже перенесён из process-only map в SQLCipher и проверяется
сразу после authenticated WebSocket result, до публикации REST binding и
offline sync. Повторное точное наблюдение разрешено, а замена user/identity/
signing key на одном origin отклоняется также после file-backed restart.
Self binding и identity directory теперь образуют симметричный инвариант:
directory batch не может позднее заменить self user/identity/signing key или
создать их alias, а reconnect повторно проверяет уже сохранённый каталог.
Signing key также уникален для account locator внутри origin; одинаковый
key на другом self-hosted origin остаётся отдельным account namespace.
Это pre-release hard cutover: если в старой development БД уже есть
неоднозначный same-origin signing alias, open отклоняется до restore/reseed
из проверенного backup; migration не выбирает и не удаляет строки молча.
Server-member directory обязан содержать точную локальную account identity до
любой SQLCipher-записи или runtime pin; ошибка откатывает весь directory batch.
REST response дополнительно привязан к exact origin/generation и повторно
проверяется под transition/client lock: запоздавший ответ поколения N не
может изменить durable/runtime/UI state после reconnect к N+1.
`get_group_members` теперь применяет directory только под exact renderer
origin/generation; server kick предварительно quarantine-ит origin-scoped
channel rosters. Неиспользуемые standalone session/group-member IPC удалены.
Перед изменением схемы сохранена совпадающая по SHA-256 копия development DB,
WAL и SHM в локальной игнорируемой `backups/`.

Этот блок затрагивает адресацию локального хранения сообщений, поэтому перед
реализацией требуется отдельное объяснение schema/cutover, backup реальной
development БД и полный restart/collision/recovery test matrix.

### Identity foundation: canonical identity directory

1. Ввести origin-scoped каталог профилей и общий `ProfileLocator`.
2. Нормализовать данные self, DM peer, friend/request, message author,
   group member и server member в одну account snapshot без потери исходных ID.
3. Зафиксировать порядок доверия при merge: native/auth identity → подписанный
   directory/member response → локальный SQLCipher cache → conversation
   metadata → имя из message event только как неавторитетный fallback.
4. Хранить profile cache в SQLCipher с server origin, profile version и временем
   последней проверки. На lock очищать renderer state и object URLs.
5. Для удалённого/бывшего участника сохранять историческую author snapshot, но
   помечать её как `Former member`, а не приписывать текущие роли или presence.

### Phaseprint, UserAvatar и Identity Island

- Один `UserAvatar` для footer, списков, header, сообщений, друзей и members.
- До настоящих картинок использовать детерминированный **Phaseprint** из
  identity key; fallback — user ID, затем username. Смена nickname не меняет
  рисунок. Ошибка image decode возвращает Phaseprint без broken-image UI.
- На широком desktop существующий правый остров морфит `Members → Identity`;
  новый пятый остров не добавляется. Из members доступен `Back to Members`.
- На узком desktop это focus-trapped right sheet, на mobile — bottom sheet.
- Внутри три спокойных блока: `Person`, `Context`, `Identity Proof`. Без
  декоративного banner, перекрывающего avatar, и без россыпи badges.
- Точки открытия: собственный footer, DM row/header, author сообщения,
  friend/request/search row, group/server member, server settings member и
  context menus. Reply preview сохраняет навигацию к сообщению и не перехватывает
  click ради профиля.
- Server context показывает nickname первым, затем глобальное display name/
  technical handle; owner и первые три роли показываются отдельно и не меняют
  identity trust.

Phaseprint v1 foundation реализован как чистая синхронная presentation-
функция и inline SVG без network/canvas/HTML injection. Это не crypto fingerprint
и не сигнал `Verified`: результат нигде не участвует в trust, ACL или
Sender-Key rotation. Seed берёт только valid non-zero identity key, иначе
canonical `(origin, user_id)`, затем `(origin, technical_username)`; без valid
origin показывается нейтральный anonymous print, а не bare-UUID identity.

Единый `UserAvatar` уже используется в self footer, DM rows/header,
message authors, friend/search/request rows, group/server members и server settings.
Group/channel/server entity icons остаются отдельными от person avatar. Nickname
не передаётся в seed, а keyed member row не remount-ит Phaseprint при его
смене. Remote/data image URL отклоняются; будущий native-validated
`blob:` должен успешно decode-нуться над уже отрисованным Phaseprint;
error/abort не даёт broken-image flash. Сам image pipeline и сетевые аватары
на этом checkpoint не реализованы.
Закрытый Members island не mount-ит row/SVG DOM, а открытый Members,
Server Settings и активная вкладка friends/requests имеют явный presentation
budget в 256 rows с честным truncation status до pagination/virtualization.
Неактивные friends tabs не держат скрытые Phaseprint trees. Этот renderer budget
никогда не ограничивает полный store/native state для friendship, ACL,
authorization и Sender Keys.

Identity Island теперь использует один локальный `closed | members | identity`
route вместо набора boolean overlays. На wide desktop сохраняется тот же DOM-
остров: `Members` морфит в `Identity` и обратно без закрытия ширины и потери
member scroll/focus. На `<=1080px` тот же route показывается одним modal
`IslandSheet`: background inert, Tab trapped, Escape/close возвращают focus в
исходную кнопку. Старые unguarded 50/450 ms open/close timers удалены.

Профиль имеет только три блока `Person`, `Context`, `Identity Proof`; без banner,
badge cloud и remote image. `Not compared` прямо объясняет service-mediated TOFU
и никогда не выводится как `Verified`. Неполный locator показывает
`Identity unavailable`, self не предлагает Verify. Nickname, owner и максимум
три роли остаются только Context и не меняют Phaseprint/trust/ACL/Sender Keys.

Точки открытия подключены к self footer, DM row/header, message author,
friend/request/user-search row, group/server members, server member context menu
и server settings. Reply preview по-прежнему только переходит к сообщению.
`Message` сначала ищет ровно один origin/user/key-compatible local DM, а новую
conversation создаёт только в текущем published authenticated scope; UI не
предполагает заранее, что privacy/server policy разрешит действие.
Показанный identity key передаётся в native `create_dm` как ожидаемый: ответ
`POST` и подписанный member directory обязаны согласоваться с ним до первой
локальной durable/runtime публикации. Поздний async-ответ привязан к session,
profile и action epoch и не может переключить уже закрытый либо сменившийся
Identity Island. Открытие единственного exact local DM остаётся доступно offline.

Completion evidence local-data Identity Island checkpoint (2026-07-12):
`cargo fmt`, workspace `clippy -D warnings` и workspace/all-targets tests;
`go test`, `go vet` и Docker integration suite; frontend 66/66 tests и
production build; visual matrix 20 passed / 4 expected skips; Windows release,
launch smoke, MSI и NSIS. NSIS SHA-256:
`39ED964D4634AA1E78510F9AA2F0B896FA94A20AA365721FDAB457A4A396E756`.
Installer всё ещё не подписан, как и зафиксировано в residual risks.

Outgoing friend request не использует перегруженный self `fromUserId`: он
открывает только ограниченный username/origin view без proof/DM action. Global
Command Palette остаётся локальным message search: author action появляется
только после точной origin/message/conversation/sender/plaintext сверки RAM-hit
с авторитетным SQLCipher message-author snapshot. Голая строка `sender` больше
не выходит в renderer DTO и никогда не используется как account locator.
Friend/request DTO без полного locator честно используют partial view и не
объявляются verified.
Новый network profile API, network avatar fetch и crypto/storage protocol этим
checkpoint не добавлены.

Completion evidence identity-bearing search checkpoint (2026-07-13): workspace
`cargo fmt`, `clippy -D warnings` и all-targets tests; Go unit/vet и свежий
Docker integration suite; frontend 80/80 tests, production build и visual/a11y
matrix 20 passed / 4 expected skips. Windows native desktop test binary собран и
выполнен из ASCII target; release/NSIS намеренно не пересобирался, поскольку
package/config/runtime entrypoint этим checkpoint не менялись.

### Versioned text profile

Первый сетевой релиз профилей не требует avatar upload:

**Server checkpoint 2026-07-13:** отдельный schema/privacy/security review
зафиксирован в
[`docs/reviews/phase-4d-text-profile-security-review.md`](docs/reviews/phase-4d-text-profile-security-review.md).
Миграция 020 и gateway реализуют signed origin-local GET/self PUT, bounded NFC
plain text и атомарный `expected_version` conflict. Неизвестные поля, включая
`avatar_url`, отклоняются; reserved `avatar_asset_id` не доступен через API.
Этот server-only checkpoint ещё не добавлял `ProfileUpdated`, native
client/SQLCipher refresh, UI-редактор или avatar pipeline. Последующие
checkpoint'ы ниже закрывают text profile/event/proof части; avatar pipeline
остаётся отдельным незавершённым deliverable.

- PostgreSQL: `display_name`, короткий `about`, nullable `avatar_asset_id`,
  `profile_version`, `profile_updated_at`; технический username остаётся
  безопасным fallback, а не свободным display name;
- v1 хранит plain text, не HTML/Markdown: NFC normalization, bounded UTF-8,
  запрет управляющих/bidi-override символов, 64 grapheme для display name и
  280 для about; renderer выводит их только как text content;
- signed `GET /v1/users/{id}/profile` и self-only `PUT/PATCH /v1/users/me/profile`;
- optimistic concurrency через `expected_version`; конфликт возвращает `409`,
  update одной версии атомарен;
- отдельный `ProfileUpdated { user_id, profile_version }` event. Он не является
  roster/member event и не должен инициировать Sender Key rotation;
- серверные nickname/roles остаются context-owned полями. Приоритет отображения:
  server nickname → global display name → technical username;
- profile endpoint не возвращает recovery data, private keys, email, IP,
  presence history или device secrets.

### Isolated avatar asset pipeline

**Implementation checkpoint 2026-07-13:** миграция 022 и signed profile routes
реализуют отдельный avatar store, CAS по `profile_version`, случайный asset UUID и
24-часовой orphan grace. Сервер принимает только strict PNG/JPEG до 2 МиБ и
4096×4096/16 MP, ограничивает параллельный decode, применяет orientation,
center-crop 512×512 и повторно кодирует bounded JPEG без исходных metadata.
Desktop выбирает файл нативно, подписывает точный origin/query/body, проверяет
MIME, magic, 256-КиБ budget, digest и 512×512 до передачи base64 в renderer.
Renderer создаёт только локальный `blob:`, использует bounded LRU и отзывает URL
при replace/error/lock/logout/origin change; decode error возвращает Phaseprint.
UI явно сообщает, что avatar видим серверу и не E2EE. Отдельный review:
[`docs/reviews/phase-4d-avatar-security-review.md`](docs/reviews/phase-4d-avatar-security-review.md).

**Mobile adaptation checkpoint 2026-07-13:** прототип использует единый
identity-key-first Phaseprint в members и сообщениях; member/message action
открывает modal bottom sheet с `Person`, `Context`, `Identity Proof`, Android back
и accessibility modal isolation. Nickname не входит в seed, а service-mediated
TOFU подписан `Not compared`, не `Verified`. Runtime/network integration остаётся
владельцем Phase 5A/5B, а не скрытым хвостом Phase 4D.

Существующий tus attachment pipeline переиспользовать нельзя: он принимает E2EE
ciphertext, имеет message ACL и retention, поэтому сервер не может очистить
публично отображаемое изображение.

Нужен отдельный signed ingest:

- v1 принимает только PNG/JPEG; SVG, GIF/animation, remote URL и недоверенный
  declared MIME отвергаются;
- максимум 2 МиБ исходника, 4096×4096 и 16 MP; bounded decoder concurrency и
  allocation limit;
- server-side decode, orientation, crop/resize до 512×512 и повторное кодирование
  с удалением EXIF/GPS/XMP/IPTC/ICC/имени файла; максимум 256 КиБ результата;
- наружу выдаётся случайный opaque asset ID, digest хранится и проверяется
  отдельно; raw content hash не используется как публичный cross-instance URL;
- desktop загружает avatar нативным authenticated fetch только с текущего
  origin, проверяет size/MIME/magic/dimensions/digest и передаёт renderer локальный
  `blob:` URL. Нельзя расширять CSP до произвольного `img-src https:`;
- object URL отзывается при replace, LRU eviction, lock и logout; старый asset
  удаляется после короткого orphan grace period;
- UI предупреждает: avatar и текст профиля видны оператору выбранного сервера и
  не являются содержимым E2EE-сообщения.

### Local identity proof

**Durable client checkpoint 2026-07-13:** SQLCipher теперь имеет отдельный
`network_profiles_v1`, который принимает versioned profile только для уже
закреплённого exact `(origin, user_id, identity_key)` и отклоняет rollback/
equal-version equivocation. `local_identity_verifications_v1` хранит явное
физическое сравнение отдельно от profile metadata, переживает restart и
возвращает `Identity changed` при другом наблюдаемом ключе; self-verification
запрещена самим storage layer.

**Native profile checkpoint 2026-07-13:** signed GET/self PUT подключены к
нативной origin/generation-bound REST boundary. Ответ строго проверяет schema,
UUID, bounded text, bidi/control characters и monotonic version до SQLCipher.
Peer принимается только для уже закреплённого exact locator; fresh self может
создать directory snapshot только из ключей текущей аутентифицированной native
session и существующего immutable self-binding. Directory + profile сохраняются
одной транзакцией, а binding и session повторно проверяются после сетевого
ожидания. Profile event, renderer editor и интерактивный proof flow ещё не
подключены, поэтому deliverable не закрыт.

**Renderer profile checkpoint 2026-07-13:** Identity Island неблокирующе
обновляет точный locator через native profile API и сохраняет локальную карточку
видимой при offline/error. Late completion применяется только к всё ещё открытому
exact profile route в той же опубликованной server binding. Renderer повторно
проверяет origin/user/key/schema, хранит `profile_version` строкой без потери
точности JavaScript и показывает `about`, revision, `Verified on this device` и
blocking `Identity changed` без переименования TOFU в Verified. Editor, event и
действие физического сравнения на этом checkpoint ещё не подключены.

**Self editor checkpoint 2026-07-13:** exact self profile редактируется прямо в
Identity Island через native self-only PUT. Renderer проверяет bounded text до
IPC, передаёт canonical string revision, не применяет optimistic presentation и
публикует результат только для всё ещё открытого exact route. При CAS 409
актуальная версия загружается заново, черновик не заменяет подтверждённый профиль
молча, а пользователь получает явное предложение review/retry. Peer profile
остаётся read-only; editor не меняет trust, ACL, Sender Keys или Phaseprint seed.

**Local proof checkpoint 2026-07-13:** Identity Island показывает полный
симметричный hex+emoji fingerprint только для уже закреплённого exact peer
locator. Пользователь отдельно открывает сравнение и явно подтверждает, что
сверил весь fingerprint по независимому доверенному каналу. Native повторно
вычисляет fingerprint из текущей identity, constant-time сравнивает его с
показанным значением и лишь затем записывает device-local verification в
SQLCipher. Self и отсутствующий directory locator отклоняются; late route,
origin, binding или session completion не публикуется. Phaseprint/profile text
явно не называются proof, а identity change остаётся blocking состоянием до
нового физического сравнения.

**Profile event checkpoint 2026-07-13:** успешный CAS update публикует отдельный
presentation-only `ProfileUpdated { user_id, profile_version }` только самому
аккаунту и уже связанным пользователям на том же origin (friend/shared
conversation/shared server). Event не содержит profile text/keys, не использует
offline push и не является roster/member событием. Миграция 021 добавляет
обратные membership indexes для bounded audience lookup без full-table scan.
Native принимает только
canonical UUID и bounded positive revision, привязывает renderer event к точной
authenticated origin/generation, а открытый Identity Island refetch-ит профиль
только при совпадении origin/user и более новой версии. Ни membership refresh,
ни conversation quarantine, ни ACL/Sender-Key rotation этот путь не вызывает.

- Native API возвращает стабильный fingerprint в hex + визуальном/emoji формате.
- SQLCipher хранит verification по server origin, account и наблюдаемой identity,
  а не только по mutable имени.
- Состояния: `Not compared`, `Verified on this device`, `Identity changed`,
  `Identity unavailable in this context`.
- Verification локальна конкретному устройству, не синхронизируется через
  публичный профиль и не наследуется новым ключом.
- Self profile не предлагает Verify; для отсутствующего authoritative key
  действие заблокировано с объяснением.

### Порядок реализации 4D

1. **Закрыто:** canonical identity mapping, origin-scoped local directory,
   pre-release storage cutover, persisted author metadata и authenticated
   origin/binding transition fence.
2. **Закрыто:** детерминированный Phaseprint и единый `UserAvatar` во всех
   существующих person surfaces.
3. **Закрыто:** единый right-island route,
   responsive Identity Island, server context и безопасные profile triggers на
   уже доступных locator-bearing данных.
4. **Закрыто:** versioned signed text profile API/cache/editor, отдельный
   relationship-scoped `ProfileUpdated` event и identity-bearing local search
   DTO с точной SQLCipher hydration.
5. **Закрыто:** local identity verification и blocking identity-change flow.
6. Только затем добавить изолированный avatar pipeline и mobile adaptation.

### Критерии готовности 4D

- Один и тот же account стабильно разрешается после restart во всех desktop
  contexts; разные server origins никогда не смешиваются.
- Display metadata не участвует в crypto trust/ACL, а смена профиля не запускает
  group/channel key rotation.
- API ownership, CAS/version rollback, malformed input, rate limits и
  cross-origin cache isolation покрыты unit/integration tests.
- Avatar fuzz/corpus tests покрывают decompression bombs, metadata stripping,
  animation/polyglot rejection и bounded memory; arbitrary network image fetch
  невозможен.
- Identity-change тест сбрасывает verification и показывает blocking warning,
  не подменяя его обычным profile update.
- Все profile triggers доступны клавиатурой, возвращают focus и корректно
  работают в wide/right-sheet/mobile-bottom-sheet вариантах.
- UI явно раскрывает server-visible metadata model и не обещает E2EE для
  display name/about/avatar.
- Desktop build, Rust/Go tests, profile API integration tests и visual/a11y
  matrix зелёные; независимый security review закрывает profile/avatar boundary.

---

## Phase 4E — Server Experience

**Статус:** запланировано. Эта фаза владеет продуктовым scope, который раньше
делал Phase 4A бесконечной, но не меняет закрытый access/crypto contract.

- Явно развести private group и server/channel navigation, empty states и
  creation flows.
- Завершить server/channel settings, private/public policy, future-only history
  UX и правдивые encrypted/rotation/quarantine indicators.
- Провести ручную desktop↔desktop и затем desktop↔Android матрицу на нескольких
  физических устройствах: create/join/leave/kick/role/overwrite/offline/revoke.
- Не вводить «упрощённое шифрование» или silent plaintext fallback ради сходства
  с Discord. Любой будущий public/plain channel — отдельный явный профиль и ADR.

Критерий выхода: пользователь без чтения документации отличает DM, group и
server channel; permission change и device revoke доказуемо меняют exact roster;
UI и protocol tests показывают одно и то же crypto state.

---

## Phase 5 — Android

**Текущее состояние:** существует качественный четырёхстраничный visual prototype
`servers → channels/DM → chat → members` на React Navigation + PagerView.
Island-компоненты, onboarding и локальные tokens уже есть. Это ещё не мессенджер:
chat/server data захардкожены, сеть и SQLCipher отсутствуют, auth живёт только в
Zustand, а `VeilCrypto` в dev возвращает mock identity/signatures.

Текущие обязательные исправления проекта:

- Исправить TypeScript config (`module: commonjs` несовместим с
  `moduleResolution: bundler`).
- Добавить реальный ESLint dependency/config и первые unit/component tests.
- Mock crypto разрешён только в изолированном demo mode без сети/persistence;
  production и connected dev обязаны fail closed.
- Не мигрировать на NativeWind/Expo Router только ради совпадения со старым
  планом. React Navigation + StyleSheet допустимы; общими должны быть semantic
  tokens и поведение, а не конкретная CSS-библиотека.

### Phase 5A — Android foundation

1. Воспроизводимый Rust build для `arm64-v8a` и `x86_64`, Expo config plugin
   либо versioned native Android project, плюс mobile CI.
2. Высокоуровневый native `VeilMobileRuntime` поверх `veil-client`/`veil-store`:
   JS вызывает `create/restore/unlock/lock/connect/list/send/sync`, но не получает
   raw ratchet state, DB key или seed.
3. Android Keystore-wrapped key, SQLCipher, native PIN throttle, biometric gate,
   auto-lock и очистка чувствительного runtime при background/process death.
4. Безопасный onboarding: убрать copy recovery phrase, включить `FLAG_SECURE` на
   secret screens, скрывать preview в Recents и подтверждать несколько слов.
5. Разделить состояния `identityExists`, `unlocked`, `connected`,
   `directoryReady`; текущий `isAuthenticated` слишком грубый.
6. Реальный endpoint config, certificate validation, signed REST/WS,
   reconnect/offline outbox и атомарные crypto+message SQLCipher transactions.
7. Enrollment второго устройства и revoke flow как prerequisite для групп,
   server channels и MLS.
8. Android Back закрывает dialog/sheet, затем возвращает pager на предыдущий
   остров, и только потом покидает экран.
9. Профилировать blur, HebrewRain и четыре смонтированных pager page на слабых
   устройствах; respect reduced motion и battery saver.

Результат 5A: подписанный internal APK запускается на чистом устройстве,
создаёт/восстанавливает identity, переживает restart, безопасно lock/unlock и
соединяется с тестовым gateway без доступа JS к секретному состоянию.

### Phase 5B — Android messaging

1. Сначала один честный Desktop ↔ Android DM: X3DH/Double Ratchet, history sync,
   ack/outbox, reconnect, airplane mode и process death.
2. Реальные DM list/chat, затем private groups на Sender Keys.
3. Servers/channels подключать только после Phase 4C и per-device roster.
4. Generic notification «Новое сообщение» + foreground sync. Encrypted preview
   включать только после полного `K_push` lifecycle.
5. Затем attachments, search, settings/Appearance и server management.
6. Device/instrumentation tests, signed AAB и закрытый beta rollout.

Оценка: закрытый Android DM-MVP — примерно 8–12 недель одного опытного
разработчика. Groups/servers, push previews и attachments добавят ещё 4–8
недель; полная desktop parity потребует отдельного многомесячного этапа и
независимого security review.

---

## Phase 6 — OpenMLS

Добавить [OpenMLS](https://github.com/openmls/openmls) (RFC 9420) как новый
явный crypto mode для подходящих DM и небольших приватных групп. Существующие
DM остаются на Double Ratchet, группы/каналы — на Sender Keys, пока пользователь
или миграция явно не переключит совместимый разговор.

Универсальный порог участников пока не фиксируем: прежние документы
противоречили друг другу (`>50`, `2–500`, «маленькие группы»). Граница MLS
принимается после multi-device orchestration, churn benchmarks и Phase 4C ADR.
Большие server channels продолжают использовать Sender Keys.

`conversations.crypto_mode` должен честно представлять текущие режимы.
Существующий enum `sender_key | mls` недостаточен для DM на Double Ratchet;
до runtime-включения MLS нужно добавить `double_ratchet` либо однозначно
выводить legacy mode из типа conversation.

Cipher suite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. Один, не менять.

Migration plan:
1. Старые разговоры не меняют crypto mode автоматически.
2. Новые совместимые DM/маленькие группы могут предложить MLS только если все
   устройства поддерживают capability и имеют свежие KeyPackages.
3. Кнопка "Upgrade to MLS" в настройках группы + system message "шифрование обновлено"
4. Double Ratchet остаётся поддерживаемым. Решение о прекращении его использования
   для новых DM принимается только после двух стабильных MLS-релизов,
   multi-device тестов и независимого аудита.

Проблемы которые точно вылезут:
- Async member adds: Alice добавляет Bob пока Charlie оффлайн. Charlie возвращается и должен обработать commits по порядку. Сервер хранит все commits с last-seen-epoch, bounded 30 дней. После — re-join через Welcome
- KeyPackage exhaustion: автопополнение при < 10 штук, иначе новые разговоры молча ломаются
- Per-device leaf: каждое устройство — отдельный лист в дереве. Добавить новое устройство = Add commit. Не путать user и device
- Migration determinism: "Upgrade to MLS" должен дать одинаковый результат независимо от того кто его нажал; порядок по user_id + server-assigned migration epoch

### Что уже сделано (фундамент)

- `veil-mls` crate (openmls 0.7.4): `MlsClient` с операциями create/restore, `generate_key_package`, `create_group`, `add_member`, `process_welcome`, `process_commit`, `encrypt`, `decrypt`, `export_secret`, `epoch`. Cipher suite зафиксирован константой. 2-сторонний round-trip тест проходит.
- SQLCipher миграция (`veil-store/src/db.rs`): таблицы `mls_signer`, `mls_key_packages_local`, `mls_state` + колонка `conversations.crypto_mode` (через `ALTER ADD COLUMN`, идемпотентно).
- PostgreSQL миграция `008_mls.sql`: колонка `crypto_mode` с CHECK-констрейнтом, таблицы `mls_key_packages`, `mls_welcomes`, `mls_commits` с индексами и наглядным TTL-планом.
- Серверный пакет `internal/mls`: `Store` (батчевая публикация KP, атомарный consume через `DELETE … FOR UPDATE SKIP LOCKED`, append-only лог commits с `ErrEpochConflict` на 23505) и `Handler` с REST: `POST /v1/mls/keypackages`, `GET …/count`, `GET …/{user}/{device}`, `POST/GET/DELETE /v1/mls/welcomes`, `POST /v1/mls/commits`, `GET /v1/mls/commits/{conv}?after_epoch=N`. Интеграция с подписной middleware (`X-Veil-User/Timestamp/Signature`).
- Hub реализует `mls.Fanout` (стабы с slog) — клиенты пока подбирают welcomes/commits через REST на reconnect; перевод на отдельный envelope-вариант WS — следующий шаг.
- Tauri command implementations и renderer wrappers существуют, но не все
  зарегистрированы в runtime handler; это ещё не пользовательская функция.

### Что осталось

- HTTP-клиент в `veil-client` для подписанных REST-запросов к `/v1/mls/*` (сейчас клиент целиком работает поверх WS protobuf).
- Адаптер `MlsKeyStore` поверх `VeilDb` (сохранение `SignatureKeyPair` в SQLCipher).
- Ветвление `send_text`/`receive` в `veil-client/src/api.rs` по `crypto_mode` разговора.
- Зарегистрировать и связать существующие Tauri-команды; добавить отсутствующий
  `mls_upgrade_group`, UI-индикатор «MLS active» и кнопку Upgrade.
- Полноценный WS-канал `mls.welcome`/`mls.commit` (новый вариант `pb.Envelope`) вместо текущего log-стаба.
- Интеграционные тесты: catch-up Charlie оффлайн, авто-пополнение KP при count < 10, упорядоченное применение commits на трёх устройствах.
- До всего перечисленного: формализовать per-device identity и capability
  negotiation. Без этого MLS для Android/desktop multi-device не включается.

---

## Phase 7 — LiveKit звонки

**Текущее состояние:** протокольный фундамент заложен, но runtime звонков не
начат. `veil-proto/veil/v1/voice.proto` определяет запрос/ответ voice token,
`veil-client/build.rs` уже компилирует этот контракт, channel type `voice` и
push kind `KindCall` зарезервированы. Это не означает готовый signaling или
media path: `veil-voice`, LiveKit/coturn deployment, выдача токенов, WebRTC
permissions/lifecycle и E2EE media ещё отсутствуют и обязаны пройти отдельный
ADR/threat-model gate до включения микрофона или камеры.

1:1 + групповые войс-румы. E2EE через LiveKit insertable streams, ключи деривируются из MLS exporter secret (или sender-key chain) с меткой `"livekit-call-v1"`.

SFU видит только encrypted RTP. Ротация ключей при kick — нужно успеть до следующего фрейма, иначе отрезанный участник всё ещё слышит. Цель — < 1 RTT.

Desktop: `livekit-client` (npm), WebRTC в webview работает с `webrtc` фичей в `tauri.conf.json`.  
Mobile: `@livekit/react-native-client`. Android нужен foreground service для ongoing call. iOS — `AVAudioSession` config.

UI: Island-стиль, floating draggable CallView, те же материалы что и диалоги. Incoming call — toast с Accept/Decline. В группе — participant grid с glow-ring по амплитуде.

Compose: `livekit` + `coturn` (для ~10% за NAT). Codec: Opus + VP8. H.264 не трогать — patent surface и неровная поддержка в Tauri webview.

---

## Phase 8 — Полировка и релиз

**Статус:** security CI, dependency locks и fail-closed Windows release/signing
workflow уже есть. Без сертификата workflow не должен выпускать артефакт.
Visual regression, updater, полный signed matrix и public beta ещё не готовы.

- Grafana dashboard для метрик фаз 2-7, JSON в `grafana-dashboards/`
- Playwright visual regression baseline, запускается в CI на каждом PR
- Desktop: AppImage/.deb (Linux), .dmg (macOS), NSIS/MSI (Windows) через
  воспроизводимый `tauri build`; каждый публичный артефакт подписан
- Signed releases + Tauri updater (Ed25519)
- SECURITY.md: поддерживаемые версии, disclosure policy, threat model
- Android: reproducible signed AAB, internal track, crash-free/ANR monitoring
  без содержимого сообщений, ключей и стабильных user identifiers
- Release gate: desktop/mobile E2E, process-death/offline tests, restore drill,
  secret scan, dependency review и проверка отсутствия mock crypto

### Публичный сайт, документация и загрузки

Публичный продуктовый сайт и documentation/download surface являются
обязательным launch deliverable до public beta, а не необязательным маркетингом:

- отдельный статический product site знакомит с Veil, его native-only моделью,
  возможностями, ограничениями, E2EE/TOFU и self-hosting без преувеличений;
- versioned documentation содержит onboarding, account recovery, identity
  verification, server administration, threat model, privacy/disclosure policy
  и инструкции self-hosting/backup/upgrade;
- download surface публикует только подписанные desktop/mobile артефакты,
  release notes, SHA-256, signing-key information и reproducibility evidence;
- сайт не содержит аккаунты, сообщения, recovery flow, JS-криптографию или
  authenticated gateway session; assets/fonts self-hosted, third-party scripts
  и tracking отсутствуют, CSP и immutable versioned assets обязательны;
- существующая встроенная gateway landing/download page остаётся локальной
  страницей конкретного self-hosted instance и не подменяет канонический сайт
  продукта;
- браузерного клиента Veil не будет. Единственное узкое web-исключение — уже
  отделённый one-time Share Viewer с собственным ограниченным threat model; он
  никогда не становится web messenger и не получает account identity/session.

Компрометация сайта не должна позволять выдать изменённый клиент за Veil:
подпись приложения проверяется ОС, hashes/signing metadata дублируются в
GitHub release, а updater использует отдельную подписанную manifest chain.

### Локализация в конце разработки

Полная локализация выполняется в Phase 8, когда основная продуктовая IA
стабилизирована. Первый обязательный набор — `en` как canonical fallback и `ru`
как полноценно поддерживаемая локаль. Чтобы поздняя локализация не потребовала
переписывать протоколы, до Phase 8 сохраняются следующие правила:

- сервер возвращает стабильные machine-readable error/event codes; локализует
  их клиент, wire values, IDs, keys, origins и crypto labels не переводятся;
- новые UI-фразы не собираются конкатенацией из грамматических фрагментов;
  пользовательские имена/текст передаются отдельными variables и изолируются
  по направлению, но никогда не переводятся;
- trust-термины имеют единый glossary: `Not compared`, `Verified on this
  device`, `Identity changed`, `Current account`, `Recovery phrase` и
  `Phaseprint`; перевод не имеет права повышать заявленный trust state.

Финальная реализация:

1. Один versioned Fluent-compatible catalog contract для desktop, mobile,
   installer и публичных web surfaces; semantic keys, translator comments,
   plurals/cases, dates/numbers и accessibility labels.
2. Явный выбор языка в приложении, системная locale по умолчанию, offline
   bundled catalogs, deterministic English fallback и отсутствие remote
   translation/code loading.
3. Последовательный перенос onboarding → shell/chat → identity/settings →
   server/mobile → installer/site/docs без смешанного языка внутри одного flow.
4. CI проверяет missing/unused keys, variable parity и forbidden raw strings;
   pseudo-locale/long-text, `en`, `ru`, 125–200% scale и RTL/bidi isolation
   входят в component/visual/accessibility matrix.
5. Security review подтверждает, что локализация не меняет ACL/crypto decisions,
   не скрывает identity-change warnings и не вставляет переводы как HTML.

Локализация считается готовой только когда оба языка покрывают все release
flows, включая installer, recovery, errors, notifications, сайт и документацию;
частичный русский интерфейс не проходит public-beta gate.

---

## Открытые вопросы

- P2: persistent Tantivy index больше не нужен; RAM-only считается текущим решением
- P5: React Navigation + PagerView остаются текущей мобильной оболочкой;
  миграция на Expo Router допустима только при конкретной пользе
- P5: UnifiedPush-only либо опциональный FCM wake-up с generic encrypted payload?
- P6: per-device credential — стабильный opaque device ID; человекочитаемый
  label не входит в криптографическую identity и может меняться
- P6: окончательный MLS threshold определяется benchmark/ADR, а не числом из старого roadmap
- P7: свой coturn или внешний? → свой в compose, ради приватности
- P8: code signing certs (macOS/Windows) → нужны до public beta, отдельный бюджетный вопрос
- P8: Play Store internal/closed beta либо параллельный direct APK/F-Droid канал
